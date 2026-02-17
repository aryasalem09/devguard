pub mod report;
pub mod scanner;
pub mod score;

use crate::config::Config;
use crate::core::report::{Category, FinalReport, Issue, Severity};
use crate::providers;
use crate::utils::{fs as fs_utils, git as git_utils};
use anyhow::{Context, Result, bail};
use git2::Repository;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::{DirEntry, WalkDir};

#[derive(Debug, Clone)]
pub struct DotenvVar {
    pub value: String,
    pub file: String,
    pub line: usize,
}

pub struct RepoContext {
    pub repo_root: PathBuf,
    pub package_json: Option<String>,
    pub dotenv_vars: Vec<DotenvVar>,
    pub dotenv_keys: HashSet<String>,
    pub git_repo: Option<Repository>,
    pub has_supabase_dir: bool,
    pub has_vercel_dir: bool,
}

impl RepoContext {
    pub fn build(repo_root: &Path, cfg: &Config) -> Result<Self> {
        if !repo_root.exists() {
            bail!("path does not exist: {}", repo_root.display());
        }
        if !repo_root.is_dir() {
            bail!("path is not a directory: {}", repo_root.display());
        }

        let repo_root = repo_root
            .canonicalize()
            .with_context(|| format!("failed to canonicalize {}", repo_root.display()))?;

        let package_json = fs::read_to_string(repo_root.join("package.json")).ok();

        let mut dotenv_vars = Vec::new();
        let mut dotenv_keys = HashSet::new();
        for rel_path in &cfg.env.dotenv_files {
            let path = repo_root.join(rel_path);
            if !path.is_file() {
                continue;
            }

            let content = match fs::read_to_string(&path) {
                Ok(content) => content,
                Err(_) => continue,
            };

            for entry in fs_utils::parse_dotenv(&content) {
                dotenv_keys.insert(entry.key.clone());
                dotenv_vars.push(DotenvVar {
                    value: entry.value,
                    file: fs_utils::relative_path(&repo_root, &path),
                    line: entry.line,
                });
            }
        }

        Ok(Self {
            repo_root: repo_root.clone(),
            package_json,
            dotenv_vars,
            dotenv_keys,
            git_repo: git_utils::discover_repo(&repo_root),
            has_supabase_dir: repo_root.join("supabase").is_dir(),
            has_vercel_dir: repo_root.join(".vercel").is_dir(),
        })
    }

    pub fn package_json_contains(&self, needle: &str) -> bool {
        self.package_json
            .as_ref()
            .is_some_and(|content| content.contains(needle))
    }

    pub fn has_env_key(&self, key: &str) -> bool {
        self.dotenv_keys.contains(key) || std::env::var_os(key).is_some()
    }

    pub fn tracked_status(&self, path: &Path) -> Option<bool> {
        let repo = self.git_repo.as_ref()?;
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.repo_root.join(path)
        };
        git_utils::is_path_tracked(repo, &self.repo_root, &absolute).ok()
    }
}

#[derive(Debug, Clone, Copy)]
pub enum RunProfile {
    Full,
    SecretsOnly,
    EnvOnly,
    GitOnly,
    SupabaseVerify { force: bool },
}

pub fn run_checks(repo_root: &Path, cfg: &Config, profile: RunProfile) -> Result<FinalReport> {
    let ctx = RepoContext::build(repo_root, cfg)?;
    let mut issues = Vec::new();

    if matches!(
        profile,
        RunProfile::Full | RunProfile::SecretsOnly | RunProfile::SupabaseVerify { .. }
    ) {
        issues.extend(scanner::scan_secrets(&ctx, cfg));
    }

    if matches!(
        profile,
        RunProfile::Full | RunProfile::EnvOnly | RunProfile::SupabaseVerify { .. }
    ) {
        issues.extend(run_env_checks(&ctx, cfg));
    }

    if matches!(profile, RunProfile::Full | RunProfile::GitOnly) {
        issues.extend(run_git_checks(&ctx, cfg));
    }

    issues.extend(run_provider_checks(&ctx, cfg, profile));
    dedupe_issues(&mut issues);
    sort_issues(&mut issues);

    let score = score::calculate_score(&issues);
    let label = score::label_for_score(score).to_string();
    let counts = report::Counts::from_issues(&issues);
    let exit = report::evaluate_exit(score, &issues, cfg);

    Ok(FinalReport {
        score,
        label,
        counts,
        issues,
        config: report::ConfigSummary {
            fail_on: cfg.general.fail_on,
            min_score: cfg.general.min_score,
        },
        exit,
    })
}

fn run_provider_checks(ctx: &RepoContext, cfg: &Config, profile: RunProfile) -> Vec<Issue> {
    let mut issues = Vec::new();

    for provider in providers::all_providers() {
        match profile {
            RunProfile::Full => {
                if provider.is_enabled(cfg) && provider.detect(ctx) {
                    issues.extend(provider.run_checks(ctx, cfg));
                }
            }
            RunProfile::SupabaseVerify { force } => {
                if provider.name() != "supabase" {
                    continue;
                }

                if !provider.is_enabled(cfg) {
                    issues.push(Issue::new(
                        Severity::Info,
                        Category::Supabase,
                        "supabase provider disabled in config",
                        "set [providers.supabase].enabled = true to run supabase checks",
                    ));
                } else if !provider.detect(ctx) && !force {
                    issues.push(Issue::new(
                        Severity::Info,
                        Category::Supabase,
                        "supabase not detected",
                        "no supabase project markers found (use --force to run anyway)",
                    ));
                } else {
                    issues.extend(provider.run_checks(ctx, cfg));
                }
            }
            RunProfile::SecretsOnly | RunProfile::EnvOnly | RunProfile::GitOnly => {}
        }
    }

    issues
}

fn run_env_checks(ctx: &RepoContext, cfg: &Config) -> Vec<Issue> {
    let mut issues = Vec::new();

    for required_key in &cfg.env.required {
        if !ctx.has_env_key(required_key) {
            issues.push(Issue::new(
                Severity::Warning,
                Category::Env,
                format!("missing required env var {}", required_key),
                format!(
                    "add {} to local dotenv files and CI environment settings",
                    required_key
                ),
            ));
        }
    }

    let env_keys: HashSet<String> = ctx.dotenv_keys.iter().cloned().collect();
    let (example_keys, has_example_files) = collect_example_keys(ctx, cfg);
    if has_example_files {
        let mut missing_from_examples: Vec<String> =
            env_keys.difference(&example_keys).cloned().collect();
        missing_from_examples.sort();
        for key in missing_from_examples {
            issues.push(
                Issue::new(
                    Severity::Warning,
                    Category::Env,
                    format!("env example missing key {}", key),
                    "add this key to .env.example or .env.template",
                )
                .with_detail("the key exists in dotenv files but not in example files"),
            );
        }

        let mut stale_example_keys: Vec<String> =
            example_keys.difference(&env_keys).cloned().collect();
        stale_example_keys.sort();
        for key in stale_example_keys {
            issues.push(
                Issue::new(
                    Severity::Warning,
                    Category::Env,
                    format!(
                        "example file contains key {} not found in dotenv files",
                        key
                    ),
                    "either add this key to active dotenv files or remove stale example entries",
                )
                .with_detail("keeping example files aligned avoids onboarding and CI drift"),
            );
        }
    }

    issues.extend(check_forbidden_env_files(ctx, cfg));
    issues
}

fn run_git_checks(ctx: &RepoContext, cfg: &Config) -> Vec<Issue> {
    let mut issues = Vec::new();

    let Some(repo) = &ctx.git_repo else {
        issues.push(Issue::new(
            Severity::Info,
            Category::Git,
            "not a git repo",
            "initialize git to enable repository hygiene checks",
        ));
        return issues;
    };

    match git_utils::is_working_tree_dirty(repo) {
        Ok(true) => issues.push(
            Issue::new(
                Severity::Info,
                Category::Git,
                "working tree has changes",
                "commit or stash changes before running release checks",
            )
            .with_detail("modified or untracked files were detected"),
        ),
        Ok(false) => issues.push(Issue::new(
            Severity::Pass,
            Category::Git,
            "working tree is clean",
            "no action needed",
        )),
        Err(err) => issues.push(
            Issue::new(
                Severity::Info,
                Category::Git,
                "unable to read git status",
                "run `git status` manually to inspect repository state",
            )
            .with_detail(err.to_string()),
        ),
    }

    match repo.head() {
        Ok(head) if head.is_branch() => {
            let branch = head.shorthand().unwrap_or("unknown");
            issues.push(
                Issue::new(
                    Severity::Pass,
                    Category::Git,
                    format!("current branch: {}", branch),
                    "no action needed",
                )
                .with_detail("head points to a named branch"),
            );
        }
        Ok(_) => issues.push(Issue::new(
            Severity::Warning,
            Category::Git,
            "detached HEAD state",
            "check out a branch before regular development or release work",
        )),
        Err(err) => issues.push(
            Issue::new(
                Severity::Info,
                Category::Git,
                "unable to resolve HEAD",
                "run `git rev-parse --abbrev-ref HEAD` manually",
            )
            .with_detail(err.to_string()),
        ),
    }

    let large_file_threshold: u64 = 5 * 1024 * 1024;
    for entry in WalkDir::new(&ctx.repo_root)
        .into_iter()
        .filter_entry(|entry| should_visit(entry, &cfg.scan.exclude))
        .filter_map(Result::ok)
    {
        if !entry.file_type().is_file() {
            continue;
        }

        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };

        if metadata.len() <= large_file_threshold {
            continue;
        }

        issues.push(
            Issue::new(
                Severity::Warning,
                Category::Git,
                "large file detected (>5MB)",
                "consider git-lfs or artifact storage for large files",
            )
            .with_file(fs_utils::relative_path(&ctx.repo_root, entry.path()))
            .with_detail(format!(
                "size: {:.2} MB",
                metadata.len() as f64 / (1024.0 * 1024.0)
            )),
        );
    }

    issues
}

fn check_forbidden_env_files(ctx: &RepoContext, cfg: &Config) -> Vec<Issue> {
    let mut issues = Vec::new();
    let forbidden_files: HashSet<String> = cfg
        .env
        .forbid_commit
        .iter()
        .map(|name| name.to_ascii_lowercase())
        .collect();

    for entry in WalkDir::new(&ctx.repo_root)
        .into_iter()
        .filter_entry(|entry| should_visit(entry, &cfg.scan.exclude))
        .filter_map(Result::ok)
    {
        if !entry.file_type().is_file() {
            continue;
        }

        let file_name = entry.file_name().to_string_lossy().to_ascii_lowercase();
        if !forbidden_files.contains(&file_name) {
            continue;
        }

        let relative_file = fs_utils::relative_path(&ctx.repo_root, entry.path());
        match ctx.tracked_status(entry.path()) {
            Some(true) => issues.push(
                Issue::new(
                    Severity::Critical,
                    Category::Env,
                    "forbidden env file appears tracked",
                    "remove it from git index and add the path to .gitignore",
                )
                .with_file(relative_file),
            ),
            Some(false) => {}
            None => issues.push(
                Issue::new(
                    Severity::Critical,
                    Category::Env,
                    "forbidden env file exists",
                    "remove this file or secure it before sharing the repository",
                )
                .with_file(relative_file)
                .with_detail("git tracking status could not be verified"),
            ),
        }
    }

    issues
}

fn collect_example_keys(ctx: &RepoContext, cfg: &Config) -> (HashSet<String>, bool) {
    let mut keys = HashSet::new();
    let mut found_any = false;

    for rel_path in &cfg.env.example_files {
        let path = ctx.repo_root.join(rel_path);
        if !path.is_file() {
            continue;
        }

        found_any = true;
        let content = match fs::read_to_string(&path) {
            Ok(content) => content,
            Err(_) => continue,
        };

        for entry in fs_utils::parse_dotenv(&content) {
            keys.insert(entry.key);
        }
    }

    (keys, found_any)
}

fn should_visit(entry: &DirEntry, excludes: &[String]) -> bool {
    if !entry.file_type().is_dir() {
        return true;
    }

    let dir_name = entry.file_name().to_string_lossy();
    !excludes
        .iter()
        .any(|excluded| excluded.eq_ignore_ascii_case(&dir_name))
}

fn dedupe_issues(issues: &mut Vec<Issue>) {
    let mut seen = HashSet::new();
    issues.retain(|issue| {
        let key = format!(
            "{:?}|{:?}|{}|{:?}|{:?}",
            issue.severity, issue.category, issue.title, issue.file, issue.line
        );
        seen.insert(key)
    });
}

fn sort_issues(issues: &mut [Issue]) {
    issues.sort_by(|a, b| {
        severity_rank(a.severity)
            .cmp(&severity_rank(b.severity))
            .then(a.category.to_string().cmp(&b.category.to_string()))
            .then(a.file.cmp(&b.file))
            .then(a.line.cmp(&b.line))
            .then(a.title.cmp(&b.title))
    });
}

fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 0,
        Severity::Warning => 1,
        Severity::Info => 2,
        Severity::Pass => 3,
    }
}
