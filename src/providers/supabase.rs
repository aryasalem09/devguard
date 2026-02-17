use crate::config::Config;
use crate::core::RepoContext;
use crate::core::report::{Category, Issue, Severity};
use crate::providers::Provider;
use crate::utils::fs::{is_likely_binary, relative_path};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;
use std::fs;
use walkdir::WalkDir;

pub struct SupabaseProvider;

static SERVICE_ROLE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(service_role|SUPABASE_SERVICE_ROLE_KEY|SUPABASE_SERVICE_ROLE)\b")
        .expect("valid supabase service role regex")
});

impl Provider for SupabaseProvider {
    fn name(&self) -> &'static str {
        "supabase"
    }

    fn is_enabled(&self, cfg: &Config) -> bool {
        cfg.providers.supabase.enabled
    }

    fn detect(&self, ctx: &RepoContext) -> bool {
        ctx.repo_root.join("supabase/config.toml").exists()
            || ctx.has_supabase_dir
            || ctx.package_json_contains("@supabase/supabase-js")
    }

    fn run_checks(&self, ctx: &RepoContext, cfg: &Config) -> Vec<Issue> {
        let mut issues = Vec::new();

        if cfg.providers.supabase.require_migrations {
            let migrations_dir = ctx.repo_root.join(&cfg.providers.supabase.migrations_dir);
            if !migrations_dir.is_dir() {
                issues.push(
                    Issue::new(
                        Severity::Warning,
                        Category::Supabase,
                        "missing migrations directory",
                        format!(
                            "create {} and commit SQL migration files",
                            cfg.providers.supabase.migrations_dir
                        ),
                    )
                    .with_detail("this helps keep schema changes reproducible"),
                );
            } else {
                let has_sql_file = WalkDir::new(&migrations_dir)
                    .into_iter()
                    .filter_map(Result::ok)
                    .any(|entry| {
                        entry.file_type().is_file()
                            && entry
                                .path()
                                .extension()
                                .map(|ext| ext.to_string_lossy().eq_ignore_ascii_case("sql"))
                                .unwrap_or(false)
                    });

                if !has_sql_file {
                    issues.push(
                        Issue::new(
                            Severity::Warning,
                            Category::Supabase,
                            "no SQL migration files found",
                            "add at least one .sql migration file",
                        )
                        .with_file(relative_path(&ctx.repo_root, &migrations_dir)),
                    );
                }
            }
        }

        if cfg.providers.supabase.forbid_service_role_in_client {
            issues.extend(scan_frontend_for_service_role(ctx, cfg));
        }

        for key in ["SUPABASE_URL", "SUPABASE_ANON_KEY"] {
            if cfg.env.required.iter().any(|required| required == key) && !ctx.has_env_key(key) {
                issues.push(
                    Issue::new(
                        Severity::Warning,
                        Category::Supabase,
                        format!("missing required Supabase env var {}", key),
                        format!("add {} to local env files and CI", key),
                    )
                    .with_detail(
                        "provider check expected this key because it is listed in env.required",
                    ),
                );
            }
        }

        issues
    }
}

fn scan_frontend_for_service_role(ctx: &RepoContext, cfg: &Config) -> Vec<Issue> {
    let mut issues = Vec::new();
    let mut seen = HashSet::new();
    let max_bytes = cfg.scan.max_file_size_kb * 1024;

    for root in ["src", "app", "pages"] {
        let path = ctx.repo_root.join(root);
        if !path.is_dir() {
            continue;
        }

        for entry in WalkDir::new(&path).into_iter().filter_map(Result::ok) {
            if !entry.file_type().is_file() {
                continue;
            }

            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(_) => continue,
            };
            if metadata.len() > max_bytes {
                continue;
            }

            let bytes = match fs::read(entry.path()) {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };
            if is_likely_binary(&bytes) {
                continue;
            }

            let content = String::from_utf8_lossy(&bytes);
            for hit in SERVICE_ROLE_RE.find_iter(&content) {
                let line = line_number(&content, hit.start());
                let relative_file = relative_path(&ctx.repo_root, entry.path());
                let dedupe_key = format!("{}:{}", relative_file, line);
                if !seen.insert(dedupe_key) {
                    continue;
                }

                issues.push(
                    Issue::new(
                        Severity::Critical,
                        Category::Supabase,
                        "service role reference found in client code",
                        "remove service role access from client bundles and use a secure backend endpoint",
                    )
                    .with_file(relative_file)
                    .with_line(line),
                );
            }
        }
    }

    issues
}

fn line_number(content: &str, byte_index: usize) -> usize {
    content[..byte_index]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1
}
