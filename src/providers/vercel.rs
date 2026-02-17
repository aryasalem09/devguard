use crate::config::Config;
use crate::core::RepoContext;
use crate::core::report::{Category, Issue, Severity};
use crate::providers::Provider;
use crate::utils::{fs as fs_utils, git as git_utils};
use serde_json::Value;
use std::fs;
use std::path::Path;

pub struct VercelProvider;

impl Provider for VercelProvider {
    fn name(&self) -> &'static str {
        "vercel"
    }

    fn is_enabled(&self, cfg: &Config) -> bool {
        cfg.providers.vercel.enabled
    }

    fn detect(&self, ctx: &RepoContext) -> bool {
        ctx.repo_root.join("vercel.json").is_file()
            || ctx.has_vercel_dir
            || ctx.package_json_contains("\"vercel\"")
    }

    fn run_checks(&self, ctx: &RepoContext, _cfg: &Config) -> Vec<Issue> {
        let mut issues = Vec::new();

        let vercel_json = ctx.repo_root.join("vercel.json");
        if let Some(value) = parse_vercel_json(&vercel_json)
            && contains_key_recursive(&value, "env")
        {
            issues.push(
                Issue::new(
                    Severity::Info,
                    Category::Vercel,
                    "vercel.json contains env keys",
                    "prefer Vercel dashboard environment variables instead of committed env fields",
                )
                .with_file(fs_utils::relative_path(&ctx.repo_root, &vercel_json)),
            );
        }

        let dot_vercel = ctx.repo_root.join(".vercel");
        if dot_vercel.exists() {
            let tracked = if let Some(repo) = &ctx.git_repo {
                git_utils::has_tracked_prefix(repo, ".vercel").ok()
            } else {
                None
            };

            match tracked {
                Some(true) => issues.push(
                    Issue::new(
                        Severity::Warning,
                        Category::Vercel,
                        ".vercel directory appears tracked",
                        "remove .vercel from git and add it to .gitignore",
                    )
                    .with_file(fs_utils::relative_path(&ctx.repo_root, &dot_vercel)),
                ),
                Some(false) => {}
                None => issues.push(
                    Issue::new(
                        Severity::Info,
                        Category::Vercel,
                        ".vercel directory exists locally",
                        "confirm .vercel is gitignored to avoid leaking local metadata",
                    )
                    .with_file(fs_utils::relative_path(&ctx.repo_root, &dot_vercel)),
                ),
            }
        }

        issues
    }
}

fn contains_key_recursive(value: &Value, key: &str) -> bool {
    match value {
        Value::Object(map) => {
            if map.contains_key(key) {
                return true;
            }
            map.values().any(|child| contains_key_recursive(child, key))
        }
        Value::Array(items) => items.iter().any(|child| contains_key_recursive(child, key)),
        _ => false,
    }
}

fn parse_vercel_json(path: &Path) -> Option<Value> {
    if !path.is_file() {
        return None;
    }

    let raw = match fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(_) => return None,
    };

    serde_json::from_str::<Value>(&raw).ok()
}
