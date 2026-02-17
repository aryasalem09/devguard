use crate::config::Config;
use crate::core::RepoContext;
use crate::core::report::{Category, Issue, Severity};
use crate::providers::Provider;
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;

pub struct StripeProvider;

static STRIPE_LIVE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"sk_live_[0-9A-Za-z]{16,}").expect("valid stripe live regex"));
static STRIPE_TEST_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"sk_test_[0-9A-Za-z]{16,}").expect("valid stripe test regex"));

impl Provider for StripeProvider {
    fn name(&self) -> &'static str {
        "stripe"
    }

    fn is_enabled(&self, cfg: &Config) -> bool {
        cfg.providers.stripe.enabled
    }

    fn detect(&self, ctx: &RepoContext) -> bool {
        ctx.package_json_contains("\"stripe\"")
            || ctx.has_env_key("STRIPE_SECRET_KEY")
            || ctx.has_env_key("STRIPE_PUBLISHABLE_KEY")
    }

    fn run_checks(&self, ctx: &RepoContext, cfg: &Config) -> Vec<Issue> {
        let mut issues = Vec::new();
        let mut found_live = HashSet::new();
        let mut found_test = HashSet::new();

        for variable in &ctx.dotenv_vars {
            if STRIPE_LIVE_RE.is_match(&variable.value) {
                found_live.insert(variable.file.clone());
                if cfg.providers.stripe.warn_live_keys {
                    issues.push(
                        Issue::new(
                            Severity::Critical,
                            Category::Stripe,
                            "live Stripe key found in dotenv file",
                            "move live keys to deployment secrets and rotate exposed values",
                        )
                        .with_file(variable.file.clone())
                        .with_line(variable.line),
                    );
                }
            }

            if STRIPE_TEST_RE.is_match(&variable.value) {
                found_test.insert(variable.file.clone());
                issues.push(
                    Issue::new(
                        Severity::Warning,
                        Category::Stripe,
                        "test Stripe key found in dotenv file",
                        "keep test keys in local-only env files and out of source control",
                    )
                    .with_file(variable.file.clone())
                    .with_line(variable.line),
                );
            }
        }

        if !found_live.is_empty() && !found_test.is_empty() {
            issues.push(
                Issue::new(
                    Severity::Warning,
                    Category::Stripe,
                    "mixed Stripe modes detected",
                    "separate test and live credentials by environment",
                )
                .with_detail("both sk_live_* and sk_test_* were found across dotenv files"),
            );
        }

        issues
    }
}
