use crate::config::FailOn;
use colored::Colorize;
use serde::Serialize;
use std::fmt;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
    Info,
    Pass,
}

impl Severity {
    pub const ALL: [Self; 4] = [Self::Error, Self::Warning, Self::Info, Self::Pass];

    pub fn label(self) -> &'static str {
        match self {
            Self::Error => "ERROR",
            Self::Warning => "WARNING",
            Self::Info => "INFO",
            Self::Pass => "PASS",
        }
    }

    pub fn slug(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Info => "info",
            Self::Pass => "pass",
        }
    }

    pub fn meets_fail_on(self, fail_on: FailOn) -> bool {
        match fail_on {
            FailOn::None => false,
            FailOn::Error => matches!(self, Self::Error),
            FailOn::Warning => matches!(self, Self::Error | Self::Warning),
        }
    }

    pub fn colorized_label(self) -> String {
        match self {
            Self::Error => self.label().red().bold().to_string(),
            Self::Warning => self.label().yellow().bold().to_string(),
            Self::Info => self.label().blue().bold().to_string(),
            Self::Pass => self.label().green().bold().to_string(),
        }
    }

    pub fn sarif_level(self) -> Option<&'static str> {
        match self {
            Self::Error => Some("error"),
            Self::Warning => Some("warning"),
            Self::Info => Some("note"),
            Self::Pass => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Secrets,
    Env,
    Git,
    Supabase,
    Vercel,
    Stripe,
}

impl Category {
    pub const ALL: [Self; 6] = [
        Self::Secrets,
        Self::Env,
        Self::Git,
        Self::Supabase,
        Self::Vercel,
        Self::Stripe,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Secrets => "Secrets",
            Self::Env => "Env",
            Self::Git => "Git",
            Self::Supabase => "Supabase",
            Self::Vercel => "Vercel",
            Self::Stripe => "Stripe",
        }
    }

    pub fn slug(self) -> &'static str {
        match self {
            Self::Secrets => "secrets",
            Self::Env => "env",
            Self::Git => "git",
            Self::Supabase => "supabase",
            Self::Vercel => "vercel",
            Self::Stripe => "stripe",
        }
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RuleSpec {
    pub code: &'static str,
    pub rule_title: &'static str,
    pub category: Category,
}

impl RuleSpec {
    pub const fn new(code: &'static str, rule_title: &'static str, category: Category) -> Self {
        Self {
            code,
            rule_title,
            category,
        }
    }
}

pub mod rules {
    use super::{Category, RuleSpec};

    pub const SECRET_STRIPE_LIVE_PATTERN: RuleSpec = RuleSpec::new(
        "DG_SEC_001",
        "Committed Stripe live secret detected",
        Category::Secrets,
    );
    pub const SECRET_STRIPE_TEST_PATTERN: RuleSpec = RuleSpec::new(
        "DG_SEC_002",
        "Committed Stripe test secret detected",
        Category::Secrets,
    );
    pub const SECRET_VERCEL_TOKEN: RuleSpec = RuleSpec::new(
        "DG_SEC_003",
        "Committed Vercel token detected",
        Category::Secrets,
    );
    pub const SECRET_AWS_ACCESS_KEY: RuleSpec = RuleSpec::new(
        "DG_SEC_004",
        "Committed AWS access key detected",
        Category::Secrets,
    );
    pub const SECRET_PRIVATE_KEY: RuleSpec = RuleSpec::new(
        "DG_SEC_005",
        "Committed private key material detected",
        Category::Secrets,
    );
    pub const SECRET_SUPABASE_JWT: RuleSpec = RuleSpec::new(
        "DG_SEC_006",
        "Committed Supabase JWT-like secret detected",
        Category::Secrets,
    );

    pub const ENV_REQUIRED_VAR_MISSING: RuleSpec = RuleSpec::new(
        "DG_ENV_001",
        "Required environment variable is missing",
        Category::Env,
    );
    pub const ENV_EXAMPLE_MISSING_KEY: RuleSpec = RuleSpec::new(
        "DG_ENV_002",
        "Environment example file is missing an active key",
        Category::Env,
    );
    pub const ENV_EXAMPLE_STALE_KEY: RuleSpec = RuleSpec::new(
        "DG_ENV_003",
        "Environment example file contains a stale key",
        Category::Env,
    );
    pub const ENV_FORBIDDEN_FILE_TRACKED: RuleSpec = RuleSpec::new(
        "DG_ENV_004",
        "Forbidden environment file appears tracked",
        Category::Env,
    );
    pub const ENV_FORBIDDEN_FILE_PRESENT: RuleSpec = RuleSpec::new(
        "DG_ENV_005",
        "Forbidden environment file exists and should be secured",
        Category::Env,
    );

    pub const GIT_NOT_A_REPO: RuleSpec = RuleSpec::new(
        "DG_GIT_001",
        "Repository is not initialized as git",
        Category::Git,
    );
    pub const GIT_DIRTY_TREE: RuleSpec =
        RuleSpec::new("DG_GIT_002", "Working tree has changes", Category::Git);
    pub const GIT_CLEAN_TREE: RuleSpec =
        RuleSpec::new("DG_GIT_003", "Working tree is clean", Category::Git);
    pub const GIT_STATUS_UNAVAILABLE: RuleSpec =
        RuleSpec::new("DG_GIT_004", "Unable to read git status", Category::Git);
    pub const GIT_BRANCH_IDENTIFIED: RuleSpec =
        RuleSpec::new("DG_GIT_005", "Current branch is identified", Category::Git);
    pub const GIT_DETACHED_HEAD: RuleSpec = RuleSpec::new(
        "DG_GIT_006",
        "Repository is in detached HEAD state",
        Category::Git,
    );
    pub const GIT_HEAD_UNAVAILABLE: RuleSpec =
        RuleSpec::new("DG_GIT_007", "Unable to resolve git HEAD", Category::Git);
    pub const GIT_LARGE_FILE: RuleSpec = RuleSpec::new(
        "DG_GIT_008",
        "Large repository file detected",
        Category::Git,
    );

    pub const SUPABASE_PROVIDER_DISABLED: RuleSpec = RuleSpec::new(
        "DG_SUPABASE_001",
        "Supabase provider is disabled",
        Category::Supabase,
    );
    pub const SUPABASE_NOT_DETECTED: RuleSpec = RuleSpec::new(
        "DG_SUPABASE_002",
        "Supabase markers were not detected",
        Category::Supabase,
    );
    pub const SUPABASE_MIGRATIONS_DIR_MISSING: RuleSpec = RuleSpec::new(
        "DG_SUPABASE_003",
        "Supabase migrations directory is missing",
        Category::Supabase,
    );
    pub const SUPABASE_SQL_MIGRATIONS_MISSING: RuleSpec = RuleSpec::new(
        "DG_SUPABASE_004",
        "Supabase migrations directory has no SQL files",
        Category::Supabase,
    );
    pub const SUPABASE_REQUIRED_ENV_MISSING: RuleSpec = RuleSpec::new(
        "DG_SUPABASE_005",
        "Required Supabase environment variable is missing",
        Category::Supabase,
    );
    pub const SUPABASE_SERVICE_ROLE_IN_CLIENT: RuleSpec = RuleSpec::new(
        "DG_SUPABASE_006",
        "Supabase service role reference found in client code",
        Category::Supabase,
    );

    pub const VERCEL_JSON_ENV: RuleSpec = RuleSpec::new(
        "DG_VERCEL_001",
        "vercel.json contains committed environment keys",
        Category::Vercel,
    );
    pub const VERCEL_DIR_TRACKED: RuleSpec = RuleSpec::new(
        "DG_VERCEL_002",
        ".vercel directory appears tracked",
        Category::Vercel,
    );
    pub const VERCEL_DIR_PRESENT: RuleSpec = RuleSpec::new(
        "DG_VERCEL_003",
        ".vercel directory exists locally",
        Category::Vercel,
    );

    pub const STRIPE_LIVE_KEY_IN_DOTENV: RuleSpec = RuleSpec::new(
        "DG_STRIPE_001",
        "Live Stripe key found in dotenv file",
        Category::Stripe,
    );
    pub const STRIPE_TEST_KEY_IN_DOTENV: RuleSpec = RuleSpec::new(
        "DG_STRIPE_002",
        "Test Stripe key found in dotenv file",
        Category::Stripe,
    );
    pub const STRIPE_MIXED_MODES: RuleSpec = RuleSpec::new(
        "DG_STRIPE_003",
        "Mixed Stripe modes detected",
        Category::Stripe,
    );
}

#[derive(Debug, Clone, Serialize)]
pub struct Issue {
    pub code: &'static str,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub severity: Severity,
    pub category: Category,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    pub remediation: String,
    #[serde(skip)]
    pub weight_override: Option<u8>,
    #[serde(skip)]
    pub rule_title: &'static str,
}

impl Issue {
    pub fn from_rule(
        rule: RuleSpec,
        severity: Severity,
        title: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self {
            code: rule.code,
            title: title.into(),
            description: None,
            severity,
            category: rule.category,
            file: None,
            line: None,
            remediation: remediation.into(),
            weight_override: None,
            rule_title: rule.rule_title,
        }
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    pub fn with_file(mut self, file: impl Into<String>) -> Self {
        self.file = Some(file.into());
        self
    }

    pub fn with_line(mut self, line: usize) -> Self {
        self.line = Some(line);
        self
    }

    pub fn location(&self) -> Option<String> {
        match (&self.file, self.line) {
            (Some(file), Some(line)) => Some(format!("{}:{}", file, line)),
            (Some(file), None) => Some(file.clone()),
            _ => None,
        }
    }
}
