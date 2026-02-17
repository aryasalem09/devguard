use crate::config::{Config, FailOn};
use colored::Colorize;
use serde::Serialize;
use std::fmt;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Hash)]
pub enum Severity {
    Critical,
    Warning,
    Info,
    Pass,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "CRITICAL",
            Self::Warning => "WARNING",
            Self::Info => "INFO",
            Self::Pass => "PASS",
        }
    }

    pub fn meets_fail_on(self, fail_on: FailOn) -> bool {
        match fail_on {
            FailOn::None => false,
            FailOn::Error => matches!(self, Self::Critical),
            FailOn::Warning => matches!(self, Self::Critical | Self::Warning),
        }
    }

    fn colored(self) -> String {
        match self {
            Self::Critical => self.as_str().red().bold().to_string(),
            Self::Warning => self.as_str().yellow().bold().to_string(),
            Self::Info => self.as_str().blue().bold().to_string(),
            Self::Pass => self.as_str().green().bold().to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Hash)]
pub enum Category {
    Secrets,
    Env,
    Git,
    Supabase,
    Vercel,
    Stripe,
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Secrets => write!(f, "Secrets"),
            Self::Env => write!(f, "Env"),
            Self::Git => write!(f, "Git"),
            Self::Supabase => write!(f, "Supabase"),
            Self::Vercel => write!(f, "Vercel"),
            Self::Stripe => write!(f, "Stripe"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Issue {
    pub severity: Severity,
    pub category: Category,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    pub hint: String,
}

impl Issue {
    pub fn new(
        severity: Severity,
        category: Category,
        title: impl Into<String>,
        hint: impl Into<String>,
    ) -> Self {
        Self {
            severity,
            category,
            title: title.into(),
            detail: None,
            file: None,
            line: None,
            hint: hint.into(),
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
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
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Counts {
    pub critical: usize,
    pub warning: usize,
    pub info: usize,
    pub pass: usize,
    pub total: usize,
}

impl Counts {
    pub fn from_issues(issues: &[Issue]) -> Self {
        let mut counts = Self::default();
        for issue in issues {
            match issue.severity {
                Severity::Critical => counts.critical += 1,
                Severity::Warning => counts.warning += 1,
                Severity::Info => counts.info += 1,
                Severity::Pass => counts.pass += 1,
            }
        }
        counts.total = issues.len();
        counts
    }
}

#[derive(Debug, Clone)]
pub struct ExitStatus {
    pub ok: bool,
    pub reasons: Vec<String>,
}

impl ExitStatus {
    pub fn reason_line(&self) -> String {
        self.reasons.join("; ")
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ConfigSummary {
    pub fail_on: FailOn,
    pub min_score: u8,
}

#[derive(Debug, Clone)]
pub struct FinalReport {
    pub score: u8,
    pub label: String,
    pub counts: Counts,
    pub issues: Vec<Issue>,
    pub config: ConfigSummary,
    pub exit: ExitStatus,
}

#[derive(Debug, Clone, Serialize)]
pub struct JsonReport {
    pub score: u8,
    pub label: String,
    pub counts: Counts,
    pub issues: Vec<Issue>,
    pub config: ConfigSummary,
}

impl From<&FinalReport> for JsonReport {
    fn from(report: &FinalReport) -> Self {
        Self {
            score: report.score,
            label: report.label.clone(),
            counts: report.counts.clone(),
            issues: report.issues.clone(),
            config: report.config.clone(),
        }
    }
}

pub fn evaluate_exit(score: u8, issues: &[Issue], cfg: &Config) -> ExitStatus {
    let mut reasons = Vec::new();

    if score < cfg.general.min_score {
        reasons.push(format!(
            "score {} is below min_score {}",
            score, cfg.general.min_score
        ));
    }

    if cfg.general.fail_on != FailOn::None
        && issues
            .iter()
            .any(|issue| issue.severity.meets_fail_on(cfg.general.fail_on))
    {
        reasons.push(match cfg.general.fail_on {
            FailOn::Warning => "found warning-or-higher issues".to_string(),
            FailOn::Error => "found critical issues".to_string(),
            FailOn::None => String::new(),
        });
    }

    ExitStatus {
        ok: reasons.is_empty(),
        reasons,
    }
}

pub fn print_human(report: &FinalReport) {
    println!("Repo Health Score: {}/100 ({})", report.score, report.label);

    for severity in [Severity::Critical, Severity::Warning, Severity::Info] {
        let grouped: Vec<&Issue> = report
            .issues
            .iter()
            .filter(|issue| issue.severity == severity)
            .collect();

        if grouped.is_empty() {
            continue;
        }

        println!();
        println!("{} ({})", severity.colored(), grouped.len());

        for issue in grouped {
            let location = match (&issue.file, issue.line) {
                (Some(file), Some(line)) => format!(" - {}:{}", file, line),
                (Some(file), None) => format!(" - {}", file),
                _ => String::new(),
            };

            println!(
                "[{}] ({}) {}{}",
                issue.severity.as_str(),
                issue.category,
                issue.title,
                location
            );
            println!("-> hint: {}", issue.hint);
            if let Some(detail) = &issue.detail {
                println!("details: {}", detail);
            }
        }
    }

    println!();
    if report.exit.ok {
        println!("exit: OK");
    } else {
        println!("exit: FAILED ({})", report.exit.reason_line());
    }
}
