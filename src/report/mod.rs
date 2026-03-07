pub mod human;
pub mod json;
pub mod markdown;
pub mod sarif;

use crate::config::FailOn;
use crate::core::{Issue, Severity};
use crate::score::{self, PenaltyProfile, ScoreBreakdown};
use anyhow::{Context, Result};
use clap::ValueEnum;
use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

pub const REPORT_SCHEMA_VERSION: &str = "1";
pub const TOOL_NAME: &str = env!("CARGO_PKG_NAME");
pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ReportFormat {
    Human,
    Json,
    Markdown,
    Sarif,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RenderOptions {
    pub summary_only: bool,
    pub color: bool,
    pub github_step_summary: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ToolInfo {
    pub name: &'static str,
    pub version: &'static str,
}

impl Default for ToolInfo {
    fn default() -> Self {
        Self {
            name: TOOL_NAME,
            version: TOOL_VERSION,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Counts {
    pub error: usize,
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
                Severity::Error => counts.error += 1,
                Severity::Warning => counts.warning += 1,
                Severity::Info => counts.info += 1,
                Severity::Pass => counts.pass += 1,
            }
        }
        counts.total = issues.len();
        counts
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FinalReport {
    pub schema_version: &'static str,
    pub tool: ToolInfo,
    pub repository_path: String,
    pub score: u8,
    pub max_score: u8,
    pub label: String,
    pub min_score: u8,
    pub passed: bool,
    pub fail_on: FailOn,
    pub exit_reasons: Vec<String>,
    pub counts: Counts,
    pub scoring: ScoreBreakdown,
    pub issues: Vec<Issue>,
}

pub fn build_report(
    repository_path: &Path,
    issues: Vec<Issue>,
    min_score: u8,
    fail_on: FailOn,
) -> FinalReport {
    let scoring = score::calculate_breakdown(&issues, PenaltyProfile::default());
    let policy = score::evaluate_policy(scoring.final_score, &issues, min_score, fail_on);

    FinalReport {
        schema_version: REPORT_SCHEMA_VERSION,
        tool: ToolInfo::default(),
        repository_path: normalize_path(repository_path),
        score: scoring.final_score,
        max_score: score::MAX_SCORE,
        label: score::label_for_score(scoring.final_score).to_string(),
        min_score,
        passed: policy.passed,
        fail_on,
        exit_reasons: policy.reasons,
        counts: Counts::from_issues(&issues),
        scoring,
        issues,
    }
}

pub fn render(
    report: &FinalReport,
    format: ReportFormat,
    options: RenderOptions,
) -> Result<String> {
    match format {
        ReportFormat::Human => Ok(human::render(report, options)),
        ReportFormat::Json => json::render(report),
        ReportFormat::Markdown => Ok(markdown::render(report, options)),
        ReportFormat::Sarif => sarif::render(report),
    }
}

pub fn write_output(path: &Path, content: &str) -> Result<()> {
    fs::write(path, content).with_context(|| format!("failed writing {}", path.display()))?;
    Ok(())
}

pub fn write_github_step_summary(report: &FinalReport) -> Result<()> {
    let Ok(path) = std::env::var("GITHUB_STEP_SUMMARY") else {
        eprintln!("warning: GITHUB_STEP_SUMMARY is not set; skipping step summary output");
        return Ok(());
    };

    let content = markdown::render(
        report,
        RenderOptions {
            summary_only: true,
            color: false,
            github_step_summary: true,
        },
    );

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("failed opening {}", path))?;
    file.write_all(content.as_bytes())
        .with_context(|| format!("failed writing {}", path))?;
    file.write_all(b"\n")
        .with_context(|| format!("failed finalizing {}", path))?;
    Ok(())
}

pub fn issue_location(issue: &Issue) -> Option<String> {
    issue.location()
}

fn normalize_path(path: &Path) -> String {
    let raw = path.to_string_lossy().replace('\\', "/");
    raw.strip_prefix("//?/").unwrap_or(&raw).to_string()
}

#[cfg(test)]
pub(crate) fn sample_report() -> FinalReport {
    use crate::core::{Issue, Severity, rules};

    build_report(
        Path::new("/tmp/devguard-example"),
        vec![
            Issue::from_rule(
                rules::SECRET_AWS_ACCESS_KEY,
                Severity::Error,
                "AWS access key pattern detected",
                "revoke and rotate the key, then remove it from git history",
            )
            .with_file("config/secrets.env")
            .with_line(7),
            Issue::from_rule(
                rules::ENV_REQUIRED_VAR_MISSING,
                Severity::Warning,
                "missing required env var DATABASE_URL",
                "add DATABASE_URL to local dotenv files and CI environment settings",
            )
            .with_description("this key is listed in env.required but was not found"),
            Issue::from_rule(
                rules::GIT_DIRTY_TREE,
                Severity::Info,
                "working tree has changes",
                "commit or stash changes before running release checks",
            )
            .with_description("modified or untracked files were detected"),
            Issue::from_rule(
                rules::GIT_CLEAN_TREE,
                Severity::Pass,
                "working tree is clean",
                "no action needed",
            ),
        ],
        80,
        FailOn::Warning,
    )
}
