use crate::core::{Issue, Severity};
use crate::report::{FinalReport, RenderOptions, issue_location};
use crate::score::PenaltyProfile;

pub fn render(report: &FinalReport, options: RenderOptions) -> String {
    let mut sections = Vec::new();
    sections.push(format!(
        "DevGuard {} | {}",
        report.tool.version, report.repository_path
    ));
    sections.push(format!(
        "Score: {}/{} ({})",
        report.score, report.max_score, report.label
    ));
    sections.push(format!(
        "Policy: min-score {} | fail-on {} | status {}",
        report.min_score,
        report.fail_on,
        if report.passed { "PASS" } else { "FAIL" }
    ));

    if !report.exit_reasons.is_empty() {
        sections.push(format!("Reasons: {}", report.exit_reasons.join("; ")));
    }

    sections.push(format!(
        "Counts: error {} | warning {} | info {} | pass {} | total {}",
        report.counts.error,
        report.counts.warning,
        report.counts.info,
        report.counts.pass,
        report.counts.total
    ));
    sections.push(format!(
        "Penalty totals: error -{} | warning -{} | info -{} | total -{}",
        report.scoring.by_severity.error.penalty,
        report.scoring.by_severity.warning.penalty,
        report.scoring.by_severity.info.penalty,
        report.scoring.total_deductions
    ));

    if options.summary_only {
        sections.push(render_summary_issues(report));
        return sections.join("\n") + "\n";
    }

    let mut grouped = Vec::new();
    for severity in Severity::ALL {
        let issues = report
            .issues
            .iter()
            .filter(|issue| issue.severity == severity)
            .collect::<Vec<_>>();
        if issues.is_empty() {
            continue;
        }

        grouped.push(String::new());
        grouped.push(format!(
            "{} ({})",
            render_severity(severity, options.color),
            issues.len()
        ));

        for issue in issues {
            grouped.push(render_issue(issue));
        }
    }

    if grouped.is_empty() {
        sections.push("No issues detected.".to_string());
    } else {
        sections.push(grouped.join("\n"));
    }

    sections.join("\n") + "\n"
}

fn render_summary_issues(report: &FinalReport) -> String {
    let mut lines = Vec::new();
    let visible = report
        .issues
        .iter()
        .filter(|issue| issue.severity != Severity::Pass)
        .take(10)
        .collect::<Vec<_>>();

    if visible.is_empty() {
        lines.push("Issues: none".to_string());
        return lines.join("\n");
    }

    lines.push("Top issues:".to_string());
    for issue in &visible {
        let profile = PenaltyProfile::default();
        let (penalty, _) = profile.penalty_for(issue);
        let location = issue_location(issue)
            .map(|location| format!(" ({})", location))
            .unwrap_or_default();
        lines.push(format!(
            "- [{}] [{}] {} (-{}){}",
            issue.severity.label(),
            issue.code,
            issue.title,
            penalty,
            location
        ));
    }

    let remaining = report
        .issues
        .iter()
        .filter(|issue| issue.severity != Severity::Pass)
        .count()
        .saturating_sub(visible.len());
    if remaining > 0 {
        lines.push(format!("+ {} more issue(s)", remaining));
    }

    lines.join("\n")
}

fn render_issue(issue: &Issue) -> String {
    let profile = PenaltyProfile::default();
    let (penalty, _) = profile.penalty_for(issue);
    let mut lines = Vec::new();
    let location = issue_location(issue)
        .map(|location| format!(" ({})", location))
        .unwrap_or_default();
    lines.push(format!(
        "- [{}] [{}] ({}) {}{}{}",
        issue.severity.label(),
        issue.code,
        issue.category,
        issue.title,
        if penalty > 0 {
            format!(" [-{}]", penalty)
        } else {
            String::new()
        },
        location
    ));
    lines.push(format!("  remediation: {}", issue.remediation));
    if let Some(description) = &issue.description {
        lines.push(format!("  details: {}", description));
    }
    lines.join("\n")
}

fn render_severity(severity: Severity, color: bool) -> String {
    if color {
        severity.colorized_label()
    } else {
        severity.label().to_string()
    }
}
