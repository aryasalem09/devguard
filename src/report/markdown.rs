use crate::core::Category;
use crate::report::{FinalReport, RenderOptions, issue_location};

pub fn render(report: &FinalReport, options: RenderOptions) -> String {
    let mut lines = Vec::new();

    lines.push("## DevGuard Summary".to_string());
    lines.push(String::new());
    lines.push("| Field | Value |".to_string());
    lines.push("| --- | --- |".to_string());
    lines.push(format!(
        "| Tool | `{}` {} |",
        report.tool.name, report.tool.version
    ));
    lines.push(format!(
        "| Repository | `{}` |",
        escape_cell(&report.repository_path)
    ));
    lines.push(format!(
        "| Score | **{}/{} ({})** |",
        report.score, report.max_score, report.label
    ));
    lines.push(format!("| Min score | `{}` |", report.min_score));
    lines.push(format!("| Fail on | `{}` |", report.fail_on));
    lines.push(format!(
        "| Status | **{}** |",
        if report.passed { "pass" } else { "fail" }
    ));

    lines.push(String::new());
    lines.push("### Counts".to_string());
    lines.push(String::new());
    lines.push("| Severity | Count | Penalty |".to_string());
    lines.push("| --- | ---: | ---: |".to_string());
    lines.push(format!(
        "| error | {} | {} |",
        report.counts.error, report.scoring.by_severity.error.penalty
    ));
    lines.push(format!(
        "| warning | {} | {} |",
        report.counts.warning, report.scoring.by_severity.warning.penalty
    ));
    lines.push(format!(
        "| info | {} | {} |",
        report.counts.info, report.scoring.by_severity.info.penalty
    ));
    lines.push(format!(
        "| pass | {} | {} |",
        report.counts.pass, report.scoring.by_severity.pass.penalty
    ));
    lines.push(format!(
        "| total deductions | {} | {} |",
        report.scoring.deductions.len(),
        report.scoring.total_deductions
    ));

    if !report.exit_reasons.is_empty() {
        lines.push(String::new());
        lines.push("### Failure Reasons".to_string());
        lines.push(String::new());
        for reason in &report.exit_reasons {
            lines.push(format!("- {}", reason));
        }
    }

    lines.push(String::new());
    lines.push("### Scoring".to_string());
    lines.push(String::new());
    lines.push(format!("- Start at `{}`.", report.scoring.starting_score));
    lines.push(format!(
        "- Weighted deductions total `{}`.",
        report.scoring.total_deductions
    ));
    lines.push(format!(
        "- Default weights: info `{}`, warning `{}`, error `{}`.",
        report.scoring.weights.info, report.scoring.weights.warning, report.scoring.weights.error
    ));
    if options.github_step_summary {
        lines.push("- This summary is optimized for `$GITHUB_STEP_SUMMARY`.".to_string());
    }

    let visible_deductions = if options.summary_only {
        report
            .scoring
            .deductions
            .iter()
            .take(10)
            .collect::<Vec<_>>()
    } else {
        report.scoring.deductions.iter().collect::<Vec<_>>()
    };
    if visible_deductions.is_empty() {
        lines.push("- No score deductions were applied.".to_string());
    } else {
        for deduction in &visible_deductions {
            lines.push(format!(
                "- `{}` [{} / {}] {} (`-{}`)",
                deduction.code,
                deduction.severity.slug(),
                deduction.category.slug(),
                deduction.title,
                deduction.penalty
            ));
        }
    }
    if options.summary_only && report.scoring.deductions.len() > visible_deductions.len() {
        lines.push(format!(
            "- {} additional deduction(s) omitted from summary.",
            report.scoring.deductions.len() - visible_deductions.len()
        ));
    }

    lines.push(String::new());
    lines.push("### Issues by Category".to_string());
    for category in Category::ALL {
        let issues = report
            .issues
            .iter()
            .filter(|issue| issue.category == category)
            .collect::<Vec<_>>();
        if issues.is_empty() {
            continue;
        }

        lines.push(String::new());
        lines.push(format!("#### {}", category.label()));

        let issue_count = issues.len();
        let visible_issues = if options.summary_only {
            issues.iter().take(6).copied().collect::<Vec<_>>()
        } else {
            issues.clone()
        };

        for issue in &visible_issues {
            let location = issue_location(issue)
                .map(|location| format!(" (`{}`)", escape_cell(&location)))
                .unwrap_or_default();
            lines.push(format!(
                "- `{}` `{}` {}{}",
                issue.severity.slug(),
                issue.code,
                escape_cell(&issue.title),
                location
            ));
            if !options.summary_only {
                if let Some(description) = &issue.description {
                    lines.push(format!("  Details: {}", escape_cell(description)));
                }
                lines.push(format!(
                    "  Remediation: {}",
                    escape_cell(&issue.remediation)
                ));
            }
        }

        if options.summary_only && issue_count > visible_issues.len() {
            lines.push(format!(
                "- {} additional issue(s) omitted from summary.",
                issue_count - visible_issues.len()
            ));
        }
    }

    lines.join("\n") + "\n"
}

fn escape_cell(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', "<br>")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{RenderOptions, sample_report};

    #[test]
    fn markdown_report_includes_key_sections() {
        let rendered = render(
            &sample_report(),
            RenderOptions {
                summary_only: false,
                color: false,
                github_step_summary: false,
            },
        );

        assert!(rendered.contains("## DevGuard Summary"));
        assert!(rendered.contains("| Score | **70/100 (Fair)** |"));
        assert!(rendered.contains("### Counts"));
        assert!(rendered.contains("### Issues by Category"));
        assert!(rendered.contains("#### Secrets"));
        assert!(rendered.contains("`DG_SEC_004`"));
    }
}
