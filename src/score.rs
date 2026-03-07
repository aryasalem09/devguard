use crate::config::FailOn;
use crate::core::{Category, Issue, Severity};
use serde::Serialize;

pub const MAX_SCORE: u8 = 100;

#[derive(Debug, Clone, Copy, Serialize)]
pub struct SeverityWeights {
    pub info: u8,
    pub warning: u8,
    pub error: u8,
}

impl Default for SeverityWeights {
    fn default() -> Self {
        Self {
            info: 2,
            warning: 8,
            error: 20,
        }
    }
}

impl SeverityWeights {
    fn penalty_for(self, severity: Severity) -> u8 {
        match severity {
            Severity::Error => self.error,
            Severity::Warning => self.warning,
            Severity::Info => self.info,
            Severity::Pass => 0,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Default)]
pub struct CategoryAdjustments {
    pub secrets: u8,
    pub env: u8,
    pub git: u8,
    pub supabase: u8,
    pub vercel: u8,
    pub stripe: u8,
}

impl CategoryAdjustments {
    fn adjustment_for(self, category: Category) -> u8 {
        match category {
            Category::Secrets => self.secrets,
            Category::Env => self.env,
            Category::Git => self.git,
            Category::Supabase => self.supabase,
            Category::Vercel => self.vercel,
            Category::Stripe => self.stripe,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Default)]
pub struct WeightedBucket {
    pub count: usize,
    pub penalty: u16,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct WeightedSeverityBreakdown {
    pub error: WeightedBucket,
    pub warning: WeightedBucket,
    pub info: WeightedBucket,
    pub pass: WeightedBucket,
}

impl WeightedSeverityBreakdown {
    fn bucket_mut(&mut self, severity: Severity) -> &mut WeightedBucket {
        match severity {
            Severity::Error => &mut self.error,
            Severity::Warning => &mut self.warning,
            Severity::Info => &mut self.info,
            Severity::Pass => &mut self.pass,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CategoryPenalty {
    pub category: Category,
    pub count: usize,
    pub penalty: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScoreDeduction {
    pub code: &'static str,
    pub title: String,
    pub severity: Severity,
    pub category: Category,
    pub penalty: u8,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScoreBreakdown {
    pub starting_score: u8,
    pub max_score: u8,
    pub final_score: u8,
    pub total_deductions: u16,
    pub weights: SeverityWeights,
    pub category_adjustments: CategoryAdjustments,
    pub by_severity: WeightedSeverityBreakdown,
    pub by_category: Vec<CategoryPenalty>,
    pub deductions: Vec<ScoreDeduction>,
}

#[derive(Debug, Clone, Copy, Serialize, Default)]
pub struct PenaltyProfile {
    pub weights: SeverityWeights,
    pub category_adjustments: CategoryAdjustments,
}

impl PenaltyProfile {
    pub fn penalty_for(self, issue: &Issue) -> (u8, String) {
        if let Some(weight_override) = issue.weight_override {
            return (
                weight_override,
                format!("rule override {}", weight_override),
            );
        }

        let base_penalty = self.weights.penalty_for(issue.severity);
        let category_adjustment = self.category_adjustments.adjustment_for(issue.category);
        let total_penalty = base_penalty.saturating_add(category_adjustment);
        let reason = if total_penalty == 0 {
            "no penalty".to_string()
        } else {
            format!(
                "{} base {} + {} adjustment {}",
                issue.severity.slug(),
                base_penalty,
                issue.category.slug(),
                category_adjustment
            )
        };

        (total_penalty, reason)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyEvaluation {
    pub passed: bool,
    pub reasons: Vec<String>,
}

pub fn calculate_breakdown(issues: &[Issue], profile: PenaltyProfile) -> ScoreBreakdown {
    let mut by_severity = WeightedSeverityBreakdown::default();
    let mut by_category = Category::ALL
        .into_iter()
        .map(|category| CategoryPenalty {
            category,
            count: 0,
            penalty: 0,
        })
        .collect::<Vec<_>>();
    let mut total_deductions = 0_u16;
    let mut deductions = Vec::new();

    for issue in issues {
        let (penalty, reason) = profile.penalty_for(issue);
        let severity_bucket = by_severity.bucket_mut(issue.severity);
        severity_bucket.count += 1;
        severity_bucket.penalty += u16::from(penalty);

        if let Some(category_bucket) = by_category
            .iter_mut()
            .find(|bucket| bucket.category == issue.category)
        {
            category_bucket.count += 1;
            category_bucket.penalty += u16::from(penalty);
        }

        total_deductions += u16::from(penalty);
        if penalty > 0 {
            deductions.push(ScoreDeduction {
                code: issue.code,
                title: issue.title.clone(),
                severity: issue.severity,
                category: issue.category,
                penalty,
                reason,
            });
        }
    }

    let final_score =
        (i32::from(MAX_SCORE) - i32::from(total_deductions)).clamp(0, i32::from(MAX_SCORE)) as u8;

    ScoreBreakdown {
        starting_score: MAX_SCORE,
        max_score: MAX_SCORE,
        final_score,
        total_deductions,
        weights: profile.weights,
        category_adjustments: profile.category_adjustments,
        by_severity,
        by_category,
        deductions,
    }
}

pub fn evaluate_policy(
    score: u8,
    issues: &[Issue],
    min_score: u8,
    fail_on: FailOn,
) -> PolicyEvaluation {
    let mut reasons = Vec::new();

    if score < min_score {
        reasons.push(format!("score {} is below min_score {}", score, min_score));
    }

    let fail_count = issues
        .iter()
        .filter(|issue| issue.severity.meets_fail_on(fail_on))
        .count();
    if fail_count > 0 {
        reasons.push(format!(
            "fail_on {} triggered by {} issue{}",
            fail_on,
            fail_count,
            if fail_count == 1 { "" } else { "s" }
        ));
    }

    PolicyEvaluation {
        passed: reasons.is_empty(),
        reasons,
    }
}

pub fn label_for_score(score: u8) -> &'static str {
    match score {
        90..=100 => "Excellent",
        75..=89 => "Good",
        50..=74 => "Fair",
        _ => "At Risk",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{Issue, Severity, rules};

    #[test]
    fn no_issues_scores_one_hundred() {
        let breakdown = calculate_breakdown(&[], PenaltyProfile::default());
        assert_eq!(breakdown.final_score, 100);
        assert_eq!(breakdown.total_deductions, 0);
    }

    #[test]
    fn mixed_severities_use_weighted_penalties() {
        let issues = vec![
            Issue::from_rule(
                rules::SECRET_AWS_ACCESS_KEY,
                Severity::Error,
                "AWS access key pattern detected",
                "rotate it",
            ),
            Issue::from_rule(
                rules::ENV_REQUIRED_VAR_MISSING,
                Severity::Warning,
                "missing required env var DATABASE_URL",
                "add DATABASE_URL",
            ),
            Issue::from_rule(
                rules::GIT_DIRTY_TREE,
                Severity::Info,
                "working tree has changes",
                "clean it up",
            ),
            Issue::from_rule(
                rules::GIT_CLEAN_TREE,
                Severity::Pass,
                "working tree is clean",
                "no action needed",
            ),
        ];

        let breakdown = calculate_breakdown(&issues, PenaltyProfile::default());
        assert_eq!(breakdown.final_score, 70);
        assert_eq!(breakdown.total_deductions, 30);
        assert_eq!(breakdown.by_severity.error.penalty, 20);
        assert_eq!(breakdown.by_severity.warning.penalty, 8);
        assert_eq!(breakdown.by_severity.info.penalty, 2);
        assert_eq!(breakdown.by_severity.pass.penalty, 0);
    }

    #[test]
    fn rule_weight_override_takes_precedence() {
        let mut issue = Issue::from_rule(
            rules::SECRET_AWS_ACCESS_KEY,
            Severity::Error,
            "AWS access key pattern detected",
            "rotate it",
        );
        issue.weight_override = Some(9);

        let breakdown = calculate_breakdown(&[issue], PenaltyProfile::default());
        assert_eq!(breakdown.final_score, 91);
        assert_eq!(breakdown.deductions[0].reason, "rule override 9");
    }

    #[test]
    fn fail_on_warning_and_error_behave_as_expected() {
        let issues = vec![Issue::from_rule(
            rules::ENV_REQUIRED_VAR_MISSING,
            Severity::Warning,
            "missing required env var DATABASE_URL",
            "add DATABASE_URL",
        )];

        let warning_eval = evaluate_policy(92, &issues, 80, FailOn::Warning);
        assert!(!warning_eval.passed);
        assert!(
            warning_eval
                .reasons
                .iter()
                .any(|reason| reason.contains("fail_on warning"))
        );

        let error_eval = evaluate_policy(92, &issues, 80, FailOn::Error);
        assert!(error_eval.passed);
    }

    #[test]
    fn min_score_override_behavior_is_reported() {
        let issues = vec![Issue::from_rule(
            rules::ENV_REQUIRED_VAR_MISSING,
            Severity::Warning,
            "missing required env var DATABASE_URL",
            "add DATABASE_URL",
        )];

        let breakdown = calculate_breakdown(&issues, PenaltyProfile::default());
        let evaluation = evaluate_policy(breakdown.final_score, &issues, 95, FailOn::None);

        assert_eq!(breakdown.final_score, 92);
        assert!(!evaluation.passed);
        assert_eq!(evaluation.reasons, vec!["score 92 is below min_score 95"]);
    }
}
