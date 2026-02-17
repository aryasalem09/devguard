use crate::core::report::{Issue, Severity};

pub fn calculate_score(issues: &[Issue]) -> u8 {
    let mut score = 100_i32;

    for issue in issues {
        score -= match issue.severity {
            Severity::Critical => 30,
            Severity::Warning => 15,
            Severity::Info => 5,
            Severity::Pass => 0,
        };
    }

    score.clamp(0, 100) as u8
}

pub fn label_for_score(score: u8) -> &'static str {
    match score {
        90..=100 => "Excellent",
        75..=89 => "Good",
        50..=74 => "Fair",
        _ => "At Risk",
    }
}
