use crate::report::FinalReport;
use anyhow::Result;

pub fn render(report: &FinalReport) -> Result<String> {
    Ok(format!("{}\n", serde_json::to_string_pretty(report)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::sample_report;
    use serde_json::Value;

    #[test]
    fn json_report_has_stable_top_level_shape() {
        let rendered = render(&sample_report()).expect("json render succeeds");
        let parsed: Value = serde_json::from_str(&rendered).expect("json parses");

        assert_eq!(parsed["schema_version"], "1");
        assert_eq!(parsed["tool"]["name"], "devguard");
        assert!(parsed["repository_path"].as_str().is_some());
        assert!(parsed["score"].is_u64());
        assert!(parsed["max_score"].is_u64());
        assert!(parsed["passed"].is_boolean());
        assert_eq!(parsed["fail_on"], "warning");
        assert!(parsed["counts"]["error"].is_u64());
        assert_eq!(parsed["issues"][0]["code"], "DG_SEC_004");
        assert_eq!(parsed["issues"][0]["severity"], "error");
        assert_eq!(parsed["issues"][0]["category"], "secrets");
        assert!(parsed["issues"][0]["remediation"].is_string());
    }
}
