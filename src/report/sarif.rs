use crate::report::FinalReport;
use anyhow::Result;
use serde::Serialize;
use std::collections::BTreeMap;

const SARIF_VERSION: &str = "2.1.0";
const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";

#[derive(Debug, Serialize)]
struct SarifLog {
    version: &'static str,
    #[serde(rename = "$schema")]
    schema: &'static str,
    runs: Vec<SarifRun>,
}

#[derive(Debug, Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Debug, Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Debug, Serialize)]
struct SarifDriver {
    name: &'static str,
    version: &'static str,
    #[serde(rename = "informationUri")]
    information_uri: &'static str,
    rules: Vec<SarifRule>,
}

#[derive(Debug, Serialize)]
struct SarifRule {
    id: &'static str,
    name: String,
    #[serde(rename = "shortDescription")]
    short_description: SarifMessage,
    #[serde(rename = "fullDescription", skip_serializing_if = "Option::is_none")]
    full_description: Option<SarifMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    help: Option<SarifMessage>,
    properties: SarifRuleProperties,
}

#[derive(Debug, Serialize)]
struct SarifRuleProperties {
    tags: Vec<String>,
}

#[derive(Debug, Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: &'static str,
    level: &'static str,
    message: SarifMessage,
    #[serde(skip_serializing_if = "Option::is_none")]
    locations: Option<Vec<SarifLocation>>,
}

#[derive(Debug, Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(Debug, Serialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Serialize)]
struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<SarifRegion>,
}

#[derive(Debug, Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Debug, Serialize)]
struct SarifRegion {
    #[serde(rename = "startLine")]
    start_line: usize,
}

pub fn render(report: &FinalReport) -> Result<String> {
    let mut rules = BTreeMap::<&'static str, SarifRule>::new();
    let mut results = Vec::new();

    for issue in report
        .issues
        .iter()
        .filter(|issue| issue.severity.sarif_level().is_some())
    {
        rules.entry(issue.code).or_insert_with(|| SarifRule {
            id: issue.code,
            name: issue.rule_title.to_string(),
            short_description: SarifMessage {
                text: issue.rule_title.to_string(),
            },
            full_description: issue.description.as_ref().map(|description| SarifMessage {
                text: description.clone(),
            }),
            help: Some(SarifMessage {
                text: issue.remediation.clone(),
            }),
            properties: SarifRuleProperties {
                tags: vec![
                    issue.category.slug().to_string(),
                    issue.severity.slug().to_string(),
                ],
            },
        });

        let locations = issue.file.as_ref().map(|file| {
            vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation { uri: file.clone() },
                    region: issue.line.map(|line| SarifRegion { start_line: line }),
                },
            }]
        });

        results.push(SarifResult {
            rule_id: issue.code,
            level: issue.severity.sarif_level().expect("filtered above"),
            message: SarifMessage {
                text: issue.title.clone(),
            },
            locations,
        });
    }

    let log = SarifLog {
        version: SARIF_VERSION,
        schema: SARIF_SCHEMA,
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: report.tool.name,
                    version: report.tool.version,
                    information_uri: env!("CARGO_PKG_REPOSITORY"),
                    rules: rules.into_values().collect(),
                },
            },
            results,
        }],
    };

    Ok(format!("{}\n", serde_json::to_string_pretty(&log)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::sample_report;
    use serde_json::Value;

    #[test]
    fn sarif_output_has_expected_top_level_structure() {
        let rendered = render(&sample_report()).expect("sarif render succeeds");
        let parsed: Value = serde_json::from_str(&rendered).expect("sarif parses");

        assert_eq!(parsed["version"], "2.1.0");
        assert_eq!(parsed["runs"][0]["tool"]["driver"]["name"], "devguard");
        assert_eq!(parsed["runs"][0]["results"][0]["ruleId"], "DG_SEC_004");
        assert_eq!(parsed["runs"][0]["results"][0]["level"], "error");
        assert!(parsed["runs"][0]["tool"]["driver"]["rules"].is_array());
    }
}
