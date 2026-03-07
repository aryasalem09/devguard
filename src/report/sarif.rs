use crate::core::{Category, Issue};
use crate::report::FinalReport;
use anyhow::Result;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;
use walkdir::WalkDir;

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
    locations: Vec<SarifLocation>,
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
    region: SarifRegion,
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

        results.push(SarifResult {
            rule_id: issue.code,
            level: issue.severity.sarif_level().expect("filtered above"),
            message: SarifMessage {
                text: issue.title.clone(),
            },
            locations: vec![sarif_location_for_issue(report, issue)],
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

fn sarif_location_for_issue(report: &FinalReport, issue: &Issue) -> SarifLocation {
    SarifLocation {
        physical_location: SarifPhysicalLocation {
            artifact_location: SarifArtifactLocation {
                uri: artifact_uri_for_issue(report, issue),
            },
            region: SarifRegion {
                start_line: issue.line.unwrap_or(1),
            },
        },
    }
}

fn artifact_uri_for_issue(report: &FinalReport, issue: &Issue) -> String {
    if let Some(file) = issue.file.as_deref() {
        if let Some(uri) = resolve_issue_file_uri(report, file) {
            return uri;
        }
    }

    fallback_artifact_uri(report, issue)
}

fn resolve_issue_file_uri(report: &FinalReport, file: &str) -> Option<String> {
    let repo_root = Path::new(&report.repository_path);
    if !repo_root.is_dir() {
        return Some(normalize_uri(file));
    }

    let candidate = repo_root.join(file);
    if candidate.is_file() {
        return relative_uri(repo_root, &candidate);
    }

    if candidate.is_dir() {
        if let Some(uri) =
            first_file_in_tree(&candidate).and_then(|path| relative_uri(repo_root, &path))
        {
            return Some(uri);
        }

        return None;
    }

    Some(normalize_uri(file))
}

fn fallback_artifact_uri(report: &FinalReport, issue: &Issue) -> String {
    let repo_root = Path::new(&report.repository_path);
    let candidates = preferred_anchor_candidates(issue.category);

    if repo_root.is_dir() {
        for candidate in candidates {
            let path = repo_root.join(candidate);
            if path.is_file() {
                return normalize_uri(candidate);
            }
        }

        if let Some(uri) =
            first_file_in_tree(repo_root).and_then(|path| relative_uri(repo_root, &path))
        {
            return uri;
        }
    }

    candidates
        .first()
        .copied()
        .unwrap_or("README.md")
        .to_string()
}

fn preferred_anchor_candidates(category: Category) -> &'static [&'static str] {
    match category {
        Category::Secrets => &["README.md", "package.json", "Cargo.toml", ".gitignore"],
        Category::Env => &[
            "devguard.toml",
            ".env.example",
            ".env.template",
            ".env",
            ".env.local",
            "README.md",
        ],
        Category::Git => &[".gitignore", "README.md", "package.json", "Cargo.toml"],
        Category::Supabase => &[
            "supabase/config.toml",
            "package.json",
            "Cargo.toml",
            "README.md",
        ],
        Category::Vercel => &[
            "vercel.json",
            ".vercel/project.json",
            "package.json",
            "README.md",
        ],
        Category::Stripe => &[
            ".env",
            ".env.local",
            ".env.example",
            ".env.template",
            "package.json",
            "README.md",
        ],
    }
}

fn first_file_in_tree(root: &Path) -> Option<std::path::PathBuf> {
    WalkDir::new(root)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| entry.file_name().to_string_lossy() != ".git")
        .filter_map(Result::ok)
        .find(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
}

fn relative_uri(repo_root: &Path, path: &Path) -> Option<String> {
    path.strip_prefix(repo_root).ok().map(normalize_path)
}

fn normalize_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn normalize_uri(uri: &str) -> String {
    uri.replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FailOn;
    use crate::core::{Issue, Severity, rules};
    use crate::report::build_report;
    use crate::report::sample_report;
    use serde_json::Value;
    use std::path::Path;

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

    #[test]
    fn sarif_results_always_include_locations_with_start_lines() {
        let mut report = sample_report();
        report.repository_path = normalize_uri(env!("CARGO_MANIFEST_DIR"));

        let rendered = render(&report).expect("sarif render succeeds");
        let parsed: Value = serde_json::from_str(&rendered).expect("sarif parses");
        let results = parsed["runs"][0]["results"]
            .as_array()
            .expect("results are serialized as an array");

        assert!(!results.is_empty());
        assert!(results.iter().all(|result| {
            let location = &result["locations"][0]["physicalLocation"];
            location["artifactLocation"]["uri"].as_str().is_some()
                && location["region"]["startLine"].as_u64().is_some()
        }));

        let repo_level_issue = results
            .iter()
            .find(|result| result["ruleId"] == "DG_ENV_001")
            .expect("sample report includes a repo-level env issue");
        assert_eq!(
            repo_level_issue["locations"][0]["physicalLocation"]["region"]["startLine"],
            1
        );
    }

    #[test]
    fn sarif_directory_locations_resolve_to_a_file_anchor() {
        let report = build_report(
            Path::new(env!("CARGO_MANIFEST_DIR")),
            vec![
                Issue::from_rule(
                    rules::VERCEL_DIR_PRESENT,
                    Severity::Info,
                    ".vercel directory exists locally",
                    "confirm the directory is ignored",
                )
                .with_file(".github"),
            ],
            80,
            FailOn::Warning,
        );

        let rendered = render(&report).expect("sarif render succeeds");
        let parsed: Value = serde_json::from_str(&rendered).expect("sarif parses");
        let location = &parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"];
        let uri = location["artifactLocation"]["uri"]
            .as_str()
            .expect("directory issue resolves to a file uri");

        assert!(uri.starts_with(".github/"));
        assert_eq!(location["region"]["startLine"], 1);
    }
}
