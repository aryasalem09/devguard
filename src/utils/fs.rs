use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DotenvEntry {
    pub key: String,
    pub value: String,
    pub line: usize,
}

pub fn relative_path(repo_root: &Path, path: &Path) -> String {
    path.strip_prefix(repo_root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

pub fn is_likely_binary(bytes: &[u8]) -> bool {
    let sample_len = bytes.len().min(8192);
    bytes[..sample_len].contains(&0)
}

pub fn parse_dotenv(content: &str) -> Vec<DotenvEntry> {
    let mut entries = Vec::new();

    for (idx, raw_line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw_line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !line.contains('=') {
            continue;
        }

        let mut parts = line.splitn(2, '=');
        let key = parts.next().unwrap_or("").trim();
        let value_raw = parts.next().unwrap_or("").trim();
        if key.is_empty() {
            continue;
        }

        entries.push(DotenvEntry {
            key: key.to_string(),
            value: strip_quotes(value_raw),
            line: line_no,
        });
    }

    entries
}

fn strip_quotes(value: &str) -> String {
    if value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
    {
        value[1..value.len() - 1].to_string()
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dotenv_lines() {
        let input = r#"
# comment
DATABASE_URL=postgres://localhost/dev
STRIPE_SECRET_KEY="sk_test_abc123abc123abc1"
EMPTY=
"#;
        let parsed = parse_dotenv(input);
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].key, "DATABASE_URL");
        assert_eq!(parsed[1].value, "sk_test_abc123abc123abc1");
        assert_eq!(parsed[2].value, "");
    }

    #[test]
    fn ignores_invalid_or_comment_lines() {
        let input = r#"
# ignored
NOT_VALID
=ALSO_INVALID
VALID_KEY=value
"#;
        let parsed = parse_dotenv(input);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].key, "VALID_KEY");
        assert_eq!(parsed[0].value, "value");
    }
}
