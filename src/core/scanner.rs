use crate::config::Config;
use crate::core::RepoContext;
use crate::core::report::{Category, Issue, Severity};
use crate::utils::fs::{is_likely_binary, relative_path};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;
use std::fs;
use walkdir::{DirEntry, WalkDir};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecretKind {
    StripeLive,
    StripeTest,
    VercelToken,
    AwsAccessKey,
    PrivateKeyBlock,
    SupabaseJwt,
}

static STRIPE_LIVE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"sk_live_[0-9A-Za-z]{16,}").expect("valid stripe live regex"));
static STRIPE_TEST_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"sk_test_[0-9A-Za-z]{16,}").expect("valid stripe test regex"));
static VERCEL_ASSIGNMENT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\bvercel_token\b\s*[:=]\s*["']?[A-Za-z0-9._-]{10,}"#)
        .expect("valid vercel assignment regex")
});
static VERCEL_TOKEN_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bv1\.[A-Za-z0-9._-]{20,}\b").expect("valid vercel token regex"));
static VERCEL_MARKER_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bvercel[_-]?token\b").expect("valid vercel marker regex"));
static AWS_ACCESS_KEY_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bAKIA[0-9A-Z]{16}\b").expect("valid aws access key regex"));
static PRIVATE_KEY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"-----BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY-----").expect("valid private key regex")
});
static JWT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
        .expect("valid jwt regex")
});

pub fn scan_secrets(ctx: &RepoContext, cfg: &Config) -> Vec<Issue> {
    let mut issues = Vec::new();
    let max_bytes = cfg.scan.max_file_size_kb * 1024;

    for entry in WalkDir::new(&ctx.repo_root)
        .into_iter()
        .filter_entry(|entry| should_visit(entry, &cfg.scan.exclude))
        .filter_map(Result::ok)
    {
        if !entry.file_type().is_file() {
            continue;
        }

        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        if metadata.len() > max_bytes {
            continue;
        }

        let bytes = match fs::read(entry.path()) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        if is_likely_binary(&bytes) {
            continue;
        }

        let content = String::from_utf8_lossy(&bytes);
        let rel = relative_path(&ctx.repo_root, entry.path());
        for (kind, line) in scan_text_for_hits(&content) {
            issues.push(build_issue_for_hit(kind, line, &rel, &content, cfg));
        }
    }

    issues
}

fn should_visit(entry: &DirEntry, excludes: &[String]) -> bool {
    if !entry.file_type().is_dir() {
        return true;
    }

    let dir_name = entry.file_name().to_string_lossy();
    !excludes
        .iter()
        .any(|excluded| excluded.eq_ignore_ascii_case(&dir_name))
}

fn scan_text_for_hits(content: &str) -> Vec<(SecretKind, usize)> {
    let mut hits = Vec::new();
    let mut seen = HashSet::new();

    for found in STRIPE_LIVE_RE.find_iter(content) {
        insert_hit(
            &mut hits,
            &mut seen,
            SecretKind::StripeLive,
            line_number(content, found.start()),
        );
    }
    for found in STRIPE_TEST_RE.find_iter(content) {
        insert_hit(
            &mut hits,
            &mut seen,
            SecretKind::StripeTest,
            line_number(content, found.start()),
        );
    }
    for found in AWS_ACCESS_KEY_RE.find_iter(content) {
        insert_hit(
            &mut hits,
            &mut seen,
            SecretKind::AwsAccessKey,
            line_number(content, found.start()),
        );
    }
    for found in PRIVATE_KEY_RE.find_iter(content) {
        insert_hit(
            &mut hits,
            &mut seen,
            SecretKind::PrivateKeyBlock,
            line_number(content, found.start()),
        );
    }
    for found in VERCEL_ASSIGNMENT_RE.find_iter(content) {
        insert_hit(
            &mut hits,
            &mut seen,
            SecretKind::VercelToken,
            line_number(content, found.start()),
        );
    }

    if VERCEL_MARKER_RE.is_match(content) {
        for found in VERCEL_TOKEN_RE.find_iter(content) {
            insert_hit(
                &mut hits,
                &mut seen,
                SecretKind::VercelToken,
                line_number(content, found.start()),
            );
        }
    }

    let lowered = content.to_ascii_lowercase();
    let has_supabase_marker = lowered.contains("supabase") || lowered.contains("supabase_");
    if has_supabase_marker {
        for found in JWT_RE.find_iter(content) {
            let line_no = line_number(content, found.start());
            let line = line_text(content, line_no);
            if !is_supabase_keyish_line(&line) {
                continue;
            }

            insert_hit(&mut hits, &mut seen, SecretKind::SupabaseJwt, line_no);
        }
    }

    hits
}

fn insert_hit(
    hits: &mut Vec<(SecretKind, usize)>,
    seen: &mut HashSet<(SecretKind, usize)>,
    kind: SecretKind,
    line: usize,
) {
    if seen.insert((kind, line)) {
        hits.push((kind, line));
    }
}

fn build_issue_for_hit(
    kind: SecretKind,
    line: usize,
    relative_file: &str,
    content: &str,
    cfg: &Config,
) -> Issue {
    match kind {
        SecretKind::StripeLive => {
            let severity = if cfg.providers.stripe.enabled && cfg.providers.stripe.warn_live_keys {
                Severity::Critical
            } else {
                Severity::Warning
            };

            Issue::new(
                severity,
                Category::Secrets,
                "Stripe live key pattern detected",
                "rotate the key and move it to a secret manager or deployment env",
            )
            .with_file(relative_file.to_string())
            .with_line(line)
        }
        SecretKind::StripeTest => Issue::new(
            Severity::Warning,
            Category::Secrets,
            "Stripe test key pattern detected",
            "keep test keys in local env files and out of tracked files",
        )
        .with_file(relative_file.to_string())
        .with_line(line),
        SecretKind::VercelToken => Issue::new(
            Severity::Warning,
            Category::Secrets,
            "Vercel token-like value detected",
            "prefer Vercel dashboard env configuration instead of committed tokens",
        )
        .with_file(relative_file.to_string())
        .with_line(line),
        SecretKind::AwsAccessKey => Issue::new(
            Severity::Critical,
            Category::Secrets,
            "AWS access key pattern detected",
            "revoke and rotate the key, then remove it from git history",
        )
        .with_file(relative_file.to_string())
        .with_line(line),
        SecretKind::PrivateKeyBlock => Issue::new(
            Severity::Critical,
            Category::Secrets,
            "Private key block detected",
            "remove private key material from source and rotate credentials",
        )
        .with_file(relative_file.to_string())
        .with_line(line),
        SecretKind::SupabaseJwt => {
            let lowered = content.to_ascii_lowercase();
            let has_service_role_marker = lowered.contains("service_role")
                || lowered.contains("supabase_service_role_key")
                || lowered.contains("supabase_service_role");

            Issue::new(
                if has_service_role_marker {
                    Severity::Critical
                } else {
                    Severity::Warning
                },
                Category::Secrets,
                "Supabase JWT-like key detected",
                "store Supabase JWT secrets in server-side env only",
            )
            .with_file(relative_file.to_string())
            .with_line(line)
        }
    }
}

fn line_number(content: &str, byte_index: usize) -> usize {
    content[..byte_index]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1
}

fn line_text(content: &str, line_no: usize) -> String {
    if line_no == 0 {
        return String::new();
    }

    content
        .lines()
        .nth(line_no.saturating_sub(1))
        .unwrap_or("")
        .to_string()
}

fn is_supabase_keyish_line(line: &str) -> bool {
    let lowered = line.to_ascii_lowercase();
    if !lowered.contains("supabase") {
        return false;
    }

    // strip jwt bodies before keyword checks so random payload bytes don't trigger.
    let without_jwt = JWT_RE.replace_all(&lowered, " ");
    ["anon", "service", "jwt", "key", "token", "url", "secret"]
        .iter()
        .any(|keyword| without_jwt.contains(keyword))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_stripe_keys() {
        let live = format!(
            "STRIPE_SECRET_KEY={}{}",
            "sk_live_",
            "abcdefghijklmnopqrstuvwxyz123456"
        );
        let hits = scan_text_for_hits(&live);
        assert!(hits.iter().any(|(kind, _)| *kind == SecretKind::StripeLive));

        let test = format!(
            "STRIPE_SECRET_KEY={}{}",
            "sk_test_",
            "abcdefghijklmnopqrstuvwxyz123456"
        );
        let hits = scan_text_for_hits(&test);
        assert!(hits.iter().any(|(kind, _)| *kind == SecretKind::StripeTest));
    }

    #[test]
    fn detects_private_key_and_aws_key() {
        let content = r#"
AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF
-----BEGIN PRIVATE KEY-----
abc
-----END PRIVATE KEY-----
"#;
        let hits = scan_text_for_hits(content);
        assert!(
            hits.iter()
                .any(|(kind, _)| *kind == SecretKind::AwsAccessKey)
        );
        assert!(
            hits.iter()
                .any(|(kind, _)| *kind == SecretKind::PrivateKeyBlock)
        );
    }

    #[test]
    fn detects_supabase_jwt_on_keyish_line() {
        let content = "SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.abcdefghijklmnopqrstuvwxyz1234567890";
        let hits = scan_text_for_hits(content);
        assert!(
            hits.iter()
                .any(|(kind, _)| *kind == SecretKind::SupabaseJwt)
        );
    }

    #[test]
    fn ignores_supabase_jwt_in_comment_docs_line() {
        let content = "// supabase docs example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.abcdefghijklmnopqrstuvwxyz1234567890";
        let hits = scan_text_for_hits(content);
        assert!(
            !hits
                .iter()
                .any(|(kind, _)| *kind == SecretKind::SupabaseJwt)
        );
    }
}
