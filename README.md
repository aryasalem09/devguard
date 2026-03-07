# devguard [![crates.io](https://img.shields.io/crates/v/devguard.svg)](https://crates.io/crates/devguard)

-------------------------------------
```bash
cargo install devguard
devguard --help
```
-------------------------------------

[![crates.io](https://img.shields.io/crates/v/devguard.svg)](https://crates.io/crates/devguard)
[![License](https://img.shields.io/crates/l/devguard.svg)](https://github.com/aryasalem09/devguard)
[![GitHub Actions](https://github.com/aryasalem09/devguard/actions/workflows/devguard.yml/badge.svg)](https://github.com/aryasalem09/devguard/actions/workflows/devguard.yml)

`devguard` is a Rust CLI for repository security and delivery hygiene.

It is built around one source of truth: the CLI. You can run it locally with `devguard check`, wire it into CI with the composite GitHub Action in this repo, and export the same results as human-readable text, JSON, markdown, or SARIF.

## Install

```bash
cargo install devguard
```

## What It Checks

- secrets and token leaks
- env setup drift and missing variables
- git hygiene
- provider-specific checks for Supabase, Vercel, and Stripe

## Commands

Existing commands are preserved:

- `devguard check`
- `devguard init`
- `devguard scan secrets`
- `devguard env validate`
- `devguard git health`
- `devguard supabase verify`

Shared run flags now available on `check` and the scan/validate/health/verify flows:

- `--format human|json|markdown|sarif`
- `--output <path>`
- `--summary-only`
- `--min-score <u8>`
- `--fail-on none|warning|error`
- `--github-step-summary`

Backward compatibility note:

- legacy `--json` still works and maps to `--format json`

## Local Usage

```bash
devguard check
```

```bash
devguard check --summary-only
```

```bash
devguard check --format json --output devguard-report.json
```

```bash
devguard check --format markdown --summary-only
```

```bash
devguard check --format sarif --output devguard.sarif
```

```bash
devguard check --min-score 90 --fail-on error
```

```bash
devguard supabase verify --format markdown --summary-only
```

## Report Formats

### `human`

The default console view. It shows the score, policy status, severity counts, weighted deductions, and grouped issues.

### `json`

Stable machine-readable report for CI and integrations.

Top-level fields:

| Field | Type | Notes |
| --- | --- | --- |
| `schema_version` | string | Current JSON schema version. |
| `tool` | object | Includes `name` and `version`. |
| `repository_path` | string | Normalized absolute repository path. |
| `score` | integer | Final score after deductions. |
| `max_score` | integer | Always `100` in the current model. |
| `label` | string | `Excellent`, `Good`, `Fair`, or `At Risk`. |
| `min_score` | integer | Active score threshold after overrides. |
| `passed` | boolean | Final pass/fail result. |
| `fail_on` | string | `none`, `warning`, or `error`. |
| `exit_reasons` | array | Reasons the run failed policy, if any. |
| `counts` | object | Counts for `error`, `warning`, `info`, `pass`, and `total`. |
| `scoring` | object | Weight configuration, per-severity totals, per-category totals, and deduction list. |
| `issues` | array | Issue list with code, title, optional description, severity, category, optional file/line, and remediation text. |

Sample JSON:

```json
{
  "schema_version": "1",
  "tool": {
    "name": "devguard",
    "version": "0.1.1"
  },
  "repository_path": "/workspace/repo",
  "score": 72,
  "max_score": 100,
  "label": "Fair",
  "min_score": 80,
  "passed": false,
  "fail_on": "warning",
  "exit_reasons": [
    "score 72 is below min_score 80",
    "fail_on warning triggered by 2 issues"
  ],
  "counts": {
    "error": 1,
    "warning": 2,
    "info": 1,
    "pass": 1,
    "total": 5
  },
  "issues": [
    {
      "code": "DG_SEC_004",
      "title": "AWS access key pattern detected",
      "severity": "error",
      "category": "secrets",
      "file": "config/.env",
      "line": 4,
      "remediation": "revoke and rotate the key, then remove it from git history"
    }
  ]
}
```

### `markdown`

Compact markdown report designed for GitHub job summaries and README-style examples.

Sample markdown summary:

```md
## DevGuard Summary

| Field | Value |
| --- | --- |
| Tool | `devguard` 0.1.1 |
| Repository | `/workspace/repo` |
| Score | **72/100 (Fair)** |
| Min score | `80` |
| Fail on | `warning` |
| Status | **fail** |

### Counts

| Severity | Count | Penalty |
| --- | ---: | ---: |
| error | 1 | 20 |
| warning | 2 | 16 |
| info | 1 | 2 |
| pass | 1 | 0 |
| total deductions | 4 | 38 |
```

### `sarif`

`devguard` emits SARIF 2.1.0 JSON for GitHub code scanning upload.

- includes tool metadata and rules
- maps severities to SARIF `error`, `warning`, and `note`
- includes locations when a file or line is known
- omits `pass` issues from SARIF results

## Scoring Model

`devguard` now uses a weighted deduction model.

- start at `100`
- subtract `2` for each `info`
- subtract `8` for each `warning`
- subtract `20` for each `error`
- `pass` issues do not deduct score

The internal scoring model is ready for future extensions:

- per-category adjustments for `secrets`, `env`, `git`, `supabase`, `vercel`, and `stripe`
- per-rule weight overrides

The report includes:

- final score
- active threshold
- per-severity weighted totals
- per-category weighted totals
- a deduction list showing why points were removed

## Pass / Fail Rules

A run fails when either of these is true:

- `score < min_score`
- the active `fail_on` threshold is reached by any issue

`fail_on` behavior:

- `none`: ignore severities for fail/pass decisions
- `warning`: fail on any `warning` or `error`
- `error`: fail only on `error`

Exit behavior:

| Condition | Result | Exit code |
| --- | --- | --- |
| score is at or above threshold and no `fail_on` severity is hit | pass | `0` |
| score is below threshold or `fail_on` threshold is hit | policy failure | `1` |
| runtime/config/CLI error | execution failure | `2` |

## GitHub Action

This repo ships a composite action in [`action.yml`](action.yml).

Design notes:

- the action wraps the CLI instead of reimplementing checks
- it assumes `cargo` is already available on the runner
- it installs `devguard` from the checked-out action source with `cargo install --path`
- it can generate a primary report, a GitHub step summary, and an optional SARIF file

Recommended remote usage:

```yaml
- name: Install Rust toolchain
  uses: dtolnay/rust-toolchain@stable

- name: Run DevGuard
  uses: aryasalem09/devguard@main
  with:
    format: markdown
    github-step-summary: true
    sarif: true
    sarif-path: devguard.sarif
```

Replace `@main` with a release tag such as `@v0.1.1` once published.

### Action Inputs

| Input | Default | Notes |
| --- | --- | --- |
| `path` | `.` | Repository path to scan. |
| `format` | `human` | Primary output format. |
| `min-score` | empty | Optional CLI override. |
| `fail-on` | empty | Optional CLI override. |
| `args` | empty | Extra raw CLI args appended to `devguard check`. |
| `github-step-summary` | `true` | Writes compact markdown to `$GITHUB_STEP_SUMMARY`. |
| `sarif` | `false` | Generates an additional SARIF file. |
| `sarif-path` | `devguard.sarif` | Path for SARIF output. |

### Action Outputs

| Output | Description |
| --- | --- |
| `report-path` | Primary report file path. |
| `score` | Final score from the JSON report. |
| `passed` | `true` or `false`. |

## Example Workflow

The repo includes [`.github/workflows/devguard.yml`](.github/workflows/devguard.yml) as a full example.

Key points:

- `actions/checkout` stays in the workflow, not hidden inside the action
- Rust is installed explicitly before the action runs
- the action is invoked with `uses: ./` when testing locally inside this repo
- SARIF upload uses `github/codeql-action/upload-sarif@v3`
- forked pull requests skip SARIF upload because `security-events: write` may not be granted

Example upload snippet:

```yaml
- name: Upload SARIF
  if: always() && (github.event_name != 'pull_request' || github.event.pull_request.head.repo.fork == false)
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: devguard.sarif
```

## Config

Config lookup order:

1. `--config <path>`
2. `./devguard.toml`
3. built-in defaults

Create a starter config:

```bash
devguard init
```

Main config sections:

- `[general]`
  - `fail_on = "warning" | "error" | "none"`
  - `min_score = <int>`
  - `json = <bool>`
- `[scan]`
  - excluded directories
  - max scanned file size
- `[env]`
  - required variables
  - forbidden committed filenames
  - dotenv/example file lists
- `[providers.supabase]`, `[providers.vercel]`, `[providers.stripe]`
  - provider toggles and provider-specific checks

## Provider Checks

- **Supabase**
  - detection via `supabase/`, `supabase/config.toml`, or `@supabase/supabase-js`
  - migration checks
  - client-side service role detection
- **Vercel**
  - detection via `vercel.json`, `.vercel`, or package markers
  - warns on committed `env` keys in `vercel.json`
  - checks `.vercel` tracking state
- **Stripe**
  - detection via package markers or Stripe env keys
  - live/test key checks in dotenv files
  - mixed-mode warning

## Development Validation

```bash
cargo fmt
cargo test
cargo clippy -- -D warnings
```
