# devguard

`devguard` is a Rust CLI for repo hygiene checks in modern app stacks. It scans for common footguns in:

- secrets
- env setup and drift
- git hygiene
- provider-specific practices (Supabase, Vercel, Stripe)

It outputs a **Repo Health Score**, categorized issues, actionable hints, and optional JSON for CI.

## Requirements

- Rust toolchain compatible with edition 2024
- Git repo for full git-aware checks (tool still runs outside a git repo)

## Quickstart

```bash
cargo run -- check
```

```bash
cargo run -- init
```

```bash
cargo run -- check --json
```

```bash
cargo run -- supabase verify
```

```bash
cargo run -- supabase verify --force
```

## Commands

- `devguard check [--path <repo>] [--config <path>] [--json]`
- `devguard init [--config <path>]`
- `devguard scan secrets [--path <repo>] [--config <path>] [--json]`
- `devguard env validate [--path <repo>] [--config <path>] [--json]`
- `devguard git health [--path <repo>] [--config <path>] [--json]`
- `devguard supabase verify [--path <repo>] [--config <path>] [--json] [--force]`

## Config

Config lookup order:

1. `--config <path>`
2. `./devguard.toml` in current directory
3. defaults if no file is found

Create a default config:

```bash
devguard init
```

An example config is included at `devguard.example.toml`.

### Main config sections

- `[general]`
  - `fail_on = "warning" | "error" | "none"`
  - `min_score = <int>`
  - `json = <bool>` (overridden by CLI `--json`)
- `[scan]`
  - excluded dirs
  - max scanned file size
- `[env]`
  - required vars
  - forbidden committed filenames
  - dotenv/example file lists
- `[providers.supabase]`, `[providers.vercel]`, `[providers.stripe]`
  - provider toggles and provider-specific controls

## Supabase Verify Behavior

`devguard supabase verify` includes core env/secrets checks plus Supabase provider checks.

- if Supabase provider is disabled in config: emits an Info issue to enable it
- if provider is enabled but Supabase is not detected: emits an Info issue and skips Supabase checks
- use `--force` to run Supabase checks even when markers are not detected

## Output Example

```text
Repo Health Score: 72/100 (Fair)

CRITICAL (1)
[CRITICAL] (Secrets) Private key block detected - config/keys.pem:1
-> hint: remove private key material from source and rotate credentials

WARNING (2)
[WARNING] (Env) missing required env var DATABASE_URL
-> hint: add DATABASE_URL to local dotenv files and CI environment settings

exit: FAILED (score 72 is below min_score 80; found warning-or-higher issues)
```

## JSON Output Example

```json
{
  "score": 80,
  "label": "Good",
  "counts": {
    "critical": 0,
    "warning": 1,
    "info": 1,
    "pass": 1,
    "total": 3
  },
  "issues": [
    {
      "severity": "Warning",
      "category": "Env",
      "title": "missing required env var DATABASE_URL",
      "hint": "add DATABASE_URL to local dotenv files and CI environment settings"
    },
    {
      "severity": "Info",
      "category": "Git",
      "title": "working tree has changes",
      "detail": "modified or untracked files were detected",
      "hint": "commit or stash changes before running release checks"
    },
    {
      "severity": "Pass",
      "category": "Git",
      "title": "working tree is clean",
      "hint": "no action needed"
    }
  ],
  "config": {
    "fail_on": "warning",
    "min_score": 80
  }
}
```

## Exit Codes

- `0`: checks passed policy
- `1`: checks completed but failed policy (`min_score` and/or `fail_on`)
- `2`: runtime/config/CLI error

## CI Usage

```yaml
- name: Run devguard
  run: cargo run -- check --json > devguard-report.json
```

## Provider Checks (v1)

- **Supabase**
  - detection via `supabase/`, `supabase/config.toml`, or `@supabase/supabase-js`
  - migration checks
  - service role usage in frontend paths
- **Vercel**
  - detection via `vercel.json`, `.vercel`, or package marker
  - warns on `env` fields in `vercel.json`
  - checks `.vercel` tracking status
- **Stripe**
  - detection via package marker or Stripe env keys
  - live/test key checks in dotenv values
  - mixed-mode warning

## Extending Providers

Providers implement `Provider` in `src/providers/mod.rs`:

- `name`
- `is_enabled`
- `detect`
- `run_checks`
