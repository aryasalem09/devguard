mod cli;
mod config;
mod core;
mod providers;
mod report;
mod score;
mod utils;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands, RunArgs};
use core::RunProfile;
use report::{RenderOptions, ReportFormat};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

fn main() {
    let exit_code = match run() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            2
        }
    };

    std::process::exit(exit_code);
}

fn run() -> Result<i32> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Check { args } => run_profile(args, RunProfile::Full),
        Commands::Init { args } => {
            if args.config.is_some() {
                eprintln!(
                    "warning: --config is ignored by `devguard init`; writing ./devguard.toml"
                );
            }

            let path = std::env::current_dir()?.join("devguard.toml");
            config::write_default_config(&path)?;
            println!("created {}", path.display());
            Ok(0)
        }
        Commands::Scan { command } => match command {
            cli::ScanSubcommand::Secrets { args } => run_profile(args, RunProfile::SecretsOnly),
        },
        Commands::Env { command } => match command {
            cli::EnvSubcommand::Validate { args } => run_profile(args, RunProfile::EnvOnly),
        },
        Commands::Git { command } => match command {
            cli::GitSubcommand::Health { args } => run_profile(args, RunProfile::GitOnly),
        },
        Commands::Supabase { command } => match command {
            cli::SupabaseSubcommand::Verify { args } => {
                run_profile(args.run, RunProfile::SupabaseVerify { force: args.force })
            }
        },
    }
}

fn run_profile(args: RunArgs, profile: RunProfile) -> Result<i32> {
    let cwd = std::env::current_dir()?;
    let loaded = config::load_config(args.config.as_deref(), &cwd)?;
    let repo_root = resolve_repo_root(&cwd, &args.path);
    let format = determine_format(&args, &loaded.config);
    let min_score = args.min_score.unwrap_or(loaded.config.general.min_score);
    let fail_on = args.fail_on.unwrap_or(loaded.config.general.fail_on);
    let report = core::run_checks(&repo_root, &loaded.config, profile, min_score, fail_on)?;

    if args.github_step_summary {
        report::write_github_step_summary(&report)?;
    }

    let render_options = RenderOptions {
        summary_only: args.summary_only,
        color: args.output.is_none() && std::io::stdout().is_terminal(),
        github_step_summary: false,
    };
    let rendered = report::render(&report, format, render_options)?;

    if let Some(output_path) = args.output {
        let output_path = resolve_output_path(&cwd, &output_path);
        report::write_output(&output_path, &rendered)?;
    } else {
        print!("{rendered}");
    }

    if report.passed { Ok(0) } else { Ok(1) }
}

fn determine_format(args: &RunArgs, cfg: &config::Config) -> ReportFormat {
    args.format.unwrap_or(if args.json || cfg.general.json {
        ReportFormat::Json
    } else {
        ReportFormat::Human
    })
}

fn resolve_repo_root(cwd: &Path, path: &PathBuf) -> PathBuf {
    if path.is_absolute() {
        path.clone()
    } else {
        cwd.join(path)
    }
}

fn resolve_output_path(cwd: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    }
}
