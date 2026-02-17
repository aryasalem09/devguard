mod cli;
mod config;
mod core;
mod providers;
mod utils;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands, RunArgs};
use core::RunProfile;
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
        Commands::Check(args) => run_profile(args, RunProfile::Full),
        Commands::Init(args) => {
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
            cli::ScanSubcommand::Secrets(args) => run_profile(args, RunProfile::SecretsOnly),
        },
        Commands::Env { command } => match command {
            cli::EnvSubcommand::Validate(args) => run_profile(args, RunProfile::EnvOnly),
        },
        Commands::Git { command } => match command {
            cli::GitSubcommand::Health(args) => run_profile(args, RunProfile::GitOnly),
        },
        Commands::Supabase { command } => match command {
            cli::SupabaseSubcommand::Verify(args) => {
                run_profile(args.run, RunProfile::SupabaseVerify { force: args.force })
            }
        },
    }
}

fn run_profile(args: RunArgs, profile: RunProfile) -> Result<i32> {
    let cwd = std::env::current_dir()?;
    let loaded = config::load_config(args.config.as_deref(), &cwd)?;
    let repo_root = resolve_repo_root(&cwd, &args.path);
    let report = core::run_checks(&repo_root, &loaded.config, profile)?;

    let output_json = args.json || loaded.config.general.json;
    if output_json {
        let json_report = core::report::JsonReport::from(&report);
        println!("{}", serde_json::to_string_pretty(&json_report)?);
    } else {
        core::report::print_human(&report);
    }

    if report.exit.ok { Ok(0) } else { Ok(1) }
}

fn resolve_repo_root(cwd: &Path, path: &PathBuf) -> PathBuf {
    if path.is_absolute() {
        path.clone()
    } else {
        cwd.join(path)
    }
}
