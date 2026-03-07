use crate::config::FailOn;
use crate::report::ReportFormat;
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "devguard",
    version,
    about = "Repository footgun scanner for modern stacks"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    Check {
        #[command(flatten)]
        args: RunArgs,
    },
    Init {
        #[command(flatten)]
        args: InitArgs,
    },
    Scan {
        #[command(subcommand)]
        command: ScanSubcommand,
    },
    Env {
        #[command(subcommand)]
        command: EnvSubcommand,
    },
    Git {
        #[command(subcommand)]
        command: GitSubcommand,
    },
    Supabase {
        #[command(subcommand)]
        command: SupabaseSubcommand,
    },
}

#[derive(Debug, Args, Clone)]
pub struct RunArgs {
    #[arg(long, default_value = ".")]
    pub path: PathBuf,
    #[arg(long)]
    pub config: Option<PathBuf>,
    #[arg(long, value_enum)]
    pub format: Option<ReportFormat>,
    #[arg(long)]
    pub output: Option<PathBuf>,
    #[arg(long)]
    pub summary_only: bool,
    #[arg(long)]
    pub min_score: Option<u8>,
    #[arg(long, value_enum)]
    pub fail_on: Option<FailOn>,
    #[arg(long)]
    pub github_step_summary: bool,
    #[arg(long, hide = true, conflicts_with = "format")]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct InitArgs {
    #[arg(long)]
    pub config: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub enum ScanSubcommand {
    Secrets {
        #[command(flatten)]
        args: RunArgs,
    },
}

#[derive(Debug, Subcommand)]
pub enum EnvSubcommand {
    Validate {
        #[command(flatten)]
        args: RunArgs,
    },
}

#[derive(Debug, Subcommand)]
pub enum GitSubcommand {
    Health {
        #[command(flatten)]
        args: RunArgs,
    },
}

#[derive(Debug, Subcommand)]
pub enum SupabaseSubcommand {
    Verify {
        #[command(flatten)]
        args: SupabaseVerifyArgs,
    },
}

#[derive(Debug, Args, Clone)]
pub struct SupabaseVerifyArgs {
    #[command(flatten)]
    pub run: RunArgs,
    #[arg(long)]
    pub force: bool,
}
