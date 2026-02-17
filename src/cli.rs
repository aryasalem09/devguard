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
    Check(RunArgs),
    Init(InitArgs),
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
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct InitArgs {
    #[arg(long)]
    pub config: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub enum ScanSubcommand {
    Secrets(RunArgs),
}

#[derive(Debug, Subcommand)]
pub enum EnvSubcommand {
    Validate(RunArgs),
}

#[derive(Debug, Subcommand)]
pub enum GitSubcommand {
    Health(RunArgs),
}

#[derive(Debug, Subcommand)]
pub enum SupabaseSubcommand {
    Verify(SupabaseVerifyArgs),
}

#[derive(Debug, Args, Clone)]
pub struct SupabaseVerifyArgs {
    #[command(flatten)]
    pub run: RunArgs,
    #[arg(long)]
    pub force: bool,
}
