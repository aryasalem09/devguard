use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct LoadedConfig {
    pub config: Config,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub general: GeneralConfig,
    pub scan: ScanConfig,
    pub env: EnvConfig,
    pub providers: ProvidersConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GeneralConfig {
    pub fail_on: FailOn,
    pub min_score: u8,
    pub json: bool,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            fail_on: FailOn::Warning,
            min_score: 80,
            json: false,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum FailOn {
    #[default]
    Warning,
    Error,
    None,
}

impl fmt::Display for FailOn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Warning => write!(f, "warning"),
            Self::Error => write!(f, "error"),
            Self::None => write!(f, "none"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanConfig {
    pub exclude: Vec<String>,
    pub max_file_size_kb: u64,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            exclude: vec![
                "node_modules".to_string(),
                "target".to_string(),
                ".git".to_string(),
                "dist".to_string(),
                "build".to_string(),
                ".next".to_string(),
            ],
            max_file_size_kb: 512,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EnvConfig {
    pub required: Vec<String>,
    pub forbid_commit: Vec<String>,
    pub dotenv_files: Vec<String>,
    pub example_files: Vec<String>,
}

impl Default for EnvConfig {
    fn default() -> Self {
        Self {
            required: vec!["DATABASE_URL".to_string()],
            forbid_commit: vec![
                ".env".to_string(),
                ".env.local".to_string(),
                ".env.production".to_string(),
                "serviceAccount.json".to_string(),
            ],
            dotenv_files: vec![
                ".env".to_string(),
                ".env.local".to_string(),
                ".env.development".to_string(),
                ".env.production".to_string(),
            ],
            example_files: vec![".env.example".to_string(), ".env.template".to_string()],
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ProvidersConfig {
    pub supabase: SupabaseConfig,
    pub vercel: VercelConfig,
    pub stripe: StripeConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SupabaseConfig {
    pub enabled: bool,
    pub require_migrations: bool,
    pub migrations_dir: String,
    pub forbid_service_role_in_client: bool,
}

impl Default for SupabaseConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            require_migrations: true,
            migrations_dir: "supabase/migrations".to_string(),
            forbid_service_role_in_client: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct VercelConfig {
    pub enabled: bool,
}

impl Default for VercelConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StripeConfig {
    pub enabled: bool,
    pub warn_live_keys: bool,
}

impl Default for StripeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            warn_live_keys: true,
        }
    }
}

pub fn load_config(cli_config_path: Option<&Path>, cwd: &Path) -> Result<LoadedConfig> {
    if let Some(path) = cli_config_path {
        if !path.exists() {
            bail!(
                "config file not found at {} (passed with --config)",
                path.display()
            );
        }

        return Ok(LoadedConfig {
            config: read_config(path)?,
        });
    }

    let local_path = cwd.join("devguard.toml");
    if local_path.exists() {
        return Ok(LoadedConfig {
            config: read_config(&local_path)?,
        });
    }

    Ok(LoadedConfig {
        config: Config::default(),
    })
}

pub fn write_default_config(path: &Path) -> Result<()> {
    if path.exists() {
        bail!(
            "refusing to overwrite existing config file: {}",
            path.display()
        );
    }

    let content = default_config_toml()?;
    fs::write(path, content).with_context(|| format!("failed writing {}", path.display()))?;
    Ok(())
}

pub fn default_config_toml() -> Result<String> {
    toml::to_string_pretty(&Config::default()).context("failed to serialize default config")
}

fn read_config(path: &Path) -> Result<Config> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed reading config file {}", path.display()))?;
    let config = toml::from_str::<Config>(&content)
        .with_context(|| format!("failed parsing config file {}", path.display()))?;
    Ok(config)
}
