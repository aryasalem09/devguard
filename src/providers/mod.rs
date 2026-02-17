use crate::config::Config;
use crate::core::RepoContext;
use crate::core::report::Issue;

pub mod stripe;
pub mod supabase;
pub mod vercel;

pub trait Provider {
    fn name(&self) -> &'static str;
    fn is_enabled(&self, cfg: &Config) -> bool;
    fn detect(&self, ctx: &RepoContext) -> bool;
    fn run_checks(&self, ctx: &RepoContext, cfg: &Config) -> Vec<Issue>;
}

pub fn all_providers() -> Vec<Box<dyn Provider>> {
    vec![
        Box::new(supabase::SupabaseProvider),
        Box::new(vercel::VercelProvider),
        Box::new(stripe::StripeProvider),
    ]
}
