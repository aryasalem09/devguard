use anyhow::{Context, Result};
use git2::{Repository, StatusOptions};
use std::path::{Path, PathBuf};

fn de_verbatim(p: &Path) -> PathBuf {
    let s = p.to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\") {
        PathBuf::from(rest)
    } else {
        p.to_path_buf()
    }
}

pub fn discover_repo(repo_root: &Path) -> Option<Repository> {
    Repository::discover(repo_root).ok()
}

pub fn is_working_tree_dirty(repo: &Repository) -> Result<bool> {
    let mut opts = StatusOptions::new();
    opts.include_untracked(true)
        .recurse_untracked_dirs(true)
        .include_ignored(false)
        .renames_head_to_index(true)
        .renames_index_to_workdir(true);

    let statuses = repo
        .statuses(Some(&mut opts))
        .context("failed to read git status")?;

    Ok(!statuses.is_empty())
}

pub fn is_path_tracked(repo: &Repository, repo_root: &Path, path: &Path) -> Result<bool> {
    let workdir = repo.workdir().unwrap_or(repo_root);
    let workdir = de_verbatim(workdir);

    let abs = if path.is_absolute() {
        de_verbatim(path)
    } else {
        workdir.join(path)
    };

    let rel = match abs.strip_prefix(&workdir) {
        Ok(p) => p,
        Err(_) => return Ok(false),
    };

    let idx = repo.index().context("failed to open git index")?;
    Ok(idx.get_path(rel, 0).is_some())
}

pub fn has_tracked_prefix(repo: &Repository, prefix: &str) -> Result<bool> {
    let mut p = prefix.replace('\\', "/");
    while p.starts_with("./") {
        p = p[2..].to_string();
    }
    let p_slash = if p.ends_with('/') {
        p.clone()
    } else {
        format!("{}/", p)
    };

    let idx = repo.index().context("failed to open git index")?;
    for e in idx.iter() {
        if let Ok(path_str) = std::str::from_utf8(&e.path) {
            let s = path_str.replace('\\', "/");
            if s == p || s.starts_with(&p_slash) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}
