use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ignore::WalkBuilder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, io::Read, path::{Path, PathBuf}};

#[derive(Parser)]
#[command(name="file-hash", about="Create/verify SHA-256 manifest for files")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create manifest.json from a directory tree
    Create {
        /// Root path to scan
        path: PathBuf,
        /// Output manifest file
        #[arg(short, long, default_value = "manifest.json")]
        out: PathBuf,
        /// Respect .gitignore files
        #[arg(long, default_value_t = true)]
        gitignore: bool,
    },
    /// Verify files against a manifest.json
    Verify {
        /// Manifest file path
        manifest: PathBuf,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct Entry {
    path: String,
    sha256: String,
    size: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct Manifest {
    root: String,
    entries: Vec<Entry>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Create { path, out, gitignore } => create(&path, &out, gitignore),
        Cmd::Verify { manifest } => verify(&manifest),
    }
}

fn create(root: &Path, out: &Path, gitignore: bool) -> Result<()> {
    let mut entries = Vec::new();
    let mut walker = WalkBuilder::new(root);
    walker.hidden(false).git_ignore(gitignore).git_global(gitignore).git_exclude(gitignore);
    let walker = walker.build();

    for dent in walker {
        let dent = dent?;
        let p = dent.path();

        if p.is_file() {
            let (hash, size) = hash_file(p)?;
            let rel = pathdiff::diff_paths(p, root).unwrap_or_else(|| p.to_path_buf());
            entries.push(Entry {
                path: rel.to_string_lossy().to_string(),
                sha256: hash,
                size,
            });
        }
    }

    let manifest = Manifest {
        root: root.to_string_lossy().to_string(),
        entries,
    };

    let json = serde_json::to_string_pretty(&manifest)?;
    fs::write(out, json).with_context(|| format!("Writing {:?}", out))?;
    println!("Wrote manifest: {}", out.display());
    Ok(())
}

fn verify(manifest_path: &Path) -> Result<()> {
    let data = fs::read_to_string(manifest_path).with_context(|| "Reading manifest")?;
    let manifest: Manifest = serde_json::from_str(&data).with_context(|| "Parsing manifest")?;

    let mut ok = 0usize;
    let mut changed = 0usize;
    let mut missing = 0usize;

    for e in &manifest.entries {
        let file_path = Path::new(&manifest.root).join(&e.path);
        if !file_path.exists() {
            println!("MISSING  {}", e.path);
            missing += 1;
            continue;
        }
        let (hash, _size) = hash_file(&file_path)?;
        if hash == e.sha256 {
            println!("OK       {}", e.path);
            ok += 1;
        } else {
            println!("CHANGED  {}", e.path);
            changed += 1;
        }
    }

    println!("\nSummary: OK={}, CHANGED={}, MISSING={}", ok, changed, missing);
    if changed == 0 && missing == 0 {
        println!("All files verified.");
    } else {
        std::process::exit(2);
    }
    Ok(())
}

fn hash_file(p: &Path) -> Result<(String, u64)> {
    let mut f = fs::File::open(p).with_context(|| format!("Opening {:?}", p))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 1024 * 64];
    let mut total: u64 = 0;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    let hash = hasher.finalize();
    Ok((hex::encode(hash), total))
}

// tiny helper so we don't add pathdiff to Cargo.toml manually:
mod pathdiff {
    use std::path::{Path, PathBuf};
    pub fn diff_paths(path: &Path, base: &Path) -> Option<PathBuf> {
        pathdiff::diff_paths(path, base)
    }
}

// Re-export the real pathdiff crate by including it as a build dependency:
