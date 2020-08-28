#[macro_use]
extern crate log;

use std::collections::HashSet;
use std::io::prelude::*;
use std::iter::FromIterator;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use anyhow::{bail, Result};
use argh::FromArgs;

use diesel::prelude::*;
use sshkt::models::*;

mod cli;

#[derive(FromArgs)]
/// SSH Key Management tool, written in Rust
pub struct Args {
    #[argh(subcommand)]
    /// command to run
    cmd: SubCommand,

    #[argh(option)]
    /// database password for secrets
    password: Option<String>,
}

#[derive(FromArgs)]
#[argh(subcommand)]
pub enum SubCommand {
    AddSecret(AddSecretArgs),
    ShowSecret(ShowSecretArgs),
    Fetch(FetchArgs),
    Cleanup(CleanupArgs),
}

#[derive(FromArgs)]
/// Add a secret for decrypting key files
#[argh(subcommand, name = "add-secret")]
pub struct AddSecretArgs {
    #[argh(option)]
    /// hostname to add the secret for
    host_name: String,

    #[argh(option)]
    /// os to add the secret for
    host_os: String,

    #[argh(positional)]
    /// value of the secret
    value: String,
}

#[derive(FromArgs)]
/// Show a secret for decrypting key files
#[argh(subcommand, name = "show-secret")]
pub struct ShowSecretArgs {
    #[argh(option)]
    /// hostname to add the secret for
    host_name: String,

    #[argh(option)]
    /// os to add the secret for
    host_os: String,
}

#[derive(FromArgs)]
/// Fetch all the SSH information from remote hosts
#[argh(subcommand, name = "fetch")]
pub struct FetchArgs {
    #[argh(option)]
    /// only hostnames to include in the fetch
    only: Vec<String>,
}

#[derive(FromArgs)]
/// Cleanup obsolete entries from the database
#[argh(subcommand, name = "cleanup")]
pub struct CleanupArgs {
    #[argh(switch, short = 'n')]
    /// dry-run
    dry_run: bool,
}

fn main() -> Result<()> {
    // Load arguments from .env
    dotenv::dotenv().ok();

    // Initialize logging
    env_logger::builder().format_timestamp(None).init();

    // Parse args
    let mut args: Args = argh::from_env();

    // Fill in password from env
    if args.password.is_none() {
        if let Ok(env_pw) = std::env::var("SSHKT_PASSWORD") {
            args.password = Some(env_pw);
        }
    }

    // Derive the key from the password
    let key = args
        .password
        .map(|s| sshkt::models::SecretKey::new(s.as_str()));

    // Establish connection
    let conn = sshkt::establish_connection();

    match args.cmd {
        SubCommand::AddSecret(args) => cli::add_secret(&conn, key.as_ref(), args),
        SubCommand::ShowSecret(args) => cli::show_secret(&conn, key.as_ref(), args),
        SubCommand::Fetch(args) => cli::fetch(&conn, key.as_ref(), args),
        SubCommand::Cleanup(args) => cli::cleanup(&conn, key.as_ref(), args),
    }
}

#[cfg(target_os = "linux")]
fn set_key_permissions(fs: &mut std::fs::File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs.metadata()?.permissions();
    permissions.set_mode(0o600);
    Ok(fs.set_permissions(permissions)?)
}

#[cfg(not(target_os = "linux"))]
fn set_key_permissions(_fs: &mut std::fs::File) -> Result<()> {
    Ok(())
}

fn trim_bytes(mut value: Vec<u8>) -> Vec<u8> {
    while let Some(b' ') | Some(b'\t') | Some(b'\r') | Some(b'\n') = value.last() {
        value.pop();
    }

    value
}

fn base_digest(value: &[u8]) -> Vec<u8> {
    let parts: Vec<_> = value.splitn(3, |i| *i == b' ').collect();
    let mut res = Vec::new();

    res.extend(parts[0]);
    res.push(b' ');
    res.extend(parts[1]);
    res.push(b' ');
    res.extend(parts[2].rsplitn(2, |i| *i == b' ').next().unwrap());

    res
}
