#[macro_use]
extern crate log;

use std::collections::HashSet;
use std::io::prelude::*;
use std::iter::FromIterator;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use color_eyre::eyre::{bail, Result};
use structopt::StructOpt;

use diesel::prelude::*;
use sshkt::models::*;

mod cli;

#[derive(StructOpt)]
/// SSH Key Management tool, written in Rust
pub struct Args {
    #[structopt(subcommand)]
    /// command to run
    cmd: SubCommand,

    #[structopt(short, long = "db", env = "SSHKT_DATABASE")]
    /// database url
    database_url: String,

    #[structopt(short, long, env = "SSHKT_PASSWORD")]
    /// database password for secrets
    password: Option<String>,
}

#[derive(StructOpt)]
pub enum SubCommand {
    AddSecret(AddSecretArgs),
    ShowSecret(ShowSecretArgs),
    Fetch(FetchArgs),
    Cleanup(CleanupArgs),
    RemoveHost(RemoveHostArgs),
    GenFolders(GenFoldersArgs),
    SwapKey(SwapKeyArgs),
}

#[derive(StructOpt)]
/// Add a secret for decrypting key files
pub struct AddSecretArgs {
    #[structopt(long)]
    /// hostname to add the secret for
    host_name: String,

    #[structopt(long)]
    /// os to add the secret for
    host_os: String,

    /// value of the secret
    value: String,
}

#[derive(StructOpt)]
/// Show a secret for decrypting key files
pub struct ShowSecretArgs {
    #[structopt(long)]
    /// hostname to add the secret for
    host_name: String,

    #[structopt(long)]
    /// os to add the secret for
    host_os: String,
}

#[derive(StructOpt)]
/// Fetch all the SSH information from remote hosts
pub struct FetchArgs {
    #[structopt(long)]
    /// only hostnames to include in the fetch
    only: Vec<String>,
}

#[derive(StructOpt)]
/// Cleanup obsolete entries from the database
pub struct CleanupArgs {
    #[structopt(short = "n", long)]
    /// dry-run
    dry_run: bool,
}

#[derive(StructOpt)]
/// Remove a host from known configurations
pub struct RemoveHostArgs {
    #[structopt(short, long)]
    /// run cleanup after removing host
    cleanup: bool,

    /// hosts specification to remove
    hosts: Vec<String>,
}

#[derive(StructOpt)]
/// Generate .ssh folders for the configured hosts
pub struct GenFoldersArgs {}

#[derive(StructOpt)]
/// Change the key used in an IdentityFile directive
pub struct SwapKeyArgs {
    #[structopt(long)]
    /// host specification to change
    host_spec_from: String,

    #[structopt(long)]
    /// host name hosting the config
    host_from: String,

    #[structopt(long)]
    /// host os hosting the config
    host_os_from: String,

    #[structopt(long)]
    /// path to the target key to use instead
    key_path: String,
}

#[paw::main]
fn main(args: Args) -> Result<()> {
    color_eyre::install()?;

    // Initialize logging
    env_logger::builder().format_timestamp(None).init();

    // Derive the key from the password
    let key = args
        .password
        .map(|s| sshkt::models::SecretKey::new(s.as_str()));

    // Establish connection
    let conn = sshkt::establish_connection(&args.database_url);

    match args.cmd {
        SubCommand::AddSecret(args) => cli::add_secret(&conn, key.as_ref(), args),
        SubCommand::ShowSecret(args) => cli::show_secret(&conn, key.as_ref(), args),
        SubCommand::Fetch(args) => cli::fetch(&conn, key.as_ref(), args),
        SubCommand::Cleanup(args) => cli::cleanup(&conn, key.as_ref(), args),
        SubCommand::RemoveHost(args) => {
            let cleanup = args.cleanup;
            cli::remove_host(&conn, key.as_ref(), args)?;
            if cleanup {
                cli::cleanup(&conn, key.as_ref(), CleanupArgs { dry_run: false })
            } else {
                Ok(())
            }
        }
        SubCommand::GenFolders(args) => {
            let un = whoami::username();
            cli::gen_folders(&conn, key.as_ref(), args, un.as_str())
        }
        SubCommand::SwapKey(args) => cli::swap_key(&conn, key.as_ref(), args),
    }
}

#[cfg(unix)]
fn set_key_permissions(fs: &mut std::fs::File, perms: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs.metadata()?.permissions();
    permissions.set_mode(perms);
    Ok(fs.set_permissions(permissions)?)
}

#[cfg(not(unix))]
fn set_key_permissions(_fs: &mut std::fs::File, perms: u32) -> Result<()> {
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
