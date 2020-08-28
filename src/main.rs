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

#[derive(FromArgs)]
/// SSH Key Management tool, written in Rust
struct Args {
    #[argh(subcommand)]
    /// command to run
    cmd: SubCommand,

    #[argh(option)]
    /// database password for secrets
    password: Option<String>,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum SubCommand {
    AddSecret(AddSecretArgs),
    ShowSecret(ShowSecretArgs),
    FetchKeys(FetchKeysArgs),
    FetchConfig(FetchConfigArgs),
}

#[derive(FromArgs)]
/// Add a secret for decrypting key files
#[argh(subcommand, name = "add-secret")]
struct AddSecretArgs {
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
struct ShowSecretArgs {
    #[argh(option)]
    /// hostname to add the secret for
    host_name: String,

    #[argh(option)]
    /// os to add the secret for
    host_os: String,
}

#[derive(FromArgs)]
/// Fetch the keys from remote sources
#[argh(subcommand, name = "fetch-keys")]
struct FetchKeysArgs {
    #[argh(option)]
    /// only hostnames to include in the fetch
    only: Vec<String>,
}

#[derive(FromArgs)]
/// Fetch the configs from remote sources
#[argh(subcommand, name = "fetch-configs")]
struct FetchConfigArgs {
    #[argh(option)]
    /// only hostnames to include in the fetch
    only: Vec<String>,
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
        SubCommand::AddSecret(AddSecretArgs {
            host_name,
            host_os,
            value,
        }) => {
            // Find host matching secret
            if let Ok(host_id) = {
                use sshkt::schema::hosts::dsl::*;
                hosts
                    .select(id)
                    .filter(name.eq(&host_name))
                    .filter(os.eq(&host_os))
                    .first::<i32>(&conn)
            } {
                info!("found host id {}", host_id);

                // Create the insertable
                let mut secret = NewSecret {
                    host_id,
                    secret: value.as_bytes().to_vec(),
                    encrypted: 0,
                };

                // Encrypt secret
                if let Some(key) = &key {
                    secret.encrypt(key);
                    debug!("encrypted secret");
                }

                // Add secret to DB
                {
                    use sshkt::schema::secrets;
                    diesel::insert_into(secrets::table)
                        .values(&secret)
                        .execute(&conn)?;
                }

                info!("inserted secret into database");
            } else {
                bail!("host {} (os type: {}) not found", host_name, host_os);
            }
        }
        SubCommand::ShowSecret(ShowSecretArgs { host_name, host_os }) => {
            // Find host matching secret
            if let Ok(host) = {
                use sshkt::schema::hosts::dsl::*;
                hosts
                    .filter(name.eq(&host_name))
                    .filter(os.eq(&host_os))
                    .first::<Host>(&conn)
            } {
                info!("found host id {}", host.id);

                for mut secret in Secret::belonging_to(&host).load::<Secret>(&conn)? {
                    if secret.encrypted != 0 {
                        if secret.decrypt(key.as_ref()).is_some() {
                            info!(
                                "decrypted secret {} for {}: {}",
                                secret.id,
                                host,
                                String::from_utf8_lossy(&secret.secret[..])
                            );
                        } else {
                            warn!("failed to decrypt secret {} for {}", secret.id, host);
                        }
                    } else {
                        info!(
                            "secret {} for {}: {}",
                            secret.id,
                            host,
                            String::from_utf8_lossy(&secret.secret[..])
                        );
                    }
                }
            } else {
                bail!("host {} (os type: {}) not found", host_name, host_os);
            }
        }
        SubCommand::FetchKeys(fetch_keys_args) => {
            let allowed_hosts: HashSet<String> =
                HashSet::from_iter(fetch_keys_args.only.into_iter());

            // List hosts
            //let mut all_hosts = Vec::new();
            for host in {
                use sshkt::schema::hosts::dsl::*;
                hosts.load::<Host>(&conn)
            }? {
                if !allowed_hosts.is_empty() && !allowed_hosts.contains(&host.name) {
                    info!("skipping host: {}", host);
                    continue;
                }

                // Connect to the host
                let host = sshkt::connect(host)?;

                // Find secrets for this host
                let mut secrets = vec![];
                for mut secret in Secret::belonging_to(&host.host).load::<Secret>(&conn)? {
                    if let Some(()) = secret.decrypt(key.as_ref()) {
                        secrets.push(Some(secret));
                    }
                }

                // So we always try no key last
                secrets.push(None);

                // Fetch all keys from the server
                let sftp = host.ssh_connection.sftp()?;
                for (file, stat) in sftp.readdir(&Path::new(&host.host.ssh_base_folder))? {
                    // Skip files which are probably not private keys
                    let basename = if let Some(os_str) = file.file_name() {
                        os_str.to_string_lossy()
                    } else {
                        // Silently discard non-UTF8 names
                        continue;
                    };

                    if basename.starts_with("authorized_keys")
                        || basename.starts_with("known_hosts")
                        || basename.ends_with(".pub")
                        || basename.starts_with("config")
                    {
                        continue;
                    }

                    info!("found key {:?}", file);

                    // Fetch the key from the server
                    let mut io = sftp.open(&file)?;
                    let mut raw_private_key =
                        Vec::with_capacity(stat.size.unwrap_or(4096) as usize);
                    io.read_to_end(&mut raw_private_key)?;

                    // ssh-keygen is... weird
                    // TODO: umask?
                    let mut tmp = tempfile::tempfile()?;
                    set_key_permissions(&mut tmp)?;
                    // Write the private key to the temp file
                    std::io::copy(
                        &mut std::io::Cursor::new(&mut raw_private_key[..]),
                        &mut tmp,
                    )?;
                    // Seek back the temp file
                    tmp.seek(std::io::SeekFrom::Start(0))?;

                    let tmp = Rc::new(tmp);

                    for secret in &secrets {
                        let passphrase = if let Some(secret) = secret {
                            String::from_utf8_lossy(&secret.secret[..])
                        } else {
                            std::borrow::Cow::Owned("".to_owned())
                        };

                        // Extract its public key part with ssh-keygen
                        let mut p = subprocess::Popen::create(
                            &[
                                "ssh-keygen",
                                "-y",
                                "-q",
                                "-f",
                                "/dev/stdin",
                                "-P",
                                passphrase.as_ref(),
                            ],
                            subprocess::PopenConfig {
                                stdout: subprocess::Redirection::Pipe,
                                stdin: subprocess::Redirection::RcFile(tmp.clone()),
                                stderr: subprocess::Redirection::Pipe,
                                ..Default::default()
                            },
                        )?;

                        let (raw_public_key, err) = p.communicate_bytes(None)?;

                        let raw_public_key = raw_public_key.unwrap();
                        let err = err.unwrap();

                        if err.is_empty() {
                            debug!(
                                "public key: {:?}",
                                String::from_utf8_lossy(&raw_public_key[..])
                            );

                            // Extract the digest
                            let mut p = subprocess::Popen::create(
                                &[
                                    "ssh-keygen",
                                    "-l",
                                    "-q",
                                    "-f",
                                    "/dev/stdin",
                                    "-P",
                                    passphrase.as_ref(),
                                ],
                                subprocess::PopenConfig {
                                    stdout: subprocess::Redirection::Pipe,
                                    stdin: subprocess::Redirection::RcFile(tmp.clone()),
                                    stderr: subprocess::Redirection::Pipe,
                                    ..Default::default()
                                },
                            )?;

                            let (raw_digest, _) = p.communicate_bytes(None)?;

                            let new_key = NewKey {
                                host_id: host.host.id,
                                secret_id: secret.as_ref().map(|s| s.id),
                                private_key: raw_private_key,
                                public_key: raw_public_key,
                                digest: raw_digest.unwrap(),
                                path: file.to_string_lossy().to_string(),
                            };

                            {
                                use sshkt::schema::keys;
                                diesel::replace_into(keys::table)
                                    .values(&new_key)
                                    .execute(&conn)?;
                            }

                            info!("inserted key into database");
                            break;
                        } else {
                            warn!(
                                "error extracting public key: {}",
                                String::from_utf8_lossy(&err[..]).trim_end()
                            );
                        }
                    }
                }
            }
        }
        SubCommand::FetchConfig(fetch_config_args) => {
            let allowed_hosts: HashSet<String> =
                HashSet::from_iter(fetch_config_args.only.into_iter());

            let re = regex::Regex::new(r#"^\s*([a-zA-Z0-9]+)\s*(.*?)\s*$"#).unwrap();

            // List hosts
            //let mut all_hosts = Vec::new();
            for host in {
                use sshkt::schema::hosts::dsl::*;
                hosts.load::<Host>(&conn)
            }? {
                if !allowed_hosts.is_empty() && !allowed_hosts.contains(&host.name) {
                    info!("skipping host: {}", host);
                    continue;
                }

                // Connect to the host
                let host = sshkt::connect(host)?;

                // Fetch config from this server
                let sftp = host.ssh_connection.sftp()?;
                if let Ok(file) =
                    sftp.open(&PathBuf::from(&host.host.ssh_base_folder).join("config"))
                {
                    let reader = std::io::BufReader::new(file);
                    let mut current_host = None;

                    for line in reader.lines() {
                        if let Some(m) = re.captures(line?.as_str()) {
                            if m.get(1).unwrap().as_str().to_lowercase() == "host" {
                                current_host = Some(m.get(2).unwrap().as_str().to_owned());
                            } else {
                                let key = m.get(1).unwrap().as_str();
                                let value = m.get(2).unwrap().as_str();

                                let key_id = if key.to_lowercase() == "identityfile" {
                                    // Resolve full path
                                    let key_path = if value.starts_with("~/.ssh/") {
                                        PathBuf::from(&host.host.ssh_base_folder)
                                            .join(&value["~/.ssh/".len()..])
                                            .to_string_lossy()
                                            .to_string()
                                    } else {
                                        value.to_string()
                                    };

                                    // Find result
                                    {
                                        use sshkt::schema::keys::dsl::*;
                                        Key::belonging_to(&host.host)
                                            .select(id)
                                            .filter(path.eq(&key_path))
                                            .load::<i32>(&conn)
                                            .into_iter()
                                            .next()
                                            .and_then(|v| v.get(0).cloned())
                                    }
                                } else {
                                    None
                                };

                                let new_config = NewConfig {
                                    host_id: host.host.id,
                                    host: current_host.as_ref().map(|s| s.as_str()),
                                    key,
                                    value,
                                    key_id,
                                };

                                info!("discovered config: {:?}", new_config);

                                {
                                    use sshkt::schema::configs;
                                    diesel::replace_into(configs::table)
                                        .values(&new_config)
                                        .execute(&conn)?;
                                }
                            }
                        }
                    }
                } else {
                    warn!("no .ssh/config for {}", &host.host);
                }
            }
        }
    }

    Ok(())
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
