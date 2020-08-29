use crate::*;

pub fn add_secret(
    conn: &SqliteConnection,
    key: Option<&SecretKey>,
    args: AddSecretArgs,
) -> Result<()> {
    let AddSecretArgs {
        host_name,
        host_os,
        value,
    } = args;

    // Find host matching secret
    if let Ok(host_id) = {
        use sshkt::schema::hosts::dsl::*;
        hosts
            .select(id)
            .filter(name.eq(&host_name))
            .filter(os.eq(&host_os))
            .first::<i32>(conn)
    } {
        info!("found host id {}", host_id);

        // Create the insertable
        let mut secret = NewSecret {
            host_id,
            secret: value.as_bytes().to_vec(),
            encrypted: 0,
        };

        // Encrypt secret
        if let Some(key) = key {
            secret.encrypt(key);
            debug!("encrypted secret");
        }

        // Add secret to DB
        {
            use sshkt::schema::secrets;
            diesel::insert_into(secrets::table)
                .values(&secret)
                .execute(conn)?;
        }

        info!("inserted secret into database");
    } else {
        bail!("host {} (os type: {}) not found", host_name, host_os);
    }

    Ok(())
}

pub fn show_secret(
    conn: &SqliteConnection,
    key: Option<&SecretKey>,
    args: ShowSecretArgs,
) -> Result<()> {
    let ShowSecretArgs { host_name, host_os } = args;

    // Find host matching secret
    if let Ok(host) = {
        use sshkt::schema::hosts::dsl::*;
        hosts
            .filter(name.eq(&host_name))
            .filter(os.eq(&host_os))
            .first::<Host>(conn)
    } {
        info!("found host id {}", host.id);

        for mut secret in Secret::belonging_to(&host).load::<Secret>(conn)? {
            if secret.encrypted != 0 {
                if secret.decrypt(key).is_some() {
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
    Ok(())
}

pub fn fetch(conn: &SqliteConnection, key: Option<&SecretKey>, args: FetchArgs) -> Result<()> {
    // List of hosts we're considering for this fetch round
    let allowed_hosts: HashSet<String> = HashSet::from_iter(args.only.into_iter());

    // Regular expression for parsing config lines
    let re = regex::Regex::new(r#"^\s*([a-zA-Z0-9]+)\s*(.*?)\s*$"#).unwrap();

    // First, connect to all hosts
    let mut all_hosts = Vec::new();
    for host in {
        use sshkt::schema::hosts::dsl::*;
        hosts.load::<Host>(conn)
    }? {
        if !allowed_hosts.is_empty() && !allowed_hosts.contains(&host.name) {
            info!("skipping host: {}", host);
            continue;
        }

        // Connect to the host
        let host = sshkt::connect(host)?;
        let sftp = host.ssh_connection.sftp()?;

        // Find secrets for this host
        let mut secrets = vec![];
        for mut secret in Secret::belonging_to(&host.host).load::<Secret>(conn)? {
            if let Some(()) = secret.decrypt(key) {
                secrets.push(Some(secret));
            }
        }

        // So we always try no key last
        secrets.push(None);

        all_hosts.push((host, sftp, secrets));
    }

    // List hosts
    for (host, sftp, secrets) in &all_hosts {
        // Fetch all keys from the server
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
            let mut raw_private_key = Vec::with_capacity(stat.size.unwrap_or(4096) as usize);
            io.read_to_end(&mut raw_private_key)?;

            // ssh-keygen is... weird
            // TODO: umask?
            let mut tmp = tempfile::tempfile()?;
            platform::set_file_permissions(&mut tmp, 0o600)?;
            // Write the private key to the temp file
            std::io::copy(
                &mut std::io::Cursor::new(&mut raw_private_key[..]),
                &mut tmp,
            )?;
            // Seek back the temp file
            tmp.seek(std::io::SeekFrom::Start(0))?;

            let tmp = Rc::new(tmp);

            for secret in secrets {
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
                            stdin: subprocess::Redirection::Pipe,
                            stderr: subprocess::Redirection::Pipe,
                            ..Default::default()
                        },
                    )?;

                    let (raw_digest, _) = p.communicate_bytes(Some(&raw_public_key[..]))?;

                    let raw_digest = base_digest(&trim_bytes(raw_digest.unwrap()));
                    let public_key = trim_bytes(raw_public_key);

                    let new_key = NewKey {
                        host_id: host.host.id,
                        secret_id: secret.as_ref().map(|s| s.id),
                        private_key: raw_private_key,
                        public_key,
                        digest: raw_digest,
                        path: file.to_string_lossy().to_string(),
                    };

                    {
                        use sshkt::schema::keys;
                        diesel::replace_into(keys::table)
                            .values(&new_key)
                            .execute(conn)?;
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

    for (host, sftp, _) in &all_hosts {
        // Fetch config
        if let Ok(file) = sftp.open(&PathBuf::from(&host.host.ssh_base_folder).join("config")) {
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
                                    .load::<i32>(conn)
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
                                .execute(conn)?;
                        }
                    }
                }
            }
        } else {
            warn!("no .ssh/config for {}", &host.host);
        }
    }

    for (host, sftp, _) in &all_hosts {
        // Fetch authorized_keys from this server
        if let Ok(file) =
            sftp.open(&PathBuf::from(&host.host.ssh_base_folder).join("authorized_keys"))
        {
            let reader = std::io::BufReader::new(file);

            for line in reader.lines() {
                let line = line?;
                let line = line.trim_end();

                // Extract digest
                let mut p = subprocess::Popen::create(
                    &["ssh-keygen", "-l", "-q", "-f", "/dev/stdin"],
                    subprocess::PopenConfig {
                        stdout: subprocess::Redirection::Pipe,
                        stdin: subprocess::Redirection::Pipe,
                        stderr: subprocess::Redirection::Pipe,
                        ..Default::default()
                    },
                )?;

                let (raw_digest, _) = p.communicate(Some(line))?;
                if let Some(raw_digest) = raw_digest {
                    let raw_digest = base_digest(raw_digest.trim_end().as_bytes());

                    if !raw_digest.is_empty() {
                        info!(
                            "host {} has authorized key {}",
                            host.host,
                            String::from_utf8_lossy(&raw_digest)
                        );

                        let new_key = NewAuthorizedKey {
                            host_id: host.host.id,
                            public_key: line.as_bytes(),
                            digest: &raw_digest,
                        };

                        // Insert (or update) key in the database
                        {
                            use sshkt::schema::authorized_keys;
                            diesel::replace_into(authorized_keys::table)
                                .values(new_key)
                                .execute(conn)?;
                        }

                        // Find out the id of the target
                        let authorized_key = {
                            use sshkt::schema::authorized_keys::dsl::*;
                            AuthorizedKey::belonging_to(&host.host)
                                .filter(digest.eq(&raw_digest))
                                .get_result::<AuthorizedKey>(conn)
                        }?;

                        // Ensure all references to this key are properly set up
                        for existing_key in {
                            use sshkt::schema::keys::dsl::*;
                            keys.filter(digest.eq(&raw_digest)).load::<Key>(conn)
                        }? {
                            info!(
                                "key is present on host {} (id: {})",
                                sshkt::schema::hosts::dsl::hosts
                                    .find(existing_key.host_id)
                                    .get_result::<Host>(conn)?,
                                existing_key.id
                            );

                            {
                                use sshkt::schema::authorized_keys_keys;
                                diesel::replace_into(authorized_keys_keys::table)
                                    .values(&AuthorizedKeyKey {
                                        authorized_key_id: authorized_key.id,
                                        key_id: existing_key.id,
                                    })
                                    .execute(conn)?;
                            }
                        }
                    } else {
                        warn!(
                            "failed to extract key digest for host {} (key line: {:?})",
                            host.host, line
                        );
                    }
                }
            }
        } else {
            warn!("no .ssh/authorized_keys for {}", &host.host);
        }
    }

    Ok(())
}

pub fn cleanup(conn: &SqliteConnection, _key: Option<&SecretKey>, args: CleanupArgs) -> Result<()> {
    let CleanupArgs { dry_run } = args;

    if !dry_run {
        // First, remove all config entries for hosts where the IdentityFile is not found
        let changed = diesel::sql_query(
            "UPDATE configs
SET removed = 1
WHERE NOT removed
  AND id in (SELECT c1.id
             FROM configs c1
             WHERE (SELECT COUNT(*)
                    FROM configs c2
                    WHERE lower(c2.key) = 'identityfile'
                      AND c2.key_id IS NULL
                      AND c1.host_id = c2.host_id
                      AND (c1.host = c2.host OR c2.host = '*' OR c2.host IS NULL)) > 0)",
        )
        .execute(conn)?;
        info!(
            "removed {} config elements whose IdentityFile was not found",
            changed
        );

        // Remove all authorized_keys which don't have any known private key files
        let changed = diesel::sql_query(
            "UPDATE authorized_keys
SET removed = 1
WHERE NOT removed
  AND id IN (SELECT ak1.id
             FROM authorized_keys ak1
             WHERE (SELECT COUNT(*) FROM authorized_keys_keys akk WHERE akk.authorized_key_id = ak1.id) = 0)",
        )
        .execute(conn)?;
        info!(
            "removed {} authorized keys with no associated private key file",
            changed
        );

        // Remove all unused keys
        let changed = diesel::sql_query(
            "UPDATE keys
SET removed = 1
WHERE NOT removed
  AND id in (SELECT k1.id
             FROM keys k1
             WHERE ((SELECT COUNT(*)
                     FROM authorized_keys_keys akk
                              LEFT JOIN authorized_keys ak1 ON ak1.id = akk.authorized_key_id
                     WHERE akk.key_id = k1.id
                       AND NOT ak1.removed) +
                    (SELECT COUNT(*)
                     FROM configs c1
                     WHERE c1.key_id IS NOT NULL AND c1.key_id = k1.id AND NOT c1.removed)) = 0)",
        )
        .execute(conn)?;
        info!("removed {} keys which weren't used anywhere", changed);
    }

    Ok(())
}

pub fn remove_host(
    conn: &SqliteConnection,
    _key: Option<&SecretKey>,
    args: RemoveHostArgs,
) -> Result<()> {
    use sshkt::schema::configs::dsl::*;

    // Remove all matching hosts
    for host_spec in &args.hosts {
        let changed = diesel::update(configs.filter(host.eq(host_spec)).filter(removed.eq(false)))
            .set(removed.eq(true))
            .execute(conn)?;
        info!("removed {} directives for {}", changed, host_spec);
    }

    Ok(())
}

pub fn gen_folders(
    conn: &SqliteConnection,
    _key: Option<&SecretKey>,
    _args: GenFoldersArgs,
    default_user: &str,
) -> Result<()> {
    let target_path = std::env::current_dir()?.join("out");

    if target_path.exists() {
        // Clear output
        std::fs::remove_dir_all(&target_path)?;
    }

    std::fs::create_dir(&target_path)?;
    crate::platform::set_folder_permissions(&target_path, 0o700)?;

    for host in {
        use sshkt::schema::hosts::dsl::*;
        hosts.load::<Host>(conn)
    }? {
        // Build path to the generated SSH folder
        let host_dir_name = format!("{}_{}", host.name, host.os);
        let host_dir = target_path.join(host_dir_name);
        std::fs::create_dir(&host_dir)?;
        crate::platform::set_folder_permissions(&host_dir, 0o700)?;

        // Add (non-removed) keys
        for key in {
            use sshkt::schema::keys::dsl::*;
            Key::belonging_to(&host)
                .filter(removed.eq(false))
                .load::<Key>(conn)
        }? {
            // Write private key file
            {
                let path = host_dir.join(PathBuf::from(&key.path).file_name().unwrap());

                let mut f = std::fs::File::create(&path)?;
                crate::platform::set_file_permissions(&mut f, 0o600)?;
                f.write_all(&key.private_key)?;

                info!(
                    "wrote {} private key for {} to {}",
                    host,
                    String::from_utf8_lossy(&key.digest),
                    path.display()
                );
            }

            // Write public key file, and add a comment
            {
                let path = host_dir
                    .join(PathBuf::from(&key.path).file_name().unwrap())
                    .with_extension("pub");

                let mut f = std::fs::File::create(&path)?;
                crate::platform::set_file_permissions(&mut f, 0o644)?;
                f.write_all(&key.public_key)?;

                writeln!(
                    f,
                    " {}@{}",
                    host.ssh_user
                        .as_ref()
                        .map(|s| s.as_str())
                        .unwrap_or(default_user),
                    host.name
                )?;

                info!(
                    "wrote {} public key for {} to {}",
                    host,
                    String::from_utf8_lossy(&key.digest),
                    path.display()
                );
            }
        }

        // Write authorized_keys file
        {
            let path = host_dir.join("authorized_keys");
            let mut f = std::fs::File::create(&path)?;
            crate::platform::set_file_permissions(&mut f, 0o644)?;

            for authorized_key in {
                use sshkt::schema::authorized_keys::dsl::*;
                AuthorizedKey::belonging_to(&host)
                    .filter(removed.eq(false))
                    .load::<AuthorizedKey>(conn)
            }? {
                f.write_all(&authorized_key.public_key)?;
                writeln!(f, "")?;

                info!(
                    "added {} to authorized_keys for {}",
                    String::from_utf8_lossy(&authorized_key.digest),
                    host
                );
            }

            info!("wrote {}", path.display());
        }

        // Write config file
        {
            let path = host_dir.join("config");
            let mut f = std::fs::File::create(&path)?;
            crate::platform::set_file_permissions(&mut f, 0o644)?;

            writeln!(f, "# Generated by sshkt.rs")?;
            writeln!(f, "#")?;

            // First, write everything with no Host directive
            write_host_config(&mut f, conn, &host, None)?;

            // Then, for all other hosts
            let current_host = host;
            for host_name in {
                // TODO: Diesel doesn't support GROUP BY
                use sshkt::schema::configs::dsl::*;
                let mut hs = HashSet::new();

                hs.extend(
                    Config::belonging_to(&current_host)
                        .filter(removed.eq(false))
                        .select(host)
                        .load::<Option<String>>(conn)?
                        .into_iter()
                        .filter_map(|s| s),
                );
                let mut vec = Vec::from_iter(hs);
                vec.sort();
                vec
            } {
                debug!("{}: looking for entries for {}", current_host, host_name);
                write_host_config(&mut f, conn, &current_host, Some(host_name.as_str()))?;
            }

            info!("wrote {}", path.display());
        }
    }

    Ok(())
}

fn write_host_config(
    f: &mut std::fs::File,
    conn: &SqliteConnection,
    current_host: &Host,
    host_spec: Option<&str>,
) -> Result<()> {
    let mut wrote_host = false;
    let mut indent = "";

    for directive in {
        use sshkt::schema::configs::dsl::*;
        Config::belonging_to(current_host)
            .filter(removed.eq(false))
            .filter(host.eq(host_spec))
            .order(key.asc())
            .load::<Config>(conn)
    }? {
        if !wrote_host {
            writeln!(f, "")?;
            if let Some(spec) = host_spec {
                writeln!(f, "Host {}", spec)?;
                indent = "    ";
            }

            wrote_host = true;
        }

        writeln!(
            f,
            "{indent}{key} {value}",
            indent = indent,
            key = directive.key,
            value = directive.value
        )?;
    }

    Ok(())
}

pub fn swap_key(
    conn: &SqliteConnection,
    _key: Option<&SecretKey>,
    args: SwapKeyArgs,
) -> Result<()> {
    // Try to find the source host
    let host = {
        use sshkt::schema::hosts::dsl::*;
        hosts
            .filter(name.eq(&args.host_from))
            .filter(os.eq(&args.host_os_from))
            .get_result::<Host>(conn)
    }?;

    // Find the target key

    // Resolve full path
    let key_path = if args.key_path.starts_with("~/.ssh/") {
        PathBuf::from(&host.ssh_base_folder)
            .join(&args.key_path["~/.ssh/".len()..])
            .to_string_lossy()
            .to_string()
    } else {
        args.key_path.to_string()
    };

    // Find key based on path and host
    let key = {
        use sshkt::schema::keys::dsl::*;
        Key::belonging_to(&host)
            .filter(path.eq(&key_path))
            .get_result::<Key>(conn)
    }?;

    // Ensure the key isn't deleted
    if key.removed {
        use sshkt::schema::keys::dsl::*;
        diesel::update(keys.find(key.id))
            .set(removed.eq(false))
            .execute(conn)?;
    }

    // Set the IdentityFile property
    let changed = diesel::replace_into(sshkt::schema::configs::dsl::configs)
        .values(NewConfig {
            host_id: host.id,
            host: Some(&args.host_spec_from),
            key: "IdentityFile",
            value: &args.key_path,
            key_id: Some(key.id),
        })
        .execute(conn)?;

    info!("updated {} config directives", changed);

    Ok(())
}
