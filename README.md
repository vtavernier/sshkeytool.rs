# sshkeytool.rs

This is an early PoC of a tool to manage SSH keys, when you went overboard and
used way too many different identities.

## Usage

Set your password for database secrets (i.e. private key passphrases stored in
the database):

    export SSHKT_PASSWORD=password

Insert some hosts in the hosts table:

    $ sqlite3 db.sqlite3
    sqlite> INSERT INTO hosts(name, os, ssh_identity_path, ssh_host, ssh_base_folder) VALUES
       ...> ('my-computer', 'linux', '/home/me/.ssh/id_rsa', 'localhost', '/home/me/.ssh');

Add secrets for decrypting private keys (note: they will still be stored
encrypted in the keys table):

    cargo run -- add-secret --host-name my-computer --host-os linux 'password'

Fetch the keys:

    cargo run -- fetch-keys

Fetch the configuration details:

    cargo run -- fetch-configs

Now you can explore `db.sqlite3` to analyze the contents of your SSH
configuration and keys.

## Author

Vincent Tavernier <vince.tavernier@gmail.com>

## License

MIT
