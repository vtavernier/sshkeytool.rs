#[macro_use]
extern crate diesel;
#[macro_use]
extern crate log;

use std::net::TcpStream;
use std::path::Path;

use anyhow::Result;

use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;

pub mod models;
pub mod schema;

pub fn establish_connection() -> SqliteConnection {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let res = SqliteConnection::establish(&database_url)
        .expect(&format!("Error connecting to {}", database_url));

    info!("established connection to {}", database_url);
    res
}

pub struct ConnectedHost {
    pub host: models::Host,
    pub ssh_connection: ssh2::Session,
}

pub fn connect(host: models::Host) -> Result<ConnectedHost> {
    let tcp = TcpStream::connect((host.ssh_host.as_str(), host.ssh_port.unwrap_or(22) as u16))?;
    let username;
    let un = match host.ssh_user.as_ref() {
        Some(s) => s.as_str(),
        None => {
            username = whoami::username();
            username.as_str()
        }
    };

    let mut sess = ssh2::Session::new()?;
    sess.set_tcp_stream(tcp);
    sess.handshake()?;
    sess.userauth_pubkey_file(un, None, &Path::new(&host.ssh_identity_path), None)?;

    info!(
        "established connection to {}@{} for {}",
        un, host.ssh_host, host
    );

    Ok(ConnectedHost {
        host,
        ssh_connection: sess,
    })
}
