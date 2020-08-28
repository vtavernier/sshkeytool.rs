use crate::schema::hosts;

#[derive(Identifiable, Queryable, PartialEq, Debug)]
pub struct Host {
    pub id: i32,
    pub name: String,
    pub os: String,
    pub ssh_identity_path: String,
    pub ssh_user: Option<String>,
    pub ssh_host: String,
    pub ssh_port: Option<i32>,
    pub ssh_base_folder: String,
}

impl std::fmt::Display for Host {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (os type: {})", self.name, self.os)
    }
}
