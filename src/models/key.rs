use crate::schema::keys;

use super::Host;

#[derive(Identifiable, Queryable, Associations, PartialEq, Debug)]
#[belongs_to(Host)]
pub struct Key {
    pub id: i32,
    pub host_id: i32,
    pub secret_id: Option<i32>,
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub digest: Vec<u8>,
    pub path: String,
}

#[derive(Insertable, PartialEq, Debug)]
#[table_name = "keys"]
pub struct NewKey {
    pub host_id: i32,
    pub secret_id: Option<i32>,
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub digest: Vec<u8>,
    pub path: String,
}
