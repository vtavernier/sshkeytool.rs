use crate::schema::{authorized_keys, authorized_keys_keys};

use super::Host;

#[derive(Identifiable, Queryable, Associations, PartialEq, Debug)]
#[belongs_to(Host)]
pub struct AuthorizedKey {
    pub id: i32,
    pub host_id: i32,
    pub public_key: Vec<u8>,
    pub digest: Vec<u8>,
    pub removed: bool,
}

#[derive(Insertable, PartialEq, Debug)]
#[table_name = "authorized_keys"]
pub struct NewAuthorizedKey<'a> {
    pub host_id: i32,
    pub public_key: &'a [u8],
    pub digest: &'a [u8],
}

#[derive(Identifiable, Queryable, Insertable, Associations, PartialEq, Debug)]
#[primary_key(authorized_key_id, key_id)]
#[table_name = "authorized_keys_keys"]
pub struct AuthorizedKeyKey {
    pub authorized_key_id: i32,
    pub key_id: i32,
}
