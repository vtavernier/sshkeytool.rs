use crate::schema::configs;

use super::Host;

#[derive(Identifiable, Queryable, Associations, PartialEq, Debug)]
#[belongs_to(Host)]
pub struct Config {
    pub id: i32,
    pub host_id: i32,
    pub host: Option<String>,
    pub key: String,
    pub value: String,
    pub key_id: Option<i32>,
}

#[derive(Insertable, PartialEq, Debug)]
#[table_name = "configs"]
pub struct NewConfig<'a> {
    pub host_id: i32,
    pub host: Option<&'a str>,
    pub key: &'a str,
    pub value: &'a str,
    pub key_id: Option<i32>,
}
