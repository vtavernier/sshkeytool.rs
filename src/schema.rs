table! {
    authorized_keys (id) {
        id -> Integer,
        host_id -> Integer,
        public_key -> Binary,
        digest -> Binary,
        removed -> Bool,
    }
}

table! {
    authorized_keys_keys (authorized_key_id, key_id) {
        authorized_key_id -> Integer,
        key_id -> Integer,
    }
}

table! {
    configs (id) {
        id -> Integer,
        host_id -> Integer,
        host -> Nullable<Text>,
        key -> Text,
        value -> Text,
        key_id -> Nullable<Integer>,
        removed -> Bool,
    }
}

table! {
    hosts (id) {
        id -> Integer,
        name -> Text,
        os -> Text,
        ssh_identity_path -> Text,
        ssh_user -> Nullable<Text>,
        ssh_host -> Text,
        ssh_port -> Nullable<Integer>,
        ssh_base_folder -> Text,
    }
}

table! {
    keys (id) {
        id -> Integer,
        host_id -> Integer,
        secret_id -> Nullable<Integer>,
        private_key -> Binary,
        public_key -> Binary,
        digest -> Binary,
        path -> Text,
        removed -> Bool,
    }
}

table! {
    secrets (id) {
        id -> Integer,
        host_id -> Integer,
        secret -> Binary,
        encrypted -> Integer,
    }
}

joinable!(authorized_keys -> hosts (host_id));
joinable!(authorized_keys_keys -> authorized_keys (authorized_key_id));
joinable!(authorized_keys_keys -> keys (key_id));
joinable!(configs -> keys (key_id));
joinable!(keys -> hosts (host_id));
joinable!(keys -> secrets (secret_id));
joinable!(secrets -> hosts (host_id));

allow_tables_to_appear_in_same_query!(
    authorized_keys,
    authorized_keys_keys,
    configs,
    hosts,
    keys,
    secrets,
);
