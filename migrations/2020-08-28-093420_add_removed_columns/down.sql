PRAGMA foreign_keys = off;

CREATE TABLE IF NOT EXISTS keys_copy(
	id INTEGER PRIMARY KEY NOT NULL,
	host_id INTEGER NOT NULL,
	secret_id INTEGER,
	private_key BLOB NOT NULL,
	public_key BLOB NOT NULL,
	digest BLOB NOT NULL,
	path TEXT NOT NULL,
	FOREIGN KEY (host_id) REFERENCES hosts(id),
	FOREIGN KEY (secret_id) REFERENCES secrets(id),
	UNIQUE (host_id, path)
);

INSERT INTO keys_copy(id, host_id, secret_id, private_key, public_key, digest, path)
SELECT id, host_id, secret_id, private_key, public_key, digest, path FROM keys;

DROP TABLE keys;
ALTER TABLE keys_copy RENAME TO keys;

CREATE TABLE configs_copy(
	id INTEGER PRIMARY KEY NOT NULL,
	host_id INTEGER NOT NULL,
	host TEXT,
	key TEXT NOT NULL,
	value TEXT NOT NULL,
	key_id INTEGER,
	FOREIGN KEY (key_id) REFERENCES keys(id),
	UNIQUE (host_id, host, key)
);

INSERT INTO configs_copy(id, host_id, host, key, value, key_id)
SELECT id, host_id, host, key, value, key_id FROM configs;

DROP TABLE configs;
ALTER TABLE configs_copy RENAME TO configs;

PRAGMA foreign_keys = on;
