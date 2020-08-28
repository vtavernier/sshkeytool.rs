CREATE TABLE authorized_keys (
	id INTEGER PRIMARY KEY NOT NULL,
	host_id INTEGER NOT NULL,
	public_key BLOB NOT NULL,
	digest BLOB NOT NULL,
	removed BOOLEAN NOT NULL DEFAULT FALSE,
	FOREIGN KEY (host_id) REFERENCES hosts(id),
	UNIQUE (host_id, digest)
);

CREATE TABLE authorized_keys_keys (
	authorized_key_id INTEGER NOT NULL,
	key_id INTEGER NOT NULL,
	PRIMARY KEY (authorized_key_id, key_id),
	FOREIGN KEY (authorized_key_id) REFERENCES authorized_keys(id),
	FOREIGN KEY (key_id) REFERENCES keys(id)
);
