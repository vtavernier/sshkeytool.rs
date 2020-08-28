CREATE TABLE keys (
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
)
