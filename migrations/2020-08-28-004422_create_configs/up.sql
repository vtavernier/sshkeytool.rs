CREATE TABLE configs (
	id INTEGER PRIMARY KEY NOT NULL,
	host_id INTEGER NOT NULL,
	host TEXT,
	key TEXT NOT NULL,
	value TEXT NOT NULL,
	key_id INTEGER,
	FOREIGN KEY (key_id) REFERENCES keys(id),
	UNIQUE (host_id, host, key)
)
