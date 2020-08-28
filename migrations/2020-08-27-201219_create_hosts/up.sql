CREATE TABLE hosts (
	id INTEGER PRIMARY KEY NOT NULL,
	name TEXT NOT NULL,
	os TEXT NOT NULL,
	ssh_identity_path TEXT NOT NULL,
	ssh_user TEXT,
	ssh_host TEXT NOT NULL,
	ssh_port INTEGER,
	ssh_base_folder TEXT NOT NULL,
	UNIQUE (name, os)
)
