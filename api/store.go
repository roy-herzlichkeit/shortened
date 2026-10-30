package main

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite" // pure-Go driver, keeps CGO_ENABLED=0 builds working
)

// The files table is the quota ledger. A row is written when an upload URL is
// signed, with the exact size that URL allows, so URLs that are signed but not
// yet used still count against the quota. syncFiles later reconciles the
// ledger with what is really in the bucket.
const schema = `
CREATE TABLE IF NOT EXISTS users (
	id            INTEGER PRIMARY KEY,
	username      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
	password_hash TEXT    NOT NULL,
	created_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
	token_hash TEXT    PRIMARY KEY,
	user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
CREATE TABLE IF NOT EXISTS files (
	key        TEXT    PRIMARY KEY,
	user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	size       INTEGER NOT NULL,
	created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS files_user ON files(user_id);
`

func openDB(path string) (*sql.DB, error) {
	dsn := path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One connection serializes every statement, which makes "check the quota,
	// then insert" and "check the username, then insert" atomic inside a plain
	// transaction. The app does a handful of tiny queries per request, so the
	// lost concurrency does not matter. Never use s.db inside an open tx: with
	// one connection that deadlocks.
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(schema); err != nil {
		_ = db.Close() // the schema error is the one worth reporting
		return nil, fmt.Errorf("create schema: %w", err)
	}
	return db, nil
}
