package main

import (
	"database/sql"
	"fmt"
	"strings"

	_ "modernc.org/sqlite" // pure-Go driver, keeps CGO_ENABLED=0 builds working
)

// AUTOINCREMENT on users.id matters: without it SQLite hands out the highest
// deleted id again, and a new account would inherit the old account's u/<id>/
// folder in the bucket. migrateUsersAutoincrement upgrades older databases.
//
// The files table is the quota ledger. A row is written when an upload URL is
// signed, with the exact size that URL allows, so URLs that are signed but not
// yet used still count against the quota. syncFiles later reconciles the
// ledger with what is really in the bucket.
const schema = `
CREATE TABLE IF NOT EXISTS users (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
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
	if err := migrateUsersAutoincrement(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate users table: %w", err)
	}
	return db, nil
}

// migrateUsersAutoincrement rebuilds a users table created before ids were
// AUTOINCREMENT. CREATE TABLE IF NOT EXISTS leaves an existing table alone and
// SQLite can't add AUTOINCREMENT in place, so this copies the rows into a new
// table and swaps it in, keeping every id so sessions, ledger rows and bucket
// folders still line up.
func migrateUsersAutoincrement(db *sql.DB) error {
	var ddl string
	if err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'users'`).Scan(&ddl); err != nil {
		return err
	}
	if strings.Contains(strings.ToUpper(ddl), "AUTOINCREMENT") {
		return nil
	}

	// Dropping users while sessions and files reference it needs foreign keys
	// off. The pragma is ignored inside a transaction, so it is set first, and
	// the pool's single connection guarantees the transaction runs on it.
	if _, err := db.Exec(`PRAGMA foreign_keys = OFF`); err != nil {
		return err
	}
	defer func() { _, _ = db.Exec(`PRAGMA foreign_keys = ON`) }()

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	for _, stmt := range []string{
		// Same columns as users in schema above; keep the two in step.
		`CREATE TABLE users_new (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			username      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
			password_hash TEXT    NOT NULL,
			created_at    INTEGER NOT NULL
		)`,
		// Explicit ids also advance sqlite_sequence to the current maximum.
		`INSERT INTO users_new (id, username, password_hash, created_at)
			SELECT id, username, password_hash, created_at FROM users`,
		`DROP TABLE users`,
		`ALTER TABLE users_new RENAME TO users`,
	} {
		if _, err := tx.Exec(stmt); err != nil {
			return err
		}
	}

	// The swap must leave every session and ledger row pointing at a user.
	rows, err := tx.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		return err
	}
	broken := rows.Next()
	if err := rows.Close(); err != nil {
		return err
	}
	if broken {
		return fmt.Errorf("foreign key check failed after rebuilding users")
	}
	return tx.Commit()
}
