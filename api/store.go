package main

import (
	"database/sql"
	"fmt"
	"log"
	"strings"

	_ "modernc.org/sqlite" // pure-Go driver, keeps CGO_ENABLED=0 builds working
)

// AUTOINCREMENT on users.id matters: without it SQLite hands out the highest
// deleted id again, and a new account would inherit the old account's u/<id>/
// folder in the bucket. migrateUsersAutoincrement upgrades older databases.
//
// The files table is the quota ledger. A row is written when an upload URL is
// signed, with the exact size that URL allows, so URLs that are signed but not
// yet used still count against the quota. The browser then confirms the upload
// (confirmed_at is set once the object is seen in the bucket) or releases it
// (the row goes at once). replaces names the file a "Replace" upload swaps out
// when it is confirmed. syncFiles reconciles the ledger with the bucket.
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
	key          TEXT    PRIMARY KEY,
	user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	size         INTEGER NOT NULL,
	created_at   INTEGER NOT NULL,
	confirmed_at INTEGER NOT NULL DEFAULT 0,
	replaces     TEXT    NOT NULL DEFAULT ''
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
	if err := migrateFilesColumns(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate files table: %w", err)
	}
	return db, nil
}

// migrateFilesColumns adds the ledger columns that came with confirm, release
// and replace. Rows that existed before keep confirmed_at = 0, so they follow
// the old rule: dropped once the reservation window has passed without an
// object. Opening an already-migrated database does nothing.
func migrateFilesColumns(db *sql.DB) error {
	have := map[string]bool{}
	rows, err := db.Query(`SELECT name FROM pragma_table_info('files')`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			_ = rows.Close()
			return err
		}
		have[name] = true
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}

	var added []string
	for _, col := range []struct{ name, ddl string }{
		{"confirmed_at", `ALTER TABLE files ADD COLUMN confirmed_at INTEGER NOT NULL DEFAULT 0`},
		{"replaces", `ALTER TABLE files ADD COLUMN replaces TEXT NOT NULL DEFAULT ''`},
	} {
		if have[col.name] {
			continue
		}
		if _, err := db.Exec(col.ddl); err != nil {
			return err
		}
		added = append(added, col.name)
	}
	if len(added) > 0 {
		log.Printf("migration: files table gained %s", strings.Join(added, ", "))
	}
	return nil
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
