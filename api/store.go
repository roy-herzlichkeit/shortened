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
//
// users.email is the verified address only (unique, case-insensitive, NULL
// until verified); pending_email is an address waiting for its code. Keeping
// them apart means an address nobody has proved they own can't block the
// real owner from using it. otps holds one live code per account and purpose,
// as a bcrypt hash; mail_log counts mails per account for the hourly limit.
//
// signups holds sign-ups waiting for their code (see signup.go): no users row
// exists until the code is entered. signup_mail counts sign-up mails per
// address for the same hourly limit.
//
// shares holds share links (see shares.go). key has no foreign key on purpose:
// a link whose file row is gone is dead, and its row stays so the page can say
// so. revoked_at is 0 while the owner hasn't turned the link off.
const schema = `
CREATE TABLE IF NOT EXISTS users (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	username      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
	password_hash TEXT    NOT NULL,
	created_at    INTEGER NOT NULL,
	email         TEXT,
	pending_email TEXT
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
CREATE TABLE IF NOT EXISTS otps (
	user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	purpose    TEXT    NOT NULL,
	target     TEXT    NOT NULL,
	code_hash  TEXT    NOT NULL,
	expires_at INTEGER NOT NULL,
	tries      INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (user_id, purpose)
);
CREATE TABLE IF NOT EXISTS mail_log (
	user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	sent_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS mail_log_user ON mail_log(user_id, sent_at);
CREATE TABLE IF NOT EXISTS signups (
	token_hash    TEXT    PRIMARY KEY,
	username      TEXT    NOT NULL,
	password_hash TEXT    NOT NULL,
	email         TEXT    NOT NULL,
	code_hash     TEXT    NOT NULL,
	expires_at    INTEGER NOT NULL,
	tries         INTEGER NOT NULL DEFAULT 0,
	created_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS signup_mail (
	email   TEXT    NOT NULL,
	sent_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS signup_mail_email ON signup_mail(email, sent_at);
CREATE TABLE IF NOT EXISTS shares (
	code       TEXT    PRIMARY KEY,
	key        TEXT    NOT NULL,
	user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	revoked_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS shares_user ON shares(user_id, expires_at);
CREATE INDEX IF NOT EXISTS shares_key ON shares(key);
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

	var hadShares int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'shares'`).Scan(&hadShares); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("read schema: %w", err)
	}
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
	if err := migrateUsersEmail(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate users email: %w", err)
	}
	if hadShares == 0 {
		log.Printf("migration: shares table created")
	}
	return db, nil
}

// columnsOf lists a table's column names.
func columnsOf(db *sql.DB, table string) (map[string]bool, error) {
	have := map[string]bool{}
	rows, err := db.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		have[name] = true
	}
	return have, rows.Err()
}

// migrateUsersEmail adds email and pending_email to a users table from before
// v2 email, and the unique index on the verified address. Existing accounts
// keep everything and start with no address; they are asked for one at their
// next sign-in. Opening an already-migrated database does nothing.
func migrateUsersEmail(db *sql.DB) error {
	have, err := columnsOf(db, "users")
	if err != nil {
		return err
	}
	var added []string
	for _, col := range []string{"email", "pending_email"} {
		if have[col] {
			continue
		}
		if _, err := db.Exec(`ALTER TABLE users ADD COLUMN ` + col + ` TEXT`); err != nil { // #nosec G202 -- col is one of two literals above
			return err
		}
		added = append(added, col)
	}
	// NULLs don't collide in a unique index, so accounts without an address
	// are fine; two verified accounts can't share one, whatever the case.
	if _, err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS users_email ON users(email COLLATE NOCASE)`); err != nil {
		return err
	}
	if len(added) > 0 {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
			return err
		}
		log.Printf("migration: users table gained %s (%d existing users kept, no address yet)", strings.Join(added, ", "), n)
	}
	return nil
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
