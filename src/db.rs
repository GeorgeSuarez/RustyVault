use std::fs::OpenOptions;
use std::path::Path;
use std::time::Duration;

use color_eyre::Result;
use rusqlite::{Connection, params};

use crate::app::{Account, ApiCredential};

/// How long SQLite waits for a lock held by another process before failing.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Open (creating if necessary) the vault database and ensure its schema,
/// permissions, and safety pragmas are in place.
pub fn init(path: &Path) -> Result<Connection> {
    prepare_database_file(path)?;
    let conn = Connection::open(path)?;
    conn.busy_timeout(BUSY_TIMEOUT)?;
    // Overwrite deleted rows on disk instead of leaving ciphertext behind in
    // free pages, so `delete` and master-password rotation scrub the file.
    conn.pragma_update(None, "secure_delete", true)?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS accounts (
            id       INTEGER PRIMARY KEY,
            website  TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )",
        [],
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS api_credentials (
            id            INTEGER PRIMARY KEY,
            name          TEXT NOT NULL,
            api_key       TEXT NOT NULL,
            client_id     TEXT NOT NULL,
            client_secret TEXT NOT NULL
        )",
        [],
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS meta (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )",
        [],
    )?;
    Ok(conn)
}

/// Create the database file with owner-only permissions *before* SQLite opens
/// it, and tighten permissions on pre-existing files. The database holds
/// plaintext site names/usernames plus the encrypted secrets, so it must not
/// be group- or world-readable.
fn prepare_database_file(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }

    if !path.exists() {
        let mut options = OpenOptions::new();
        options.create(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(path)?;
    }

    restrict_permissions(path)
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = std::fs::metadata(path)?;
    if metadata.permissions().mode() & 0o077 != 0 {
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o600);
        std::fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

pub fn load_all(conn: &Connection) -> Result<Vec<Account>> {
    let mut stmt =
        conn.prepare("SELECT id, website, username, password FROM accounts ORDER BY id")?;
    let accounts = stmt
        .query_map([], |row| {
            Ok(Account {
                id: row.get(0)?,
                website: row.get(1)?,
                username: row.get(2)?,
                password: row.get(3)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(accounts)
}

pub fn insert(conn: &Connection, website: &str, username: &str, password: &str) -> Result<i64> {
    conn.execute(
        "INSERT INTO accounts (website, username, password) VALUES (?1, ?2, ?3)",
        params![website, username, password],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn update(
    conn: &Connection,
    id: i64,
    website: &str,
    username: &str,
    password: &str,
) -> Result<()> {
    conn.execute(
        "UPDATE accounts SET website = ?1, username = ?2, password = ?3 WHERE id = ?4",
        params![website, username, password, id],
    )?;
    Ok(())
}

pub fn delete(conn: &Connection, id: i64) -> Result<()> {
    conn.execute("DELETE FROM accounts WHERE id = ?1", params![id])?;
    Ok(())
}

pub fn load_all_api(conn: &Connection) -> Result<Vec<ApiCredential>> {
    let mut stmt = conn.prepare(
        "SELECT id, name, api_key, client_id, client_secret FROM api_credentials ORDER BY id",
    )?;
    let creds = stmt
        .query_map([], |row| {
            Ok(ApiCredential {
                id: row.get(0)?,
                name: row.get(1)?,
                api_key: row.get(2)?,
                client_id: row.get(3)?,
                client_secret: row.get(4)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(creds)
}

pub fn insert_api(
    conn: &Connection,
    name: &str,
    api_key: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<i64> {
    conn.execute(
        "INSERT INTO api_credentials (name, api_key, client_id, client_secret)
         VALUES (?1, ?2, ?3, ?4)",
        params![name, api_key, client_id, client_secret],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn update_api(
    conn: &Connection,
    id: i64,
    name: &str,
    api_key: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<()> {
    conn.execute(
        "UPDATE api_credentials SET name = ?1, api_key = ?2, client_id = ?3, client_secret = ?4
         WHERE id = ?5",
        params![name, api_key, client_id, client_secret, id],
    )?;
    Ok(())
}

pub fn delete_api(conn: &Connection, id: i64) -> Result<()> {
    conn.execute("DELETE FROM api_credentials WHERE id = ?1", params![id])?;
    Ok(())
}

pub fn get_meta(conn: &Connection, key: &str) -> Result<Option<String>> {
    let mut stmt = conn.prepare("SELECT value FROM meta WHERE key = ?1")?;
    let mut rows = stmt.query(params![key])?;
    if let Some(row) = rows.next()? {
        Ok(Some(row.get(0)?))
    } else {
        Ok(None)
    }
}

pub fn set_meta(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Each test gets its own directory so parallel runs cannot collide.
    fn temp_db_dir(label: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "rusty-vault-db-test-{}-{n}-{label}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn init_creates_schema_and_roundtrips_accounts() {
        let dir = temp_db_dir("accounts");
        let conn = init(&dir.join("vault.db")).unwrap();

        let id = insert(&conn, "example.com", "alice", "ciphertext").unwrap();
        let accounts = load_all(&conn).unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].id, id);
        assert_eq!(accounts[0].website, "example.com");

        update(&conn, id, "example.org", "bob", "ciphertext2").unwrap();
        let accounts = load_all(&conn).unwrap();
        assert_eq!(accounts[0].website, "example.org");
        assert_eq!(accounts[0].username, "bob");

        delete(&conn, id).unwrap();
        assert!(load_all(&conn).unwrap().is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn init_creates_schema_and_roundtrips_api_credentials() {
        let dir = temp_db_dir("api");
        let conn = init(&dir.join("vault.db")).unwrap();

        let id = insert_api(&conn, "stripe", "key", "client", "secret").unwrap();
        let creds = load_all_api(&conn).unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].id, id);

        update_api(&conn, id, "stripe-live", "key2", "client2", "secret2").unwrap();
        let creds = load_all_api(&conn).unwrap();
        assert_eq!(creds[0].name, "stripe-live");
        assert_eq!(creds[0].client_secret, "secret2");

        delete_api(&conn, id).unwrap();
        assert!(load_all_api(&conn).unwrap().is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn meta_roundtrips_and_overwrites() {
        let dir = temp_db_dir("meta");
        let conn = init(&dir.join("vault.db")).unwrap();

        assert_eq!(get_meta(&conn, "salt").unwrap(), None);
        set_meta(&conn, "salt", "abc").unwrap();
        assert_eq!(get_meta(&conn, "salt").unwrap(), Some("abc".to_string()));
        set_meta(&conn, "salt", "def").unwrap();
        assert_eq!(get_meta(&conn, "salt").unwrap(), Some("def".to_string()));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn init_creates_owner_only_file_and_tightens_existing_files() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_db_dir("permissions");
        let path = dir.join("vault.db");

        let conn = init(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "fresh database must be owner-only");

        // A pre-existing world-readable file is tightened on next open.
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o644);
        std::fs::set_permissions(&path, permissions).unwrap();
        drop(conn);

        let _conn = init(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "existing database must be tightened");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn init_creates_missing_parent_directories() {
        let dir = temp_db_dir("nested");
        let path = dir.join("a/b/vault.db");
        let conn = init(&path).unwrap();
        assert!(path.exists());
        drop(conn);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
