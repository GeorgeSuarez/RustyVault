use color_eyre::Result;
use rusqlite::{Connection, params};

use crate::app::{Account, ApiCredential};

pub fn init() -> Result<Connection> {
    let conn = Connection::open("rusty-vault.db")?;
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

pub fn load_all(conn: &Connection) -> Result<Vec<Account>> {
    let mut stmt = conn.prepare("SELECT id, website, username, password FROM accounts ORDER BY id")?;
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

pub fn insert(
    conn: &Connection,
    website: &str,
    username: &str,
    password: &str,
) -> Result<i64> {
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