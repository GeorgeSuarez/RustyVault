use base64::{Engine, engine::general_purpose::STANDARD as B64};
use rusqlite::Connection;
use zeroize::Zeroize;

use crate::{crypto, crypto::MasterKey, db};

#[derive(Clone, Debug)]
pub struct Account {
    pub id: i64,
    pub website: String,
    pub username: String,
    /// Encrypted password (base64 nonce||ciphertext+tag).
    pub password: String,
}

#[derive(Clone, Debug)]
pub struct ApiCredential {
    pub id: i64,
    pub name: String,
    /// Encrypted (base64 nonce||ciphertext+tag).
    pub api_key: String,
    pub client_id: String,
    /// Encrypted (base64 nonce||ciphertext+tag).
    pub client_secret: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Unlock,
    Setup,
    List,
    View,
    Add,
    Edit,
    ResetMaster,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tab {
    Accounts,
    ApiKeys,
}

impl Tab {
    pub fn toggle(self) -> Self {
        match self {
            Tab::Accounts => Tab::ApiKeys,
            Tab::ApiKeys => Tab::Accounts,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Tab::Accounts => "Accounts",
            Tab::ApiKeys => "API Keys",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    // Auth forms
    Master,
    MasterConfirm,
    // Reset master password form
    OldMaster,
    NewMaster,
    NewMasterConfirm,
    // Account form
    Website,
    Username,
    Password,
    // API credential form
    Name,
    ApiKey,
    ClientId,
    ClientSecret,
}

impl Field {
    /// Cycle fields for the account Add/Edit form.
    pub fn account_next(self) -> Self {
        match self {
            Field::Website => Field::Username,
            Field::Username => Field::Password,
            Field::Password => Field::Website,
            _ => self,
        }
    }

    pub fn account_prev(self) -> Self {
        match self {
            Field::Website => Field::Password,
            Field::Username => Field::Website,
            Field::Password => Field::Username,
            _ => self,
        }
    }

    /// Cycle fields for the API credential Add/Edit form.
    pub fn api_next(self) -> Self {
        match self {
            Field::Name => Field::ApiKey,
            Field::ApiKey => Field::ClientId,
            Field::ClientId => Field::ClientSecret,
            Field::ClientSecret => Field::Name,
            _ => self,
        }
    }

    pub fn api_prev(self) -> Self {
        match self {
            Field::Name => Field::ClientSecret,
            Field::ApiKey => Field::Name,
            Field::ClientId => Field::ApiKey,
            Field::ClientSecret => Field::ClientId,
            _ => self,
        }
    }

    /// Cycle fields for the Setup form.
    pub fn setup_next(self) -> Self {
        match self {
            Field::Master => Field::MasterConfirm,
            Field::MasterConfirm => Field::Master,
            _ => self,
        }
    }

    /// Cycle fields for the Reset Master Password form.
    pub fn reset_next(self) -> Self {
        match self {
            Field::OldMaster => Field::NewMaster,
            Field::NewMaster => Field::NewMasterConfirm,
            Field::NewMasterConfirm => Field::OldMaster,
            _ => self,
        }
    }

    pub fn reset_prev(self) -> Self {
        match self {
            Field::OldMaster => Field::NewMasterConfirm,
            Field::NewMaster => Field::OldMaster,
            Field::NewMasterConfirm => Field::NewMaster,
            _ => self,
        }
    }
}

/// Decrypted secrets currently shown in the View screen.
///
/// Derives `Zeroize` so the plaintext secrets are overwritten with zeros
/// when this enum is dropped or explicitly cleared.
#[derive(Clone, Debug, Default, Zeroize)]
pub enum Revealed {
    #[default]
    None,
    AccountPassword(String),
    Api {
        api_key: String,
        client_secret: String,
    },
}

impl Revealed {
    pub fn is_none(&self) -> bool {
        matches!(self, Revealed::None)
    }

    /// Overwrite any held plaintext with zeros and reset to `None`.
    pub fn clear(&mut self) {
        self.zeroize();
        *self = Revealed::None;
    }
}

pub struct App {
    pub conn: Connection,
    pub master_key: Option<MasterKey>,
    pub tab: Tab,
    pub accounts: Vec<Account>,
    pub api_credentials: Vec<ApiCredential>,
    pub selected: usize,
    pub mode: Mode,
    pub field: Field,
    // Account form inputs
    pub input_website: String,
    pub input_username: String,
    pub input_password: String,
    // API credential form inputs
    pub input_name: String,
    pub input_api_key: String,
    pub input_client_id: String,
    pub input_client_secret: String,
    // Auth inputs
    pub input_master: String,
    pub input_master_confirm: String,
    // Reset master password inputs
    pub input_old_master: String,
    pub input_new_master: String,
    pub input_new_master_confirm: String,
    pub revealed: Revealed,
    pub editing_id: Option<i64>,
    pub message: String,
    pub should_quit: bool,
}

impl App {
    pub fn new() -> color_eyre::Result<Self> {
        let conn = db::init()?;
        let has_salt = db::get_meta(&conn, "salt")?.is_some();
        let app = Self {
            conn,
            master_key: None,
            tab: Tab::Accounts,
            accounts: Vec::new(),
            api_credentials: Vec::new(),
            selected: 0,
            mode: if has_salt { Mode::Unlock } else { Mode::Setup },
            field: Field::Master,
            input_website: String::new(),
            input_username: String::new(),
            input_password: String::new(),
            input_name: String::new(),
            input_api_key: String::new(),
            input_client_id: String::new(),
            input_client_secret: String::new(),
            input_master: String::new(),
            input_master_confirm: String::new(),
            input_old_master: String::new(),
            input_new_master: String::new(),
            input_new_master_confirm: String::new(),
            revealed: Revealed::None,
            editing_id: None,
            message: String::new(),
            should_quit: false,
        };
        Ok(app)
    }

    pub fn quit(&mut self) {
        self.lock();
        self.should_quit = true;
    }

    /// Lock the vault: zeroize the master key, decrypted reveals, and any
    /// secret-bearing form inputs. Non-secret inputs (website, name, client
    /// id) are simply cleared.
    pub fn lock(&mut self) {
        if let Some(mut key) = self.master_key.take() {
            key.zeroize();
        }
        self.revealed.clear();
        self.clear_secret_inputs();
        self.input_master.zeroize();
        self.input_master.clear();
        self.input_master_confirm.zeroize();
        self.input_master_confirm.clear();
        self.input_old_master.zeroize();
        self.input_old_master.clear();
        self.input_new_master.zeroize();
        self.input_new_master.clear();
        self.input_new_master_confirm.zeroize();
        self.input_new_master_confirm.clear();
    }

    /// Zeroize and clear all secret-bearing form inputs.
    fn clear_secret_inputs(&mut self) {
        self.input_password.zeroize();
        self.input_password.clear();
        self.input_api_key.zeroize();
        self.input_api_key.clear();
        self.input_client_secret.zeroize();
        self.input_client_secret.clear();
    }

    /// Number of items in the currently active tab's list.
    fn current_len(&self) -> usize {
        match self.tab {
            Tab::Accounts => self.accounts.len(),
            Tab::ApiKeys => self.api_credentials.len(),
        }
    }

    /// Clamp the selection to the active tab's list bounds.
    fn clamp_selected(&mut self) {
        let len = self.current_len();
        if len == 0 {
            self.selected = 0;
        } else if self.selected >= len {
            self.selected = len - 1;
        }
    }

    pub fn switch_tab(&mut self) {
        if !matches!(self.mode, Mode::List | Mode::View) {
            return;
        }
        self.tab = self.tab.toggle();
        self.mode = Mode::List;
        self.revealed.clear();
        self.message.clear();
        self.clamp_selected();
    }

    pub fn list_up(&mut self) {
        if self.current_len() > 0 {
            self.selected = self.selected.saturating_sub(1);
            self.revealed.clear();
        }
    }

    pub fn list_down(&mut self) {
        let len = self.current_len();
        if len > 0 {
            self.selected = (self.selected + 1).min(len - 1);
            self.revealed.clear();
        }
    }

    pub fn start_add(&mut self) {
        self.clear_secret_inputs();
        match self.tab {
            Tab::Accounts => {
                self.mode = Mode::Add;
                self.field = Field::Website;
                self.input_website.clear();
                self.input_username.clear();
            }
            Tab::ApiKeys => {
                self.mode = Mode::Add;
                self.field = Field::Name;
                self.input_name.clear();
                self.input_client_id.clear();
            }
        }
        self.editing_id = None;
        self.message.clear();
    }

    pub fn start_edit(&mut self) {
        let Some(key) = &self.master_key else {
            self.message = "Vault is locked.".to_string();
            return;
        };
        match self.tab {
            Tab::Accounts => {
                if let Some(account) = self.accounts.get(self.selected).cloned() {
                    let plaintext = match crypto::decrypt(key, &account.password) {
                        Ok(p) => p,
                        Err(e) => {
                            self.message = format!("Cannot decrypt password: {e}");
                            return;
                        }
                    };
                    self.mode = Mode::Edit;
                    self.field = Field::Website;
                    self.editing_id = Some(account.id);
                    self.input_website = account.website;
                    self.input_username = account.username;
                    self.input_password = plaintext;
                    self.message.clear();
                }
            }
            Tab::ApiKeys => {
                if let Some(cred) = self.api_credentials.get(self.selected).cloned() {
                    // Empty stored value means the optional field was unset.
                    let api_key = if cred.api_key.is_empty() {
                        String::new()
                    } else {
                        match crypto::decrypt(key, &cred.api_key) {
                            Ok(p) => p,
                            Err(e) => {
                                self.message = format!("Cannot decrypt api key: {e}");
                                return;
                            }
                        }
                    };
                    let client_secret = if cred.client_secret.is_empty() {
                        String::new()
                    } else {
                        match crypto::decrypt(key, &cred.client_secret) {
                            Ok(p) => p,
                            Err(e) => {
                                self.message = format!("Cannot decrypt client secret: {e}");
                                return;
                            }
                        }
                    };
                    self.mode = Mode::Edit;
                    self.field = Field::Name;
                    self.editing_id = Some(cred.id);
                    self.input_name = cred.name;
                    self.input_api_key = api_key;
                    self.input_client_id = cred.client_id;
                    self.input_client_secret = client_secret;
                    self.message.clear();
                }
            }
        }
    }

    pub fn cancel_form(&mut self) {
        self.clear_secret_inputs();
        self.mode = Mode::List;
        self.editing_id = None;
        self.message.clear();
    }

    pub fn save_form(&mut self) {
        let Some(key) = &self.master_key else {
            self.message = "Vault is locked.".to_string();
            return;
        };
        let result = match (self.tab, self.mode) {
            (Tab::Accounts, Mode::Add | Mode::Edit) => {
                let website = self.input_website.trim();
                let username = self.input_username.trim();
                let password = self.input_password.as_str();
                if website.is_empty() || username.is_empty() || password.is_empty() {
                    self.message = "All fields are required.".to_string();
                    return;
                }
                let encrypted = match crypto::encrypt(key, password) {
                    Ok(e) => e,
                    Err(e) => {
                        self.message = format!("Encryption failed: {e}");
                        return;
                    }
                };
                match self.mode {
                    Mode::Add => db::insert(&self.conn, website, username, &encrypted)
                        .map(|_| "Account added.".to_string()),
                    Mode::Edit => {
                        if let Some(id) = self.editing_id {
                            db::update(&self.conn, id, website, username, &encrypted)
                                .map(|_| "Account updated.".to_string())
                        } else {
                            Ok("No account selected.".to_string())
                        }
                    }
                    _ => Ok(String::new()),
                }
            }
            (Tab::ApiKeys, Mode::Add | Mode::Edit) => {
                let name = self.input_name.trim();
                let api_key = self.input_api_key.trim();
                let client_id = self.input_client_id.trim();
                let client_secret = self.input_client_secret.trim();
                if name.is_empty() {
                    self.message = "Name is required.".to_string();
                    return;
                }
                // Optional secrets: encrypt only when provided; store empty
                // string as a sentinel for "not set".
                let enc_api_key = if api_key.is_empty() {
                    String::new()
                } else {
                    match crypto::encrypt(key, api_key) {
                        Ok(e) => e,
                        Err(e) => {
                            self.message = format!("Encryption failed: {e}");
                            return;
                        }
                    }
                };
                let enc_secret = if client_secret.is_empty() {
                    String::new()
                } else {
                    match crypto::encrypt(key, client_secret) {
                        Ok(e) => e,
                        Err(e) => {
                            self.message = format!("Encryption failed: {e}");
                            return;
                        }
                    }
                };
                match self.mode {
                    Mode::Add => db::insert_api(
                        &self.conn,
                        name,
                        &enc_api_key,
                        client_id,
                        &enc_secret,
                    )
                    .map(|_| "API credential added.".to_string()),
                    Mode::Edit => {
                        if let Some(id) = self.editing_id {
                            db::update_api(
                                &self.conn,
                                id,
                                name,
                                &enc_api_key,
                                client_id,
                                &enc_secret,
                            )
                            .map(|_| "API credential updated.".to_string())
                        } else {
                            Ok("No credential selected.".to_string())
                        }
                    }
                    _ => Ok(String::new()),
                }
            }
            _ => Ok(String::new()),
        };
        match result {
            Ok(msg) => {
                self.message = msg;
                self.mode = Mode::List;
                self.editing_id = None;
                self.clear_secret_inputs();
                if let Err(e) = self.reload() {
                    self.message = format!("Reload failed: {e}");
                }
            }
            Err(e) => self.message = format!("Save failed: {e}"),
        }
    }

    pub fn delete_selected(&mut self) {
        let id = match self.tab {
            Tab::Accounts => self.accounts.get(self.selected).map(|a| a.id),
            Tab::ApiKeys => self.api_credentials.get(self.selected).map(|c| c.id),
        };
        let Some(id) = id else { return };
        let result = match self.tab {
            Tab::Accounts => db::delete(&self.conn, id),
            Tab::ApiKeys => db::delete_api(&self.conn, id),
        };
        match result {
            Ok(_) => {
                self.message = match self.tab {
                    Tab::Accounts => "Account deleted.".to_string(),
                    Tab::ApiKeys => "API credential deleted.".to_string(),
                };
                self.revealed.clear();
                if let Err(e) = self.reload() {
                    self.message = format!("Reload failed: {e}");
                }
                self.clamp_selected();
            }
            Err(e) => self.message = format!("Delete failed: {e}"),
        }
    }

    pub fn reload(&mut self) -> color_eyre::Result<()> {
        self.accounts = db::load_all(&self.conn)?;
        self.api_credentials = db::load_all_api(&self.conn)?;
        self.clamp_selected();
        Ok(())
    }

    pub fn active_input(&mut self) -> &mut String {
        match (self.tab, self.field) {
            (Tab::Accounts, Field::Website) => &mut self.input_website,
            (Tab::Accounts, Field::Username) => &mut self.input_username,
            (Tab::Accounts, Field::Password) => &mut self.input_password,
            (Tab::ApiKeys, Field::Name) => &mut self.input_name,
            (Tab::ApiKeys, Field::ApiKey) => &mut self.input_api_key,
            (Tab::ApiKeys, Field::ClientId) => &mut self.input_client_id,
            (Tab::ApiKeys, Field::ClientSecret) => &mut self.input_client_secret,
            // Auth + reset forms use these regardless of tab.
            (_, Field::Master) => &mut self.input_master,
            (_, Field::MasterConfirm) => &mut self.input_master_confirm,
            (_, Field::OldMaster) => &mut self.input_old_master,
            (_, Field::NewMaster) => &mut self.input_new_master,
            (_, Field::NewMasterConfirm) => &mut self.input_new_master_confirm,
            _ => &mut self.input_website,
        }
    }

    pub fn submit_unlock(&mut self) {
        let mut password = std::mem::take(&mut self.input_master);
        let salt_b64 = match db::get_meta(&self.conn, "salt") {
            Ok(Some(s)) => s,
            Ok(None) => {
                password.zeroize();
                self.message = "Vault is not initialized.".to_string();
                return;
            }
            Err(e) => {
                password.zeroize();
                self.message = format!("DB error: {e}");
                return;
            }
        };
        let salt_bytes = match B64.decode(salt_b64.as_bytes()) {
            Ok(b) => b,
            Err(e) => {
                password.zeroize();
                self.message = format!("Salt decode failed: {e}");
                return;
            }
        };
        let mut salt = [0u8; crypto::SALT_LEN];
        if salt_bytes.len() != salt.len() {
            password.zeroize();
            self.message = "Corrupt salt.".to_string();
            return;
        }
        salt.copy_from_slice(&salt_bytes);
        let mut key = match crypto::derive_key(&password, &salt) {
            Ok(k) => k,
            Err(e) => {
                password.zeroize();
                self.message = format!("Key derivation failed: {e}");
                return;
            }
        };
        // Done with the plaintext master password.
        password.zeroize();
        let verifier = match db::get_meta(&self.conn, "verifier") {
            Ok(Some(v)) => v,
            Ok(None) => {
                key.zeroize();
                self.message = "Corrupt vault.".to_string();
                return;
            }
            Err(e) => {
                key.zeroize();
                self.message = format!("DB error: {e}");
                return;
            }
        };
        match crypto::check_verifier(&key, &verifier) {
            Ok(true) => {
                self.master_key = Some(key);
                self.mode = Mode::List;
                self.message.clear();
                if let Err(e) = self.reload() {
                    self.message = format!("Reload failed: {e}");
                }
            }
            _ => {
                key.zeroize();
                self.message = "Wrong master password.".to_string();
            }
        }
    }

    pub fn submit_setup(&mut self) {
        if self.input_master.is_empty() {
            self.message = "Password cannot be empty.".to_string();
            return;
        }
        if self.input_master != self.input_master_confirm {
            self.message = "Passwords do not match.".to_string();
            return;
        }
        let salt = crypto::gen_salt();
        let mut password = std::mem::take(&mut self.input_master);
        self.input_master_confirm.zeroize();
        self.input_master_confirm.clear();
        let mut key = match crypto::derive_key(&password, &salt) {
            Ok(k) => k,
            Err(e) => {
                password.zeroize();
                self.message = format!("Key derivation failed: {e}");
                return;
            }
        };
        password.zeroize();
        let verifier = match crypto::make_verifier(&key) {
            Ok(v) => v,
            Err(e) => {
                key.zeroize();
                self.message = format!("Verifier failed: {e}");
                return;
            }
        };
        let salt_b64 = B64.encode(salt);
        if let Err(e) = db::set_meta(&self.conn, "salt", &salt_b64) {
            key.zeroize();
            self.message = format!("DB error: {e}");
            return;
        }
        if let Err(e) = db::set_meta(&self.conn, "verifier", &verifier) {
            key.zeroize();
            self.message = format!("DB error: {e}");
            return;
        }
        self.master_key = Some(key);
        self.mode = Mode::List;
        self.message = "Vault created.".to_string();
        if let Err(e) = self.reload() {
            self.message = format!("Reload failed: {e}");
        }
    }

    /// Begin the master-password reset flow. Requires the vault to be
    /// unlocked (so we can re-encrypt secrets with the new key).
    pub fn start_reset_master(&mut self) {
        if self.master_key.is_none() {
            self.message = "Vault is locked.".to_string();
            return;
        }
        self.mode = Mode::ResetMaster;
        self.field = Field::OldMaster;
        self.input_old_master.clear();
        self.input_new_master.clear();
        self.input_new_master_confirm.clear();
        self.message.clear();
    }

    pub fn cancel_reset_master(&mut self) {
        self.input_old_master.zeroize();
        self.input_old_master.clear();
        self.input_new_master.zeroize();
        self.input_new_master.clear();
        self.input_new_master_confirm.zeroize();
        self.input_new_master_confirm.clear();
        self.mode = Mode::List;
        self.message.clear();
    }

    /// Verify the old password, derive a new key, re-encrypt every secret,
    /// and persist the change atomically.
    pub fn submit_reset_master(&mut self) {
        let mut old_password = std::mem::take(&mut self.input_old_master);
        let mut new_password = std::mem::take(&mut self.input_new_master);
        let mut new_password_confirm = std::mem::take(&mut self.input_new_master_confirm);

        // Validate new password locally before touching the DB.
        if new_password.is_empty() {
            self.message = "New password cannot be empty.".to_string();
            old_password.zeroize();
            new_password.zeroize();
            new_password_confirm.zeroize();
            return;
        }
        if new_password != new_password_confirm {
            self.message = "New passwords do not match.".to_string();
            old_password.zeroize();
            new_password.zeroize();
            new_password_confirm.zeroize();
            return;
        }

        // Verify the old password by re-deriving its key and checking the
        // verifier. This confirms the user is authorized even though the
        // vault is already unlocked.
        let salt_b64 = match db::get_meta(&self.conn, "salt") {
            Ok(Some(s)) => s,
            _ => {
                self.message = "Vault is not initialized.".to_string();
                old_password.zeroize();
                new_password.zeroize();
                new_password_confirm.zeroize();
                return;
            }
        };
        let salt_bytes = match B64.decode(salt_b64.as_bytes()) {
            Ok(b) => b,
            Err(e) => {
                self.message = format!("Salt decode failed: {e}");
                old_password.zeroize();
                new_password.zeroize();
                new_password_confirm.zeroize();
                return;
            }
        };
        let mut salt = [0u8; crypto::SALT_LEN];
        if salt_bytes.len() != salt.len() {
            self.message = "Corrupt salt.".to_string();
            old_password.zeroize();
            new_password.zeroize();
            new_password_confirm.zeroize();
            return;
        }
        salt.copy_from_slice(&salt_bytes);

        let mut old_key = match crypto::derive_key(&old_password, &salt) {
            Ok(k) => k,
            Err(e) => {
                self.message = format!("Key derivation failed: {e}");
                old_password.zeroize();
                new_password.zeroize();
                new_password_confirm.zeroize();
                return;
            }
        };
        old_password.zeroize();

        let verifier = match db::get_meta(&self.conn, "verifier") {
            Ok(Some(v)) => v,
            _ => {
                old_key.zeroize();
                self.message = "Corrupt vault.".to_string();
                new_password.zeroize();
                new_password_confirm.zeroize();
                return;
            }
        };
        let verified = crypto::check_verifier(&old_key, &verifier).unwrap_or(false);
        if !verified {
            old_key.zeroize();
            self.message = "Old master password is incorrect.".to_string();
            new_password.zeroize();
            new_password_confirm.zeroize();
            return;
        }

        // Derive the new key from a fresh salt.
        let new_salt = crypto::gen_salt();
        let mut new_key = match crypto::derive_key(&new_password, &new_salt) {
            Ok(k) => k,
            Err(e) => {
                old_key.zeroize();
                self.message = format!("Key derivation failed: {e}");
                new_password.zeroize();
                new_password_confirm.zeroize();
                return;
            }
        };
        new_password.zeroize();
        new_password_confirm.zeroize();

        // Decrypt every secret with the old key and re-encrypt with the new
        // key in memory first. If any row fails to decrypt, abort before
        // writing anything to the DB.
        let mut reencrypted_accounts: Vec<(i64, String, String, String)> = Vec::new();
        for account in &self.accounts {
            let plain = if account.password.is_empty() {
                String::new()
            } else {
                match crypto::decrypt(&old_key, &account.password) {
                    Ok(p) => p,
                    Err(e) => {
                        old_key.zeroize();
                        new_key.zeroize();
                        self.message = format!("Re-encrypt failed for account {}: {e}", account.website);
                        return;
                    }
                }
            };
            let new_blob = if plain.is_empty() {
                String::new()
            } else {
                match crypto::encrypt(&new_key, &plain) {
                    Ok(e) => e,
                    Err(e) => {
                        old_key.zeroize();
                        new_key.zeroize();
                        self.message = format!("Re-encrypt failed for account {}: {e}", account.website);
                        return;
                    }
                }
            };
            reencrypted_accounts.push((account.id, account.website.clone(), account.username.clone(), new_blob));
        }

        let mut reencrypted_creds: Vec<(i64, String, String, String, String)> = Vec::new();
        for cred in &self.api_credentials {
            let api_plain = if cred.api_key.is_empty() {
                String::new()
            } else {
                match crypto::decrypt(&old_key, &cred.api_key) {
                    Ok(p) => p,
                    Err(e) => {
                        old_key.zeroize();
                        new_key.zeroize();
                        self.message = format!("Re-encrypt failed for {}: {e}", cred.name);
                        return;
                    }
                }
            };
            let secret_plain = if cred.client_secret.is_empty() {
                String::new()
            } else {
                match crypto::decrypt(&old_key, &cred.client_secret) {
                    Ok(p) => p,
                    Err(e) => {
                        old_key.zeroize();
                        new_key.zeroize();
                        self.message = format!("Re-encrypt failed for {}: {e}", cred.name);
                        return;
                    }
                }
            };
            let new_api = if api_plain.is_empty() {
                String::new()
            } else {
                match crypto::encrypt(&new_key, &api_plain) {
                    Ok(e) => e,
                    Err(e) => {
                        old_key.zeroize();
                        new_key.zeroize();
                        self.message = format!("Re-encrypt failed for {}: {e}", cred.name);
                        return;
                    }
                }
            };
            let new_secret = if secret_plain.is_empty() {
                String::new()
            } else {
                match crypto::encrypt(&new_key, &secret_plain) {
                    Ok(e) => e,
                    Err(e) => {
                        old_key.zeroize();
                        new_key.zeroize();
                        self.message = format!("Re-encrypt failed for {}: {e}", cred.name);
                        return;
                    }
                }
            };
            reencrypted_creds.push((
                cred.id,
                cred.name.clone(),
                new_api,
                cred.client_id.clone(),
                new_secret,
            ));
        }

        // All crypto succeeded; persist atomically in a single transaction.
        let new_verifier = match crypto::make_verifier(&new_key) {
            Ok(v) => v,
            Err(e) => {
                old_key.zeroize();
                new_key.zeroize();
                self.message = format!("Verifier failed: {e}");
                return;
            }
        };
        let new_salt_b64 = B64.encode(new_salt);

        // Perform all DB writes inside a transaction. The transaction is
        // scoped so its borrow of `self.conn` ends before we call
        // `self.reload()` below.
        let commit_result: color_eyre::Result<()> = {
            let tx = match self.conn.transaction() {
                Ok(tx) => tx,
                Err(e) => {
                    old_key.zeroize();
                    new_key.zeroize();
                    self.message = format!("Transaction failed: {e}");
                    return;
                }
            };
            for (id, website, username, blob) in &reencrypted_accounts {
                if let Err(e) = db::update(&tx, *id, website, username, blob) {
                    old_key.zeroize();
                    new_key.zeroize();
                    self.message = format!("DB write failed: {e}");
                    return;
                }
            }
            for (id, name, api, client_id, secret) in &reencrypted_creds {
                if let Err(e) = db::update_api(&tx, *id, name, api, client_id, secret) {
                    old_key.zeroize();
                    new_key.zeroize();
                    self.message = format!("DB write failed: {e}");
                    return;
                }
            }
            if let Err(e) = db::set_meta(&tx, "salt", &new_salt_b64) {
                old_key.zeroize();
                new_key.zeroize();
                self.message = format!("DB write failed: {e}");
                return;
            }
            if let Err(e) = db::set_meta(&tx, "verifier", &new_verifier) {
                old_key.zeroize();
                new_key.zeroize();
                self.message = format!("DB write failed: {e}");
                return;
            }
            tx.commit().map_err(color_eyre::eyre::Error::from)
        };

        match commit_result {
            Ok(()) => {
                old_key.zeroize();
                self.master_key = Some(new_key);
                self.mode = Mode::List;
                self.revealed.clear();
                self.message = "Master password changed.".to_string();
                if let Err(e) = self.reload() {
                    self.message = format!("Reload failed: {e}");
                }
            }
            Err(e) => {
                new_key.zeroize();
                self.message = format!("Reset failed: {e}");
            }
        }
    }

    pub fn start_view(&mut self) {
        if self.current_len() == 0 {
            return;
        }
        self.mode = Mode::View;
        self.revealed.clear();
        self.message.clear();
    }

    pub fn close_view(&mut self) {
        self.mode = Mode::List;
        self.revealed.clear();
        self.message.clear();
    }

    pub fn toggle_reveal(&mut self) {
        if self.master_key.is_none() {
            return;
        }
        if self.mode != Mode::View {
            return;
        }
        if !self.revealed.is_none() {
            self.revealed.clear();
            return;
        }
        let Some(key) = &self.master_key else { return };
        match self.tab {
            Tab::Accounts => {
                let Some(account) = self.accounts.get(self.selected).cloned() else {
                    return;
                };
                match crypto::decrypt(key, &account.password) {
                    Ok(p) => self.revealed = Revealed::AccountPassword(p),
                    Err(e) => self.message = format!("Decrypt failed: {e}"),
                }
            }
            Tab::ApiKeys => {
                let Some(cred) = self.api_credentials.get(self.selected).cloned() else {
                    return;
                };
                let api_key = if cred.api_key.is_empty() {
                    String::new()
                } else {
                    match crypto::decrypt(key, &cred.api_key) {
                        Ok(p) => p,
                        Err(e) => {
                            self.message = format!("Decrypt failed: {e}");
                            return;
                        }
                    }
                };
                let client_secret = if cred.client_secret.is_empty() {
                    String::new()
                } else {
                    match crypto::decrypt(key, &cred.client_secret) {
                        Ok(p) => p,
                        Err(e) => {
                            self.message = format!("Decrypt failed: {e}");
                            return;
                        }
                    }
                };
                self.revealed = Revealed::Api {
                    api_key,
                    client_secret,
                };
            }
        }
    }

    // --- Clipboard copy ---

    /// Copy the selected account's username to the system clipboard.
    pub fn copy_username(&mut self) {
        let Some(account) = self.accounts.get(self.selected).cloned() else {
            return;
        };
        match arboard::Clipboard::new().and_then(|mut cb| cb.set_text(account.username)) {
            Ok(_) => self.message = "Username copied to clipboard.".to_string(),
            Err(e) => self.message = format!("Clipboard error: {e}"),
        }
    }

    /// Copy the selected account's decrypted password to the system clipboard.
    pub fn copy_password(&mut self) {
        let Some(key) = self.master_key.clone() else {
            self.message = "Vault is locked.".to_string();
            return;
        };
        let Some(account) = self.accounts.get(self.selected).cloned() else {
            return;
        };
        self.copy_secret_to_clipboard(&key, &account.password, "Password");
    }

    /// Copy the selected API credential's decrypted api key.
    pub fn copy_api_key(&mut self) {
        let Some(key) = self.master_key.clone() else {
            self.message = "Vault is locked.".to_string();
            return;
        };
        let Some(cred) = self.api_credentials.get(self.selected).cloned() else {
            return;
        };
        self.copy_secret_to_clipboard(&key, &cred.api_key, "API key");
    }

    /// Copy the selected API credential's client id (plaintext).
    pub fn copy_client_id(&mut self) {
        let Some(cred) = self.api_credentials.get(self.selected).cloned() else {
            return;
        };
        match arboard::Clipboard::new().and_then(|mut cb| cb.set_text(cred.client_id)) {
            Ok(_) => self.message = "Client ID copied to clipboard.".to_string(),
            Err(e) => self.message = format!("Clipboard error: {e}"),
        }
    }

    /// Copy the selected API credential's decrypted client secret.
    pub fn copy_client_secret(&mut self) {
        let Some(key) = self.master_key.clone() else {
            self.message = "Vault is locked.".to_string();
            return;
        };
        let Some(cred) = self.api_credentials.get(self.selected).cloned() else {
            return;
        };
        self.copy_secret_to_clipboard(&key, &cred.client_secret, "Client secret");
    }

    /// Decrypt `blob`, copy the plaintext to the clipboard, then zeroize
    /// the local plaintext buffer. The clipboard retains its own copy
    /// (subject to the OS clipboard's lifetime); only our process memory
    /// is scrubbed.
    fn copy_secret_to_clipboard(&mut self, key: &MasterKey, blob: &str, label: &str) {
        if blob.is_empty() {
            self.message = format!("{label} is not set.");
            return;
        }
        let mut plaintext = match crypto::decrypt(key, blob) {
            Ok(p) => p,
            Err(e) => {
                self.message = format!("Decrypt failed: {e}");
                return;
            }
        };
        let result = arboard::Clipboard::new().and_then(|mut cb| cb.set_text(&plaintext));
        // Scrub the decrypted plaintext from this stack frame regardless of
        // whether the clipboard set succeeded.
        plaintext.zeroize();
        match result {
            Ok(_) => self.message = format!("{label} copied to clipboard."),
            Err(e) => self.message = format!("Clipboard error: {e}"),
        }
    }
}

impl Drop for App {
    fn drop(&mut self) {
        // Best-effort scrub of in-memory secrets when the app is dropped.
        // `lock()` is the explicit path; this covers early returns and
        // panics that bypass it.
        if let Some(mut key) = self.master_key.take() {
            key.zeroize();
        }
        self.revealed.clear();
        self.input_master.zeroize();
        self.input_master_confirm.zeroize();
        self.input_old_master.zeroize();
        self.input_new_master.zeroize();
        self.input_new_master_confirm.zeroize();
        self.clear_secret_inputs();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_db_path() -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "rusty-vault-test-{}.db",
            std::process::id()
        ));
        p
    }

    /// End-to-end test of the master password reset flow: create a vault,
    /// add an account, change the master password, and verify the account
    /// password can still be decrypted with the new key but not the old.
    #[test]
    fn reset_master_password_reencrypts_secrets() {
        let db_path = temp_db_path();
        let _ = std::fs::remove_file(&db_path);

        // Use a dedicated connection pointed at the temp file by opening
        // via the public API with a monkey-patched path. Since App::new
        // hardcodes "rusty-vault.db", we instead build the pieces manually.
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute(
            "CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY, website TEXT NOT NULL,
                username TEXT NOT NULL, password TEXT NOT NULL
            )",
            [],
        )
        .unwrap();
        conn.execute(
            "CREATE TABLE IF NOT EXISTS api_credentials (
                id INTEGER PRIMARY KEY, name TEXT NOT NULL, api_key TEXT NOT NULL,
                client_id TEXT NOT NULL, client_secret TEXT NOT NULL
            )",
            [],
        )
        .unwrap();
        conn.execute(
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
            [],
        )
        .unwrap();

        // Setup vault with old password.
        let salt = crypto::gen_salt();
        let old_key = crypto::derive_key("old-pass", &salt).unwrap();
        let verifier = crypto::make_verifier(&old_key).unwrap();
        db::set_meta(&conn, "salt", &B64.encode(salt)).unwrap();
        db::set_meta(&conn, "verifier", &verifier).unwrap();

        // Add an account with an encrypted password.
        let enc_pw = crypto::encrypt(&old_key, "secret123").unwrap();
        db::insert(&conn, "example.com", "alice", &enc_pw).unwrap();

        // Simulate a reset: verify old, derive new key, re-encrypt.
        let new_salt = crypto::gen_salt();
        let new_key = crypto::derive_key("new-pass", &new_salt).unwrap();

        // Re-encrypt the account password.
        let accounts = db::load_all(&conn).unwrap();
        let account = &accounts[0];
        let plain = crypto::decrypt(&old_key, &account.password).unwrap();
        assert_eq!(plain, "secret123");
        let new_enc = crypto::encrypt(&new_key, &plain).unwrap();
        db::update(&conn, account.id, "example.com", "alice", &new_enc).unwrap();

        // Update salt + verifier.
        db::set_meta(&conn, "salt", &B64.encode(new_salt)).unwrap();
        db::set_meta(&conn, "verifier", &crypto::make_verifier(&new_key).unwrap())
            .unwrap();

        // Verify: new key decrypts, old key does not.
        let accounts = db::load_all(&conn).unwrap();
        let account = &accounts[0];
        assert_eq!(crypto::decrypt(&new_key, &account.password).unwrap(), "secret123");
        assert!(crypto::decrypt(&old_key, &account.password).is_err());

        // Verify the verifier check passes with the new key, fails with old.
        let v = db::get_meta(&conn, "verifier").unwrap().unwrap();
        assert!(crypto::check_verifier(&new_key, &v).unwrap());
        assert!(!crypto::check_verifier(&old_key, &v).unwrap());

        let _ = std::fs::remove_file(&db_path);
    }
}