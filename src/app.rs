use std::time::{Duration, Instant};

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use rusqlite::Connection;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::cli::Cli;
use crate::crypto::{self, KdfParams, MasterKey};
use crate::{db, password};

/// Seconds before a copied secret is cleared from the clipboard, provided the
/// clipboard still holds that secret.
pub const CLIPBOARD_CLEAR_SECS: u64 = 30;

/// Minimum accepted master password length.
pub const MIN_MASTER_PASSWORD_LEN: usize = 8;

/// How long info/success messages stay visible.
const MESSAGE_TTL: Duration = Duration::from_secs(4);

/// Errors stay visible longer so they can be read.
const ERROR_TTL: Duration = Duration::from_secs(8);

/// Severity of the transient status message, used to pick a display color.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageKind {
    Info,
    Success,
    Error,
}

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
    /// A destructive action is waiting for `y`/`n` confirmation.
    ConfirmDelete,
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

/// A destructive action awaiting confirmation.
#[derive(Clone, Debug)]
pub struct PendingDelete {
    pub tab: Tab,
    pub id: i64,
    pub label: String,
    /// Set when confirmation was requested from the detail view, so cancel
    /// can return there instead of the list.
    pub from_view: bool,
}

/// Decrypted secrets currently shown in the View screen.
///
/// `ZeroizeOnDrop` scrubs the plaintext when the value is dropped or replaced,
/// in addition to the explicit [`Revealed::clear`] used on lock/navigation.
#[derive(Clone, Debug, Default, Zeroize, ZeroizeOnDrop)]
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

/// Byte offset of a char index, or the string length when past the end.
fn char_to_byte(s: &str, char_index: usize) -> usize {
    s.char_indices()
        .nth(char_index)
        .map(|(byte, _)| byte)
        .unwrap_or(s.len())
}

pub struct App {
    pub conn: Connection,
    pub master_key: Option<MasterKey>,
    /// Argon2 costs of the open vault; written back when the vault is created
    /// or its master password is changed.
    pub kdf_params: KdfParams,
    pub tab: Tab,
    pub accounts: Vec<Account>,
    pub api_credentials: Vec<ApiCredential>,
    /// Indices into the active tab's list that match `search`, in order.
    pub visible: Vec<usize>,
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
    // Search / filter
    pub search: String,
    pub searching: bool,
    pub revealed: Revealed,
    pub editing_id: Option<i64>,
    pub pending_delete: Option<PendingDelete>,
    /// Text of the transient status message (see [`App::visible_message`]).
    pub message: String,
    pub message_kind: MessageKind,
    pub message_expires_at: Option<Instant>,
    /// Char index of the caret inside the field currently being edited.
    pub cursor: usize,
    pub should_quit: bool,
    /// `None` disables the idle auto-lock.
    pub idle_lock: Option<Duration>,
    pub last_activity: Instant,
    /// Plaintext most recently copied to the clipboard, cleared on a timer.
    clipboard_secret: String,
    clipboard_deadline: Option<Instant>,
}

impl App {
    pub fn new(cli: &Cli) -> color_eyre::Result<Self> {
        let conn = db::init(&cli.db_path)?;
        let has_salt = db::get_meta(&conn, "salt")?.is_some();
        // Vaults created before KDF parameters were persisted fall back to
        // the historical defaults, which is what they were created with.
        let kdf_params = match db::get_meta(&conn, KdfParams::META_KEY)? {
            Some(encoded) => KdfParams::decode(&encoded).unwrap_or_default(),
            None => KdfParams::default(),
        };
        let app = Self {
            conn,
            master_key: None,
            kdf_params,
            tab: Tab::Accounts,
            accounts: Vec::new(),
            api_credentials: Vec::new(),
            visible: Vec::new(),
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
            search: String::new(),
            searching: false,
            revealed: Revealed::None,
            editing_id: None,
            pending_delete: None,
            message: String::new(),
            message_kind: MessageKind::Info,
            message_expires_at: None,
            cursor: 0,
            should_quit: false,
            idle_lock: cli.idle_lock,
            last_activity: Instant::now(),
            clipboard_secret: String::new(),
            clipboard_deadline: None,
        };
        Ok(app)
    }

    pub fn quit(&mut self) {
        self.lock();
        self.should_quit = true;
    }

    /// Record user activity so the idle auto-lock timer restarts.
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    // --- Status messages ---

    pub fn set_info(&mut self, text: impl Into<String>) {
        self.set_message(MessageKind::Info, text.into());
    }

    pub fn set_success(&mut self, text: impl Into<String>) {
        self.set_message(MessageKind::Success, text.into());
    }

    pub fn set_error(&mut self, text: impl Into<String>) {
        self.set_message(MessageKind::Error, text.into());
    }

    fn set_message(&mut self, kind: MessageKind, text: String) {
        self.message = text;
        self.message_kind = kind;
        let ttl = if kind == MessageKind::Error {
            ERROR_TTL
        } else {
            MESSAGE_TTL
        };
        self.message_expires_at = Some(Instant::now() + ttl);
    }

    pub fn clear_message(&mut self) {
        self.message.clear();
        self.message_expires_at = None;
    }

    /// The status message to draw, if it has not expired yet.
    pub fn visible_message(&self) -> Option<(&str, MessageKind)> {
        if self.message.is_empty() {
            return None;
        }
        match self.message_expires_at {
            Some(deadline) if Instant::now() >= deadline => None,
            _ => Some((self.message.as_str(), self.message_kind)),
        }
    }

    // --- Caret / text editing ---

    /// String backing the field currently being edited.
    fn active_text(&mut self) -> &mut String {
        if self.searching {
            &mut self.search
        } else {
            self.active_input()
        }
    }

    fn active_text_len(&mut self) -> usize {
        self.active_text().chars().count()
    }

    /// Put the caret at the end of the active field.
    pub fn cursor_end(&mut self) {
        self.cursor = self.active_text_len();
    }

    pub fn input_insert(&mut self, c: char) {
        let len = self.active_text_len();
        self.cursor = self.cursor.min(len);
        let cursor = self.cursor;
        let input = self.active_text();
        let byte = char_to_byte(input, cursor);
        input.insert(byte, c);
        self.cursor = cursor + 1;
    }

    pub fn input_backspace(&mut self) {
        let len = self.active_text_len();
        let cursor = self.cursor.min(len);
        if cursor == 0 {
            self.cursor = 0;
            return;
        }
        let input = self.active_text();
        let start = char_to_byte(input, cursor - 1);
        let end = char_to_byte(input, cursor);
        input.replace_range(start..end, "");
        self.cursor = cursor - 1;
    }

    pub fn input_delete(&mut self) {
        let len = self.active_text_len();
        let cursor = self.cursor.min(len);
        if cursor >= len {
            self.cursor = len;
            return;
        }
        let input = self.active_text();
        let start = char_to_byte(input, cursor);
        let end = char_to_byte(input, cursor + 1);
        input.replace_range(start..end, "");
        self.cursor = cursor;
    }

    pub fn cursor_left(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    pub fn cursor_right(&mut self) {
        let len = self.active_text_len();
        self.cursor = (self.cursor + 1).min(len);
    }

    pub fn cursor_home(&mut self) {
        self.cursor = 0;
    }

    /// Ctrl+U: clear the active field.
    pub fn input_clear(&mut self) {
        let input = self.active_text();
        input.zeroize();
        input.clear();
        self.cursor = 0;
    }

    /// Ctrl+W: delete the word before the caret.
    pub fn input_delete_word(&mut self) {
        let len = self.active_text_len();
        let cursor = self.cursor.min(len);
        if cursor == 0 {
            return;
        }
        let chars: Vec<char> = self.active_text().chars().collect();
        let mut start = cursor;
        while start > 0 && chars[start - 1].is_whitespace() {
            start -= 1;
        }
        while start > 0 && !chars[start - 1].is_whitespace() {
            start -= 1;
        }
        let input = self.active_text();
        let byte_start = char_to_byte(input, start);
        let byte_end = char_to_byte(input, cursor);
        input.replace_range(byte_start..byte_end, "");
        self.cursor = start;
    }

    /// Periodic work driven by the event loop tick.
    pub fn tick(&mut self) {
        if self
            .message_expires_at
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            self.clear_message();
        }
        self.clear_expired_clipboard();
        self.auto_lock_if_idle();
    }

    fn auto_lock_if_idle(&mut self) {
        let Some(timeout) = self.idle_lock else {
            return;
        };
        if self.master_key.is_none() || self.last_activity.elapsed() < timeout {
            return;
        }
        self.lock();
        self.set_info("Vault locked after inactivity.");
    }

    /// Lock the vault: zeroize the master key, decrypted reveals, clipboard
    /// tracking, and any secret-bearing form inputs, and drop the decrypted
    /// lists. Non-secret inputs (website, name, client id) are simply cleared.
    pub fn lock(&mut self) {
        // Assigning `None` drops the key, which zeroizes via ZeroizeOnDrop.
        self.master_key = None;
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
        self.clear_clipboard_if_unchanged();
        self.accounts.clear();
        self.api_credentials.clear();
        self.visible.clear();
        self.selected = 0;
        self.search.zeroize();
        self.search.clear();
        self.searching = false;
        self.pending_delete = None;
        self.editing_id = None;
        self.mode = Mode::Unlock;
        self.field = Field::Master;
        self.cursor = 0;
    }

    /// Lock on demand (Ctrl+L), keeping the vault file open.
    pub fn lock_and_notify(&mut self) {
        if self.master_key.is_none() {
            return;
        }
        self.lock();
        self.set_info("Vault locked.");
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

    /// Number of items visible in the active tab (after filtering).
    fn current_len(&self) -> usize {
        self.visible.len()
    }

    /// Clamp the selection to the visible list bounds.
    fn clamp_selected(&mut self) {
        let len = self.current_len();
        if len == 0 {
            self.selected = 0;
        } else if self.selected >= len {
            self.selected = len - 1;
        }
    }

    /// Account under the cursor, if any.
    pub fn selected_account(&self) -> Option<&Account> {
        self.visible
            .get(self.selected)
            .and_then(|&index| self.accounts.get(index))
    }

    /// API credential under the cursor, if any.
    pub fn selected_credential(&self) -> Option<&ApiCredential> {
        self.visible
            .get(self.selected)
            .and_then(|&index| self.api_credentials.get(index))
    }

    /// Recompute `visible` from `search` and clamp the selection.
    pub fn apply_filter(&mut self) {
        let query = self.search.trim().to_lowercase();
        self.visible = match self.tab {
            Tab::Accounts => self
                .accounts
                .iter()
                .enumerate()
                .filter(|(_, account)| {
                    query.is_empty()
                        || account.website.to_lowercase().contains(&query)
                        || account.username.to_lowercase().contains(&query)
                })
                .map(|(index, _)| index)
                .collect(),
            Tab::ApiKeys => self
                .api_credentials
                .iter()
                .enumerate()
                .filter(|(_, credential)| {
                    query.is_empty()
                        || credential.name.to_lowercase().contains(&query)
                        || credential.client_id.to_lowercase().contains(&query)
                })
                .map(|(index, _)| index)
                .collect(),
        };
        self.clamp_selected();
    }

    // --- Search ---

    pub fn start_search(&mut self) {
        if self.mode != Mode::List {
            return;
        }
        self.searching = true;
        self.cursor_end();
        self.clear_message();
    }

    pub fn submit_search(&mut self) {
        self.searching = false;
        self.cursor = 0;
    }

    /// Abandon the search and clear the filter.
    pub fn cancel_search(&mut self) {
        self.searching = false;
        self.search.zeroize();
        self.search.clear();
        self.selected = 0;
        self.cursor = 0;
        self.apply_filter();
    }

    pub fn search_push(&mut self, c: char) {
        self.input_insert(c);
        self.selected = 0;
        self.apply_filter();
    }

    pub fn search_backspace(&mut self) {
        self.input_backspace();
        self.selected = 0;
        self.apply_filter();
    }

    pub fn switch_tab(&mut self) {
        if !matches!(self.mode, Mode::List | Mode::View) {
            return;
        }
        self.tab = self.tab.toggle();
        self.mode = Mode::List;
        self.revealed.clear();
        self.message.clear();
        self.searching = false;
        self.search.zeroize();
        self.search.clear();
        self.selected = 0;
        self.cursor = 0;
        self.apply_filter();
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
        self.cursor_end();
        self.clear_message();
    }

    pub fn start_edit(&mut self) {
        let Some(key) = &self.master_key else {
            self.set_error("Vault is locked.");
            return;
        };
        match self.tab {
            Tab::Accounts => {
                if let Some(account) = self.selected_account().cloned() {
                    let plaintext = match crypto::decrypt(key, &account.password) {
                        Ok(p) => p,
                        Err(e) => {
                            self.set_error(format!("Cannot decrypt password: {e}"));
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
                if let Some(cred) = self.selected_credential().cloned() {
                    // Empty stored value means the optional field was unset.
                    let api_key = if cred.api_key.is_empty() {
                        String::new()
                    } else {
                        match crypto::decrypt(key, &cred.api_key) {
                            Ok(p) => p,
                            Err(e) => {
                                self.set_error(format!("Cannot decrypt api key: {e}"));
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
                                self.set_error(format!("Cannot decrypt client secret: {e}"));
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
        self.cursor_end();
    }

    pub fn cancel_form(&mut self) {
        self.clear_secret_inputs();
        self.mode = Mode::List;
        self.editing_id = None;
        self.cursor = 0;
        self.message.clear();
    }

    /// Fill a generated password into the form's primary secret field.
    ///
    /// The account form always targets the password field; the API form
    /// targets the focused secret field, falling back to the API key.
    pub fn generate_secret(&mut self) {
        let generated = password::generate_password(password::DEFAULT_LEN);
        match self.tab {
            Tab::Accounts => {
                self.input_password.zeroize();
                self.input_password.clear();
                self.input_password.push_str(&generated);
                self.field = Field::Password;
            }
            Tab::ApiKeys => {
                if self.field == Field::ClientSecret {
                    self.input_client_secret.zeroize();
                    self.input_client_secret.clear();
                    self.input_client_secret.push_str(&generated);
                } else {
                    self.input_api_key.zeroize();
                    self.input_api_key.clear();
                    self.input_api_key.push_str(&generated);
                    self.field = Field::ApiKey;
                }
            }
        }
        self.cursor_end();
        self.set_success("Generated password.");
    }

    pub fn save_form(&mut self) {
        let Some(key) = &self.master_key else {
            self.set_error("Vault is locked.");
            return;
        };
        let result = match (self.tab, self.mode) {
            (Tab::Accounts, Mode::Add | Mode::Edit) => {
                let website = self.input_website.trim();
                let username = self.input_username.trim();
                let password = self.input_password.as_str();
                if website.is_empty() || username.is_empty() || password.is_empty() {
                    self.set_error("All fields are required.");
                    return;
                }
                let encrypted = match crypto::encrypt(key, password) {
                    Ok(e) => e,
                    Err(e) => {
                        self.set_error(format!("Encryption failed: {e}"));
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
                    self.set_error("Name is required.");
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
                            self.set_error(format!("Encryption failed: {e}"));
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
                            self.set_error(format!("Encryption failed: {e}"));
                            return;
                        }
                    }
                };
                match self.mode {
                    Mode::Add => {
                        db::insert_api(&self.conn, name, &enc_api_key, client_id, &enc_secret)
                            .map(|_| "API credential added.".to_string())
                    }
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
                self.set_success(msg);
                self.mode = Mode::List;
                self.editing_id = None;
                self.clear_secret_inputs();
                self.cursor = 0;
                if let Err(e) = self.reload() {
                    self.set_error(format!("Reload failed: {e}"));
                }
            }
            Err(e) => self.set_error(format!("Save failed: {e}")),
        }
    }

    /// Ask for confirmation before deleting the selected entry.
    pub fn request_delete(&mut self) {
        let pending = match self.tab {
            Tab::Accounts => self.selected_account().map(|a| (a.id, a.website.clone())),
            Tab::ApiKeys => self.selected_credential().map(|c| (c.id, c.name.clone())),
        };
        let Some((id, label)) = pending else {
            self.set_info("Nothing selected to delete.");
            return;
        };
        self.pending_delete = Some(PendingDelete {
            tab: self.tab,
            id,
            label,
            from_view: self.mode == Mode::View,
        });
        self.mode = Mode::ConfirmDelete;
        self.cursor = 0;
        self.message.clear();
    }

    /// Delete the entry recorded by [`App::request_delete`].
    pub fn confirm_delete(&mut self) {
        let Some(pending) = self.pending_delete.take() else {
            self.mode = Mode::List;
            return;
        };
        let result = match pending.tab {
            Tab::Accounts => db::delete(&self.conn, pending.id),
            Tab::ApiKeys => db::delete_api(&self.conn, pending.id),
        };
        match result {
            Ok(()) => {
                self.set_success(match pending.tab {
                    Tab::Accounts => "Account deleted.".to_string(),
                    Tab::ApiKeys => "API credential deleted.".to_string(),
                });
                self.revealed.clear();
                self.mode = Mode::List;
                self.cursor = 0;
                if let Err(e) = self.reload() {
                    self.set_error(format!("Reload failed: {e}"));
                }
            }
            Err(e) => {
                self.set_error(format!("Delete failed: {e}"));
                self.mode = Mode::List;
                self.cursor = 0;
            }
        }
    }

    pub fn cancel_delete(&mut self) {
        let from_view = self
            .pending_delete
            .take()
            .map(|pending| pending.from_view)
            .unwrap_or(false);
        self.mode = if from_view { Mode::View } else { Mode::List };
        self.cursor = 0;
        self.message.clear();
    }

    pub fn reload(&mut self) -> color_eyre::Result<()> {
        self.accounts = db::load_all(&self.conn)?;
        self.api_credentials = db::load_all_api(&self.conn)?;
        self.apply_filter();
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
        self.cursor = 0;
        let salt_b64 = match db::get_meta(&self.conn, "salt") {
            Ok(Some(s)) => s,
            Ok(None) => {
                password.zeroize();
                self.set_error("Vault is not initialized.");
                return;
            }
            Err(e) => {
                password.zeroize();
                self.set_error(format!("DB error: {e}"));
                return;
            }
        };
        let kdf_params = match db::get_meta(&self.conn, KdfParams::META_KEY) {
            Ok(Some(encoded)) => match KdfParams::decode(&encoded) {
                Some(params) => params,
                None => {
                    password.zeroize();
                    self.set_error("Corrupt KDF parameters.");
                    return;
                }
            },
            // Vault created before the parameters were persisted.
            Ok(None) => KdfParams::default(),
            Err(e) => {
                password.zeroize();
                self.set_error(format!("DB error: {e}"));
                return;
            }
        };
        let salt_bytes = match B64.decode(salt_b64.as_bytes()) {
            Ok(b) => b,
            Err(e) => {
                password.zeroize();
                self.set_error(format!("Salt decode failed: {e}"));
                return;
            }
        };
        let mut salt = [0u8; crypto::SALT_LEN];
        if salt_bytes.len() != salt.len() {
            password.zeroize();
            self.set_error("Corrupt salt.");
            return;
        }
        salt.copy_from_slice(&salt_bytes);
        let mut key = match crypto::derive_key(&password, &salt, kdf_params) {
            Ok(k) => k,
            Err(e) => {
                password.zeroize();
                self.set_error(format!("Key derivation failed: {e}"));
                return;
            }
        };
        // Done with the plaintext master password.
        password.zeroize();
        let verifier = match db::get_meta(&self.conn, "verifier") {
            Ok(Some(v)) => v,
            Ok(None) => {
                key.zeroize();
                self.set_error("Corrupt vault.");
                return;
            }
            Err(e) => {
                key.zeroize();
                self.set_error(format!("DB error: {e}"));
                return;
            }
        };
        match crypto::check_verifier(&key, &verifier) {
            Ok(true) => {
                self.kdf_params = kdf_params;
                self.master_key = Some(key);
                self.mode = Mode::List;
                self.clear_message();
                if let Err(e) = self.reload() {
                    self.set_error(format!("Reload failed: {e}"));
                }
            }
            _ => {
                key.zeroize();
                self.set_error("Wrong master password.");
            }
        }
    }

    pub fn submit_setup(&mut self) {
        if self.input_master.is_empty() {
            self.set_error("Password cannot be empty.");
            return;
        }
        if self.input_master.chars().count() < MIN_MASTER_PASSWORD_LEN {
            self.set_error(format!(
                "Master password must be at least {MIN_MASTER_PASSWORD_LEN} characters."
            ));
            return;
        }
        if self.input_master != self.input_master_confirm {
            self.set_error("Passwords do not match.");
            return;
        }
        let params = KdfParams::default();
        let salt = crypto::gen_salt();
        let mut password = std::mem::take(&mut self.input_master);
        self.cursor = 0;
        self.input_master_confirm.zeroize();
        self.input_master_confirm.clear();
        let mut key = match crypto::derive_key(&password, &salt, params) {
            Ok(k) => k,
            Err(e) => {
                password.zeroize();
                self.set_error(format!("Key derivation failed: {e}"));
                return;
            }
        };
        password.zeroize();
        let verifier = match crypto::make_verifier(&key) {
            Ok(v) => v,
            Err(e) => {
                key.zeroize();
                self.set_error(format!("Verifier failed: {e}"));
                return;
            }
        };
        let salt_b64 = B64.encode(salt);

        // Persist salt, KDF parameters, and verifier atomically so a crash
        // cannot leave a vault that is impossible to unlock.
        let persist: color_eyre::Result<()> = (|| {
            let tx = self.conn.transaction()?;
            db::set_meta(&tx, "salt", &salt_b64)?;
            db::set_meta(&tx, KdfParams::META_KEY, &params.encode())?;
            db::set_meta(&tx, "verifier", &verifier)?;
            tx.commit()?;
            Ok(())
        })();
        if let Err(e) = persist {
            self.set_error(format!("DB error: {e}"));
            return;
        }

        self.kdf_params = params;
        self.master_key = Some(key);
        self.mode = Mode::List;
        self.set_success("Vault created.");
        if let Err(e) = self.reload() {
            self.set_error(format!("Reload failed: {e}"));
        }
    }

    /// Begin the master-password reset flow. Requires the vault to be
    /// unlocked (so we can re-encrypt secrets with the new key).
    pub fn start_reset_master(&mut self) {
        if self.master_key.is_none() {
            self.set_error("Vault is locked.");
            return;
        }
        self.mode = Mode::ResetMaster;
        self.field = Field::OldMaster;
        self.input_old_master.clear();
        self.input_new_master.clear();
        self.input_new_master_confirm.clear();
        self.cursor_end();
        self.clear_message();
    }

    pub fn cancel_reset_master(&mut self) {
        self.input_old_master.zeroize();
        self.input_old_master.clear();
        self.input_new_master.zeroize();
        self.input_new_master.clear();
        self.input_new_master_confirm.zeroize();
        self.input_new_master_confirm.clear();
        self.mode = Mode::List;
        self.cursor = 0;
        self.message.clear();
    }

    /// Verify the old password, derive a new key, re-encrypt every secret,
    /// and persist the change atomically.
    pub fn submit_reset_master(&mut self) {
        let mut old_password = std::mem::take(&mut self.input_old_master);
        let mut new_password = std::mem::take(&mut self.input_new_master);
        let mut new_password_confirm = std::mem::take(&mut self.input_new_master_confirm);
        self.cursor = 0;

        // Validate new password locally before touching the DB.
        if new_password.is_empty() {
            self.set_error("New password cannot be empty.");
            old_password.zeroize();
            new_password.zeroize();
            new_password_confirm.zeroize();
            return;
        }
        if new_password.chars().count() < MIN_MASTER_PASSWORD_LEN {
            self.set_error(format!(
                "New password must be at least {MIN_MASTER_PASSWORD_LEN} characters."
            ));
            old_password.zeroize();
            new_password.zeroize();
            new_password_confirm.zeroize();
            return;
        }
        if new_password != new_password_confirm {
            self.set_error("New passwords do not match.");
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
                self.set_error("Vault is not initialized.");
                old_password.zeroize();
                new_password.zeroize();
                new_password_confirm.zeroize();
                return;
            }
        };
        let salt_bytes = match B64.decode(salt_b64.as_bytes()) {
            Ok(b) => b,
            Err(e) => {
                self.set_error(format!("Salt decode failed: {e}"));
                old_password.zeroize();
                new_password.zeroize();
                new_password_confirm.zeroize();
                return;
            }
        };
        let mut salt = [0u8; crypto::SALT_LEN];
        if salt_bytes.len() != salt.len() {
            self.set_error("Corrupt salt.");
            old_password.zeroize();
            new_password.zeroize();
            new_password_confirm.zeroize();
            return;
        }
        salt.copy_from_slice(&salt_bytes);

        let old_key = match crypto::derive_key(&old_password, &salt, self.kdf_params) {
            Ok(k) => k,
            Err(e) => {
                self.set_error(format!("Key derivation failed: {e}"));
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
                self.set_error("Corrupt vault.");
                new_password.zeroize();
                new_password_confirm.zeroize();
                return;
            }
        };
        if !crypto::check_verifier(&old_key, &verifier).unwrap_or(false) {
            self.set_error("Old master password is incorrect.");
            new_password.zeroize();
            new_password_confirm.zeroize();
            return;
        }

        // Derive the new key from a fresh salt, keeping the vault's KDF costs.
        let new_params = self.kdf_params;
        let new_salt = crypto::gen_salt();
        let new_key = match crypto::derive_key(&new_password, &new_salt, new_params) {
            Ok(k) => k,
            Err(e) => {
                self.set_error(format!("Key derivation failed: {e}"));
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
                        self.set_error(format!(
                            "Re-encrypt failed for account {}: {e}",
                            account.website
                        ));
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
                        self.set_error(format!(
                            "Re-encrypt failed for account {}: {e}",
                            account.website
                        ));
                        return;
                    }
                }
            };
            reencrypted_accounts.push((
                account.id,
                account.website.clone(),
                account.username.clone(),
                new_blob,
            ));
        }

        let mut reencrypted_creds: Vec<(i64, String, String, String, String)> = Vec::new();
        for cred in &self.api_credentials {
            let api_plain = if cred.api_key.is_empty() {
                String::new()
            } else {
                match crypto::decrypt(&old_key, &cred.api_key) {
                    Ok(p) => p,
                    Err(e) => {
                        self.set_error(format!("Re-encrypt failed for {}: {e}", cred.name));
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
                        self.set_error(format!("Re-encrypt failed for {}: {e}", cred.name));
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
                        self.set_error(format!("Re-encrypt failed for {}: {e}", cred.name));
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
                        self.set_error(format!("Re-encrypt failed for {}: {e}", cred.name));
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
                self.set_error(format!("Verifier failed: {e}"));
                return;
            }
        };
        let new_salt_b64 = B64.encode(new_salt);

        let commit_result: color_eyre::Result<()> = (|| {
            let tx = self.conn.transaction()?;
            for (id, website, username, blob) in &reencrypted_accounts {
                db::update(&tx, *id, website, username, blob)?;
            }
            for (id, name, api, client_id, secret) in &reencrypted_creds {
                db::update_api(&tx, *id, name, api, client_id, secret)?;
            }
            db::set_meta(&tx, "salt", &new_salt_b64)?;
            db::set_meta(&tx, KdfParams::META_KEY, &new_params.encode())?;
            db::set_meta(&tx, "verifier", &new_verifier)?;
            tx.commit()?;
            Ok(())
        })();

        match commit_result {
            Ok(()) => {
                self.master_key = Some(new_key);
                self.mode = Mode::List;
                self.revealed.clear();
                self.set_success("Master password changed.");
                if let Err(e) = self.reload() {
                    self.set_error(format!("Reload failed: {e}"));
                }
            }
            Err(e) => {
                self.set_error(format!("Reset failed: {e}"));
            }
        }
    }

    pub fn start_view(&mut self) {
        if self.current_len() == 0 {
            return;
        }
        self.mode = Mode::View;
        self.revealed.clear();
        self.cursor = 0;
        self.message.clear();
    }

    pub fn close_view(&mut self) {
        self.mode = Mode::List;
        self.revealed.clear();
        self.cursor = 0;
        self.message.clear();
    }

    pub fn toggle_reveal(&mut self) {
        if self.master_key.is_none() || self.mode != Mode::View {
            return;
        }
        if !self.revealed.is_none() {
            self.revealed.clear();
            return;
        }
        let Some(key) = &self.master_key else {
            return;
        };
        match self.tab {
            Tab::Accounts => {
                let Some(account) = self.selected_account().cloned() else {
                    return;
                };
                match crypto::decrypt(key, &account.password) {
                    Ok(p) => self.revealed = Revealed::AccountPassword(p),
                    Err(e) => self.set_error(format!("Decrypt failed: {e}")),
                }
            }
            Tab::ApiKeys => {
                let Some(cred) = self.selected_credential().cloned() else {
                    return;
                };
                let api_key = if cred.api_key.is_empty() {
                    String::new()
                } else {
                    match crypto::decrypt(key, &cred.api_key) {
                        Ok(p) => p,
                        Err(e) => {
                            self.set_error(format!("Decrypt failed: {e}"));
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
                            self.set_error(format!("Decrypt failed: {e}"));
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
        let Some(username) = self.selected_account().map(|a| a.username.clone()) else {
            return;
        };
        self.copy_to_clipboard(&username, "Username", false);
    }

    /// Copy the selected account's decrypted password to the system clipboard.
    pub fn copy_password(&mut self) {
        let Some(blob) = self.selected_account().map(|a| a.password.clone()) else {
            return;
        };
        self.copy_secret_to_clipboard(&blob, "Password");
    }

    /// Copy the selected API credential's decrypted api key.
    pub fn copy_api_key(&mut self) {
        let Some(blob) = self.selected_credential().map(|c| c.api_key.clone()) else {
            return;
        };
        self.copy_secret_to_clipboard(&blob, "API key");
    }

    /// Copy the selected API credential's client id (plaintext).
    pub fn copy_client_id(&mut self) {
        let Some(client_id) = self.selected_credential().map(|c| c.client_id.clone()) else {
            return;
        };
        self.copy_to_clipboard(&client_id, "Client ID", false);
    }

    /// Copy the selected API credential's decrypted client secret.
    pub fn copy_client_secret(&mut self) {
        let Some(blob) = self.selected_credential().map(|c| c.client_secret.clone()) else {
            return;
        };
        self.copy_secret_to_clipboard(&blob, "Client secret");
    }

    /// Decrypt `blob`, copy the plaintext to the clipboard, then zeroize the
    /// local plaintext buffer. When `arm_auto_clear` is set, the clipboard is
    /// cleared later if it still holds this secret.
    fn copy_secret_to_clipboard(&mut self, blob: &str, label: &str) {
        if blob.is_empty() {
            self.set_error(format!("{label} is not set."));
            return;
        }
        let Some(key) = self.master_key.as_ref() else {
            self.set_error("Vault is locked.");
            return;
        };
        let mut plaintext = match crypto::decrypt(key, blob) {
            Ok(p) => p,
            Err(e) => {
                self.set_error(format!("Decrypt failed: {e}"));
                return;
            }
        };
        self.copy_to_clipboard(&plaintext, label, true);
        plaintext.zeroize();
    }

    fn copy_to_clipboard(&mut self, text: &str, label: &str, arm_auto_clear: bool) {
        match arboard::Clipboard::new().and_then(|mut clipboard| clipboard.set_text(text)) {
            Ok(()) => {
                if arm_auto_clear {
                    self.keep_clipboard_secret(text);
                    self.set_success(format!(
                        "{label} copied to clipboard (clears in {CLIPBOARD_CLEAR_SECS}s)."
                    ));
                } else {
                    self.set_success(format!("{label} copied to clipboard."));
                }
            }
            Err(e) => self.set_error(format!("Clipboard error: {e}")),
        }
    }

    fn keep_clipboard_secret(&mut self, secret: &str) {
        self.clipboard_secret.zeroize();
        self.clipboard_secret.clear();
        self.clipboard_secret.push_str(secret);
        self.clipboard_deadline = Some(Instant::now() + Duration::from_secs(CLIPBOARD_CLEAR_SECS));
    }

    fn clear_expired_clipboard(&mut self) {
        let Some(deadline) = self.clipboard_deadline else {
            return;
        };
        if Instant::now() >= deadline {
            self.clear_clipboard_if_unchanged();
        }
    }

    /// Clear the clipboard only if it still holds the secret we copied, then
    /// forget the tracking state. The OS clipboard is never used to clobber
    /// content the user copied in the meantime.
    fn clear_clipboard_if_unchanged(&mut self) {
        if self.clipboard_secret.is_empty() {
            self.clipboard_deadline = None;
            return;
        }
        let still_ours = arboard::Clipboard::new()
            .and_then(|mut clipboard| clipboard.get_text())
            .map(|current| current == self.clipboard_secret)
            .unwrap_or(false);
        if still_ours {
            match arboard::Clipboard::new().and_then(|mut clipboard| clipboard.clear()) {
                Ok(()) => self.set_info("Clipboard cleared."),
                Err(e) => self.set_error(format!("Clipboard clear failed: {e}")),
            }
        }
        self.clipboard_secret.zeroize();
        self.clipboard_secret.clear();
        self.clipboard_deadline = None;
    }
}

impl Drop for App {
    fn drop(&mut self) {
        // Best-effort scrub of in-memory secrets when the app is dropped.
        // `lock()` is the explicit path; this covers early returns and
        // panics that bypass it. The master key and revealed secrets scrub
        // themselves through `ZeroizeOnDrop`.
        self.revealed.clear();
        self.input_master.zeroize();
        self.input_master_confirm.zeroize();
        self.input_old_master.zeroize();
        self.input_new_master.zeroize();
        self.input_new_master_confirm.zeroize();
        self.clipboard_secret.zeroize();
        self.search.zeroize();
        self.clear_secret_inputs();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::cli::Action;

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Each test gets its own directory so parallel runs cannot collide.
    fn temp_vault_dir(label: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "rusty-vault-app-test-{}-{n}-{label}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn cli_for(path: &Path) -> Cli {
        Cli {
            db_path: path.to_path_buf(),
            idle_lock: None,
            action: Action::Run,
        }
    }

    fn create_vault_through_app(label: &str, master_password: &str) -> (PathBuf, App) {
        let dir = temp_vault_dir(label);
        let path = dir.join("vault.db");
        let mut app = App::new(&cli_for(&path)).unwrap();
        assert_eq!(app.mode, Mode::Setup);
        app.input_master = master_password.to_string();
        app.input_master_confirm = master_password.to_string();
        app.submit_setup();
        assert_eq!(app.mode, Mode::List);
        assert_eq!(app.message, "Vault created.");
        (dir, app)
    }

    fn add_account(app: &mut App, website: &str, username: &str, password: &str) {
        app.start_add();
        assert_eq!(app.mode, Mode::Add);
        app.input_website = website.to_string();
        app.input_username = username.to_string();
        app.input_password = password.to_string();
        app.save_form();
        assert_eq!(app.mode, Mode::List);
    }

    #[test]
    fn master_key_and_revealed_are_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<MasterKey>();
        assert_zeroize_on_drop::<Revealed>();
    }

    #[test]
    fn vault_lifecycle_add_unlock_and_reset_master() {
        let (dir, mut app) = create_vault_through_app("lifecycle", "old-pass");

        // KDF parameters are persisted at creation.
        assert!(
            db::get_meta(&app.conn, KdfParams::META_KEY)
                .unwrap()
                .is_some()
        );

        add_account(&mut app, "example.com", "alice", "s3cret");
        assert_eq!(app.accounts.len(), 1);
        assert_eq!(app.visible.len(), 1);

        // Lock clears decrypted state and requires the password again.
        app.lock();
        assert_eq!(app.mode, Mode::Unlock);
        assert!(app.accounts.is_empty());
        app.input_master = "wrong-pass".to_string();
        app.submit_unlock();
        assert!(app.master_key.is_none());
        assert_eq!(app.message, "Wrong master password.");

        app.input_master = "old-pass".to_string();
        app.submit_unlock();
        assert_eq!(app.mode, Mode::List);
        assert_eq!(app.accounts.len(), 1);

        // Change the master password, re-encrypting every secret.
        app.start_reset_master();
        app.input_old_master = "old-pass".to_string();
        app.input_new_master = "new-pass".to_string();
        app.input_new_master_confirm = "new-pass".to_string();
        app.submit_reset_master();
        assert_eq!(app.mode, Mode::List);
        assert_eq!(app.message, "Master password changed.");
        let key = app.master_key.as_ref().unwrap();
        assert_eq!(
            crypto::decrypt(key, &app.accounts[0].password).unwrap(),
            "s3cret"
        );

        // The old password no longer unlocks the vault; the new one does.
        app.lock();
        app.input_master = "old-pass".to_string();
        app.submit_unlock();
        assert!(app.master_key.is_none());
        app.input_master = "new-pass".to_string();
        app.submit_unlock();
        assert!(app.master_key.is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn short_master_passwords_are_rejected() {
        let dir = temp_vault_dir("short-password");
        let path = dir.join("vault.db");
        let mut app = App::new(&cli_for(&path)).unwrap();
        app.input_master = "short".to_string();
        app.input_master_confirm = "short".to_string();
        app.submit_setup();
        assert_eq!(app.mode, Mode::Setup);
        assert!(app.message.contains("at least"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn search_filters_and_delete_requires_confirmation() {
        let (dir, mut app) = create_vault_through_app("search-delete", "master-pass");
        add_account(&mut app, "github.com", "george", "pw1");
        add_account(&mut app, "gitlab.com", "gs", "pw2");
        assert_eq!(app.accounts.len(), 2);
        assert_eq!(app.visible.len(), 2);

        // Filter narrows the visible list and the selection helpers follow it.
        app.start_search();
        assert!(app.searching);
        for c in "gitlab".chars() {
            app.search_push(c);
        }
        assert_eq!(app.visible.len(), 1);
        assert_eq!(app.selected_account().unwrap().website, "gitlab.com");
        app.submit_search();
        assert!(!app.searching);

        // Deleting demands confirmation; cancel keeps the entry.
        app.request_delete();
        assert_eq!(app.mode, Mode::ConfirmDelete);
        app.cancel_delete();
        assert_eq!(app.mode, Mode::List);
        assert_eq!(app.accounts.len(), 2);

        app.request_delete();
        app.confirm_delete();
        assert_eq!(app.mode, Mode::List);
        assert_eq!(app.accounts.len(), 1);
        assert!(app.visible.is_empty(), "filter still hides github.com");

        // Clearing the filter reveals the survivor.
        app.cancel_search();
        assert_eq!(app.visible.len(), 1);
        assert_eq!(app.selected_account().unwrap().website, "github.com");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn idle_timeout_locks_the_vault() {
        let (dir, mut app) = create_vault_through_app("idle-lock", "master-pass");
        app.idle_lock = Some(Duration::ZERO);
        app.tick();
        assert_eq!(app.mode, Mode::Unlock);
        assert!(app.master_key.is_none());
        assert_eq!(app.message, "Vault locked after inactivity.");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn generator_targets_the_password_field_from_any_field() {
        let (dir, mut app) = create_vault_through_app("generator", "master-pass");
        app.start_add();
        app.field = Field::Website;
        app.generate_secret();
        assert_eq!(app.input_password.chars().count(), password::DEFAULT_LEN);
        assert_eq!(app.field, Field::Password);
        assert_eq!(app.cursor, password::DEFAULT_LEN);
        assert_eq!(app.message_kind, MessageKind::Success);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn caret_editing_operations() {
        let (dir, mut app) = create_vault_through_app("caret", "master-pass");
        app.start_add();
        app.field = Field::Website;

        app.input_insert('a');
        app.input_insert('b');
        app.input_insert('c');
        assert_eq!(app.input_website, "abc");
        assert_eq!(app.cursor, 3);

        app.cursor_home();
        app.input_insert('X');
        assert_eq!(app.input_website, "Xabc");
        assert_eq!(app.cursor, 1);

        // Delete removes the character at the caret ('a').
        app.input_delete();
        assert_eq!(app.input_website, "Xbc");
        assert_eq!(app.cursor, 1);

        app.input_backspace();
        assert_eq!(app.input_website, "bc");
        assert_eq!(app.cursor, 0);

        app.cursor_end();
        app.input_clear();
        assert_eq!(app.input_website, "");
        assert_eq!(app.cursor, 0);

        for c in "hello world".chars() {
            app.input_insert(c);
        }
        app.input_delete_word();
        assert_eq!(app.input_website, "hello ");
        assert_eq!(app.cursor, 6);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn messages_carry_severity_and_expire() {
        let (dir, mut app) = create_vault_through_app("messages", "master-pass");

        app.set_error("boom");
        assert_eq!(app.message_kind, MessageKind::Error);
        assert!(app.visible_message().is_some());

        // Expired messages are hidden immediately, and scrubbed on tick.
        app.message_expires_at = Some(Instant::now() - Duration::from_secs(1));
        assert!(app.visible_message().is_none());
        app.tick();
        assert!(app.message.is_empty());

        app.set_success("ok");
        assert_eq!(app.visible_message(), Some(("ok", MessageKind::Success)));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
