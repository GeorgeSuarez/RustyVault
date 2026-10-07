use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::app::{App, Mode, Tab};

pub fn update(app: &mut App, key_event: KeyEvent) {
    app.touch();

    if is_ctrl(&key_event, 'c') {
        app.quit();
        return;
    }
    if is_ctrl(&key_event, 'l') {
        app.lock_and_notify();
        return;
    }
    if is_text_input_mode(app) {
        if is_ctrl(&key_event, 'u') {
            app.input_clear();
            return;
        }
        if is_ctrl(&key_event, 'w') {
            app.input_delete_word();
            return;
        }
    }

    // `Tab`/`BackTab` switch tabs from the list/view. In forms, Tab cycles
    // fields instead, so it is handled per-mode below. While searching, Tab
    // is left alone so it cannot accidentally change the tab.
    if key_event.code == KeyCode::Tab
        && matches!(app.mode, Mode::List | Mode::View)
        && !app.searching
    {
        app.switch_tab();
        return;
    }

    match app.mode {
        Mode::Unlock => update_unlock(app, key_event),
        Mode::Setup => update_setup(app, key_event),
        Mode::List => update_list(app, key_event),
        Mode::View => update_view(app, key_event),
        Mode::Add | Mode::Edit => update_form(app, key_event),
        Mode::ResetMaster => update_reset_master(app, key_event),
        Mode::ConfirmDelete => update_confirm_delete(app, key_event),
    };
}

fn is_ctrl(key_event: &KeyEvent, c: char) -> bool {
    key_event.modifiers == KeyModifiers::CONTROL && key_event.code == KeyCode::Char(c)
}

/// Whether a text field is currently being edited.
fn is_text_input_mode(app: &App) -> bool {
    match app.mode {
        Mode::Unlock | Mode::Setup | Mode::Add | Mode::Edit | Mode::ResetMaster => true,
        Mode::List => app.searching,
        Mode::View | Mode::ConfirmDelete => false,
    }
}

/// The printable character typed by this event, if any. Control chords are
/// rejected so e.g. Ctrl+U does not insert a literal `u` into a field.
fn typed_char(key_event: &KeyEvent) -> Option<char> {
    match key_event.code {
        KeyCode::Char(c)
            if key_event
                .modifiers
                .difference(KeyModifiers::SHIFT)
                .is_empty() =>
        {
            Some(c)
        }
        _ => None,
    }
}

/// Caret movement and deletion keys shared by every text field. Returns true
/// when the key was consumed.
fn handle_editing_key(app: &mut App, key_event: &KeyEvent) -> bool {
    match key_event.code {
        KeyCode::Left => app.cursor_left(),
        KeyCode::Right => app.cursor_right(),
        KeyCode::Home => app.cursor_home(),
        KeyCode::End => app.cursor_end(),
        KeyCode::Delete => app.input_delete(),
        KeyCode::Backspace => app.input_backspace(),
        _ => return false,
    }
    true
}

fn update_unlock(app: &mut App, key_event: KeyEvent) {
    match key_event.code {
        // `q` is a normal character here so master passwords containing it
        // can be typed; Ctrl+C still quits from anywhere.
        KeyCode::Esc => app.quit(),
        KeyCode::Enter => app.submit_unlock(),
        _ => {
            if handle_editing_key(app, &key_event) {
                return;
            }
            if let Some(c) = typed_char(&key_event) {
                app.input_insert(c);
            }
        }
    }
}

fn update_setup(app: &mut App, key_event: KeyEvent) {
    match key_event.code {
        KeyCode::Esc => app.quit(),
        // In setup, Tab cycles between master + confirm fields.
        KeyCode::Tab | KeyCode::BackTab => {
            app.field = app.field.setup_next();
            app.cursor_end();
        }
        KeyCode::Enter => app.submit_setup(),
        _ => {
            if handle_editing_key(app, &key_event) {
                return;
            }
            if let Some(c) = typed_char(&key_event) {
                app.input_insert(c);
            }
        }
    }
}

fn update_list(app: &mut App, key_event: KeyEvent) {
    if app.searching {
        match key_event.code {
            KeyCode::Esc => app.cancel_search(),
            KeyCode::Enter => app.submit_search(),
            KeyCode::Up => app.list_up(),
            KeyCode::Down => app.list_down(),
            _ => {
                if handle_editing_key(app, &key_event) {
                    return;
                }
                if let Some(c) = typed_char(&key_event) {
                    app.search_push(c);
                }
            }
        }
        return;
    }

    match key_event.code {
        KeyCode::Esc | KeyCode::Char('q') => app.quit(),
        KeyCode::Up | KeyCode::Char('k') => app.list_up(),
        KeyCode::Down | KeyCode::Char('j') => app.list_down(),
        KeyCode::Enter | KeyCode::Char('v') => app.start_view(),
        KeyCode::Char('/') => app.start_search(),
        KeyCode::Char('a') => app.start_add(),
        KeyCode::Char('e') => app.start_edit(),
        KeyCode::Char('d') => app.request_delete(),
        KeyCode::Char('p') => app.start_reset_master(),
        // Account-only quick copies
        KeyCode::Char('y') if app.tab == Tab::Accounts => app.copy_password(),
        KeyCode::Char('u') if app.tab == Tab::Accounts => app.copy_username(),
        // API credential quick copies
        KeyCode::Char('1') if app.tab == Tab::ApiKeys => app.copy_api_key(),
        KeyCode::Char('2') if app.tab == Tab::ApiKeys => app.copy_client_id(),
        KeyCode::Char('3') if app.tab == Tab::ApiKeys => app.copy_client_secret(),
        _ => {}
    }
}

fn update_view(app: &mut App, key_event: KeyEvent) {
    match key_event.code {
        KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => app.close_view(),
        KeyCode::Up | KeyCode::Char('k') => app.list_up(),
        KeyCode::Down | KeyCode::Char('j') => app.list_down(),
        KeyCode::Char('r') => app.toggle_reveal(),
        KeyCode::Char('e') => {
            app.close_view();
            app.start_edit();
        }
        // Confirmation happens in the view so cancelling returns here.
        KeyCode::Char('d') => app.request_delete(),
        // Account copies
        KeyCode::Char('c') if app.tab == Tab::Accounts => app.copy_password(),
        KeyCode::Char('u') if app.tab == Tab::Accounts => app.copy_username(),
        // API credential copies
        KeyCode::Char('1') if app.tab == Tab::ApiKeys => app.copy_api_key(),
        KeyCode::Char('2') if app.tab == Tab::ApiKeys => app.copy_client_id(),
        KeyCode::Char('3') if app.tab == Tab::ApiKeys => app.copy_client_secret(),
        _ => {}
    }
}

fn update_form(app: &mut App, key_event: KeyEvent) {
    let is_account_form = app.tab == Tab::Accounts;
    if is_ctrl(&key_event, 'g') {
        app.generate_secret();
        return;
    }
    match key_event.code {
        KeyCode::Esc => app.cancel_form(),
        KeyCode::Tab => {
            app.field = if is_account_form {
                app.field.account_next()
            } else {
                app.field.api_next()
            };
            app.cursor_end();
        }
        KeyCode::BackTab => {
            app.field = if is_account_form {
                app.field.account_prev()
            } else {
                app.field.api_prev()
            };
            app.cursor_end();
        }
        KeyCode::Enter => app.save_form(),
        _ => {
            if handle_editing_key(app, &key_event) {
                return;
            }
            if let Some(c) = typed_char(&key_event) {
                app.input_insert(c);
            }
        }
    }
}

fn update_reset_master(app: &mut App, key_event: KeyEvent) {
    match key_event.code {
        KeyCode::Esc => app.cancel_reset_master(),
        KeyCode::Tab => {
            app.field = app.field.reset_next();
            app.cursor_end();
        }
        KeyCode::BackTab => {
            app.field = app.field.reset_prev();
            app.cursor_end();
        }
        KeyCode::Enter => app.submit_reset_master(),
        _ => {
            if handle_editing_key(app, &key_event) {
                return;
            }
            if let Some(c) = typed_char(&key_event) {
                app.input_insert(c);
            }
        }
    }
}

fn update_confirm_delete(app: &mut App, key_event: KeyEvent) {
    match key_event.code {
        // Deleting requires an explicit `y`; Enter cancels so a stray
        // keystroke cannot destroy an entry.
        KeyCode::Char('y') | KeyCode::Char('Y') => app.confirm_delete(),
        KeyCode::Enter
        | KeyCode::Esc
        | KeyCode::Char('n')
        | KeyCode::Char('N')
        | KeyCode::Char('q') => app.cancel_delete(),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::app::Field;
    use crate::cli::{Action, Cli};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_app(label: &str) -> (PathBuf, App) {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "rusty-vault-update-test-{}-{n}-{label}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cli = Cli {
            db_path: dir.join("vault.db"),
            idle_lock: None,
            action: Action::Run,
        };
        let mut app = App::new(&cli).unwrap();
        app.input_master = "master-pass".to_string();
        app.input_master_confirm = "master-pass".to_string();
        app.submit_setup();
        (dir, app)
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn q_is_typed_on_the_unlock_screen_instead_of_quitting() {
        let (dir, mut app) = temp_app("unlock-q");
        app.lock();
        assert_eq!(app.mode, Mode::Unlock);
        update(&mut app, key(KeyCode::Char('q')));
        assert_eq!(app.mode, Mode::Unlock);
        assert!(!app.should_quit);
        assert_eq!(app.input_master, "q");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enter_cancels_delete_confirmation() {
        let (dir, mut app) = temp_app("confirm-enter");
        app.start_add();
        app.input_website = "example.com".to_string();
        app.input_username = "alice".to_string();
        app.input_password = "pw".to_string();
        app.save_form();
        assert_eq!(app.accounts.len(), 1);

        app.request_delete();
        assert_eq!(app.mode, Mode::ConfirmDelete);
        update(&mut app, key(KeyCode::Enter));
        assert_eq!(app.mode, Mode::List);
        assert_eq!(app.accounts.len(), 1, "Enter must not delete");

        app.request_delete();
        update(&mut app, key(KeyCode::Char('y')));
        assert_eq!(app.mode, Mode::List);
        assert!(app.accounts.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn caret_keys_edit_fields() {
        let (dir, mut app) = temp_app("caret-keys");
        app.start_add();
        app.field = Field::Website;

        update(&mut app, key(KeyCode::Char('a')));
        update(&mut app, key(KeyCode::Char('b')));
        assert_eq!(app.input_website, "ab");

        update(&mut app, key(KeyCode::Left));
        update(&mut app, key(KeyCode::Backspace));
        assert_eq!(app.input_website, "b");

        update(&mut app, key(KeyCode::End));
        update(&mut app, key(KeyCode::Char('c')));
        assert_eq!(app.input_website, "bc");

        update(&mut app, key(KeyCode::Home));
        update(&mut app, key(KeyCode::Delete));
        assert_eq!(app.input_website, "c");

        update(&mut app, key(KeyCode::Char('u'))); // plain 'u', not Ctrl+U
        // A plain `u` inserts at the caret (index 0 after Delete).
        assert_eq!(app.input_website, "uc");
        update(
            &mut app,
            KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL),
        );
        assert_eq!(app.input_website, "");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
