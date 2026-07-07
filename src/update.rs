use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::app::{App, Mode, Tab};

pub fn update(app: &mut App, key_event: KeyEvent) {
    if (key_event.code == KeyCode::Char('c') || key_event.code == KeyCode::Char('C'))
        && key_event.modifiers == KeyModifiers::CONTROL
    {
        app.quit();
        return;
    }

    // `Tab`/`BackTab` switch tabs from the list/view. In forms, Tab cycles
    // fields instead, so it is handled per-mode below.
    if key_event.code == KeyCode::Tab
        && matches!(app.mode, Mode::List | Mode::View)
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
    };
}

fn update_unlock(app: &mut App, key_event: KeyEvent) {
    match key_event.code {
        KeyCode::Esc | KeyCode::Char('q') => app.quit(),
        KeyCode::Enter => app.submit_unlock(),
        KeyCode::Backspace => {
            app.input_master.pop();
        }
        KeyCode::Char(c) => app.input_master.push(c),
        _ => {}
    }
}

fn update_setup(app: &mut App, key_event: KeyEvent) {
    match key_event.code {
        KeyCode::Esc | KeyCode::Char('q') => app.quit(),
        // In setup, Tab cycles between master + confirm fields.
        KeyCode::Tab => app.field = app.field.setup_next(),
        KeyCode::Enter => app.submit_setup(),
        KeyCode::Backspace => {
            app.active_input().pop();
        }
        KeyCode::Char(c) => app.active_input().push(c),
        _ => {}
    }
}

fn update_list(app: &mut App, key_event: KeyEvent) {
    match key_event.code {
        KeyCode::Esc | KeyCode::Char('q') => app.quit(),
        KeyCode::Up | KeyCode::Char('k') => app.list_up(),
        KeyCode::Down | KeyCode::Char('j') => app.list_down(),
        KeyCode::Enter | KeyCode::Char('v') => app.start_view(),
        KeyCode::Char('a') => app.start_add(),
        KeyCode::Char('e') => app.start_edit(),
        KeyCode::Char('d') => app.delete_selected(),
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
        KeyCode::Char('d') => {
            app.close_view();
            app.delete_selected();
        }
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
    match key_event.code {
        KeyCode::Esc => app.cancel_form(),
        KeyCode::Tab => {
            app.field = if is_account_form {
                app.field.account_next()
            } else {
                app.field.api_next()
            };
        }
        KeyCode::BackTab => {
            app.field = if is_account_form {
                app.field.account_prev()
            } else {
                app.field.api_prev()
            };
        }
        KeyCode::Enter => app.save_form(),
        KeyCode::Backspace => {
            app.active_input().pop();
        }
        KeyCode::Char(c) => app.active_input().push(c),
        _ => {}
    }
}

fn update_reset_master(app: &mut App, key_event: KeyEvent) {
    match key_event.code {
        KeyCode::Esc => app.cancel_reset_master(),
        KeyCode::Tab => app.field = app.field.reset_next(),
        KeyCode::BackTab => app.field = app.field.reset_prev(),
        KeyCode::Enter => app.submit_reset_master(),
        KeyCode::Backspace => {
            app.active_input().pop();
        }
        KeyCode::Char(c) => app.active_input().push(c),
        _ => {}
    }
}