use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::Text,
    widgets::{Block, BorderType, Borders, List, ListItem, ListState, Paragraph},
};

use crate::app::{App, Field, Mode, Revealed, Tab};

pub fn render(app: &mut App, frame: &mut Frame) {
    let area = frame.area();

    let block = Block::default()
        .title(" Rusty Vault ")
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .style(Style::default().fg(Color::Cyan));
    frame.render_widget(block, area);

    let inner = area.inner(ratatui::layout::Margin {
        horizontal: 1,
        vertical: 1,
    });

    let show_tabs = matches!(
        app.mode,
        Mode::List | Mode::View | Mode::Add | Mode::Edit
    );

    // In List mode the keybinds live in a side panel next to the list
    // instead of the bottom footer; other modes keep the bottom footer.
    let side_keybinds = app.mode == Mode::List;

    let [body, footer] = if show_tabs {
        let [tabs, body, footer] =
            Layout::vertical([Constraint::Length(1), Constraint::Min(1), Constraint::Length(2)])
                .areas(inner);
        render_tabs(app, frame, tabs);
        [body, footer]
    } else {
        Layout::vertical([Constraint::Min(1), Constraint::Length(2)]).areas(inner)
    };

    if side_keybinds {
        // Split body into [list, keybinds panel].
        let [list_area, keybinds_area] =
            Layout::horizontal([Constraint::Min(20), Constraint::Length(34)]).areas(body);
        render_list(app, frame, list_area);
        render_keybinds_panel(app, frame, keybinds_area);
        render_status_message(app, frame, footer);
    } else {
        match app.mode {
            Mode::Unlock => render_unlock(app, frame, body),
            Mode::Setup => render_setup(app, frame, body),
            Mode::View => render_view(app, frame, body),
            Mode::Add | Mode::Edit => render_form(app, frame, body),
            Mode::ResetMaster => render_reset_master(app, frame, body),
            Mode::List => unreachable!(),
        }
        render_footer(app, frame, footer);
    }
}

fn render_tabs(app: &mut App, frame: &mut Frame, area: Rect) {
    let active = app.tab;
    let line = ratatui::text::Line::from(vec![
        tab_span(Tab::Accounts, active),
        ratatui::text::Span::raw("   "),
        tab_span(Tab::ApiKeys, active),
    ]);
    frame.render_widget(
        Paragraph::new(line).alignment(Alignment::Center),
        area,
    );
}

fn tab_span(tab: Tab, active: Tab) -> ratatui::text::Span<'static> {
    let label = tab.label();
    if tab == active {
        ratatui::text::Span::styled(
            format!("[ {label} ]"),
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        ratatui::text::Span::styled(
            format!("  {label}  "),
            Style::default().fg(Color::DarkGray),
        )
    }
}

fn render_unlock(app: &mut App, frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .title(" Unlock ")
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Cyan));

    let inner = block.inner(area);
    frame.render_widget(&block, area);

    let chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(3),
        Constraint::Min(1),
    ])
    .split(inner);

    frame.render_widget(
        Paragraph::new("Enter your master password:")
            .alignment(Alignment::Center)
            .style(Style::default().fg(Color::White)),
        chunks[0],
    );

    render_field(
        frame,
        " Master Password ",
        &app.input_master,
        app.field == Field::Master,
        chunks[1],
    );

    if !app.message.is_empty() {
        frame.render_widget(
            Paragraph::new(app.message.as_str())
                .style(Style::default().fg(Color::Yellow))
                .alignment(Alignment::Center),
            chunks[2],
        );
    }
}

fn render_setup(app: &mut App, frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .title(" Create Vault ")
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Cyan));

    let inner = block.inner(area);
    frame.render_widget(&block, area);

    let chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Min(1),
    ])
    .split(inner);

    frame.render_widget(
        Paragraph::new("Choose a master password:")
            .alignment(Alignment::Center)
            .style(Style::default().fg(Color::White)),
        chunks[0],
    );

    render_field(
        frame,
        " Master Password ",
        &app.input_master,
        app.field == Field::Master,
        chunks[1],
    );
    render_field(
        frame,
        " Confirm Password ",
        &app.input_master_confirm,
        app.field == Field::MasterConfirm,
        chunks[2],
    );

    if !app.message.is_empty() {
        frame.render_widget(
            Paragraph::new(app.message.as_str())
                .style(Style::default().fg(Color::Yellow))
                .alignment(Alignment::Center),
            chunks[3],
        );
    }
}

fn render_reset_master(app: &mut App, frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .title(" Change Master Password ")
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Cyan));

    let inner = block.inner(area);
    frame.render_widget(&block, area);

    let chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Min(1),
    ])
    .split(inner);

    frame.render_widget(
        Paragraph::new("Enter your current password, then choose a new one.")
            .alignment(Alignment::Center)
            .style(Style::default().fg(Color::White)),
        chunks[0],
    );

    render_field(
        frame,
        " Current Password ",
        &app.input_old_master,
        app.field == Field::OldMaster,
        chunks[1],
    );
    render_field(
        frame,
        " New Password ",
        &app.input_new_master,
        app.field == Field::NewMaster,
        chunks[2],
    );
    render_field(
        frame,
        " Confirm New Password ",
        &app.input_new_master_confirm,
        app.field == Field::NewMasterConfirm,
        chunks[3],
    );

    if !app.message.is_empty() {
        frame.render_widget(
            Paragraph::new(app.message.as_str())
                .style(Style::default().fg(Color::Yellow))
                .alignment(Alignment::Center),
            chunks[4],
        );
    }
}

fn render_list(app: &mut App, frame: &mut Frame, area: Rect) {
    match app.tab {
        Tab::Accounts => render_account_list(app, frame, area),
        Tab::ApiKeys => render_api_list(app, frame, area),
    }
}

fn render_account_list(app: &mut App, frame: &mut Frame, area: Rect) {
    if app.accounts.is_empty() {
        frame.render_widget(
            Paragraph::new("No accounts yet. Press `a` to add one.")
                .alignment(Alignment::Center)
                .style(Style::default().fg(Color::DarkGray)),
            area,
        );
        return;
    }

    let items: Vec<ListItem> = app
        .accounts
        .iter()
        .map(|a| ListItem::new(format!("{}  —  {}", a.website, a.username)))
        .collect();

    let mut state = ListState::default();
    state.select(Some(app.selected));

    let list = List::new(items)
        .style(Style::default().fg(Color::White))
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    frame.render_stateful_widget(list, area, &mut state);
}

fn render_api_list(app: &mut App, frame: &mut Frame, area: Rect) {
    if app.api_credentials.is_empty() {
        frame.render_widget(
            Paragraph::new("No API credentials yet. Press `a` to add one.")
                .alignment(Alignment::Center)
                .style(Style::default().fg(Color::DarkGray)),
            area,
        );
        return;
    }

    let items: Vec<ListItem> = app
        .api_credentials
        .iter()
        .map(|c| ListItem::new(c.name.clone()))
        .collect();

    let mut state = ListState::default();
    state.select(Some(app.selected));

    let list = List::new(items)
        .style(Style::default().fg(Color::White))
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    frame.render_stateful_widget(list, area, &mut state);
}

fn render_view(app: &mut App, frame: &mut Frame, area: Rect) {
    match app.tab {
        Tab::Accounts => render_account_view(app, frame, area),
        Tab::ApiKeys => render_api_view(app, frame, area),
    }
}

fn render_account_view(app: &mut App, frame: &mut Frame, area: Rect) {
    let Some(account) = app.accounts.get(app.selected).cloned() else {
        frame.render_widget(
            Paragraph::new("No account selected.")
                .alignment(Alignment::Center)
                .style(Style::default().fg(Color::DarkGray)),
            area,
        );
        return;
    };

    let block = Block::default()
        .title(" Account Details ")
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Cyan));

    let inner = block.inner(area);
    frame.render_widget(&block, area);

    let (password_display, password_label) = match &app.revealed {
        Revealed::AccountPassword(p) => (p.clone(), " Password (revealed) "),
        _ => (
            "*".repeat(account.password.len().min(32)),
            " Password (hidden) ",
        ),
    };

    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Min(1),
    ])
    .split(inner);

    render_field(frame, " Website ", &account.website, false, chunks[0]);
    render_field(frame, " Username ", &account.username, false, chunks[1]);
    render_field(frame, password_label, &password_display, false, chunks[2]);

    if !app.message.is_empty() {
        frame.render_widget(
            Paragraph::new(app.message.as_str())
                .style(Style::default().fg(Color::Yellow))
                .alignment(Alignment::Center),
            chunks[3],
        );
    }
}

fn render_api_view(app: &mut App, frame: &mut Frame, area: Rect) {
    let Some(cred) = app.api_credentials.get(app.selected).cloned() else {
        frame.render_widget(
            Paragraph::new("No credential selected.")
                .alignment(Alignment::Center)
                .style(Style::default().fg(Color::DarkGray)),
            area,
        );
        return;
    };

    let block = Block::default()
        .title(" API Credential Details ")
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Cyan));

    let inner = block.inner(area);
    frame.render_widget(&block, area);

    let (api_key_display, api_key_label) = if cred.api_key.is_empty() {
        ("(not set)".to_string(), " API Key ")
    } else {
        match &app.revealed {
            Revealed::Api { api_key, .. } => (api_key.clone(), " API Key (revealed) "),
            _ => (
                "*".repeat(cred.api_key.len().min(32)),
                " API Key (hidden) ",
            ),
        }
    };
    let (secret_display, secret_label) = if cred.client_secret.is_empty() {
        ("(not set)".to_string(), " Client Secret ")
    } else {
        match &app.revealed {
            Revealed::Api { client_secret, .. } => {
                (client_secret.clone(), " Client Secret (revealed) ")
            }
            _ => (
                "*".repeat(cred.client_secret.len().min(32)),
                " Client Secret (hidden) ",
            ),
        }
    };

    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Min(1),
    ])
    .split(inner);

    render_field(frame, " Name ", &cred.name, false, chunks[0]);
    render_field(frame, api_key_label, &api_key_display, false, chunks[1]);
    render_field(frame, " Client ID ", &cred.client_id, false, chunks[2]);
    render_field(frame, secret_label, &secret_display, false, chunks[3]);

    if !app.message.is_empty() {
        frame.render_widget(
            Paragraph::new(app.message.as_str())
                .style(Style::default().fg(Color::Yellow))
                .alignment(Alignment::Center),
            chunks[4],
        );
    }
}

fn render_form(app: &mut App, frame: &mut Frame, area: Rect) {
    match app.tab {
        Tab::Accounts => render_account_form(app, frame, area),
        Tab::ApiKeys => render_api_form(app, frame, area),
    }
}

fn render_account_form(app: &mut App, frame: &mut Frame, area: Rect) {
    let title = match app.mode {
        Mode::Add => " Add Account ",
        Mode::Edit => " Edit Account ",
        _ => " Account ",
    };

    let block = Block::default()
        .title(title)
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Cyan));

    let inner = block.inner(area);
    frame.render_widget(&block, area);

    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Min(1),
    ])
    .split(inner);

    render_field(frame, " Website ", &app.input_website, app.field == Field::Website, chunks[0]);
    render_field(frame, " Username ", &app.input_username, app.field == Field::Username, chunks[1]);
    render_field(frame, " Password ", &app.input_password, app.field == Field::Password, chunks[2]);

    if !app.message.is_empty() {
        frame.render_widget(
            Paragraph::new(app.message.as_str())
                .style(Style::default().fg(Color::Yellow)),
            chunks[3],
        );
    }
}

fn render_api_form(app: &mut App, frame: &mut Frame, area: Rect) {
    let title = match app.mode {
        Mode::Add => " Add API Credential ",
        Mode::Edit => " Edit API Credential ",
        _ => " API Credential ",
    };

    let block = Block::default()
        .title(title)
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Cyan));

    let inner = block.inner(area);
    frame.render_widget(&block, area);

    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Min(1),
    ])
    .split(inner);

    render_field(frame, " Name (required) ", &app.input_name, app.field == Field::Name, chunks[0]);
    render_field(frame, " API Key (optional) ", &app.input_api_key, app.field == Field::ApiKey, chunks[1]);
    render_field(frame, " Client ID (optional) ", &app.input_client_id, app.field == Field::ClientId, chunks[2]);
    render_field(
        frame,
        " Client Secret (optional) ",
        &app.input_client_secret,
        app.field == Field::ClientSecret,
        chunks[3],
    );

    if !app.message.is_empty() {
        frame.render_widget(
            Paragraph::new(app.message.as_str())
                .style(Style::default().fg(Color::Yellow)),
            chunks[4],
        );
    }
}

fn render_field(
    frame: &mut Frame,
    label: &str,
    value: &str,
    focused: bool,
    area: Rect,
) {
    let border_style = if focused {
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    // Mask any secret field, unless it has been explicitly revealed.
    let is_secret = label.contains("Password")
        || label.contains("API Key")
        || label.contains("Client Secret")
        || label.contains("Confirm");
    let display = if is_secret && !label.contains("revealed") {
        "*".repeat(value.chars().count())
    } else {
        value.to_string()
    };

    let block = Block::default()
        .title(label)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(border_style);

    frame.render_widget(Paragraph::new(display).block(block), area);
}

fn render_keybinds_panel(app: &mut App, frame: &mut Frame, area: Rect) {
    let title = match app.tab {
        Tab::Accounts => " Keybinds — Accounts ",
        Tab::ApiKeys => " Keybinds — API Keys ",
    };

    let block = Block::default()
        .title(title)
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::DarkGray));

    let inner = block.inner(area);
    frame.render_widget(&block, area);

    let lines: Vec<ratatui::text::Line> = match app.tab {
        Tab::Accounts => vec![
            keybind_line("↑/↓  k/j", "navigate"),
            keybind_line("Enter/v", "view details"),
            keybind_line("a", "add account"),
            keybind_line("e", "edit account"),
            keybind_line("d", "delete account"),
            keybind_line("y", "copy password"),
            keybind_line("u", "copy username"),
            keybind_line("Tab", "switch to API Keys"),
            keybind_line("p", "change master pw"),
            keybind_line("q/Esc", "quit"),
        ],
        Tab::ApiKeys => vec![
            keybind_line("↑/↓  k/j", "navigate"),
            keybind_line("Enter/v", "view details"),
            keybind_line("a", "add credential"),
            keybind_line("e", "edit credential"),
            keybind_line("d", "delete credential"),
            keybind_line("1", "copy api key"),
            keybind_line("2", "copy client id"),
            keybind_line("3", "copy client secret"),
            keybind_line("Tab", "switch to Accounts"),
            keybind_line("p", "change master pw"),
            keybind_line("q/Esc", "quit"),
        ],
    };

    let help = ratatui::text::Text::from(lines).style(Style::default().fg(Color::DarkGray));
    frame.render_widget(Paragraph::new(help).alignment(Alignment::Left), inner);
}

/// Build a single keybind line: the keys in a brighter color, the
/// description in the base style.
fn keybind_line(keys: &str, desc: &str) -> ratatui::text::Line<'static> {
    ratatui::text::Line::from(vec![
        ratatui::text::Span::styled(
            format!("{keys:<10}"),
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ),
        ratatui::text::Span::raw(desc.to_string()),
    ])
}

/// Render just the transient status message at the bottom (used when the
/// keybinds are shown in the side panel and only the message belongs at
/// the bottom).
fn render_status_message(app: &mut App, frame: &mut Frame, area: Rect) {
    if !app.message.is_empty() && app.revealed.is_none() {
        frame.render_widget(
            Paragraph::new(app.message.as_str())
                .style(Style::default().fg(Color::Yellow))
                .alignment(Alignment::Center),
            area,
        );
    }
}

fn render_footer(app: &mut App, frame: &mut Frame, area: Rect) {
    let hint = match app.mode {
        Mode::Unlock => "[Enter] unlock  [Esc/q] quit",
        Mode::Setup => "[Tab] next field  [Enter] create  [Esc/q] quit",
        Mode::View => match app.tab {
            Tab::Accounts => "[r] reveal  [c] copy pw  [u] copy user  [e] edit  [d] delete  [↑/↓] nav  [Esc/Enter] back",
            Tab::ApiKeys => "[r] reveal  [1] copy key  [2] copy id  [3] copy secret  [e] edit  [d] delete  [↑/↓] nav  [Esc/Enter] back",
        },
        Mode::Add | Mode::Edit => match app.tab {
            Tab::Accounts => "[Tab] next field  [Backspace] delete  [Enter] save  [Esc] cancel",
            Tab::ApiKeys => "[Tab] next field  [Backspace] delete  [Enter] save  [Esc] cancel",
        },
        Mode::ResetMaster => "[Tab] next field  [Enter] change  [Esc] cancel",
        Mode::List => "",
    };

    let text = Text::from(hint).style(Style::default().fg(Color::DarkGray));
    frame.render_widget(Paragraph::new(text).alignment(Alignment::Center), area);

    if !app.message.is_empty()
        && matches!(app.mode, Mode::View | Mode::ResetMaster)
        && app.revealed.is_none()
    {
        let msg_area = Rect {
            y: area.y.saturating_sub(1),
            ..area
        };
        frame.render_widget(
            Paragraph::new(app.message.as_str())
                .style(Style::default().fg(Color::Yellow))
                .alignment(Alignment::Center),
            msg_area,
        );
    }
}