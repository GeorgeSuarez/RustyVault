use ratatui::{
    Frame,
    layout::{Alignment, Constraint, HorizontalAlignment, Layout, Position, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{
        Block, BorderType, Borders, Clear, List, ListItem, ListState, Paragraph, Scrollbar,
        ScrollbarOrientation, ScrollbarState,
    },
};

use crate::app::{App, Field, MessageKind, Mode, Revealed, Tab};

/// Below this width the side keybinds panel is dropped in favor of a compact
/// footer hint, so the list keeps a usable amount of space.
const KEYBINDS_PANEL_MIN_WIDTH: u16 = 88;
/// Minimum terminal size; smaller terminals get a notice instead of a
/// silently clipped layout.
const MIN_WIDTH: u16 = 60;
const MIN_HEIGHT: u16 = 18;
/// Maximum width of centered form/detail content on wide terminals.
const CONTENT_MAX_WIDTH: u16 = 76;
/// Bullets used to mask a hidden secret of unknown length.
const HIDDEN_SECRET: &str = "••••••••••";

pub fn render(app: &mut App, frame: &mut Frame) {
    let area = frame.area();

    let block = Block::default()
        .title(" Rusty Vault ")
        .title_alignment(HorizontalAlignment::Center)
        .borders(Borders::ALL)
        .border_type(BorderType::QuadrantOutside)
        .border_style(Style::default().bold())
        .style(Style::default().fg(Color::Cyan));
    frame.render_widget(block, area);

    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        render_too_small(frame, area);
        return;
    }

    let inner = area.inner(ratatui::layout::Margin {
        horizontal: 1,
        vertical: 1,
    });

    // The delete confirmation renders on top of the list layout.
    let display_mode = match app.mode {
        Mode::ConfirmDelete => Mode::List,
        mode => mode,
    };

    let show_tabs = matches!(
        display_mode,
        Mode::List | Mode::View | Mode::Add | Mode::Edit
    );
    let side_keybinds = display_mode == Mode::List && inner.width >= KEYBINDS_PANEL_MIN_WIDTH;

    let [body, footer] = if show_tabs {
        let [tabs, body, footer] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(2),
        ])
        .areas(inner);
        render_tabs(app, frame, tabs);
        [body, footer]
    } else {
        Layout::vertical([Constraint::Min(1), Constraint::Length(2)]).areas(inner)
    };

    if side_keybinds {
        let [list_area, keybinds_area] =
            Layout::horizontal([Constraint::Min(20), Constraint::Length(34)]).areas(body);
        render_list(app, frame, list_area);
        render_keybinds_panel(app, frame, keybinds_area);
    } else {
        match display_mode {
            Mode::Unlock => render_unlock(app, frame, body),
            Mode::Setup => render_setup(app, frame, body),
            Mode::View => render_view(app, frame, body),
            Mode::Add | Mode::Edit => render_form(app, frame, body),
            Mode::ResetMaster => render_reset_master(app, frame, body),
            Mode::List => render_list(app, frame, body),
            Mode::ConfirmDelete => unreachable!(),
        }
    }
    render_footer(app, frame, footer);

    if app.mode == Mode::ConfirmDelete {
        render_confirm_delete(app, frame, area);
    }
}

fn render_too_small(frame: &mut Frame, area: Rect) {
    let inner = area.inner(ratatui::layout::Margin {
        horizontal: 1,
        vertical: 1,
    });
    frame.render_widget(
        Paragraph::new(format!(
            "Terminal too small\nneeds at least {MIN_WIDTH}×{MIN_HEIGHT}"
        ))
        .alignment(HorizontalAlignment::Center)
        .style(Style::default().fg(Color::Yellow)),
        inner,
    );
}

fn render_tabs(app: &mut App, frame: &mut Frame, area: Rect) {
    let line = Line::from(vec![
        tab_span(Tab::Accounts, app.tab, app.accounts.len()),
        Span::raw("   "),
        tab_span(Tab::ApiKeys, app.tab, app.api_credentials.len()),
    ]);
    frame.render_widget(
        Paragraph::new(line).alignment(HorizontalAlignment::Center),
        area,
    );
}

fn tab_span(tab: Tab, active: Tab, count: usize) -> Span<'static> {
    let label = format!("{} ({count})", tab.label());
    if tab == active {
        Span::styled(
            format!("[ {label} ]"),
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(format!("  {label}  "), Style::default().fg(Color::DarkGray))
    }
}

fn render_unlock(app: &mut App, frame: &mut Frame, area: Rect) {
    let block = Block::default();
    let inner = block.inner(area);
    frame.render_widget(&block, area);

    // Drop the ASCII banner on short terminals so the field stays visible.
    let tall = inner.height >= 22;
    let (banner_height, prompt_height) = if tall { (15, 2) } else { (3, 1) };

    let chunks = Layout::vertical([
        Constraint::Length(banner_height),
        Constraint::Length(prompt_height),
        Constraint::Length(3),
        Constraint::Min(1),
    ])
    .split(inner);

    const TITLE: &str = "
    ▗▄▄▖ ▗▖ ▗▖ ▗▄▄▖▗▄▄▄▖▗▖  ▗▖    ▗▖  ▗▖ ▗▄▖ ▗▖ ▗▖▗▖ ▗▄▄▄▖    
    ▐▌ ▐▌▐▌ ▐▌▐▌     █   ▝▚▞▘     ▐▌  ▐▌▐▌ ▐▌▐▌ ▐▌▐▌   █      
    ▐▛▀▚▖▐▌ ▐▌ ▝▀▚▖  █    ▐▌      ▐▌  ▐▌▐▛▀▜▌▐▌ ▐▌▐▌   █      
    ▐▌ ▐▌▝▚▄▞▘▗▄▄▞▘  █    ▐▌       ▝▚▞▘ ▐▌ ▐▌▝▚▄▞▘▐▙▄▄▖█      
                ";

    if tall {
        frame.render_widget(
            Text::raw(TITLE)
                .alignment(HorizontalAlignment::Center)
                .style(Style::default().fg(Color::Cyan)),
            chunks[0],
        );
    } else {
        frame.render_widget(
            Paragraph::new("RUSTY VAULT")
                .alignment(HorizontalAlignment::Center)
                .style(
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
            chunks[0],
        );
    }

    frame.render_widget(
        Paragraph::new("Enter your master password:")
            .alignment(HorizontalAlignment::Center)
            .style(Style::default().fg(Color::White)),
        chunks[1],
    );

    let field = center_horizontally(chunks[2], 40);
    let focused = app.field == Field::Master;
    render_input_field(
        frame,
        " Master Password ",
        &app.input_master,
        focused,
        field,
        true,
        if focused { Some(app.cursor) } else { None },
    );

    render_message(app, frame, chunks[3], Alignment::Center);
}

fn render_setup(app: &mut App, frame: &mut Frame, area: Rect) {
    let area = center_horizontally(area, CONTENT_MAX_WIDTH);
    let block = Block::default()
        .title(" Create Vault ")
        .title_alignment(HorizontalAlignment::Center)
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
            .alignment(HorizontalAlignment::Center)
            .style(Style::default().fg(Color::White)),
        chunks[0],
    );

    let master_focused = app.field == Field::Master;
    render_input_field(
        frame,
        " Master Password ",
        &app.input_master,
        master_focused,
        chunks[1],
        true,
        if master_focused {
            Some(app.cursor)
        } else {
            None
        },
    );
    let confirm_focused = app.field == Field::MasterConfirm;
    render_input_field(
        frame,
        " Confirm Password ",
        &app.input_master_confirm,
        confirm_focused,
        chunks[2],
        true,
        if confirm_focused {
            Some(app.cursor)
        } else {
            None
        },
    );

    render_message(app, frame, chunks[3], Alignment::Center);
}

fn render_reset_master(app: &mut App, frame: &mut Frame, area: Rect) {
    let area = center_horizontally(area, CONTENT_MAX_WIDTH);
    let block = Block::default()
        .title(" Change Master Password ")
        .title_alignment(HorizontalAlignment::Center)
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
            .alignment(HorizontalAlignment::Center)
            .style(Style::default().fg(Color::White)),
        chunks[0],
    );

    let fields = [
        (
            Field::OldMaster,
            " Current Password ",
            &app.input_old_master,
            chunks[1],
        ),
        (
            Field::NewMaster,
            " New Password ",
            &app.input_new_master,
            chunks[2],
        ),
        (
            Field::NewMasterConfirm,
            " Confirm New Password ",
            &app.input_new_master_confirm,
            chunks[3],
        ),
    ];
    for (field, label, value, chunk) in fields {
        let focused = app.field == field;
        render_input_field(
            frame,
            label,
            value,
            focused,
            chunk,
            true,
            if focused { Some(app.cursor) } else { None },
        );
    }

    render_message(app, frame, chunks[4], Alignment::Center);
}

fn render_list(app: &mut App, frame: &mut Frame, area: Rect) {
    // Show the search box while typing or whenever a filter is active.
    let list_area = if app.searching || !app.search.is_empty() {
        let [search_area, list_area] =
            Layout::vertical([Constraint::Length(3), Constraint::Min(1)]).areas(area);
        let total = match app.tab {
            Tab::Accounts => app.accounts.len(),
            Tab::ApiKeys => app.api_credentials.len(),
        };
        let label = format!(" Search  {}/{}  (Enter/Esc) ", app.visible.len(), total);
        let focused = app.searching;
        render_input_field(
            frame,
            &label,
            &app.search,
            focused,
            search_area,
            false,
            if focused { Some(app.cursor) } else { None },
        );
        list_area
    } else {
        area
    };

    match app.tab {
        Tab::Accounts => render_account_list(app, frame, list_area),
        Tab::ApiKeys => render_api_list(app, frame, list_area),
    }
}

fn render_account_list(app: &mut App, frame: &mut Frame, area: Rect) {
    if app.accounts.is_empty() {
        render_empty_state(frame, area, "No accounts yet. Press `a` to add one.");
        return;
    }
    if app.visible.is_empty() {
        render_empty_state(
            frame,
            area,
            &format!("No accounts match \"{}\".", app.search.trim()),
        );
        return;
    }

    let content_width = list_content_width(area, app.visible.len());
    let items: Vec<ListItem> = app
        .visible
        .iter()
        .filter_map(|&index| app.accounts.get(index))
        .map(|account| {
            let site = truncate_chars(&account.website, content_width);
            let used = site.chars().count() + 2;
            let user = truncate_chars(&account.username, content_width.saturating_sub(used));
            let mut spans = vec![Span::raw(site)];
            if !user.is_empty() {
                spans.push(Span::styled(
                    format!("  {user}"),
                    Style::default().fg(Color::DarkGray),
                ));
            }
            ListItem::new(Line::from(spans))
        })
        .collect();

    render_list_widget(app, frame, area, items);
}

fn render_api_list(app: &mut App, frame: &mut Frame, area: Rect) {
    if app.api_credentials.is_empty() {
        render_empty_state(frame, area, "No API credentials yet. Press `a` to add one.");
        return;
    }
    if app.visible.is_empty() {
        render_empty_state(
            frame,
            area,
            &format!("No API credentials match \"{}\".", app.search.trim()),
        );
        return;
    }

    let content_width = list_content_width(area, app.visible.len());
    let items: Vec<ListItem> = app
        .visible
        .iter()
        .filter_map(|&index| app.api_credentials.get(index))
        .map(|cred| {
            let name = truncate_chars(&cred.name, content_width);
            let mut badges: Vec<&str> = Vec::new();
            if !cred.api_key.is_empty() {
                badges.push("key");
            }
            if !cred.client_id.is_empty() {
                badges.push("id");
            }
            if !cred.client_secret.is_empty() {
                badges.push("secret");
            }
            let mut spans = vec![Span::raw(name.clone())];
            if !badges.is_empty() {
                let badge_text = truncate_chars(
                    &format!("  {}", badges.join(" · ")),
                    content_width.saturating_sub(name.chars().count()),
                );
                spans.push(Span::styled(
                    badge_text,
                    Style::default().fg(Color::DarkGray),
                ));
            }
            ListItem::new(Line::from(spans))
        })
        .collect();

    render_list_widget(app, frame, area, items);
}

fn render_empty_state(frame: &mut Frame, area: Rect, text: &str) {
    frame.render_widget(
        Paragraph::new(text)
            .alignment(HorizontalAlignment::Center)
            .style(Style::default().fg(Color::DarkGray)),
        area,
    );
}

fn render_list_widget(app: &App, frame: &mut Frame, area: Rect, items: Vec<ListItem>) {
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

    if app.visible.len() > area.height as usize {
        let mut scrollbar_state = ScrollbarState::new(app.visible.len()).position(app.selected);
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None)
            .style(Style::default().fg(Color::DarkGray));
        frame.render_stateful_widget(scrollbar, area, &mut scrollbar_state);
    }
}

/// Usable text width inside a list row: the highlight symbol plus a column
/// reserved for the scrollbar when one is shown.
fn list_content_width(area: Rect, total: usize) -> usize {
    let scrollbar = total > area.height as usize;
    area.width.saturating_sub(2 + u16::from(scrollbar)) as usize
}

fn render_view(app: &mut App, frame: &mut Frame, area: Rect) {
    match app.tab {
        Tab::Accounts => render_account_view(app, frame, area),
        Tab::ApiKeys => render_api_view(app, frame, area),
    }
}

fn render_account_view(app: &mut App, frame: &mut Frame, area: Rect) {
    let Some(account) = app.accounts.get(app.selected).cloned() else {
        render_empty_state(frame, area, "No account selected.");
        return;
    };

    let area = center_horizontally(area, CONTENT_MAX_WIDTH);
    let block = Block::default()
        .title(" Account Details ")
        .title_alignment(HorizontalAlignment::Center)
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

    render_display_field(frame, " Website ", &account.website, chunks[0]);
    render_display_field(frame, " Username ", &account.username, chunks[1]);
    match &app.revealed {
        Revealed::AccountPassword(password) => render_display_field_styled(
            frame,
            " Password (revealed) ",
            password,
            chunks[2],
            revealed_style(),
        ),
        _ => render_display_field_styled(
            frame,
            " Password (hidden) ",
            HIDDEN_SECRET,
            chunks[2],
            hidden_style(),
        ),
    }
}

fn render_api_view(app: &mut App, frame: &mut Frame, area: Rect) {
    let Some(cred) = app.api_credentials.get(app.selected).cloned() else {
        render_empty_state(frame, area, "No credential selected.");
        return;
    };

    let area = center_horizontally(area, CONTENT_MAX_WIDTH);
    let block = Block::default()
        .title(" API Credential Details ")
        .title_alignment(HorizontalAlignment::Center)
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

    render_display_field(frame, " Name ", &cred.name, chunks[0]);
    render_secret_display(
        frame,
        " API Key ",
        &cred.api_key,
        matches!(&app.revealed, Revealed::Api { .. }),
        chunks[1],
    );
    render_display_field(frame, " Client ID ", &cred.client_id, chunks[2]);
    render_secret_display(
        frame,
        " Client Secret ",
        &cred.client_secret,
        matches!(&app.revealed, Revealed::Api { .. }),
        chunks[3],
    );
}

/// Secret value in the detail view: revealed value in yellow, otherwise a
/// fixed-width mask. Empty optional fields show `(not set)`.
fn render_secret_display(
    frame: &mut Frame,
    label: &str,
    value: &str,
    reveal_all: bool,
    area: Rect,
) {
    if value.is_empty() {
        let text = format!("{label}(not set) ");
        render_display_field_styled(frame, &text, "", area, hidden_style());
        return;
    }
    if reveal_all {
        let revealed = format!("{label}(revealed) ");
        render_display_field_styled(frame, &revealed, value, area, revealed_style());
    } else {
        let hidden = format!("{label}(hidden) ");
        render_display_field_styled(frame, &hidden, HIDDEN_SECRET, area, hidden_style());
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

    let area = center_horizontally(area, CONTENT_MAX_WIDTH);
    let block = Block::default()
        .title(title)
        .title_alignment(HorizontalAlignment::Center)
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

    for (field, label, value, mask, chunk) in [
        (
            Field::Website,
            " Website ",
            app.input_website.as_str(),
            false,
            chunks[0],
        ),
        (
            Field::Username,
            " Username ",
            app.input_username.as_str(),
            false,
            chunks[1],
        ),
        (
            Field::Password,
            " Password ",
            app.input_password.as_str(),
            true,
            chunks[2],
        ),
    ] {
        let focused = app.field == field;
        render_input_field(
            frame,
            label,
            value,
            focused,
            chunk,
            mask,
            if focused { Some(app.cursor) } else { None },
        );
    }

    render_message(app, frame, chunks[3], Alignment::Left);
}

fn render_api_form(app: &mut App, frame: &mut Frame, area: Rect) {
    let title = match app.mode {
        Mode::Add => " Add API Credential ",
        Mode::Edit => " Edit API Credential ",
        _ => " API Credential ",
    };

    let area = center_horizontally(area, CONTENT_MAX_WIDTH);
    let block = Block::default()
        .title(title)
        .title_alignment(HorizontalAlignment::Center)
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

    for (field, label, value, mask, chunk) in [
        (
            Field::Name,
            " Name (required) ",
            app.input_name.as_str(),
            false,
            chunks[0],
        ),
        (
            Field::ApiKey,
            " API Key (optional) ",
            app.input_api_key.as_str(),
            true,
            chunks[1],
        ),
        (
            Field::ClientId,
            " Client ID (optional) ",
            app.input_client_id.as_str(),
            false,
            chunks[2],
        ),
        (
            Field::ClientSecret,
            " Client Secret (optional) ",
            app.input_client_secret.as_str(),
            true,
            chunks[3],
        ),
    ] {
        let focused = app.field == field;
        render_input_field(
            frame,
            label,
            value,
            focused,
            chunk,
            mask,
            if focused { Some(app.cursor) } else { None },
        );
    }

    render_message(app, frame, chunks[4], Alignment::Left);
}

fn center_horizontally(area: Rect, width: u16) -> Rect {
    let width = width.min(area.width);
    let x = area.x + (area.width - width) / 2;
    Rect {
        x,
        y: area.y,
        width,
        height: area.height,
    }
}

fn revealed_style() -> Style {
    Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD)
}

fn hidden_style() -> Style {
    Style::default().fg(Color::DarkGray)
}

/// Options for rendering a field box.
struct FieldOptions {
    focused: bool,
    mask: bool,
    value_style: Style,
    caret: Option<usize>,
}

impl FieldOptions {
    fn input(focused: bool, mask: bool, caret: Option<usize>) -> Self {
        Self {
            focused,
            mask,
            value_style: Style::default().fg(Color::White),
            caret,
        }
    }

    fn display(value_style: Style) -> Self {
        Self {
            focused: false,
            mask: false,
            value_style,
            caret: None,
        }
    }
}

fn render_display_field(frame: &mut Frame, label: &str, value: &str, area: Rect) {
    render_display_field_styled(frame, label, value, area, Style::default().fg(Color::White));
}

fn render_display_field_styled(
    frame: &mut Frame,
    label: &str,
    value: &str,
    area: Rect,
    value_style: Style,
) {
    render_field_inner(
        frame,
        label,
        value,
        area,
        FieldOptions::display(value_style),
    );
}

/// Editable field with the terminal caret drawn at `caret` (char index) and
/// horizontal scrolling so the caret stays visible in long values.
fn render_input_field(
    frame: &mut Frame,
    label: &str,
    value: &str,
    focused: bool,
    area: Rect,
    mask: bool,
    caret: Option<usize>,
) {
    render_field_inner(
        frame,
        label,
        value,
        area,
        FieldOptions::input(focused, mask, caret),
    );
}

fn render_field_inner(
    frame: &mut Frame,
    label: &str,
    value: &str,
    area: Rect,
    options: FieldOptions,
) {
    let FieldOptions {
        focused,
        mask,
        value_style,
        caret,
    } = options;
    let border_style = if focused {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let block = Block::default()
        .title(label)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(border_style);

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let masked = if mask {
        "•".repeat(value.chars().count().min(128))
    } else {
        String::new()
    };
    let text = if mask { masked.as_str() } else { value };
    let char_count = text.chars().count();

    // Horizontal scroll keeps the caret in view while editing.
    let caret_column = caret.map(|caret| caret.min(char_count));
    let scroll = match caret_column {
        Some(column) => column.saturating_sub(inner.width as usize - 1),
        None => 0,
    };

    let visible: String = if scroll > 0 {
        text.chars().skip(scroll).collect()
    } else if caret.is_none() && char_count > inner.width as usize {
        truncate_chars(text, inner.width as usize)
    } else {
        text.to_string()
    };

    frame.render_widget(Paragraph::new(visible).style(value_style), inner);

    if let Some(column) = caret_column {
        let x = inner.x + (column - scroll) as u16;
        if x < inner.x + inner.width {
            frame.set_cursor_position(Position { x, y: inner.y });
        }
    }
}

fn render_message(app: &App, frame: &mut Frame, area: Rect, alignment: Alignment) {
    if let Some((text, kind)) = app.visible_message() {
        frame.render_widget(
            Paragraph::new(text)
                .style(message_style(kind))
                .alignment(alignment),
            area,
        );
    }
}

fn message_style(kind: MessageKind) -> Style {
    let color = match kind {
        MessageKind::Info => Color::Yellow,
        MessageKind::Success => Color::Green,
        MessageKind::Error => Color::Red,
    };
    Style::default().fg(color)
}

fn render_keybinds_panel(app: &mut App, frame: &mut Frame, area: Rect) {
    let (title, lines): (&str, Vec<Line>) = if app.mode == Mode::ConfirmDelete {
        (
            " Confirm Delete ",
            vec![
                keybind_line("y", "delete"),
                keybind_line("n/Esc", "cancel"),
                keybind_line("Enter", "cancel (safe)"),
            ],
        )
    } else {
        match app.tab {
            Tab::Accounts => (
                " Keybinds — Accounts ",
                vec![
                    keybind_line("↑/↓  k/j", "navigate"),
                    keybind_line("Enter/v", "view details"),
                    keybind_line("/", "search"),
                    keybind_line("a", "add account"),
                    keybind_line("e", "edit account"),
                    keybind_line("d", "delete (confirm)"),
                    keybind_line("y", "copy password"),
                    keybind_line("u", "copy username"),
                    keybind_line("Tab", "switch to API Keys"),
                    keybind_line("p", "change master pw"),
                    keybind_line("Ctrl+L", "lock vault"),
                    keybind_line("q/Esc", "quit"),
                ],
            ),
            Tab::ApiKeys => (
                " Keybinds — API Keys ",
                vec![
                    keybind_line("↑/↓  k/j", "navigate"),
                    keybind_line("Enter/v", "view details"),
                    keybind_line("/", "search"),
                    keybind_line("a", "add credential"),
                    keybind_line("e", "edit credential"),
                    keybind_line("d", "delete (confirm)"),
                    keybind_line("1", "copy api key"),
                    keybind_line("2", "copy client id"),
                    keybind_line("3", "copy client secret"),
                    keybind_line("Tab", "switch to Accounts"),
                    keybind_line("p", "change master pw"),
                    keybind_line("Ctrl+L", "lock vault"),
                    keybind_line("q/Esc", "quit"),
                ],
            ),
        }
    };

    // Size the panel to hug its content (line widths + top/bottom borders)
    // and center it within the allotted area.
    let content_height = lines.len() as u16 + 2;
    let content_width = lines.iter().map(|l| l.width() as u16).max().unwrap_or(0) + 2;
    let panel = Rect {
        x: area.x + (area.width.saturating_sub(content_width)),
        y: area.y,
        width: content_width.min(area.width),
        height: content_height.min(area.height),
    };

    let block = Block::default()
        .title(title)
        .title_alignment(HorizontalAlignment::Center)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Cyan).bold());

    let inner = block.inner(panel);
    frame.render_widget(&block, panel);

    let help = Text::from(lines).style(hidden_style());
    frame.render_widget(Paragraph::new(help).alignment(Alignment::Left), inner);
}

/// Build a single keybind line: the keys in a brighter color, the
/// description in the base style.
fn keybind_line(keys: &str, desc: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{keys:<10}"),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(desc.to_string()),
    ])
}

fn render_footer(app: &mut App, frame: &mut Frame, area: Rect) {
    let hint = footer_hint(app, area.width);
    let hint_area = Rect { height: 1, ..area };
    frame.render_widget(
        Paragraph::new(Text::from(hint).style(hidden_style()))
            .alignment(HorizontalAlignment::Center),
        hint_area,
    );

    // The second footer row shows the transient status message for modes
    // that do not render it inline.
    if matches!(app.mode, Mode::List | Mode::View | Mode::ConfirmDelete) {
        let message_area = Rect {
            y: area.y + 1,
            height: 1,
            ..area
        };
        render_message(app, frame, message_area, Alignment::Center);
    }
}

fn footer_hint(app: &App, width: u16) -> &'static str {
    match app.mode {
        Mode::Unlock => "[Enter] unlock   [Esc/Ctrl+C] quit",
        Mode::Setup => "[Tab] next field   [Enter] create   [Esc] quit",
        Mode::View => match app.tab {
            Tab::Accounts => {
                "[r] reveal  [c] copy pw  [u] copy user  [e] edit  [d] delete  [↑/↓] nav  [Esc] back"
            }
            Tab::ApiKeys => {
                "[r] reveal  [1] copy key  [2] copy id  [3] copy secret  [e] edit  [d] delete  [↑/↓] nav  [Esc] back"
            }
        },
        Mode::Add | Mode::Edit => {
            "[Tab] next   [Ctrl+G] generate   [Ctrl+U] clear   [Enter] save   [Esc] cancel"
        }
        Mode::ResetMaster => "[Tab] next field   [Enter] change   [Esc] cancel",
        Mode::ConfirmDelete => "[y] delete   [n/Esc/Enter] cancel",
        Mode::List if app.searching => "[type] filter   [Enter] keep filter   [Esc] clear",
        Mode::List if width < KEYBINDS_PANEL_MIN_WIDTH => {
            "[↑↓/jk] nav  [Enter] view  [/] search  [a] add  [e] edit  [d] del  [Tab] switch  [q] quit"
        }
        Mode::List => "",
    }
}

/// Centered confirmation dialog drawn over the list.
fn render_confirm_delete(app: &mut App, frame: &mut Frame, area: Rect) {
    let Some(pending) = &app.pending_delete else {
        return;
    };
    let kind = match pending.tab {
        Tab::Accounts => "account",
        Tab::ApiKeys => "API credential",
    };
    let text = Text::from(vec![
        Line::from(format!("Delete {kind} \"{}\"?", pending.label)),
        Line::from(""),
        Line::from("This cannot be undone."),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "[ y ] Delete",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::raw("         "),
            Span::styled("[ n ] Cancel", Style::default().fg(Color::Cyan)),
        ]),
    ]);

    let popup = centered_popup(area, 56, 9);
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .title(" Confirm Delete ")
        .title_alignment(HorizontalAlignment::Center)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD));
    frame.render_widget(
        Paragraph::new(text)
            .block(block)
            .alignment(HorizontalAlignment::Center),
        popup,
    );
}

fn centered_popup(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    }
}

/// Truncate to `max_chars`, appending an ellipsis when text is dropped.
fn truncate_chars(text: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let mut truncated: String = text.chars().take(max_chars.saturating_sub(1)).collect();
    truncated.push('…');
    truncated
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::cli::{Action, Cli};
    use crate::update::update;
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::{Terminal, backend::TestBackend};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_vault_dir(label: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "rusty-vault-ui-test-{}-{n}-{label}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Unlocked app with one account, created through the real setup path.
    fn test_app(label: &str) -> (PathBuf, App) {
        let dir = temp_vault_dir(label);
        let cli = Cli {
            db_path: dir.join("vault.db"),
            idle_lock: None,
            action: Action::Run,
        };
        let mut app = App::new(&cli).unwrap();
        app.input_master = "master-pass".to_string();
        app.input_master_confirm = "master-pass".to_string();
        app.submit_setup();
        app.start_add();
        app.input_website = "example.com".to_string();
        app.input_username = "alice".to_string();
        app.input_password = "pw".to_string();
        app.save_form();
        (dir, app)
    }

    /// Draw once and return the rendered screen plus the caret position.
    fn draw_with_cursor(app: &mut App, width: u16, height: u16) -> (String, Position) {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| render(app, frame)).unwrap();
        let buffer = terminal.backend().buffer();
        let mut out = String::new();
        for y in 0..height {
            for x in 0..width {
                out.push_str(buffer.content()[y as usize * width as usize + x as usize].symbol());
            }
            out.push('\n');
        }
        (out, terminal.backend().cursor_position())
    }

    fn draw(app: &mut App, width: u16, height: u16) -> String {
        draw_with_cursor(app, width, height).0
    }

    #[test]
    fn renders_every_mode_without_panicking() {
        let (dir, mut app) = test_app("modes");

        // List and search input.
        let list = draw(&mut app, 100, 30);
        assert!(list.contains("example.com"));
        app.start_search();
        app.search_push('e');
        let filtered = draw(&mut app, 100, 30);
        assert!(filtered.contains("Search"));
        app.submit_search();
        draw(&mut app, 100, 30);
        app.cancel_search();

        // Detail view, hidden and revealed.
        app.start_view();
        let hidden = draw(&mut app, 100, 30);
        assert!(hidden.contains("Account Details"));
        assert!(hidden.contains(HIDDEN_SECRET));
        app.toggle_reveal();
        let revealed = draw(&mut app, 100, 30);
        assert!(revealed.contains("(revealed)"));
        app.close_view();

        // Forms and the generator.
        app.start_add();
        app.generate_secret();
        draw(&mut app, 100, 30);
        app.cancel_form();
        app.start_edit();
        draw(&mut app, 100, 30);
        app.cancel_form();
        app.start_reset_master();
        draw(&mut app, 100, 30);
        app.cancel_reset_master();

        // Delete confirmation popup.
        app.request_delete();
        assert_eq!(app.mode, Mode::ConfirmDelete);
        let confirm = draw(&mut app, 100, 30);
        assert!(confirm.contains("Confirm Delete"));
        assert!(confirm.contains("[ y ] Delete"));
        assert!(confirm.contains("[ n ] Cancel"));
        app.cancel_delete();

        // Locked screen.
        app.lock();
        draw(&mut app, 100, 30);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn renders_small_terminal_without_panicking() {
        let (dir, mut app) = test_app("narrow");
        let screen = draw(&mut app, 40, 12);
        assert!(screen.contains("too small"));
        app.start_search();
        app.search_push('x');
        draw(&mut app, 40, 12);
        app.submit_search();
        app.start_view();
        draw(&mut app, 40, 12);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn narrow_list_uses_compact_footer_instead_of_side_panel() {
        let (dir, mut app) = test_app("compact");
        let wide = draw(&mut app, 100, 24);
        assert!(wide.contains("Keybinds"));
        let narrow = draw(&mut app, 70, 20);
        assert!(!narrow.contains("Keybinds"));
        assert!(narrow.contains("nav"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn long_list_values_are_truncated_with_ellipsis() {
        let (dir, mut app) = test_app("truncate");
        app.start_add();
        app.input_website = "a".repeat(90);
        app.input_username = "someone-with-a-long-username".to_string();
        app.input_password = "pw".to_string();
        app.save_form();

        let narrow = draw(&mut app, 60, 20);
        assert!(narrow.contains('…'), "expected an ellipsis in:\n{narrow}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tab_labels_show_entry_counts() {
        let (dir, mut app) = test_app("counts");
        let list = draw(&mut app, 100, 24);
        assert!(list.contains("Accounts (1)"));
        assert!(list.contains("API Keys (0)"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn caret_advances_with_typing_in_focused_field() {
        let (dir, mut app) = test_app("caret");
        app.start_add();
        app.field = Field::Website;

        let (_, start) = draw_with_cursor(&mut app, 100, 30);
        app.input_insert('x');
        let (_, after_one) = draw_with_cursor(&mut app, 100, 30);
        app.input_insert('y');
        let (_, after_two) = draw_with_cursor(&mut app, 100, 30);

        assert_eq!(after_one.x, start.x + 1);
        assert_eq!(after_two.x, start.x + 2);
        assert_eq!(after_two.y, start.y);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn caret_is_kept_visible_in_long_values() {
        let (dir, mut app) = test_app("caret-scroll");
        app.start_add();
        app.field = Field::Website;
        for _ in 0..200 {
            app.input_insert('x');
        }
        let (screen, cursor) = draw_with_cursor(&mut app, 100, 30);
        assert!(cursor.x < 100, "caret must stay inside the terminal");
        assert!(screen.contains('x'));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn truncate_chars_appends_ellipsis() {
        assert_eq!(truncate_chars("hello", 5), "hello");
        assert_eq!(truncate_chars("hello", 4), "hel…");
        assert_eq!(truncate_chars("hello", 0), "");
    }

    /// End-to-end check of the real key path: pressing `d` in the list must
    /// open the confirmation dialog, not delete.
    #[test]
    fn pressing_d_opens_the_confirm_dialog() {
        let (dir, mut app) = test_app("confirm-key");
        let before = app.accounts.len();
        update(
            &mut app,
            KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE),
        );
        assert_eq!(app.mode, Mode::ConfirmDelete);
        assert_eq!(app.accounts.len(), before, "`d` must not delete directly");

        let screen = draw(&mut app, 100, 30);
        assert!(screen.contains("Confirm Delete"));
        assert!(screen.contains("[ y ] Delete"));
        assert!(screen.contains("[ n ] Cancel"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
