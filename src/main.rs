/// Application
pub mod app;

/// Command-line argument and environment parsing.
pub mod cli;

/// Database access.
pub mod db;

/// Encryption helpers.
pub mod crypto;

/// Terminal events handler.
pub mod event;

/// Password generation.
pub mod password;

/// Widget renderer.
pub mod ui;

/// Terminal user interface.
pub mod tui;

/// Application updater.
pub mod update;

use std::env;

use color_eyre::Result;
use ratatui::{Terminal, backend::CrosstermBackend};

use app::App;
use cli::Action;
use event::{Event, EventHandler};
use tui::Tui;
use update::update;

fn main() -> Result<()> {
    let cli = cli::parse(env::args().skip(1), cli::Env::from_process())?;
    match cli.action {
        Action::Help => {
            print!("{}", cli::USAGE);
            return Ok(());
        }
        Action::Version => {
            println!("rusty-vault {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        Action::Run => {}
    }

    let mut app = App::new(&cli)?;

    let backend = CrosstermBackend::new(std::io::stderr());
    let terminal = Terminal::new(backend)?;
    let events = EventHandler::new(250);
    let mut tui = Tui::new(terminal, events);
    tui.enter()?;

    while !app.should_quit {
        tui.draw(&mut app)?;
        match tui.events.next()? {
            Event::Tick => app.tick(),
            Event::Key(key_event) => update(&mut app, key_event),
            Event::Mouse(_) => {}
            Event::Resize(_, _) => {}
            Event::Error(message) => color_eyre::eyre::bail!("terminal event error: {message}"),
        };
    }

    tui.exit()?;
    Ok(())
}
