use std::{
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use color_eyre::Result;
use ratatui::crossterm::event::{self, Event as CrosstermEvent, KeyEvent, MouseEvent};

#[derive(Clone, Debug)]
pub enum Event {
    Tick,
    Key(KeyEvent),
    Mouse(MouseEvent),
    Resize(u16, u16),
    /// The terminal event source failed; the UI should shut down cleanly.
    Error(String),
}

#[derive(Debug)]
pub struct EventHandler {
    #[allow(dead_code)]
    sender: mpsc::Sender<Event>,
    receiver: mpsc::Receiver<Event>,
    #[allow(dead_code)]
    handler: thread::JoinHandle<()>,
}

impl EventHandler {
    pub fn new(tick_rate: u64) -> Self {
        let tick_rate = Duration::from_millis(tick_rate);
        let (sender, receiver) = mpsc::channel();
        let handler = {
            let sender = sender.clone();
            thread::spawn(move || {
                let mut last_tick = Instant::now();
                loop {
                    let timeout = tick_rate
                        .checked_sub(last_tick.elapsed())
                        .unwrap_or(tick_rate);

                    match event::poll(timeout) {
                        Ok(true) => match event::read() {
                            Ok(CrosstermEvent::Key(e)) => {
                                if e.kind == event::KeyEventKind::Press
                                    && sender.send(Event::Key(e)).is_err()
                                {
                                    break;
                                }
                            }
                            Ok(CrosstermEvent::Mouse(e)) => {
                                if sender.send(Event::Mouse(e)).is_err() {
                                    break;
                                }
                            }
                            Ok(CrosstermEvent::Resize(w, h)) => {
                                if sender.send(Event::Resize(w, h)).is_err() {
                                    break;
                                }
                            }
                            // Focus/paste events are not used by this app.
                            Ok(_) => {}
                            Err(e) => {
                                let _ = sender.send(Event::Error(e.to_string()));
                                break;
                            }
                        },
                        Ok(false) => {}
                        Err(e) => {
                            let _ = sender.send(Event::Error(e.to_string()));
                            break;
                        }
                    }

                    if last_tick.elapsed() >= tick_rate {
                        if sender.send(Event::Tick).is_err() {
                            break;
                        }
                        last_tick = Instant::now();
                    }
                }
            })
        };
        Self {
            sender,
            receiver,
            handler,
        }
    }

    pub fn next(&self) -> Result<Event> {
        Ok(self.receiver.recv()?)
    }
}
