use crate::config::Config;
use crate::processor;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::backend::Backend;
use ratatui::Terminal;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{interval, sleep, Duration};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Tab {
    Text,
    File,
    Benchmark,
    Snake,
}

impl Tab {
    pub fn next(&self) -> Self {
        match self {
            Tab::Text => Tab::File,
            Tab::File => Tab::Benchmark,
            Tab::Benchmark => Tab::Snake,
            Tab::Snake => Tab::Text,
        }
    }

    pub fn prev(&self) -> Self {
        match self {
            Tab::Text => Tab::Snake,
            Tab::File => Tab::Text,
            Tab::Benchmark => Tab::File,
            Tab::Snake => Tab::Benchmark,
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Tab::Text => "Text",
            Tab::File => "File",
            Tab::Benchmark => "Benchmark",
            Tab::Snake => "Snake",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InputMode {
    Normal,
    Editing,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ProcessingState {
    Idle,
    Computing,
    Complete,
    Error(String),
}

use chrono::{DateTime, Local};
use ratatui::widgets::ListState;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Direction {
    Up,
    Down,
    Left,
    Right,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Position {
    pub x: i16,
    pub y: i16,
}

pub struct SnakeGame {
    pub snake: Vec<Position>,
    pub direction: Direction,
    pub food: Position,
    pub score: u32,
    pub game_over: bool,
    pub started: bool,
    pub width: i16,
    pub height: i16,
    pub food_emoji: String,
}

const FOOD_EMOJIS: &[&str] = &["🍔", "🥕", "🍟", "🍉", "🍎", "🍏", "🍑", "🥦", "🍕", "🍪"];

impl SnakeGame {
    pub fn new(width: i16, height: i16) -> Self {
        let start_x = width / 2;
        let start_y = height / 2;
        Self {
            snake: vec![Position {
                x: start_x,
                y: start_y,
            }],
            direction: Direction::Right,
            food: Position {
                x: start_x + 5,
                y: start_y,
            },
            score: 0,
            game_over: false,
            started: false,
            width,
            height,
            food_emoji: "🍎".to_string(),
        }
    }

    pub fn reset(&mut self) {
        let start_x = self.width / 2;
        let start_y = self.height / 2;
        self.snake = vec![Position {
            x: start_x,
            y: start_y,
        }];
        self.direction = Direction::Right;
        self.food = Position {
            x: start_x + 5,
            y: start_y,
        };
        self.score = 0;
        self.game_over = false;
        self.started = false;
        self.spawn_food(); // Reset food and emoji
    }

    pub fn move_snake(&mut self) {
        if self.game_over || !self.started {
            return;
        }

        let head = self.snake[0];
        let new_head = match self.direction {
            Direction::Up => Position {
                x: head.x,
                y: head.y - 1,
            },
            Direction::Down => Position {
                x: head.x,
                y: head.y + 1,
            },
            Direction::Left => Position {
                x: head.x - 1,
                y: head.y,
            },
            Direction::Right => Position {
                x: head.x + 1,
                y: head.y,
            },
        };

        // Wall wrapping
        let new_head = Position {
            x: (new_head.x + self.width) % self.width,
            y: (new_head.y + self.height) % self.height,
        };

        // Check self collision
        if self.snake.contains(&new_head) {
            self.game_over = true;
            return;
        }

        self.snake.insert(0, new_head);

        // Check food collision
        if new_head == self.food {
            self.score += 10;
            self.spawn_food();
        } else {
            self.snake.pop();
        }
    }

    fn spawn_food(&mut self) {
        use rand::Rng;
        let mut rng = rand::rng();
        loop {
            let food = Position {
                x: rng.random_range(0..self.width),
                y: rng.random_range(0..self.height),
            };
            if !self.snake.contains(&food) {
                self.food = food;
                self.food_emoji = FOOD_EMOJIS[rng.random_range(0..FOOD_EMOJIS.len())].to_string();
                break;
            }
        }
    }

    pub fn set_direction(&mut self, new_direction: Direction) {
        // Prevent reversing direction
        let valid = !matches!(
            (self.direction, new_direction),
            (Direction::Up, Direction::Down)
                | (Direction::Down, Direction::Up)
                | (Direction::Left, Direction::Right)
                | (Direction::Right, Direction::Left)
        );

        if valid {
            self.direction = new_direction;
        }
    }
}

pub struct App {
    pub current_tab: Tab,
    pub text_input: String,
    pub file_input: String,
    pub input_mode: InputMode,
    pub messages: Vec<(DateTime<Local>, String)>,
    pub config: Config,
    pub processing_state: ProcessingState,
    pub spinner_frame: usize,
    pub benchmark_result: Option<BenchmarkResult>,
    pub latest_text_checksum: Option<String>,
    pub latest_file_checksum: Option<String>,
    pub snake_game: SnakeGame,
    // File browser state
    pub current_dir: PathBuf,
    pub dir_entries: Vec<PathBuf>,
    pub dir_state: ListState,
}

#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    pub throughput_mbps: f64,
    pub duration_ms: u64,
    pub score: u64,
    pub rating: String,
}

impl App {
    pub fn new(config: Config) -> App {
        let current_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let mut app = App {
            current_tab: Tab::Text,
            text_input: String::new(),
            file_input: String::new(),
            input_mode: InputMode::Normal,
            messages: Vec::new(),
            config,
            processing_state: ProcessingState::Idle,
            spinner_frame: 0,
            benchmark_result: None,
            latest_text_checksum: None,
            latest_file_checksum: None,
            snake_game: SnakeGame::new(30, 20), // Width 30 * 2 chars = 60 chars wide
            current_dir,
            dir_entries: Vec::new(),
            dir_state: ListState::default(),
        };
        app.read_dir();
        app
    }

    // Helper methods to get/set input based on current tab
    pub fn current_input(&self) -> &str {
        match self.current_tab {
            Tab::Text => &self.text_input,
            Tab::File => &self.file_input,
            _ => "",
        }
    }

    pub fn current_input_mut(&mut self) -> &mut String {
        match self.current_tab {
            Tab::Text => &mut self.text_input,
            Tab::File => &mut self.file_input,
            _ => &mut self.text_input, // fallback, won't be used
        }
    }

    pub fn read_dir(&mut self) {
        self.dir_entries.clear();
        if let Ok(entries) = std::fs::read_dir(&self.current_dir) {
            for entry in entries.flatten() {
                self.dir_entries.push(entry.path());
            }
        }
        // Sort: directories first, then files
        self.dir_entries.sort_by(|a, b| {
            let a_is_dir = a.is_dir();
            let b_is_dir = b.is_dir();
            if a_is_dir && !b_is_dir {
                std::cmp::Ordering::Less
            } else if !a_is_dir && b_is_dir {
                std::cmp::Ordering::Greater
            } else {
                a.file_name().cmp(&b.file_name())
            }
        });
        self.dir_state.select(Some(0));
    }

    pub fn next_file(&mut self) {
        let i = match self.dir_state.selected() {
            Some(i) => {
                if i >= self.dir_entries.len().saturating_sub(1) {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.dir_state.select(Some(i));
    }

    pub fn previous_file(&mut self) {
        let i = match self.dir_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.dir_entries.len().saturating_sub(1)
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.dir_state.select(Some(i));
    }

    pub fn next_page(&mut self) {
        let i = match self.dir_state.selected() {
            Some(i) => {
                let len = self.dir_entries.len();
                if len == 0 {
                    0
                } else {
                    // Jump 10 items or to end
                    (i + 10).min(len - 1)
                }
            }
            None => 0,
        };
        self.dir_state.select(Some(i));
    }

    pub fn previous_page(&mut self) {
        let i = match self.dir_state.selected() {
            Some(i) => {
                // Jump 10 items back or to start
                i.saturating_sub(10)
            }
            None => 0,
        };
        self.dir_state.select(Some(i));
    }

    pub fn go_to_top(&mut self) {
        if !self.dir_entries.is_empty() {
            self.dir_state.select(Some(0));
        }
    }

    pub fn go_to_bottom(&mut self) {
        if !self.dir_entries.is_empty() {
            self.dir_state.select(Some(self.dir_entries.len() - 1));
        }
    }

    pub fn enter_dir(&mut self) {
        if let Some(selected) = self.dir_state.selected() {
            if let Some(path) = self.dir_entries.get(selected) {
                if path.is_dir() {
                    self.current_dir = path.clone();
                    self.read_dir();
                    self.file_input.clear(); // Clear file input when changing directory
                } else {
                    // Select file
                    self.file_input = path.to_string_lossy().to_string();
                }
            }
        }
    }

    pub fn go_to_parent(&mut self) {
        if let Some(parent) = self.current_dir.parent() {
            self.current_dir = parent.to_path_buf();
            self.read_dir();
            self.file_input.clear();
        }
    }

    pub fn update_spinner(&mut self) {
        self.spinner_frame = (self.spinner_frame + 1) % 10;
    }

    pub fn get_spinner_char(&self) -> char {
        const SPINNER_CHARS: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
        SPINNER_CHARS[self.spinner_frame]
    }

    pub async fn run<B: Backend>(&mut self, terminal: &mut Terminal<B>) -> io::Result<()> {
        let (tx, mut rx) = mpsc::channel::<AppMessage>(32);

        // Spawn spinner update task
        let spinner_tx = tx.clone();
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_millis(80));
            loop {
                interval.tick().await;
                if spinner_tx.send(AppMessage::UpdateSpinner).await.is_err() {
                    break;
                }
            }
        });

        // Spawn snake game update task
        let snake_tx = tx.clone();
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_millis(100));
            loop {
                interval.tick().await;
                if snake_tx.send(AppMessage::SnakeTick).await.is_err() {
                    break;
                }
            }
        });

        // Shared flag to signal input thread to stop
        let running = Arc::new(AtomicBool::new(true));
        let input_running = running.clone();

        // Spawn input handling task
        let input_tx = tx.clone();
        tokio::task::spawn_blocking(move || {
            loop {
                // Check if we should stop
                if !input_running.load(Ordering::Relaxed) {
                    break;
                }

                // Poll for events with a timeout to allow checking the flag
                if event::poll(Duration::from_millis(100)).unwrap_or(false) {
                    if let Ok(Event::Key(key)) = event::read() {
                        if key.kind == KeyEventKind::Press
                            && input_tx.blocking_send(AppMessage::Input(key)).is_err()
                        {
                            break;
                        }
                    }
                }
            }
        });

        loop {
            terminal.draw(|f| super::ui::ui(f, self))?;

            if let Some(msg) = rx.recv().await {
                match msg {
                    AppMessage::Input(key) => {
                        self.handle_key_event(key.code, key.modifiers, tx.clone())
                            .await;
                    }
                    AppMessage::UpdateSpinner => {
                        if self.processing_state == ProcessingState::Computing {
                            self.update_spinner();
                        }
                    }
                    AppMessage::ComputationComplete(result) => {
                        self.processing_state = ProcessingState::Complete;
                        // Extract just the hash from "Hash:  <hash>" format and store in appropriate field
                        if let Some(hash) = result.strip_prefix("Hash:  ") {
                            match self.current_tab {
                                Tab::Text => self.latest_text_checksum = Some(hash.to_string()),
                                Tab::File => self.latest_file_checksum = Some(hash.to_string()),
                                _ => {}
                            }
                        }
                        // Log to stderr for saving (TUI uses stdout)
                        eprintln!("{}", result);
                        self.messages.push((Local::now(), result));
                    }
                    AppMessage::ComputationError(err) => {
                        self.processing_state = ProcessingState::Error(err.clone());
                        let error_msg = format!("Error: {}", err);
                        eprintln!("{}", error_msg);
                        self.messages.push((Local::now(), error_msg));
                    }
                    AppMessage::BenchmarkComplete(result) => {
                        self.processing_state = ProcessingState::Complete;
                        self.benchmark_result = Some(result);
                    }
                    AppMessage::SnakeTick => {
                        if self.current_tab == Tab::Snake {
                            self.snake_game.move_snake();
                        }
                    }
                }
            }

            if self.input_mode == InputMode::Normal
                && self.messages.iter().any(|(_, m)| m == "quit")
            {
                break;
            }
        }

        running.store(false, Ordering::Relaxed);
        Ok(())
    }

    async fn handle_key_event(
        &mut self,
        code: KeyCode,
        _modifiers: KeyModifiers,
        tx: mpsc::Sender<AppMessage>,
    ) {
        match self.input_mode {
            InputMode::Normal => match code {
                KeyCode::Char('q') => {
                    self.messages.push((Local::now(), "quit".to_string()));
                }
                KeyCode::Char('e') => {
                    self.input_mode = InputMode::Editing;
                    // Don't clear input if we selected a file
                }
                KeyCode::Tab => {
                    self.current_tab = self.current_tab.next();
                    self.processing_state = ProcessingState::Idle;
                }
                KeyCode::BackTab => {
                    self.current_tab = self.current_tab.prev();
                    self.processing_state = ProcessingState::Idle;
                }
                KeyCode::Right => {
                    if self.current_tab == Tab::File {
                        self.enter_dir();
                    } else if self.current_tab == Tab::Snake {
                        self.snake_game.set_direction(Direction::Right);
                    }
                }
                KeyCode::Left => {
                    // If in File tab, Left goes to parent dir
                    if self.current_tab == Tab::File {
                        self.go_to_parent();
                    } else if self.current_tab == Tab::Snake {
                        self.snake_game.set_direction(Direction::Left);
                    }
                }
                KeyCode::Up if self.current_tab == Tab::Snake => {
                    self.snake_game.set_direction(Direction::Up);
                }
                KeyCode::Down if self.current_tab == Tab::Snake => {
                    self.snake_game.set_direction(Direction::Down);
                }
                KeyCode::Char('r') if self.current_tab == Tab::Snake => {
                    self.snake_game.reset();
                }
                KeyCode::Char('n') if self.current_tab == Tab::Snake => {
                    if !self.snake_game.started && !self.snake_game.game_over {
                        self.snake_game.started = true;
                    }
                }
                KeyCode::Char('b')
                    if self.current_tab == Tab::Benchmark
                        && self.processing_state != ProcessingState::Computing =>
                {
                    self.run_benchmark(tx);
                }
                // File browser navigation
                KeyCode::Down if self.current_tab == Tab::File => {
                    self.next_file();
                }
                KeyCode::Up if self.current_tab == Tab::File => {
                    self.previous_file();
                }
                KeyCode::PageDown if self.current_tab == Tab::File => {
                    self.next_page();
                }
                KeyCode::PageUp if self.current_tab == Tab::File => {
                    self.previous_page();
                }
                KeyCode::Home if self.current_tab == Tab::File => {
                    self.go_to_top();
                }
                KeyCode::End if self.current_tab == Tab::File => {
                    self.go_to_bottom();
                }
                KeyCode::Enter if self.current_tab == Tab::File => {
                    self.enter_dir();
                }
                KeyCode::Backspace if self.current_tab == Tab::File => {
                    self.go_to_parent();
                }
                KeyCode::Delete => {
                    self.current_input_mut().clear();
                }
                _ => {}
            },
            InputMode::Editing => match code {
                KeyCode::Enter => {
                    let input_text = self.current_input().to_string(); // Get input from current tab
                    self.input_mode = InputMode::Normal;

                    if !input_text.is_empty() {
                        match self.current_tab {
                            Tab::Text => {
                                self.process_text(input_text, tx);
                                // Don't clear input, keep it visible for reference
                            }
                            Tab::File => {
                                self.process_file(input_text, tx);
                                // Don't clear input, might want to edit it
                            }
                            _ => {}
                        }
                    }
                }
                KeyCode::Char(c) => {
                    self.current_input_mut().push(c);
                }
                KeyCode::Backspace => {
                    self.current_input_mut().pop();
                }
                KeyCode::Esc => {
                    self.input_mode = InputMode::Normal;
                    // self.input.clear(); // Keep input
                }
                _ => {}
            },
        }
    }

    fn process_text(&mut self, text: String, tx: mpsc::Sender<AppMessage>) {
        self.processing_state = ProcessingState::Computing;
        self.messages
            .push((Local::now(), format!("Input: {}", text)));

        tokio::spawn(async move {
            // Simulate some processing time for animation
            sleep(Duration::from_millis(100)).await;

            let result = processor::process_text(text.as_bytes());
            let msg = format!("Hash:  {}", result.hash);
            let _ = tx.send(AppMessage::ComputationComplete(msg)).await;
        });
    }

    fn process_file(&mut self, path_str: String, tx: mpsc::Sender<AppMessage>) {
        self.processing_state = ProcessingState::Computing;
        self.messages
            .push((Local::now(), format!("File: {}", path_str)));

        let config = self.config.clone();

        tokio::spawn(async move {
            let path = std::path::Path::new(&path_str);
            let file_counter = Arc::new(AtomicUsize::new(0));

            match processor::process_file(path, &config, &file_counter) {
                Ok(Some(result)) => {
                    let msg = format!("Hash:  {}", result.hash);
                    let _ = tx.send(AppMessage::ComputationComplete(msg)).await;
                }
                Ok(None) => {
                    let _ = tx
                        .send(AppMessage::ComputationError("Is a directory".to_string()))
                        .await;
                }
                Err(e) => {
                    let _ = tx.send(AppMessage::ComputationError(e.to_string())).await;
                }
            }
        });
    }

    fn run_benchmark(&mut self, tx: mpsc::Sender<AppMessage>) {
        self.processing_state = ProcessingState::Computing;
        self.messages
            .push((Local::now(), "Running benchmark...".to_string()));

        tokio::spawn(async move {
            use crate::config;
            use std::io::{Cursor, Read};
            use std::time::Instant;
            use whirlpool::{Digest, Whirlpool};

            // Generate test data
            let data = vec![0xA5u8; config::BENCHMARK_FILE_SIZE];
            let mut cursor = Cursor::new(&data);

            let start = Instant::now();
            let mut hasher = Whirlpool::new();
            let mut buffer = [0u8; config::BUFFER_SIZE];
            let mut bytes_processed = 0u64;

            loop {
                let bytes_read = cursor.read(&mut buffer).unwrap_or(0);
                if bytes_read == 0 {
                    break;
                }
                hasher.update(&buffer[..bytes_read]);
                bytes_processed += bytes_read as u64;
            }

            let _ = hasher.finalize();
            let duration = start.elapsed();

            let duration_ms = duration.as_millis() as u64;
            let throughput_mbps = if duration_ms > 0 {
                (bytes_processed as f64 / 1_048_576.0) / (duration_ms as f64 / 1000.0)
            } else {
                0.0
            };

            let score = (throughput_mbps * 10.0).round() as u64;
            let rating = if score >= 2000 {
                "A++"
            } else if score >= 1000 {
                "A+"
            } else if score >= 500 {
                "A"
            } else if score >= 250 {
                "B"
            } else if score >= 100 {
                "C"
            } else {
                "D"
            }
            .to_string();

            let result = BenchmarkResult {
                throughput_mbps,
                duration_ms,
                score,
                rating,
            };

            let _ = tx.send(AppMessage::BenchmarkComplete(result)).await;
        });
    }
}

pub enum AppMessage {
    UpdateSpinner,
    ComputationComplete(String),
    ComputationError(String),
    BenchmarkComplete(BenchmarkResult),
    SnakeTick,
    Input(KeyEvent),
}
