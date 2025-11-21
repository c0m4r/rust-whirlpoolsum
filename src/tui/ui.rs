use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Tabs, Wrap},
    Frame,
};

use super::app::{App, InputMode, ProcessingState, Tab};

pub fn ui(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(if app.current_tab == Tab::Benchmark || app.current_tab == Tab::Snake {
            vec![
                Constraint::Length(3), // Tabs
                Constraint::Length(3), // Help message
                Constraint::Min(5),    // Content area
                Constraint::Length(1), // Status bar
            ]
        } else {
            vec![
                Constraint::Length(3), // Tabs
                Constraint::Length(3), // Help message
                Constraint::Length(3), // Input
                Constraint::Length(3), // Latest Checksum
                Constraint::Min(5),    // Content area
                Constraint::Length(1), // Status bar
            ]
        })
        .split(f.area());

    if app.current_tab == Tab::Benchmark || app.current_tab == Tab::Snake {
        render_tabs(f, app, chunks[0]);
        render_help(f, app, chunks[1]);
        render_content(f, app, chunks[2]);
        render_status_bar(f, app, chunks[3]);
    } else {
        render_tabs(f, app, chunks[0]);
        render_help(f, app, chunks[1]);
        render_input(f, app, chunks[2]);
        render_latest_checksum(f, app, chunks[3]);
        render_content(f, app, chunks[4]);
        render_status_bar(f, app, chunks[5]);
    }
}

fn render_tabs(f: &mut Frame, app: &App, area: Rect) {
    let titles: Vec<Line> = ["Text", "File", "Benchmark", "Snake"]
        .iter()
        .map(|t| Line::from(*t))
        .collect();

    let tabs = Tabs::new(titles)
        .block(Block::default().borders(Borders::ALL).title("Mode"))
        .select(match app.current_tab {
            Tab::Text => 0,
            Tab::File => 1,
            Tab::Benchmark => 2,
            Tab::Snake => 3,
        })
        .style(Style::default().fg(Color::White))
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );

    f.render_widget(tabs, area);
}

fn render_help(f: &mut Frame, app: &App, area: Rect) {
    let (msg, style) = match app.input_mode {
        InputMode::Normal => {
            let base_msg = vec![
                Span::raw("Press "),
                Span::styled("q", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(" quit, "),
                Span::styled("Tab", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(" switch mode, "),
            ];

            let mode_specific = match app.current_tab {
                Tab::Text => vec![
                    Span::styled("e", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(" edit, "),
                    Span::styled("Del", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(" clear"),
                ],
                Tab::File => vec![
                    Span::styled("e", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(" edit path, "),
                    Span::styled(
                        "↑/↓/PgUp/PgDn/Home/End",
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(" navigate, "),
                    Span::styled("Right/Enter", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(" enter dir, "),
                    Span::styled("Left/Back", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(" parent dir, "),
                    Span::styled("Del", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(" clear"),
                ],
                Tab::Benchmark => vec![
                    Span::styled("b", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(" run benchmark"),
                ],
                Tab::Snake => vec![
                    Span::styled("n", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(" start, "),
                    Span::styled("Arrow keys", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(" move, "),
                    Span::styled("r", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(" restart"),
                ],
            };

            let mut combined = base_msg;
            combined.extend(mode_specific);
            (combined, Style::default())
        }
        InputMode::Editing => (
            vec![
                Span::raw("Press "),
                Span::styled("Esc", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(" cancel, "),
                Span::styled("Enter", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(" submit"),
            ],
            Style::default(),
        ),
    };

    let text = Line::from(msg).patch_style(style);
    let help_message = Paragraph::new(text);
    f.render_widget(help_message, area);
}

fn render_input(f: &mut Frame, app: &App, area: Rect) {
    let title = match app.current_tab {
        Tab::Text => "Text Input",
        Tab::File => "File Path",
        Tab::Benchmark => "Benchmark",
        Tab::Snake => "Snake",
    };

    let input = Paragraph::new(app.current_input())
        .style(match app.input_mode {
            InputMode::Normal => Style::default(),
            InputMode::Editing => Style::default().fg(Color::Yellow),
        })
        .block(Block::default().borders(Borders::ALL).title(title));
    f.render_widget(input, area);
}

fn render_latest_checksum(f: &mut Frame, app: &App, area: Rect) {
    let content = match app.current_tab {
        Tab::Text => {
            if let Some(ref checksum) = app.latest_text_checksum {
                checksum.as_str()
            } else {
                "(no checksum yet)"
            }
        }
        Tab::File => {
            if let Some(ref checksum) = app.latest_file_checksum {
                checksum.as_str()
            } else {
                "(no checksum yet)"
            }
        }
        _ => "(no checksum yet)",
    };

    let paragraph = Paragraph::new(content)
        .style(Style::default().fg(Color::Cyan))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Latest Checksum"),
        );
    f.render_widget(paragraph, area);
}

fn render_content(f: &mut Frame, app: &App, area: Rect) {
    match app.current_tab {
        Tab::Text => render_messages(f, app, area),
        Tab::File => {
            // Split content area for File Browser and Messages
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Percentage(35), // File Browser
                    Constraint::Percentage(65), // Results
                ])
                .split(area);
            render_file_browser(f, app, chunks[0]);
            render_messages(f, app, chunks[1]);
        }
        Tab::Benchmark => render_benchmark(f, app, area),
        Tab::Snake => render_snake(f, app, area),
    }
}

fn render_file_browser(f: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app
        .dir_entries
        .iter()
        .map(|path| {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| ".".to_string());

            let icon = if path.is_dir() { "📁 " } else { "📄 " };
            let content = Line::from(vec![
                Span::styled(icon, Style::default().fg(Color::Blue)),
                Span::raw(name),
            ]);
            ListItem::new(content)
        })
        .collect();

    let title = format!("Browser: {}", app.current_dir.display());
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(title))
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");

    f.render_stateful_widget(list, area, &mut app.dir_state.clone());
}

fn render_messages(f: &mut Frame, app: &App, area: Rect) {
    let mut lines: Vec<Line> = app
        .messages
        .iter()
        .map(|(time, m)| {
            let time_str = time.format("%H:%M:%S").to_string();
            Line::from(Span::raw(format!("[{}] {}", time_str, m)))
        })
        .collect();

    // Add processing indicator
    if app.processing_state == ProcessingState::Computing {
        let spinner = app.get_spinner_char();
        lines.push(Line::from(vec![
            Span::styled(
                format!("{} ", spinner),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Computing..."),
        ]));
    }

    let paragraph = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title("Results"))
        .wrap(Wrap { trim: false });
    f.render_widget(paragraph, area);
}

fn render_benchmark(f: &mut Frame, app: &App, area: Rect) {
    let content = if let ProcessingState::Computing = app.processing_state {
        let spinner = app.get_spinner_char();
        vec![
            Line::from(""),
            Line::from(vec![
                Span::styled(
                    format!("{}  ", spinner),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    "Running benchmark test...",
                    Style::default().fg(Color::Yellow),
                ),
            ]),
            Line::from(""),
            Line::from("Generating 100 MB of random data and computing WHIRLPOOL hash..."),
        ]
    } else if let Some(ref result) = app.benchmark_result {
        let rating_color = match result.rating.as_str() {
            "A++" => Color::Magenta,
            "A+" => Color::Green,
            "A" => Color::LightGreen,
            "B" => Color::Yellow,
            "C" => Color::Red,
            _ => Color::DarkGray,
        };

        vec![
            Line::from(""),
            Line::from(vec![Span::styled(
                "Benchmark Results",
                Style::default()
                    .add_modifier(Modifier::BOLD)
                    .fg(Color::Cyan),
            )]),
            Line::from("═══════════════════════════════════════════════"),
            Line::from(""),
            Line::from(vec![
                Span::raw("  Throughput:     "),
                Span::styled(
                    format!("{:.2} MB/s", result.throughput_mbps),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::raw("  Duration:       "),
                Span::styled(format!("{} ms", result.duration_ms), Style::default()),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("  Score:          ", Style::default()),
                Span::styled(
                    format!("{} points", result.score),
                    Style::default()
                        .add_modifier(Modifier::BOLD)
                        .fg(Color::White),
                ),
            ]),
            Line::from(vec![
                Span::raw("  Rating:         "),
                Span::styled(
                    &result.rating,
                    Style::default()
                        .add_modifier(Modifier::BOLD)
                        .fg(rating_color),
                ),
            ]),
            Line::from(""),
            Line::from("═══════════════════════════════════════════════"),
        ]
    } else {
        vec![
            Line::from(""),
            Line::from("Press 'b' to run the WHIRLPOOL benchmark test."),
            Line::from(""),
            Line::from("This will:"),
            Line::from("  • Generate 100 MB of test data"),
            Line::from("  • Compute WHIRLPOOL hash"),
            Line::from("  • Measure throughput and performance"),
            Line::from("  • Provide a performance rating (D-A++)"),
        ]
    };

    let paragraph =
        Paragraph::new(content).block(Block::default().borders(Borders::ALL).title("Benchmark"));
    f.render_widget(paragraph, area);
}

fn render_snake(f: &mut Frame, app: &App, area: Rect) {
    use super::app::Position;
    
    // Render outer block with default style
    let outer_block = Block::default()
        .borders(Borders::ALL)
        .title("Snake Game");
    f.render_widget(outer_block, area);

    let game = &app.snake_game;
    let mut lines = Vec::new();

    if game.game_over {
        // Center the game over message
        let vertical_center = area.height / 2;
        let msg_area = Rect {
            x: area.x,
            y: area.y + vertical_center.saturating_sub(3),
            width: area.width,
            height: 6,
        };
        
        lines.push(Line::from(vec![
            Span::styled(
                "GAME OVER!",
                Style::default()
                    .fg(Color::Red)
                    .add_modifier(Modifier::BOLD),
            ),
        ]));
        lines.push(Line::from(""));
        lines.push(Line::from(format!("Final Score: {}", game.score)));
        lines.push(Line::from(""));
        lines.push(Line::from("Press 'r' to restart"));
        
        let paragraph = Paragraph::new(lines)
            .alignment(ratatui::layout::Alignment::Center);
        f.render_widget(paragraph, msg_area);
        return;
    } else if !game.started {
        // Center the start message
        let vertical_center = area.height / 2;
        let msg_area = Rect {
            x: area.x,
            y: area.y + vertical_center.saturating_sub(3),
            width: area.width,
            height: 6,
        };

        lines.push(Line::from(vec![
            Span::styled(
                "Press 'n' to start the game",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
        ]));
        lines.push(Line::from(""));
        lines.push(Line::from("Use arrow keys to control the snake"));
        
        let paragraph = Paragraph::new(lines)
            .alignment(ratatui::layout::Alignment::Center);
        f.render_widget(paragraph, msg_area);
        return;
    }

    // Draw game board - use 2 chars per cell for square proportions
    for y in 0..game.height {
        let mut row = String::new();
        for x in 0..game.width {
            let pos = Position { x, y };
            if game.snake[0] == pos {
                row.push_str("██"); // Snake head (2 chars)
            } else if game.snake.contains(&pos) {
                row.push_str("▓▓"); // Snake body (2 chars)
            } else if game.food == pos {
                row.push_str(&game.food_emoji); // Food (2 chars)
            } else {
                row.push_str("  "); // Empty (2 spaces)
            }
        }
        lines.push(Line::from(row));
    }

    // Calculate centered area for the game board
    // Width: 50 * 2 = 100 chars
    // Height: 20 lines
    let board_width = (game.width * 2) as u16;
    let board_height = game.height as u16;
    
    // Add 2 for borders
    let total_width = board_width + 2;
    let total_height = board_height + 2;

    let center_x = area.x + (area.width.saturating_sub(total_width)) / 2;
    let center_y = area.y + (area.height.saturating_sub(total_height)) / 2;

    let game_area = Rect {
        x: center_x,
        y: center_y,
        width: total_width.min(area.width),
        height: total_height.min(area.height),
    };

    let paragraph = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Blue))
    );
    f.render_widget(paragraph, game_area);
}

fn render_status_bar(f: &mut Frame, app: &App, area: Rect) {
    let status = if app.current_tab == Tab::Snake {
        Span::styled(
            format!("Score: {}", app.snake_game.score),
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        )
    } else {
        match &app.processing_state {
            ProcessingState::Idle => Span::styled("Ready", Style::default().fg(Color::Green)),
            ProcessingState::Computing => {
                Span::styled("Computing...", Style::default().fg(Color::Yellow))
            }
            ProcessingState::Complete => Span::styled("Complete", Style::default().fg(Color::Cyan)),
            ProcessingState::Error(err) => {
                Span::styled(format!("Error: {}", err), Style::default().fg(Color::Red))
            }
        }
    };

    let mode = Span::styled(
        format!(" {} ", app.current_tab.as_str()),
        Style::default().fg(Color::Black).bg(Color::Cyan),
    );

    let line = Line::from(vec![mode, Span::raw(" │ "), status]);

    let paragraph = Paragraph::new(line);
    f.render_widget(paragraph, area);
}
