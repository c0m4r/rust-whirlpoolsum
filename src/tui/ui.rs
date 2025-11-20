use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Tabs},
    Frame,
};

use super::app::{App, InputMode, ProcessingState, Tab};

pub fn ui(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Tabs
            Constraint::Length(3), // Help message
            Constraint::Length(3), // Input
            Constraint::Min(5),    // Content area
            Constraint::Length(1), // Status bar
        ])
        .split(f.area());

    render_tabs(f, app, chunks[0]);
    render_help(f, app, chunks[1]);
    render_input(f, app, chunks[2]);
    render_content(f, app, chunks[3]);
    render_status_bar(f, app, chunks[4]);
}

fn render_tabs(f: &mut Frame, app: &App, area: Rect) {
    let titles: Vec<Line> = ["Text", "File", "Benchmark"]
        .iter()
        .map(|t| Line::from(*t))
        .collect();

    let tabs = Tabs::new(titles)
        .block(Block::default().borders(Borders::ALL).title("Mode"))
        .select(match app.current_tab {
            Tab::Text => 0,
            Tab::File => 1,
            Tab::Benchmark => 2,
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
                Span::styled("Tab/←→", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(" switch mode, "),
            ];

            let mode_specific = match app.current_tab {
                Tab::Text | Tab::File => vec![
                    Span::styled("e", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(" edit"),
                ],
                Tab::Benchmark => vec![
                    Span::styled("b", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(" run benchmark"),
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
    };

    let input = Paragraph::new(app.input.as_str())
        .style(match app.input_mode {
            InputMode::Normal => Style::default(),
            InputMode::Editing => Style::default().fg(Color::Yellow),
        })
        .block(Block::default().borders(Borders::ALL).title(title));
    f.render_widget(input, area);
}

fn render_content(f: &mut Frame, app: &App, area: Rect) {
    match app.current_tab {
        Tab::Text | Tab::File => render_messages(f, app, area),
        Tab::Benchmark => render_benchmark(f, app, area),
    }
}

fn render_messages(f: &mut Frame, app: &App, area: Rect) {
    let mut items: Vec<ListItem> = app
        .messages
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let content = Line::from(Span::raw(format!("{}: {}", i, m)));
            ListItem::new(content)
        })
        .collect();

    // Add processing indicator
    if app.processing_state == ProcessingState::Computing {
        let spinner = app.get_spinner_char();
        items.push(ListItem::new(Line::from(vec![
            Span::styled(
                format!("{} ", spinner),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Computing..."),
        ])));
    }

    let messages = List::new(items).block(Block::default().borders(Borders::ALL).title("Results"));
    f.render_widget(messages, area);
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

fn render_status_bar(f: &mut Frame, app: &App, area: Rect) {
    let status = match &app.processing_state {
        ProcessingState::Idle => Span::styled("Ready", Style::default().fg(Color::Green)),
        ProcessingState::Computing => {
            Span::styled("Computing...", Style::default().fg(Color::Yellow))
        }
        ProcessingState::Complete => Span::styled("Complete", Style::default().fg(Color::Cyan)),
        ProcessingState::Error(err) => {
            Span::styled(format!("Error: {}", err), Style::default().fg(Color::Red))
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
