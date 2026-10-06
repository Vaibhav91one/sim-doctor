//! A terminal view over a scan's findings (issue #15).
//!
//! [`draw`] renders ONLY fields present in the scan envelope's `payload.data`
//! (the value `scan::to_json` produces), so nothing is visible here that
//! `--json` does not carry. It reads that value defensively: a missing key or
//! a wrong type is skipped, never indexed blindly.
//!
//! The event loop in [`run`] is the only part that touches a real terminal.
//! It is not exercised in CI; `draw` and [`handle_key`] are.

use crossterm::event::KeyCode;
use ratatui::{
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Paragraph, Wrap},
};
use serde_json::Value;

/// This module's name in [`crate::MODULES`].
pub const NAME: &str = "tui";

/// Which finding is selected and how far the list is scrolled.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ViewState {
    /// Index of the selected finding.
    pub selected: usize,
    /// Index of the first visible finding; kept in range by [`draw`].
    pub scroll: usize,
}

/// Rows a PageUp/PageDown moves.
const PAGE: usize = 10;

/// Applies one key. Returns true when the user asked to quit.
pub fn handle_key(state: &mut ViewState, key: KeyCode, rows: usize) -> bool {
    let last = rows.saturating_sub(1);
    match key {
        KeyCode::Char('q') | KeyCode::Esc => return true,
        KeyCode::Up | KeyCode::Char('k') => state.selected = state.selected.saturating_sub(1),
        KeyCode::Down | KeyCode::Char('j') => state.selected = (state.selected + 1).min(last),
        KeyCode::PageUp => state.selected = state.selected.saturating_sub(PAGE),
        KeyCode::PageDown => state.selected = (state.selected + PAGE).min(last),
        KeyCode::Home => state.selected = 0,
        KeyCode::End => state.selected = last,
        _ => {}
    }
    state.selected = state.selected.min(last);
    false
}

const SEVERITIES: [&str; 5] = ["critical", "high", "medium", "low", "info"];

fn severity_style(severity: &str) -> Style {
    let colour = match severity {
        "critical" | "high" => Color::Red,
        "medium" => Color::Yellow,
        "low" => Color::Blue,
        _ => Color::DarkGray,
    };
    Style::default().fg(colour)
}

fn text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

/// `key value` pairs of an object, without `kind`; empty for anything else.
fn describe(value: Option<&Value>) -> String {
    let Some(map) = value.and_then(Value::as_object) else {
        return String::new();
    };
    let mut parts = Vec::new();
    if let Some(kind) = map.get("kind").and_then(Value::as_str) {
        parts.push(kind.to_owned());
    }
    for (key, v) in map.iter().filter(|(k, _)| *k != "kind") {
        match v {
            Value::String(s) => parts.push(format!("{key} {s}")),
            Value::Number(n) => parts.push(format!("{key} {n}")),
            _ => {}
        }
    }
    parts.join(", ")
}

/// Renders the scan data into the frame.
pub fn draw(frame: &mut ratatui::Frame, data: &Value, state: &mut ViewState) {
    let no_findings = Vec::new();
    let findings = data
        .pointer("/findings/findings")
        .and_then(Value::as_array)
        .unwrap_or(&no_findings);
    state.selected = state.selected.min(findings.len().saturating_sub(1));

    let mut header = Vec::new();
    let counts: Vec<Span> = SEVERITIES
        .iter()
        .flat_map(|level| {
            let n = findings
                .iter()
                .filter(|f| text(f, "severity") == Some(level))
                .count();
            [
                Span::styled(format!("{level} {n}"), severity_style(level)),
                Span::raw("  "),
            ]
        })
        .collect();
    header.push(Line::from(counts));
    if let Some(score) = data.get("score").and_then(Value::as_object) {
        if let (Some(value), Some(max)) = (score.get("value"), score.get("max")) {
            header.push(Line::from(format!("score {value}/{max}")));
        }
    }
    let [top, body, foot] = Layout::vertical([
        Constraint::Length(header.len() as u16),
        Constraint::Min(0),
        Constraint::Length(2),
    ])
    .areas(frame.area());
    frame.render_widget(Paragraph::new(header), top);

    let [list_area, detail_area] =
        Layout::vertical([Constraint::Percentage(60), Constraint::Percentage(40)]).areas(body);

    // List: keep the selected row inside the visible window.
    let height = list_area.height.saturating_sub(2) as usize;
    if state.selected < state.scroll {
        state.scroll = state.selected;
    } else if height > 0 && state.selected >= state.scroll + height {
        state.scroll = state.selected + 1 - height;
    }
    state.scroll = state.scroll.min(findings.len().saturating_sub(1));
    let rows: Vec<Line> = if findings.is_empty() {
        vec![Line::from("no findings")]
    } else {
        findings
            .iter()
            .enumerate()
            .skip(state.scroll)
            .take(height)
            .map(|(i, f)| {
                let sev = text(f, "severity").unwrap_or("?");
                let mut line = Line::from(vec![
                    Span::styled(format!("{sev:<8} "), severity_style(sev)),
                    Span::raw(format!(
                        "{}  {}",
                        text(f, "rule").unwrap_or("?"),
                        text(f, "message").unwrap_or("")
                    )),
                ]);
                if i == state.selected {
                    line = line.style(Style::default().add_modifier(Modifier::REVERSED));
                }
                line
            })
            .collect()
    };
    frame.render_widget(
        Paragraph::new(rows).block(Block::bordered().title("findings")),
        list_area,
    );

    let mut detail = Vec::new();
    if let Some(f) = findings.get(state.selected) {
        detail.push(Line::from(format!(
            "location: {}",
            describe(f.get("location"))
        )));
        if let Some(reason) = f.pointer("/coverage/reason").and_then(Value::as_str) {
            detail.push(Line::from(format!("coverage: partial, {reason}")));
        }
        detail.push(Line::from(format!(
            "evidence: {}",
            describe(f.get("evidence"))
        )));
    }
    frame.render_widget(
        Paragraph::new(detail)
            .wrap(Wrap { trim: false })
            .block(Block::bordered().title("detail")),
        detail_area,
    );

    let mut notes = Vec::new();
    if let Some(reason) = data
        .pointer("/findings/coverage/reason")
        .and_then(Value::as_str)
    {
        notes.push(Line::from(format!("coverage: partial, {reason}")));
    }
    if let Some(stopped) = data.pointer("/tar/stopped").and_then(Value::as_str) {
        notes.push(Line::from(format!("TAR scan stopped: {stopped}")));
    }
    notes.push(Line::from("up/down j/k PgUp/PgDn Home/End move, q quits"));
    // Show the last two lines if there is not room for all of them.
    let skip = notes.len().saturating_sub(2);
    frame.render_widget(Paragraph::new(notes.split_off(skip)), foot);
}

/// Puts the terminal back on drop, so an error or a panic cannot leave the
/// operator in raw mode on the alternate screen.
struct Restore;

impl Drop for Restore {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
        let _ = crossterm::execute!(std::io::stdout(), crossterm::terminal::LeaveAlternateScreen);
    }
}

/// Runs the interactive view until the user quits.
pub fn run(data: &Value) -> std::io::Result<()> {
    use crossterm::event::{self, Event, KeyEventKind};
    crossterm::terminal::enable_raw_mode()?;
    let _restore = Restore;
    crossterm::execute!(std::io::stdout(), crossterm::terminal::EnterAlternateScreen)?;
    let mut terminal =
        ratatui::Terminal::new(ratatui::backend::CrosstermBackend::new(std::io::stdout()))?;
    let rows = data
        .pointer("/findings/findings")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let mut state = ViewState::default();
    loop {
        terminal.draw(|f| draw(f, data, &mut state))?;
        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press && handle_key(&mut state, key.code, rows) {
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{backend::TestBackend, Terminal};
    use serde_json::json;

    fn canned() -> Value {
        json!({
            "findings": {
                "count": 3, "exhaustive": false,
                "coverage": {"status": "partial", "reason": "max_nodes bound hit"},
                "findings": [
                    {"rule": "gsma/msl-zero-allowed", "severity": "critical", "severity_rank": 4,
                     "message": "TAR 00000042 is MSL=0",
                     "location": {"kind": "tar", "tar": 66},
                     "evidence": {"kind": "text", "value": "MSL=0", "omitted": 0},
                     "coverage": {"status": "complete"}},
                    {"rule": "auth/scp03-missing-mac", "severity": "medium", "severity_rank": 2,
                     "message": "the secure channel came up without a MAC",
                     "location": {"kind": "apdu", "exchange": "READ BINARY"},
                     "evidence": {"kind": "none"},
                     "coverage": {"status": "partial", "reason": "max_nodes bound hit"}},
                    {"rule": "euicc/profile-enabled", "severity": "low", "severity_rank": 1,
                     "message": "a second profile is enabled",
                     "location": {"kind": "other", "subject": "profile", "value": "1"},
                     "evidence": {"kind": "bytes", "octets": "45", "omitted": 0},
                     "coverage": {"status": "complete"}}
                ]
            },
            "tar": {"stopped": "interrupted after 8 probes"}
        })
    }

    fn render(data: &Value, w: u16, h: u16, state: &mut ViewState) -> String {
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| draw(f, data, state)).unwrap();
        let buf = term.backend().buffer().clone();
        buf.content()
            .iter()
            .map(|c| c.symbol())
            .collect::<Vec<_>>()
            .join("")
    }

    #[test]
    fn shows_every_finding_and_the_counts() {
        let text = render(&canned(), 120, 30, &mut ViewState::default());
        for f in canned()["findings"]["findings"].as_array().unwrap() {
            assert!(text.contains(f["rule"].as_str().unwrap()), "{text}");
            assert!(text.contains(f["message"].as_str().unwrap()), "{text}");
        }
        for count in ["critical 1", "medium 1", "low 1", "high 0"] {
            assert!(text.contains(count), "missing {count}: {text}");
        }
        assert!(text.contains("interrupted after 8 probes"), "{text}");
    }

    #[test]
    fn detail_pane_shows_selected_findings_coverage_and_evidence() {
        let mut state = ViewState {
            selected: 1,
            scroll: 0,
        };
        let text = render(&canned(), 120, 30, &mut state);
        assert!(text.contains("READ BINARY"), "{text}");
        assert!(text.contains("max_nodes bound hit"), "{text}");
    }

    #[test]
    fn no_tui_only_information() {
        let data = canned();
        let json_text = serde_json::to_string(&data).unwrap();
        let text = render(&data, 120, 30, &mut ViewState::default());
        // Every value the TUI could print for a finding row must be in the JSON.
        for f in data["findings"]["findings"].as_array().unwrap() {
            for key in ["rule", "severity", "message"] {
                let s = f[key].as_str().unwrap();
                assert!(json_text.contains(s));
                assert!(text.contains(s), "{s} not shown");
            }
        }
        // And the reverse: every row on screen starts from JSON strings.
        let rows: Vec<&str> = data["findings"]["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["message"].as_str().unwrap())
            .collect();
        for row in rows {
            assert!(json_text.contains(row));
        }
    }

    #[test]
    fn draw_never_panics_on_odd_data() {
        let odd = [
            json!({}),
            json!(null),
            json!([1, 2]),
            json!({"findings": {"findings": []}}),
            json!({"findings": "nope"}),
            json!({"findings": {"findings": [1, null, "x", {}, {"rule": 5, "severity": [], "message": {}, "location": 3, "evidence": "x", "coverage": []}]}}),
            json!({"score": "x", "tar": 4}),
            json!({"score": {"value": 90, "max": 100}, "findings": {"findings": []}}),
        ];
        for data in &odd {
            for (w, h) in [(1, 1), (200, 60), (10, 3), (40, 8)] {
                let mut state = ViewState {
                    selected: 99,
                    scroll: 99,
                };
                render(data, w, h, &mut state);
            }
        }
    }

    #[test]
    fn empty_findings_say_so() {
        let text = render(
            &json!({"findings": {"findings": []}}),
            80,
            20,
            &mut ViewState::default(),
        );
        assert!(text.contains("no findings"), "{text}");
    }

    #[test]
    fn keys_move_and_clamp() {
        let mut s = ViewState::default();
        assert!(!handle_key(&mut s, KeyCode::Up, 3));
        assert_eq!(s.selected, 0);
        handle_key(&mut s, KeyCode::Char('j'), 3);
        handle_key(&mut s, KeyCode::Down, 3);
        handle_key(&mut s, KeyCode::Down, 3);
        assert_eq!(s.selected, 2);
        handle_key(&mut s, KeyCode::Home, 3);
        assert_eq!(s.selected, 0);
        handle_key(&mut s, KeyCode::End, 3);
        assert_eq!(s.selected, 2);
        handle_key(&mut s, KeyCode::PageUp, 30);
        assert_eq!(s.selected, 0);
        handle_key(&mut s, KeyCode::PageDown, 30);
        assert_eq!(s.selected, 10);
        handle_key(&mut s, KeyCode::Char('k'), 30);
        assert_eq!(s.selected, 9);
        let mut empty = ViewState::default();
        handle_key(&mut empty, KeyCode::Down, 0);
        handle_key(&mut empty, KeyCode::End, 0);
        assert_eq!(empty.selected, 0);
        assert!(handle_key(&mut s, KeyCode::Char('q'), 3));
        assert!(handle_key(&mut s, KeyCode::Esc, 3));
    }
}
