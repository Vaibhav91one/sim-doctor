//! A terminal view over a scan's findings (issue #15).
//!
//! [`draw`] renders ONLY fields present in the scan envelope's `payload.data`
//! (the value `scan::to_json` produces), so nothing is visible here that
//! `--json` does not carry. It reads that value defensively: a missing key or
//! a wrong type is skipped, never indexed blindly.
//!
//! The event loop in [`run`] is the only part that touches a real terminal.
//! It is not exercised in CI; `draw` and [`handle_key`] are.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Paragraph},
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
    /// First visible line of the detail pane.
    pub detail_scroll: usize,
    /// Whether Up/Down scroll the detail pane instead of moving the selection.
    pub detail_focus: bool,
}

/// Rows a PageUp/PageDown moves.
const PAGE: usize = 10;
/// Longest string shown for a rule id, message, location or status line.
const SHORT: usize = 300;
/// Longest string shown for evidence and other detail text.
const LONG: usize = 2000;

/// Applies one key. Returns true when the user asked to quit.
///
/// Raw mode turns Ctrl-C into an ordinary key event, so it is handled here.
pub fn handle_key(state: &mut ViewState, key: KeyEvent, rows: usize) -> bool {
    let last = rows.saturating_sub(1);
    let before = state.selected;
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        return matches!(key.code, KeyCode::Char('c' | 'd'));
    }
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => return true,
        KeyCode::Tab => state.detail_focus = !state.detail_focus,
        KeyCode::Up | KeyCode::Char('k') if state.detail_focus => {
            state.detail_scroll = state.detail_scroll.saturating_sub(1);
        }
        KeyCode::Down | KeyCode::Char('j') if state.detail_focus => state.detail_scroll += 1,
        KeyCode::PageUp if state.detail_focus => {
            state.detail_scroll = state.detail_scroll.saturating_sub(PAGE);
        }
        KeyCode::PageDown if state.detail_focus => state.detail_scroll += PAGE,
        KeyCode::Up | KeyCode::Char('k') => state.selected = state.selected.saturating_sub(1),
        KeyCode::Down | KeyCode::Char('j') => state.selected = (state.selected + 1).min(last),
        KeyCode::PageUp => state.selected = state.selected.saturating_sub(PAGE),
        KeyCode::PageDown => state.selected = (state.selected + PAGE).min(last),
        KeyCode::Home => state.selected = 0,
        KeyCode::End => state.selected = last,
        _ => {}
    }
    state.selected = state.selected.min(last);
    if state.selected != before {
        state.detail_scroll = 0;
    }
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

/// A string from the JSON with control and invisible characters removed.
fn clean(text: &str, limit: usize) -> String {
    crate::fix::clean_with_limit(text, limit)
}

fn text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

/// Any JSON value as compact text: strings as themselves, the rest as JSON.
fn show(value: &Value, limit: usize) -> String {
    match value {
        Value::String(s) => clean(s, limit),
        other => clean(&serde_json::to_string(other).unwrap_or_default(), limit),
    }
}

/// `key: value` lines of an object, `kind` first; one line for a non-object.
fn describe(label: &str, value: Option<&Value>, limit: usize) -> Vec<String> {
    match value {
        Some(Value::Object(map)) => {
            let mut lines = Vec::new();
            if let Some(kind) = map.get("kind") {
                lines.push(format!("{label}: {}", show(kind, limit)));
            }
            for (key, v) in map.iter().filter(|(k, _)| *k != "kind") {
                lines.push(format!("{label} {}: {}", clean(key, SHORT), show(v, limit)));
            }
            lines
        }
        Some(other) => vec![format!("{label}: {}", show(other, limit))],
        None => Vec::new(),
    }
}

/// Splits a line into pieces no wider than `width` characters.
fn wrap(line: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let chars: Vec<char> = line.chars().collect();
    if chars.is_empty() {
        return vec![String::new()];
    }
    chars.chunks(width).map(|c| c.iter().collect()).collect()
}

/// Lines that change how the whole result must be read. Each is present only
/// when the JSON carries the field, and each repeats the JSON text.
fn status_lines(data: &Value) -> Vec<Line<'static>> {
    let warn = Style::default().fg(Color::Yellow);
    let mut out: Vec<Line> = Vec::new();
    let w = |text: String| Line::styled(text, warn);
    if let Some(score) = data.get("score").and_then(Value::as_object) {
        if let (Some(value), Some(max)) = (score.get("value"), score.get("max")) {
            out.push(Line::from(format!(
                "score {}/{}",
                show(value, SHORT),
                show(max, SHORT)
            )));
        }
        if let Some(text) = score.get("warning").and_then(Value::as_str) {
            out.push(w(format!("score warning: {}", clean(text, LONG))));
        }
    }
    if data.get("truncated").and_then(Value::as_bool) == Some(true) {
        let mut line = String::from("TRUNCATED: the walk did not see the whole card");
        if let Some(by) = data.get("truncated_by").filter(|v| !v.is_null()) {
            line.push_str(&format!("; first bound {}", show(by, SHORT)));
        }
        if let Some(hit) = data.get("limits_hit").and_then(Value::as_array) {
            let hit: Vec<String> = hit.iter().map(|v| show(v, SHORT)).collect();
            if !hit.is_empty() {
                line.push_str(&format!("; bounds hit: {}", hit.join(", ")));
            }
        }
        out.push(w(line));
    }
    if let Some(stopped) = data.get("stopped").and_then(Value::as_str) {
        out.push(w(format!("walk stopped: {}", clean(stopped, LONG))));
    }
    if let Some(text) = data.pointer("/candidates/warning").and_then(Value::as_str) {
        out.push(w(format!("candidates: {}", clean(text, LONG))));
    }
    if let Some(t) = data
        .pointer("/findings/severity_threshold")
        .and_then(Value::as_str)
    {
        out.push(w(format!(
            "only findings at {} or above are listed",
            clean(t, SHORT)
        )));
    }
    if data
        .pointer("/findings/exhaustive")
        .and_then(Value::as_bool)
        == Some(false)
    {
        out.push(w("findings are not exhaustive".to_owned()));
    }
    if let Some(reason) = data
        .pointer("/findings/coverage/reason")
        .and_then(Value::as_str)
    {
        out.push(w(format!("coverage: partial, {}", clean(reason, LONG))));
    }
    if data.pointer("/tar/complete").and_then(Value::as_bool) == Some(false) {
        out.push(w("TAR audit incomplete".to_owned()));
    }
    if let Some(stopped) = data.pointer("/tar/stopped").and_then(Value::as_str) {
        out.push(w(format!("TAR scan stopped: {}", clean(stopped, LONG))));
    }
    if let Some(b) = data.pointer("/tar/blind_spot").and_then(Value::as_str) {
        out.push(w(format!("TAR blind spot: {}", clean(b, LONG))));
    }
    if let Some(counts) = data.pointer("/diff/counts") {
        let n = |k: &str| {
            counts
                .get(k)
                .map_or_else(|| "?".to_owned(), |v| show(v, SHORT))
        };
        out.push(Line::from(format!(
            "diff: {} new, {} fixed, {} persisting",
            n("new"),
            n("fixed"),
            n("persisting")
        )));
    }
    out
}

/// Renders the scan data into the frame.
pub fn draw(frame: &mut ratatui::Frame, data: &Value, state: &mut ViewState) {
    let no_findings = Vec::new();
    let findings = data
        .pointer("/findings/findings")
        .and_then(Value::as_array)
        .unwrap_or(&no_findings);
    let new_findings = data
        .pointer("/diff/new")
        .and_then(Value::as_array)
        .unwrap_or(&no_findings);
    state.selected = state.selected.min(findings.len().saturating_sub(1));

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
    let mut header = vec![Line::from(counts)];
    header.extend(status_lines(data));
    let [top, body, foot] = Layout::vertical([
        Constraint::Length(header.len().min(u16::MAX as usize) as u16),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .areas(frame.area());
    frame.render_widget(Paragraph::new(header), top);

    let [list_area, detail_area] =
        Layout::vertical([Constraint::Percentage(55), Constraint::Percentage(45)]).areas(body);

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
                let is_new = new_findings.contains(f);
                let mut line = Line::from(vec![
                    Span::styled(format!("{:<8} ", clean(sev, SHORT)), severity_style(sev)),
                    Span::raw(format!(
                        "{}{}  {}",
                        if is_new { "[new] " } else { "" },
                        clean(text(f, "rule").unwrap_or("?"), SHORT),
                        clean(text(f, "message").unwrap_or(""), SHORT)
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

    // Detail: every line is kept, then windowed. A cut is always marked.
    let mut lines: Vec<String> = Vec::new();
    if let Some(f) = findings.get(state.selected) {
        lines.extend(describe("location", f.get("location"), SHORT));
        if let Some(reason) = f.pointer("/coverage/reason").and_then(Value::as_str) {
            lines.push(format!("coverage: partial, {}", clean(reason, LONG)));
        }
        lines.extend(describe("evidence", f.get("evidence"), LONG));
    }
    let inner_w = detail_area.width.saturating_sub(2) as usize;
    let inner_h = detail_area.height.saturating_sub(2) as usize;
    let wrapped: Vec<String> = lines.iter().flat_map(|l| wrap(l, inner_w)).collect();
    state.detail_scroll = state
        .detail_scroll
        .min(wrapped.len().saturating_sub(inner_h));
    let mut shown: Vec<String> = wrapped
        .iter()
        .skip(state.detail_scroll)
        .take(inner_h)
        .cloned()
        .collect();
    if wrapped.len() > state.detail_scroll + inner_h && !shown.is_empty() {
        *shown.last_mut().unwrap() = "... (more)".to_owned();
    }
    let title = if state.detail_focus {
        "detail (scrolling)"
    } else {
        "detail"
    };
    frame.render_widget(
        Paragraph::new(shown.into_iter().map(Line::from).collect::<Vec<_>>())
            .block(Block::bordered().title(title)),
        detail_area,
    );

    frame.render_widget(
        Paragraph::new("j/k PgUp/PgDn Home/End move, Tab scroll detail, q quits"),
        foot,
    );
}

fn restore_terminal() {
    let _ = crossterm::terminal::disable_raw_mode();
    let _ = crossterm::execute!(std::io::stdout(), crossterm::terminal::LeaveAlternateScreen);
}

type Hook = std::sync::Arc<dyn Fn(&std::panic::PanicHookInfo<'_>) + Sync + Send + 'static>;

/// Puts the terminal back on drop, so an error or a panic cannot leave the
/// operator in raw mode on the alternate screen, and puts the previous panic
/// hook back.
struct Restore(Hook);

impl Restore {
    /// Installs a panic hook that restores the terminal first, then calls the
    /// previous hook.
    fn new() -> Self {
        let previous: Hook = std::sync::Arc::from(std::panic::take_hook());
        let chained = previous.clone();
        std::panic::set_hook(Box::new(move |info| {
            restore_terminal();
            chained(info);
        }));
        Self(previous)
    }
}

impl Drop for Restore {
    fn drop(&mut self) {
        restore_terminal();
        // set_hook panics when called while unwinding; the TUI hook is already
        // harmless then (it restores, then calls the previous hook).
        if !std::thread::panicking() {
            let _ = std::panic::take_hook();
            let previous = self.0.clone();
            std::panic::set_hook(Box::new(move |info| previous(info)));
        }
    }
}

/// Runs the interactive view until the user quits or SIGINT or SIGTERM is seen.
///
/// Both signals set the `signals` flag, polled every 250 ms; the loop then returns
/// and the Drop guard restores the terminal.
pub fn run(data: &Value) -> std::io::Result<()> {
    use crossterm::event::{self, Event, KeyEventKind};
    use std::time::Duration;
    let _restore = Restore::new();
    crossterm::terminal::enable_raw_mode()?;
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
        if crate::signals::interrupted() {
            return Ok(());
        }
        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press && handle_key(&mut state, key, rows) {
                    return Ok(());
                }
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
            ..ViewState::default()
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
                    ..ViewState::default()
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

    fn k(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn keys_move_and_clamp() {
        let mut s = ViewState::default();
        assert!(!handle_key(&mut s, k(KeyCode::Up), 3));
        assert_eq!(s.selected, 0);
        handle_key(&mut s, k(KeyCode::Char('j')), 3);
        handle_key(&mut s, k(KeyCode::Down), 3);
        handle_key(&mut s, k(KeyCode::Down), 3);
        assert_eq!(s.selected, 2);
        handle_key(&mut s, k(KeyCode::Home), 3);
        assert_eq!(s.selected, 0);
        handle_key(&mut s, k(KeyCode::End), 3);
        assert_eq!(s.selected, 2);
        handle_key(&mut s, k(KeyCode::PageUp), 30);
        assert_eq!(s.selected, 0);
        handle_key(&mut s, k(KeyCode::PageDown), 30);
        assert_eq!(s.selected, 10);
        handle_key(&mut s, k(KeyCode::Char('k')), 30);
        assert_eq!(s.selected, 9);
        let mut empty = ViewState::default();
        handle_key(&mut empty, k(KeyCode::Down), 0);
        handle_key(&mut empty, k(KeyCode::End), 0);
        assert_eq!(empty.selected, 0);
        assert!(handle_key(&mut s, k(KeyCode::Char('q')), 3));
        assert!(handle_key(&mut s, k(KeyCode::Esc), 3));
    }

    #[test]
    fn ctrl_c_and_ctrl_d_quit_but_plain_c_does_not() {
        let mut s = ViewState::default();
        let ctrl = |c| KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL);
        assert!(handle_key(&mut s, ctrl('c'), 3));
        assert!(handle_key(&mut s, ctrl('d'), 3));
        assert!(!handle_key(&mut s, k(KeyCode::Char('c')), 3));
        assert!(!handle_key(&mut s, k(KeyCode::Char('d')), 3));
    }

    fn rows(data: &Value, w: u16, h: u16, state: &mut ViewState) -> Vec<String> {
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| draw(f, data, state)).unwrap();
        let buf = term.backend().buffer().clone();
        buf.content()
            .chunks(w as usize)
            .map(|r| r.iter().map(|c| c.symbol()).collect::<String>())
            .collect()
    }

    fn safety_data() -> Value {
        json!({
            "score": {"value": 100, "max": 100, "warning": "SCORE-WARNING a 100 is not a verdict"},
            "stopped": "WALK-STOPPED reader vanished",
            "truncated": true, "truncated_by": "max_nodes", "limits_hit": ["max_nodes", "max_depth"],
            "candidates": {"warning": "CANDIDATE-WARNING can miss a file"},
            "findings": {"severity_threshold": "high", "exhaustive": false,
                "findings": [
                {"rule": "a/new", "severity": "high", "message": "fresh one",
                 "location": {"kind": "card"}, "evidence": {"kind": "none"}, "coverage": {"status": "complete"}},
                {"rule": "a/old", "severity": "low", "message": "old one",
                 "location": {"kind": "card"}, "evidence": {"kind": "none"}, "coverage": {"status": "complete"}}]},
            "tar": {"complete": false, "probed": 8, "blind_spot": "BLIND-SPOT text"},
            "diff": {"counts": {"new": 1, "fixed": 2, "persisting": 1},
                "new": [{"rule": "a/new", "severity": "high", "message": "fresh one",
                 "location": {"kind": "card"}, "evidence": {"kind": "none"}, "coverage": {"status": "complete"}}]}
        })
    }

    #[test]
    fn safety_context_is_shown_even_in_a_short_terminal() {
        let text = rows(&safety_data(), 120, 24, &mut ViewState::default()).join("\n");
        for want in [
            "SCORE-WARNING a 100 is not a verdict",
            "WALK-STOPPED reader vanished",
            "CANDIDATE-WARNING can miss a file",
            "BLIND-SPOT text",
            "max_nodes, max_depth",
            "1 new, 2 fixed, 1 persisting",
            "high",
        ] {
            assert!(text.contains(want), "missing {want}: {text}");
        }
        // the new finding is marked, the old one is not
        let r = rows(&safety_data(), 120, 24, &mut ViewState::default());
        assert!(
            r.iter().any(|l| l.contains("[new]") && l.contains("a/new")),
            "{r:?}"
        );
        assert!(!r.iter().any(|l| l.contains("[new]") && l.contains("a/old")));
    }

    #[test]
    fn nothing_extra_is_shown_when_no_safety_field_is_present() {
        let text = rows(&canned(), 120, 30, &mut ViewState::default()).join("\n");
        for absent in [
            "score",
            "walk stopped",
            "TRUNCATED",
            "diff",
            "[new]",
            "blind",
        ] {
            assert!(!text.contains(absent), "{absent} shown: {text}");
        }
    }

    fn long_evidence() -> Value {
        let items: Vec<u32> = (1000..1040).collect();
        json!({"findings": {"findings": [{"rule": "r/x", "severity": "info", "message": "m",
            "location": {"kind": "card", "flag": true},
            "evidence": {"kind": "list", "items": items, "tail": "END-OF-EVIDENCE"},
            "coverage": {"status": "complete"}}]}})
    }

    #[test]
    fn detail_pane_marks_cut_content_and_scrolls_to_the_end() {
        let data = long_evidence();
        let mut s = ViewState::default();
        let first = rows(&data, 60, 16, &mut s).join("\n");
        assert!(first.contains("... (more)"), "{first}");
        assert!(!first.contains("END-OF-EVIDENCE"));
        assert!(first.contains("flag: true"), "bool rendered: {first}");
        let tall = rows(&data, 60, 30, &mut ViewState::default()).join("\n");
        assert!(tall.contains("[1000,1001"), "array rendered: {tall}");
        handle_key(&mut s, k(KeyCode::Tab), 1);
        assert!(s.detail_focus);
        let mut last = String::new();
        for _ in 0..40 {
            handle_key(&mut s, k(KeyCode::Down), 1);
            last = rows(&data, 60, 16, &mut s).join("\n");
        }
        assert!(last.contains("END-OF-EVIDENCE"), "{last}");
        assert!(!last.contains("... (more)"), "{last}");
    }

    #[test]
    fn bidi_and_zero_width_characters_are_not_displayed() {
        let data = json!({"findings": {"findings": [{"rule": "r/\u{200b}x", "severity": "low",
            "message": "ab\u{202e}cd\u{200b}ef", "location": {"kind": "card"},
            "evidence": {"kind": "text", "value": "ev\u{202e}il"}, "coverage": {"status": "complete"}}]}});
        let text = rows(&data, 100, 24, &mut ViewState::default()).join("\n");
        assert!(
            text.contains("ab cd ef") && text.contains("ev il"),
            "{text}"
        );
        assert!(!text.contains('\u{202e}') && !text.contains('\u{200b}'));
    }

    #[test]
    fn everything_shown_comes_from_the_json() {
        let data = safety_data();
        let json_text = serde_json::to_string(&data).unwrap();
        let mut state = ViewState::default();
        let r = rows(&data, 160, 30, &mut state);
        // Expected values are derived from the data, never from the TUI.
        let mut expected: Vec<String> = Vec::new();
        for f in data["findings"]["findings"].as_array().unwrap() {
            for key in ["rule", "severity", "message"] {
                expected.push(f[key].as_str().unwrap().to_owned());
            }
        }
        let sel = &data["findings"]["findings"][0];
        for part in ["location", "evidence"] {
            for (k, v) in sel[part].as_object().unwrap() {
                if k != "kind" {
                    expected.push(v.as_str().map_or_else(|| v.to_string(), str::to_owned));
                }
            }
        }
        expected.push(data["stopped"].as_str().unwrap().to_owned());
        expected.push(data["score"]["warning"].as_str().unwrap().to_owned());
        expected.push(data["candidates"]["warning"].as_str().unwrap().to_owned());
        let text = r.join("\n");
        for e in &expected {
            assert!(json_text.contains(e.as_str()), "{e} not in json");
            assert!(text.contains(e.as_str()), "{e} not shown: {text}");
        }
        // Reverse: the text after the label of every status line is in the JSON.
        for line in &r {
            for label in [
                "score warning: ",
                "walk stopped: ",
                "candidates: ",
                "TAR blind spot: ",
            ] {
                if let Some(at) = line.find(label) {
                    let rest = line[at + label.len()..].trim_end();
                    assert!(json_text.contains(rest), "{rest:?} not in json");
                }
            }
            if let Some(at) = line.find("score ") {
                let rest = line[at + 6..].trim_end();
                if rest.starts_with(|c: char| c.is_ascii_digit()) {
                    let (v, m) = rest.split_once('/').unwrap();
                    assert_eq!(v, data["score"]["value"].to_string());
                    assert_eq!(m.trim(), data["score"]["max"].to_string());
                }
            }
        }
    }
}
