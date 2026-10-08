//! Record/replay wrappers for [`CardSession`] (issue #120, after euicc-lpa).
//!
//! **Owns.** [`Record`], which forwards to a real session and logs each
//! exchange, and [`Replay`], which answers from such a log with no reader.
//!
//! **Log format.** JSON lines, one object per successful exchange, in order:
//! `{"command":"00a4...","response":"6100"}` (lowercase hex). A transmit that
//! errors is not logged, so a recording of a run that hit a transport error
//! replays as "log exhausted" at that point rather than inventing a response.
//!
//! **Match rule.** Exact bytes, in recorded order. Replay does not search the
//! log: the first command that differs from the next recorded one, or any
//! command after the log ends, is an error naming the position and both
//! commands. A silent mismatch would turn a regression test into a rubber stamp.
//!
//! **Live use.** `SIM_DOCTOR_RECORD=<path> sim-doctor scan ...` wraps the
//! scan's session in [`Record`] (see `main.rs`). The log holds raw card
//! output, so it is data about a real card: review it before committing it.

use std::fmt::Write as _;
use std::io::Write;

use super::{CardSession, Error, ReaderName};

/// Name replay sessions report; there is no real reader behind them.
const REPLAY_READER: &str = "replay";

fn driver(reader: &ReaderName, detail: String) -> Error {
    Error::Driver {
        reader: reader.clone(),
        detail,
    }
}

/// Wraps a session and appends every exchange to `log`.
pub struct Record<S, W: Write> {
    inner: S,
    log: W,
}

impl<S: CardSession, W: Write> Record<S, W> {
    /// Forwards to `inner`, writing one JSON line per exchange to `log`.
    pub fn new(inner: S, log: W) -> Self {
        Self { inner, log }
    }

    /// Gives the log writer back, for example to read a `Vec<u8>` in a test.
    pub fn into_log(self) -> W {
        self.log
    }
}

impl<S: CardSession, W: Write> CardSession for Record<S, W> {
    fn reader(&self) -> &ReaderName {
        self.inner.reader()
    }

    fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>, Error> {
        let response = self.inner.transmit(command)?;
        let line = format!(
            "{{\"command\":\"{}\",\"response\":\"{}\"}}\n",
            hex::encode(command),
            hex::encode(&response)
        );
        // Flushed per line so a Ctrl-C mid-scan still leaves a usable prefix.
        self.log
            .write_all(line.as_bytes())
            .and_then(|()| self.log.flush())
            .map_err(|e| driver(self.inner.reader(), format!("writing the record log: {e}")))?;
        Ok(response)
    }

    fn disconnect(&mut self) -> Result<(), Error> {
        self.inner.disconnect()
    }
}

/// Answers from a recorded log; no reader, no inner session.
#[derive(Debug)]
pub struct Replay {
    reader: ReaderName,
    exchanges: Vec<(Vec<u8>, Vec<u8>)>,
    next: usize,
}

impl Replay {
    /// Parses a log written by [`Record`].
    ///
    /// # Errors
    ///
    /// A line that is not the expected JSON object with two hex strings.
    pub fn from_log(log: &str) -> Result<Self, String> {
        let mut exchanges = Vec::new();
        for (n, line) in log
            .lines()
            .enumerate()
            .filter(|(_, l)| !l.trim().is_empty())
        {
            let at = |e: String| format!("log line {}: {e}", n + 1);
            let value: serde_json::Value =
                serde_json::from_str(line).map_err(|e| at(e.to_string()))?;
            let field = |key: &str| {
                let text = value.get(key).and_then(|v| v.as_str());
                hex::decode(text.ok_or_else(|| at(format!("missing string `{key}`")))?)
                    .map_err(|e| at(format!("`{key}` is not hex: {e}")))
            };
            exchanges.push((field("command")?, field("response")?));
        }
        Ok(Self {
            reader: ReaderName::new(REPLAY_READER).expect("a fixed valid name"),
            exchanges,
            next: 0,
        })
    }

    /// Exchanges recorded but not yet asked for. Zero means the run consumed
    /// the whole log; a test should assert it.
    pub fn remaining(&self) -> usize {
        self.exchanges.len() - self.next
    }
}

impl CardSession for Replay {
    fn reader(&self) -> &ReaderName {
        &self.reader
    }

    fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>, Error> {
        let position = self.next;
        let Some((expected, response)) = self.exchanges.get(position) else {
            return Err(driver(
                &self.reader,
                format!(
                    "replay diverged: command {position} ({}) came after the log ended",
                    hex::encode(command)
                ),
            ));
        };
        if expected != command {
            let mut detail = format!("replay diverged at command {position}: recorded ");
            let _ = write!(
                detail,
                "{}, sent {}",
                hex::encode(expected),
                hex::encode(command)
            );
            return Err(driver(&self.reader, detail));
        }
        self.next += 1;
        Ok(response.clone())
    }

    fn disconnect(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fcp::TagSet;
    use crate::walk::{self, Candidates, Options};

    /// Committed synthetic log: a master file and nothing else. Generated
    /// from [`TinyCard`]; contains no real card data.
    const FIXTURE: &str = include_str!("../../tests/corpus/replay_tiny_walk.jsonl");

    /// A card with only a master file (FCP: DF, id 3F00).
    struct TinyCard(ReaderName);

    impl CardSession for TinyCard {
        fn reader(&self) -> &ReaderName {
            &self.0
        }
        fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>, Error> {
            Ok(match (command.get(1), command.get(5..)) {
                (Some(0xA4), Some([0x3F, 0x00])) => vec![0x61, 0x0F],
                (Some(0xC0), _) => {
                    let mut r = vec![
                        0x62, 0x0D, 0x82, 0x02, 0x38, 0x21, 0x83, 0x02, 0x3F, 0x00, 0x8A, 0x01,
                        0x05,
                    ];
                    r.extend_from_slice(&[0x90, 0x00]);
                    r
                }
                _ => vec![0x6A, 0x82],
            })
        }
        fn disconnect(&mut self) -> Result<(), Error> {
            Ok(())
        }
    }

    fn options() -> Options {
        Options {
            candidates: Candidates::List(vec!["7F20".parse().unwrap(), "6F07".parse().unwrap()]),
            ..Options::default()
        }
    }

    fn record_walk() -> (String, String) {
        let card = TinyCard(ReaderName::new("tiny").unwrap());
        let mut rec = Record::new(card, Vec::new());
        let tree = walk::walk(&mut rec, &TagSet::swicc(), &options()).unwrap();
        (
            String::from_utf8(rec.into_log()).unwrap(),
            format!("{tree:?}"),
        )
    }

    #[test]
    fn replay_reproduces_the_recorded_walk() {
        let (log, direct) = record_walk();
        let mut replay = Replay::from_log(&log).unwrap();
        let tree = walk::walk(&mut replay, &TagSet::swicc(), &options()).unwrap();
        assert_eq!(format!("{tree:?}"), direct);
        assert_eq!(replay.remaining(), 0);
    }

    #[test]
    fn double_capture_is_byte_equal() {
        assert_eq!(record_walk().0, record_walk().0);
    }

    #[test]
    fn committed_log_replays_through_the_walk_and_matches_a_fresh_capture() {
        let mut replay = Replay::from_log(FIXTURE).unwrap();
        let tree = walk::walk(&mut replay, &TagSet::swicc(), &options()).unwrap();
        assert_eq!(replay.remaining(), 0);
        assert_eq!(format!("{tree:?}"), record_walk().1);
        assert_eq!(FIXTURE, record_walk().0, "fixture drifted from the walk");
    }

    #[test]
    fn divergence_and_exhaustion_are_errors() {
        let (log, _) = record_walk();
        let mut replay = Replay::from_log(&log).unwrap();
        let err = replay
            .transmit(&[0x00, 0xB0, 0x00, 0x00, 0x01])
            .unwrap_err();
        assert!(err.to_string().contains("diverged at command 0"), "{err}");

        let mut empty = Replay::from_log("").unwrap();
        let err = empty.transmit(&[0x00]).unwrap_err();
        assert!(err.to_string().contains("after the log ended"), "{err}");
    }

    #[test]
    #[ignore = "regenerates tests/corpus/replay_tiny_walk.jsonl"]
    fn regenerate_fixture() {
        std::fs::write(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/corpus/replay_tiny_walk.jsonl"
            ),
            record_walk().0,
        )
        .unwrap();
    }

    #[test]
    fn a_malformed_log_is_rejected() {
        assert!(Replay::from_log("not json").is_err());
        assert!(Replay::from_log(r#"{"command":"zz","response":"9000"}"#).is_err());
    }
}
