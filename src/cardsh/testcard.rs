//! A small stateful UICC for the shell's tests (test builds only). Not a model of any real card: it
//! answers the commands the shell sends, the way ETSI TS 102 221 says a card does, so the shell's state
//! handling is exercised against something that remembers a selection.

use std::cell::RefCell;
use std::collections::{BTreeSet, VecDeque};
use std::rc::Rc;

use super::*;
use crate::transport::{Error as TransportError, ReaderName};

/// The USIM application's AID as EF.DIR lists it.
pub const USIM_AID: [u8; 12] = [
    0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02, 0xFF, 0x49, 0xFF, 0x05, 0x89,
];

/// A pseudo file identifier for "the application": ADFs have none of their own.
const ADF: u16 = 0x7FFF;

#[derive(Clone)]
pub struct File {
    pub path: Vec<u16>,
    pub df: bool,
    /// `None` for a DF; `Some(record_length)` for a record file (0 = transparent).
    pub rec_len: Option<usize>,
    pub content: Vec<Vec<u8>>,
}

pub struct TestCard {
    reader: ReaderName,
    pub files: Vec<File>,
    /// Current directory path, and the EF selected (path) if any, per channel.
    cur: [(Vec<u16>, Option<Vec<u16>>); 4],
    queued: VecDeque<Vec<u8>>,
    open: BTreeSet<u8>,
    pub sent: Rc<RefCell<Vec<Vec<u8>>>>,
}

fn f(path: &[u16], df: bool, rec_len: Option<usize>, content: Vec<Vec<u8>>) -> File {
    File {
        path: path.to_vec(),
        df,
        rec_len,
        content,
    }
}

impl TestCard {
    pub fn usim() -> Self {
        let mf = 0x3F00;
        let files = vec![
            f(&[mf], true, None, vec![]),
            f(
                &[mf, 0x2FE2],
                false,
                Some(0),
                vec![vec![
                    0x98, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98, 0x10, 0x32, 0x54,
                ]],
            ),
            f(
                &[mf, 0x2F00],
                false,
                Some(0x1C),
                vec![
                    [
                        &[0x61, 0x10, 0x4F, 0x0C][..],
                        &USIM_AID[..],
                        &[0x50, 0x04, b'U', b'S', b'I', b'M'],
                    ]
                    .concat()
                    .into_iter()
                    .chain(std::iter::repeat(0xFF))
                    .take(0x1C)
                    .collect(),
                    vec![0xFF; 0x1C],
                ],
            ),
            f(&[mf, ADF], true, None, vec![]),
            // IMSI 001010123456789: 08 09 10 10 21 43 65 87 F9
            f(
                &[mf, ADF, 0x6F07],
                false,
                Some(0),
                vec![vec![0x08, 0x09, 0x10, 0x10, 0x21, 0x43, 0x65, 0x87, 0xF9]],
            ),
            // EF.AD: operation mode normal, MNC length 2.
            f(
                &[mf, ADF, 0x6FAD],
                false,
                Some(0),
                vec![vec![0x00, 0x00, 0x00, 0x02]],
            ),
            f(&[mf, 0x7F10], true, None, vec![]),
            f(
                &[mf, 0x7F10, 0x6F3A],
                false,
                Some(0x1C),
                vec![
                    // "Ann" 0123456789 (alpha 14, then BCD number)
                    [
                        &b"Ann"[..],
                        &[0xFF; 11],
                        &[
                            0x07, 0x81, 0x10, 0x32, 0x54, 0x76, 0x98, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                            0xFF, 0xFF,
                        ],
                    ]
                    .concat(),
                    vec![0xFF; 0x1C],
                    vec![0xFF; 0x1C],
                ],
            ),
            f(
                &[mf, 0x7F10, 0x6F99],
                false,
                Some(0),
                vec![(0..300u16).map(|i| (i % 251) as u8).collect()],
            ),
            f(&[mf, 0x7F20], true, None, vec![]),
            f(
                &[mf, 0x7F20, 0x6F07],
                false,
                Some(0),
                vec![vec![0x08, 0x29, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10]],
            ),
        ];
        Self {
            reader: ReaderName::new("test card").unwrap(),
            files,
            cur: std::array::from_fn(|_| (vec![mf], None)),
            queued: VecDeque::new(),
            open: BTreeSet::from([0]),
            sent: Rc::default(),
        }
    }

    fn find(&self, path: &[u16]) -> Option<&File> {
        self.files.iter().find(|f| f.path == path)
    }

    fn fcp(&self, file: &File) -> Vec<u8> {
        let fid = *file.path.last().unwrap();
        let mut body = Vec::new();
        if file.df {
            body.extend_from_slice(&[0x82, 0x02, 0x38, 0x21]);
        } else if let Some(len) = file.rec_len.filter(|l| *l > 0) {
            let l = len as u16;
            body.extend_from_slice(&[
                0x82,
                0x05,
                0x0A,
                0x21,
                (l >> 8) as u8,
                l as u8,
                file.content.len() as u8,
            ]);
        } else {
            body.extend_from_slice(&[0x82, 0x02, 0x09, 0x21]);
        }
        if fid != ADF {
            body.extend_from_slice(&[0x83, 0x02, (fid >> 8) as u8, fid as u8]);
        } else {
            body.extend_from_slice(&[0x84, USIM_AID.len() as u8]);
            body.extend_from_slice(&USIM_AID);
        }
        if !file.df {
            let size = match file.rec_len {
                Some(l) if l > 0 => l * file.content.len(),
                _ => file.content.first().map_or(0, Vec::len),
            };
            body.extend_from_slice(&[0x80, 0x02, (size >> 8) as u8, size as u8]);
        }
        body.extend_from_slice(&[0x8A, 0x01, 0x05]);
        let mut out = vec![0x62, body.len() as u8];
        out.extend(body);
        out
    }

    /// Answers SELECT: `61 len` and the FCP queued behind it.
    fn select_ok(&mut self, ch: usize, dir: Vec<u16>, ef: Option<Vec<u16>>, p2: u8) -> Vec<u8> {
        let target = ef.clone().unwrap_or_else(|| dir.clone());
        let file = self.find(&target).cloned().unwrap();
        self.cur[ch] = (dir, ef);
        if p2 & 0x0C == 0x0C {
            return vec![0x90, 0x00];
        }
        let fcp = self.fcp(&file);
        let n = fcp.len() as u8;
        self.queued = VecDeque::from([fcp]);
        vec![0x61, n]
    }

    fn select(&mut self, ch: usize, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
        let (dir, _) = self.cur[ch].clone();
        let ids: Vec<u16> = data
            .chunks(2)
            .map(|c| u16::from_be_bytes([c[0], c.get(1).copied().unwrap_or(0)]))
            .collect();
        match p1 {
            0x00 if ids.len() == 1 => {
                let id = ids[0];
                if id == 0x3F00 {
                    return self.select_ok(ch, vec![0x3F00], None, p2);
                }
                let mut child = dir.clone();
                child.push(id);
                if let Some(file) = self.find(&child) {
                    return if file.df {
                        self.select_ok(ch, child, None, p2)
                    } else {
                        self.select_ok(ch, dir, Some(child), p2)
                    };
                }
                if dir.last() == Some(&id) {
                    return self.select_ok(ch, dir, None, p2);
                }
                if dir.len() > 1 && dir[dir.len() - 2..][0] == id || dir.len() == 2 && id == 0x3F00
                {
                    let parent = dir[..dir.len() - 1].to_vec();
                    return self.select_ok(ch, parent, None, p2);
                }
                vec![0x6A, 0x82]
            }
            0x08 | 0x09 => {
                let mut path = if p1 == 0x08 { vec![0x3F00] } else { dir };
                path.extend(ids);
                match self.find(&path) {
                    Some(file) if file.df => self.select_ok(ch, path, None, p2),
                    Some(_) => {
                        let d = path[..path.len() - 1].to_vec();
                        self.select_ok(ch, d, Some(path), p2)
                    }
                    None => vec![0x6A, 0x82],
                }
            }
            0x04 if data.len() >= 5 && USIM_AID.starts_with(data) || data == USIM_AID => {
                self.select_ok(ch, vec![0x3F00, ADF], None, p2)
            }
            _ => vec![0x6A, 0x82],
        }
    }

    fn read(&mut self, ch: usize, cmd: &[u8]) -> Vec<u8> {
        let (dir, ef) = self.cur[ch].clone();
        let Some(file) = ef.and_then(|p| self.find(&p).cloned()) else {
            let _ = dir;
            return vec![0x69, 0x86];
        };
        let le = match cmd.get(4) {
            Some(0) | None => 256,
            Some(n) => usize::from(*n),
        };
        let (p1, p2) = (cmd[2], cmd[3]);
        if cmd[1] == 0xB0 {
            if file.rec_len.is_some_and(|l| l > 0) {
                return vec![0x69, 0x81];
            }
            let off = (usize::from(p1 & 0x7F) << 8) | usize::from(p2);
            let data = &file.content[0];
            if off > data.len() {
                return vec![0x6B, 0x00];
            }
            let avail = data.len() - off;
            if le > avail {
                return vec![0x6C, avail as u8];
            }
            let mut r = data[off..off + le].to_vec();
            r.extend_from_slice(&[0x90, 0x00]);
            r
        } else {
            let Some(rl) = file.rec_len.filter(|l| *l > 0) else {
                return vec![0x69, 0x81];
            };
            if p2 != 0x04 && p2 != 0x02 && p2 != 0x03 {
                return vec![0x6B, 0x00];
            }
            let n = usize::from(p1);
            if n == 0 || n > file.content.len() {
                return vec![0x6A, 0x83];
            }
            if le != rl && le != 256 {
                return vec![0x6C, rl as u8];
            }
            let mut r = file.content[n - 1].clone();
            r.extend_from_slice(&[0x90, 0x00]);
            r
        }
    }
}

impl CardSession for TestCard {
    fn reader(&self) -> &ReaderName {
        &self.reader
    }

    fn transmit(&mut self, c: &[u8]) -> Result<Vec<u8>, TransportError> {
        self.sent.borrow_mut().push(c.to_vec());
        if c.len() < 4 {
            return Ok(vec![0x67, 0x00]);
        }
        let ch = usize::from(if c[0] & 0x40 == 0 {
            c[0] & 0x03
        } else {
            4 + (c[0] & 0x0F)
        })
        .min(3);
        let data: &[u8] = if c.len() > 5 {
            &c[5..5 + usize::from(c[4]).min(c.len() - 5)]
        } else {
            &[]
        };
        let ins = c[1];
        Ok(match ins {
            0xA4 => self.select(ch, c[2], c[3], data),
            0xC0 => match self.queued.pop_front() {
                Some(mut r) => {
                    r.extend_from_slice(&[0x90, 0x00]);
                    r
                }
                None => vec![0x6F, 0x00],
            },
            0xB0 | 0xB2 => self.read(ch, c),
            0x70 => {
                if c[2] == 0x00 {
                    match (1u8..=3).find(|n| !self.open.contains(n)) {
                        Some(n) => {
                            self.open.insert(n);
                            self.cur[usize::from(n)] = (vec![0x3F00], None);
                            vec![n, 0x90, 0x00]
                        }
                        None => vec![0x68, 0x81],
                    }
                } else if self.open.remove(&c[3]) {
                    vec![0x90, 0x00]
                } else {
                    vec![0x6A, 0x86]
                }
            }
            0xF2 => vec![0x90, 0x00],
            _ => vec![0x6D, 0x00],
        })
    }

    fn disconnect(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
}

/// A shell on a fresh [`TestCard::usim`] (a new one for every `equip`), and the log of every command
/// the cards were sent.
pub fn shell_log() -> (Shell, Rc<RefCell<Vec<Vec<u8>>>>) {
    let log: Rc<RefCell<Vec<Vec<u8>>>> = Rc::default();
    let sent = log.clone();
    let mut sh = Shell::new(
        Box::new(move |_| {
            let mut card = TestCard::usim();
            card.sent = sent.clone();
            Ok((
                Box::new(card) as Box<dyn CardSession>,
                "test card".to_owned(),
                Some(vec![0x3B, 0x9F]),
            ))
        }),
        Opts {
            yes: false,
            dialect: TagSet::ts_102_221(),
        },
    );
    sh.equip(None, Profile::Uicc).unwrap();
    (sh, log)
}

pub fn shell_on(_card: TestCard) -> Shell {
    shell_log().0
}

/// A writer into a shared buffer, so a [`Record`](crate::transport::replay::Record) log can be read back.
#[derive(Clone, Default)]
struct Sink(Rc<RefCell<Vec<u8>>>);

impl std::io::Write for Sink {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Runs `script` (`;`-separated) on a fresh test card with `--yes` as given and returns the recorded
/// exchange log (the `SIM_DOCTOR_RECORD` format) and the replies.
pub fn record(script: &str, yes: bool) -> (String, Vec<Reply>) {
    let sink = Sink::default();
    let log = sink.clone();
    let mut sh = Shell::new(
        Box::new(move |_| {
            let rec = crate::transport::replay::Record::new(TestCard::usim(), log.clone());
            Ok((
                Box::new(rec) as Box<dyn CardSession>,
                "test card".to_owned(),
                None,
            ))
        }),
        Opts {
            yes,
            dialect: TagSet::ts_102_221(),
        },
    );
    sh.equip(None, Profile::Uicc).unwrap();
    let replies = split_commands(script).iter().map(|l| sh.exec(l)).collect();
    let text = String::from_utf8(sink.0.borrow().clone()).unwrap();
    (text, replies)
}

/// The scripts whose recordings are committed under `tests/corpus/` for the process tests:
/// (file name, `--yes`, script).
pub const FIXTURES: &[(&str, bool, &str)] = &[
    (
        "cardsh_channels.jsonl",
        false,
        "open_channel; status; channel 0; status; close_channel 1; status",
    ),
    (
        "cardsh_apdu.jsonl",
        false,
        "apdu 00A4000C022FE2; apdu 00B000000A --expect-response-regex ^9810; apdu 00D6000001AA; \
         apdu --yes 00D6000001AA --expect-sw 6Dxx",
    ),
    (
        "cardsh_select.jsonl",
        false,
        "select 3F00; select 7F20; select 6F07; select 3F00; select 3F00/7F10/6F3A; select ADF.USIM; \
         select EF.IMSI; select_path 6FAD; select 2FE2",
    ),
    (
        "cardsh_read.jsonl",
        false,
        "select 2FE2; read_binary; read_binary --offset 2 --length 3; read_binary --length 20; select 3F00/7F10/6F3A; \
         read_record 1; read_records; read_record 4; select 3F00/7F10/6F99; read_binary",
    ),
];

fn fixture_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/corpus")
        .join(name)
}

#[test]
fn committed_fixtures_match_a_fresh_recording() {
    for (name, yes, script) in FIXTURES {
        let want = std::fs::read_to_string(fixture_path(name))
            .unwrap_or_else(|e| panic!("{name}: {e}; run the ignored regenerate_fixtures test"));
        assert_eq!(
            want,
            record(script, *yes).0,
            "{name} drifted from the test card"
        );
    }
}

#[test]
#[ignore = "regenerates tests/corpus/cardsh_*.jsonl"]
fn regenerate_fixtures() {
    for (name, yes, script) in FIXTURES {
        std::fs::write(fixture_path(name), record(script, *yes).0).unwrap();
    }
}
