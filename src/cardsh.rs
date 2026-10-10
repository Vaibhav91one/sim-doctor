//! The card shell: a command interpreter over one card that keeps its state between commands.
//!
//! **Owns.** [`Shell`], the state a pySim-shell style session carries (the equipped card, the logical
//! channel in use, and per channel the directory path and the selected file), the command grammar
//! ([`grammar`]) and the one entry point [`Shell::exec`] that runs a line and returns a [`Reply`].
//! `sim-doctor card` (main.rs) is the loop around it: interactive on a terminal, `-c "a; b"` for scripts,
//! `--json` for agents (one record per command).
//!
//! **Does not own.** Opening a reader (the caller hands in an [`Opener`], so a test or a replay log can
//! stand in for PC/SC), the wire protocol ([`crate::session`], [`crate::apdu`]) or the file decoders
//! ([`crate::ef`]).
//!
//! **Safety.** Reads (SELECT, READ BINARY, READ RECORD, STATUS, GET RESPONSE, MANAGE CHANNEL) are sent.
//! Anything else is a dry run that prints the APDU it would send unless `--yes` was given (to the
//! shell or to the command). Secrets (PINs, keys) never come from the command line: they come from a
//! file or an environment variable named at start-up.
//!
//! Reference behaviour: pySim-shell (`osmocom/pysim`, `pySim-shell.py`): `equip`, `apdu`, `select`.
//! The command set and the flag names follow it; the code is written here.

/// This module's name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "cardsh";

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::apdu::{self, Command, StatusWord};
use crate::fcp::{self, TagSet};
use crate::fs::{self, FileId};
use crate::session::{self, PendingFollowUp, Policy};
use crate::transport::CardSession;

/// What an [`Opener`] returns: the session, the reader's name and the ATR when the transport has one.
pub type Opened = (Box<dyn CardSession>, String, Option<Vec<u8>>);

/// Opens a card, optionally on a named reader. `equip` calls it again.
pub type Opener = Box<dyn FnMut(Option<&str>) -> Result<Opened, String>>;

/// Which command set the card speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// A UICC (ETSI TS 102 221): class `00`, SELECT asks for the FCP.
    Uicc,
    /// A GSM SIM (3GPP TS 51.011): class `A0`, SELECT answers `9F xx` and GET RESPONSE follows.
    Sim,
}

impl Profile {
    /// The spelling `--profile` takes.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Uicc => "uicc",
            Self::Sim => "sim",
        }
    }

    /// The class byte of this profile's commands (before the channel is applied).
    pub const fn cla(self) -> u8 {
        match self {
            Self::Uicc => 0x00,
            Self::Sim => 0xA0,
        }
    }
}

/// What the interpreter was started with.
#[derive(Debug, Clone)]
pub struct Opts {
    /// Send state-changing commands instead of printing them.
    pub yes: bool,
    /// Which FCP tag table the card answers SELECT with.
    pub dialect: TagSet,
}

/// What `select` learned about a file from its FCP.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FileInfo {
    /// The file identifier, when the selection or the FCP gave one.
    pub fid: Option<FileId>,
    /// The DF name (AID), for an application.
    pub name: Option<Vec<u8>>,
    /// A directory (MF, DF, ADF) rather than an elementary file.
    pub is_df: bool,
    /// `transparent`, `linear-fixed`, `linear-variable`, `cyclic`, when it is an EF.
    pub structure: Option<&'static str>,
    /// The file size in octets (an EF's body).
    pub size: Option<u32>,
    /// The record length of a record-structured EF.
    pub record_length: Option<u16>,
    /// The number of records of a record-structured EF.
    pub records: Option<u16>,
    /// The raw FCP the card sent, upper-case hex.
    pub fcp: String,
}

/// One logical channel's view of the card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chan {
    /// The directories from the master file down to the current DF.
    pub dir: Vec<FileId>,
    /// The AID of the application selected on this channel, when one is.
    pub adf: Option<Vec<u8>>,
    /// The selected file (the current DF's own info until an EF is selected).
    pub file: Option<FileInfo>,
}

impl Default for Chan {
    fn default() -> Self {
        Self {
            dir: vec![FileId::MASTER_FILE],
            adf: None,
            file: None,
        }
    }
}

impl Chan {
    /// `3F00/7F20/6F07` or `3F00/ADF:A0000000871002/6F07`.
    pub fn path(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        for (i, id) in self.dir.iter().enumerate() {
            if i == 1 {
                if let Some(aid) = &self.adf {
                    parts.push(format!("ADF:{}", hex_upper(aid)));
                    continue;
                }
            }
            parts.push(id.to_string());
        }
        if let Some(file) = self.file.as_ref().filter(|f| !f.is_df) {
            if let Some(fid) = file.fid {
                parts.push(fid.to_string());
            }
        }
        parts.join("/")
    }
}

/// The answer to one command line.
#[derive(Debug, Clone)]
pub struct Reply {
    /// The command did what it was asked to.
    pub ok: bool,
    /// What a person reads.
    pub text: String,
    /// What an agent reads.
    pub data: Value,
    /// The shell should end.
    pub quit: bool,
}

impl Reply {
    fn ok(text: impl Into<String>, data: Value) -> Self {
        Self {
            ok: true,
            text: text.into(),
            data,
            quit: false,
        }
    }

    fn failed(text: impl Into<String>, data: Value) -> Self {
        Self {
            ok: false,
            text: text.into(),
            data,
            quit: false,
        }
    }

    /// The record `--json` prints for the command `line`: one object, compact.
    pub fn record(&self, line: &str) -> String {
        let mut record = json!({ "command": line, "ok": self.ok });
        if !self.data.is_null() {
            record["data"] = self.data.clone();
        }
        if !self.ok {
            record["error"] = json!(self.text);
        }
        record.to_string()
    }
}

/// A command that could not do its job.
#[derive(Debug)]
pub struct CmdErr {
    /// The sentence a person reads.
    pub message: String,
    /// What an agent reads next to `ok: false`.
    pub data: Value,
}

impl CmdErr {
    /// A failure with only a sentence.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            data: Value::Null,
        }
    }
}

impl From<session::Error> for CmdErr {
    fn from(e: session::Error) -> Self {
        Self::new(e.to_string())
    }
}

impl From<crate::transport::Error> for CmdErr {
    fn from(e: crate::transport::Error) -> Self {
        Self::new(e.to_string())
    }
}

type CmdResult = Result<Reply, CmdErr>;

struct Equipped {
    session: Box<dyn CardSession>,
    reader: String,
    atr: Option<Vec<u8>>,
    profile: Profile,
    chans: BTreeMap<u8, Chan>,
    channel: u8,
}

impl Equipped {
    /// The class byte of a command of this profile on the channel in use.
    fn cla(&self) -> u8 {
        apdu::class_on_channel(self.profile.cla(), self.channel).unwrap_or(self.profile.cla())
    }

    /// Sends one logical command, following GET RESPONSE. A pending proactive command is never
    /// fetched on its own: FETCH is a command the operator types.
    fn send(&mut self, command: &Command) -> Result<session::Exchange, CmdErr> {
        let policy = Policy {
            proactive_command: PendingFollowUp::Ignore,
            ..Policy::default()
        };
        Ok(session::send(self.session.as_mut(), command, &policy)?)
    }
}

/// One SELECT the shell sends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectBy {
    /// By file identifier, in the current DF (or the MF, its parent, itself).
    Fid(FileId),
    /// An application by (possibly partial) AID.
    Aid(Vec<u8>),
    /// Absolute from the master file, the MF's own identifier left out.
    AbsPath(Vec<FileId>),
    /// Relative to the current DF.
    RelPath(Vec<FileId>),
}

/// The placeholder identifier an application sits under in [`Chan::dir`] (ADFs have none).
const ADF_FID: FileId = FileId::from_bytes([0x7F, 0xFF]);

/// `select_path` takes a path whether or not it starts with `/`; a bare path with no `/` must still
/// be read as a path, so it gets a leading `./`.
fn path_arg(path: &str) -> String {
    if path.contains('/') {
        path.to_owned()
    } else {
        format!("./{path}")
    }
}

/// Is this a DF by its identifier alone (3F, 7F, 5F)? Only used when the card sent no FCP.
fn df_by_fid(fid: FileId) -> bool {
    matches!(fid.to_bytes()[0], 0x3F | 0x7F | 0x5F)
}

/// Reads a GSM 11.11 SELECT response (`sim` profile): size, file id, type, structure.
fn read_gsm_response(body: &[u8]) -> FileInfo {
    let mut info = FileInfo {
        fcp: hex_upper(body),
        ..FileInfo::default()
    };
    if body.len() >= 7 {
        info.size = Some(u32::from(u16::from_be_bytes([body[2], body[3]])));
        info.fid = Some(FileId::from_bytes([body[4], body[5]]));
        info.is_df = matches!(body[6], 1 | 2);
        if !info.is_df && body.len() >= 15 {
            info.structure = Some(match body[13] {
                0 => "transparent",
                1 => "linear-fixed",
                3 => "cyclic",
                _ => "unknown",
            });
            if body[13] != 0 && body[14] > 0 {
                let rl = u16::from(body[14]);
                info.record_length = Some(rl);
                info.records = info.size.map(|sz| (sz / u32::from(rl)) as u16);
            }
        }
    }
    info
}

/// A record whose octets are all `FF` is unused.
fn is_empty_record(data: &[u8]) -> bool {
    !data.is_empty() && data.iter().all(|b| *b == 0xFF)
}

impl Equipped {
    /// The EF that is selected, or the sentence saying there is none.
    fn ef(&self) -> Result<FileInfo, CmdErr> {
        match &self.chans[&self.channel].file {
            Some(f) if !f.is_df => Ok(f.clone()),
            Some(_) => Err(CmdErr::new(
                "a directory is selected, not an elementary file: `select` an EF first",
            )),
            None => Err(CmdErr::new("no file selected: `select` an EF first")),
        }
    }

    /// One read command with `le` bytes asked for; a `6C xx` (the card says it holds `xx`) is answered
    /// with exactly one corrected re-send, the standard answer to a short file, and never more.
    fn read(&mut self, ins: u8, p1: u8, p2: u8, le: u32) -> Result<Vec<u8>, CmdErr> {
        let cla = self.cla();
        let header = apdu::Header::new(cla, ins, p1, p2);
        let mut want = le;
        for attempt in 0..2 {
            let le =
                apdu::Le::for_byte_count(want).ok_or_else(|| CmdErr::new("a read of no bytes"))?;
            let ex = self.send(&Command::case2(header, le))?;
            let sw = ex.status();
            if attempt == 0 {
                if let Some(n) = sw.and_then(|s| match s.corrected_length() {
                    Some(apdu::CorrectedLength::Accepts(n)) => Some(n),
                    _ => None,
                }) {
                    want = u32::from(n);
                    continue;
                }
            }
            if !sw.is_some_and(StatusWord::is_normal_processing) {
                return Err(CmdErr {
                    message: format!(
                        "{} refused: {}",
                        if ins == 0xB0 {
                            "READ BINARY"
                        } else {
                            "READ RECORD"
                        },
                        sw_text(sw)
                    ),
                    data: json!({ "sw": sw.map(|s| s.to_string()) }),
                });
            }
            return Ok(ex.data().to_vec());
        }
        unreachable!("the second attempt always returns")
    }

    /// READ BINARY of `length` bytes from `offset`, in reads of at most 256.
    fn read_binary(&mut self, offset: u16, length: u32) -> Result<Vec<u8>, CmdErr> {
        let mut out = Vec::new();
        while (out.len() as u32) < length {
            let at = u32::from(offset) + out.len() as u32;
            if at > 0x7FFF {
                return Err(CmdErr::new(
                    "READ BINARY addresses 32767 bytes at most (P1-P2 offset)",
                ));
            }
            let want = (length - out.len() as u32).min(256);
            let chunk = self.read(0xB0, (at >> 8) as u8, at as u8, want)?;
            let short = (chunk.len() as u32) < want;
            out.extend_from_slice(&chunk);
            // The card held less than asked for (the end of the file): that is all there is.
            if short {
                break;
            }
        }
        Ok(out)
    }

    /// Sends one SELECT and returns what the card said about the file.
    fn select(&mut self, by: &SelectBy, dialect: &TagSet) -> Result<FileInfo, CmdErr> {
        let (header, data) = match (by, self.profile) {
            (SelectBy::Fid(id), Profile::Uicc) => {
                (fs::select_capabilities_header(), id.to_bytes().to_vec())
            }
            (SelectBy::Fid(id), Profile::Sim) => {
                (apdu::Header::new(0, 0xA4, 0, 0), id.to_bytes().to_vec())
            }
            (SelectBy::Aid(aid), Profile::Uicc) => (fs::select_aid_header(), aid.clone()),
            (SelectBy::AbsPath(ids), Profile::Uicc) => (fs::select_path_header(), flat(ids)),
            (SelectBy::RelPath(ids), Profile::Uicc) => {
                (fs::select_from_current_df_header(), flat(ids))
            }
            (_, Profile::Sim) => {
                return Err(CmdErr::new(
                    "the sim profile (GSM 11.11) selects by file identifier only",
                ))
            }
        };
        let h = header;
        let cla = self.cla();
        let command = Command::case3(
            apdu::Header::new(cla, h.instruction(), h.parameter_1(), h.parameter_2()),
            data,
        );
        let ex = self.send(&command)?;
        let sw = ex.status();
        if !sw.is_some_and(StatusWord::is_normal_processing) {
            return Err(CmdErr {
                message: format!("SELECT {} refused: {}", describe(by), sw_text(sw)),
                data: json!({ "sw": sw.map(|s| s.to_string()) }),
            });
        }
        Ok(if self.profile == Profile::Sim {
            read_gsm_response(ex.data())
        } else {
            read_fcp(ex.data(), dialect)
        })
    }

    /// Moves the channel's selection to where `by` landed.
    fn land(&mut self, by: &SelectBy, mut info: FileInfo) -> FileInfo {
        let chan = self
            .chans
            .get_mut(&self.channel)
            .expect("the channel in use is open");
        let target = match by {
            SelectBy::Fid(id) => Some(*id),
            SelectBy::AbsPath(ids) | SelectBy::RelPath(ids) => ids.last().copied(),
            SelectBy::Aid(_) => None,
        };
        if info.fid.is_none() {
            info.fid = target;
        }
        // Without an FCP the identifier decides what it is.
        if info.fcp.is_empty() {
            info.is_df = info.fid.is_some_and(df_by_fid);
        }
        match by {
            SelectBy::Aid(aid) => {
                chan.dir = vec![FileId::MASTER_FILE, ADF_FID];
                chan.adf = Some(info.name.clone().unwrap_or_else(|| aid.clone()));
            }
            SelectBy::Fid(id) if *id == FileId::MASTER_FILE => {
                chan.dir = vec![FileId::MASTER_FILE];
                chan.adf = None;
            }
            SelectBy::Fid(id) => {
                if info.is_df {
                    if chan.dir.len() > 1 && chan.dir[chan.dir.len() - 2] == *id {
                        chan.dir.pop();
                        if chan.dir.len() == 1 {
                            chan.adf = None;
                        }
                    } else if chan.dir.last() != Some(id) {
                        chan.dir.push(*id);
                    }
                }
            }
            SelectBy::AbsPath(ids) => {
                chan.adf = None;
                chan.dir = std::iter::once(FileId::MASTER_FILE)
                    .chain(ids.iter().copied())
                    .collect();
                if !info.is_df {
                    chan.dir.pop();
                }
            }
            SelectBy::RelPath(ids) => {
                chan.dir.extend(ids.iter().copied());
                if !info.is_df {
                    chan.dir.pop();
                }
            }
        }
        chan.file = Some(info.clone());
        info
    }
}

fn flat(ids: &[FileId]) -> Vec<u8> {
    ids.iter().flat_map(|i| i.to_bytes()).collect()
}

fn describe(by: &SelectBy) -> String {
    let join = |ids: &[FileId]| {
        ids.iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("/")
    };
    match by {
        SelectBy::Fid(id) => id.to_string(),
        SelectBy::Aid(aid) => format!("AID {}", hex_upper(aid)),
        SelectBy::AbsPath(ids) => format!("3F00/{}", join(ids)),
        SelectBy::RelPath(ids) => format!("./{}", join(ids)),
    }
}

/// The AID prefix of a well-known application name.
fn adf_prefix(name: &str) -> Option<&'static [u8]> {
    match name.to_ascii_uppercase().as_str() {
        "ADF.USIM" => Some(&[0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02]),
        "ADF.ISIM" => Some(&[0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x04]),
        "ADF.CSIM" => Some(&[0xA0, 0x00, 0x00, 0x03, 0x43, 0x10, 0x02]),
        _ => None,
    }
}

/// One path segment, resolved.
enum Seg {
    Fid(FileId),
    Aid(Vec<u8>),
    AdfName(String),
}

fn parse_segment(word: &str) -> Result<Seg, CmdErr> {
    let hexish = !word.is_empty() && word.chars().all(|c| c.is_ascii_hexdigit());
    if hexish && word.len() == 4 {
        let b = parse_hex(word).map_err(CmdErr::new)?;
        return Ok(Seg::Fid(FileId::from_bytes([b[0], b[1]])));
    }
    if hexish && word.len() % 2 == 0 && (10..=32).contains(&word.len()) {
        return Ok(Seg::Aid(parse_hex(word).map_err(CmdErr::new)?));
    }
    if let Some(aid) = word
        .strip_prefix("ADF:")
        .or_else(|| word.strip_prefix("adf:"))
    {
        return Ok(Seg::Aid(parse_hex(aid).map_err(CmdErr::new)?));
    }
    if adf_prefix(word).is_some() {
        return Ok(Seg::AdfName(word.to_owned()));
    }
    names::fid_of(word).map(Seg::Fid).ok_or_else(|| {
        CmdErr::new(format!(
            "`{word}` is not a file identifier, an AID or a known file name"
        ))
    })
}

impl Shell {
    fn cmd_read_binary(&mut self, args: &clap::ArgMatches) -> CmdResult {
        let card = self.equipped()?;
        let ef = card.ef()?;
        if ef.structure.is_some_and(|st| st != "transparent") {
            return Err(CmdErr::new(format!(
                "the selected file is {}: use read_record / read_records",
                ef.structure.unwrap_or("record-structured")
            )));
        }
        let offset = *args.get_one::<u16>("offset").expect("default");
        let length = match args.get_one::<u32>("length") {
            Some(l) => *l,
            None => match ef.size {
                Some(sz) if u32::from(offset) >= sz && sz > 0 => {
                    return Err(CmdErr::new(format!(
                        "offset {offset} is beyond the end of the file ({sz} bytes)"
                    )))
                }
                Some(sz) => sz - u32::from(offset),
                None => 256,
            },
        };
        let data = card.read_binary(offset, length)?;
        let h = hex::encode(&data);
        Ok(Reply::ok(
            h.clone(),
            json!({ "offset": offset, "length": data.len(), "data": h, "path": card.chans[&card.channel].path() }),
        ))
    }

    fn record_length(ef: &FileInfo, args: &clap::ArgMatches) -> Result<u32, CmdErr> {
        if ef.structure == Some("transparent") {
            return Err(CmdErr::new(
                "the selected file is transparent: use read_binary",
            ));
        }
        Ok(args
            .try_get_one::<u16>("length")
            .ok()
            .flatten()
            .map(|l| u32::from(*l))
            .or(ef.record_length.map(u32::from))
            .unwrap_or(256))
    }

    fn cmd_read_record(&mut self, args: &clap::ArgMatches) -> CmdResult {
        let card = self.equipped()?;
        let ef = card.ef()?;
        let le = Self::record_length(&ef, args)?;
        let n = *args.get_one::<u8>("record").expect("required");
        let data = card.read(0xB2, n, 0x04, le)?;
        let h = hex::encode(&data);
        Ok(Reply::ok(
            h.clone(),
            json!({ "record": n, "length": data.len(), "data": h, "empty": is_empty_record(&data), "path": card.chans[&card.channel].path() }),
        ))
    }

    fn cmd_read_records(&mut self, args: &clap::ArgMatches) -> CmdResult {
        let card = self.equipped()?;
        let ef = card.ef()?;
        let le = Self::record_length(&ef, args)?;
        let from = *args.get_one::<u8>("from").expect("default");
        let to = args
            .get_one::<u8>("to")
            .copied()
            .or(ef.records.map(|r| r.min(254) as u8))
            .unwrap_or(254);
        let (mut records, mut lines) = (Vec::new(), Vec::new());
        for n in from..=to {
            match card.read(0xB2, n, 0x04, le) {
                Ok(data) => {
                    let h = hex::encode(&data);
                    lines.push(format!(
                        "{n}: {}{h}",
                        if is_empty_record(&data) {
                            "(empty) "
                        } else {
                            ""
                        }
                    ));
                    records
                        .push(json!({ "record": n, "data": h, "empty": is_empty_record(&data) }));
                }
                // Past the last record: the card says so (6A83); that ends an open-ended read.
                Err(e)
                    if e.data["sw"] == "6A83"
                        && args.get_one::<u8>("to").is_none()
                        && ef.records.is_none() =>
                {
                    break
                }
                Err(e) => return Err(e),
            }
        }
        Ok(Reply::ok(
            lines.join("\n"),
            json!({ "count": records.len(), "records": records, "path": card.chans[&card.channel].path() }),
        ))
    }

    /// The AID the card lists in EF.DIR for the application called `name`.
    fn adf_aid(&mut self, name: &str) -> Result<Vec<u8>, CmdErr> {
        let prefix = adf_prefix(name)
            .ok_or_else(|| CmdErr::new(format!("`{name}` is not a known application name")))?;
        let dialect = self.opts.dialect.clone();
        let card = self.equipped()?;
        let saved = card.chans[&card.channel].clone();
        let dir = SelectBy::AbsPath(vec![FileId::from_bytes([0x2F, 0x00])]);
        let info = card.select(&dir, &dialect)?;
        let (rl, n) = (info.record_length.unwrap_or(0), info.records.unwrap_or(0));
        let mut found = None;
        for rec in 1..=n {
            let le = apdu::Le::for_byte_count(u32::from(rl))
                .ok_or_else(|| CmdErr::new("EF.DIR has no record length"))?;
            let cla = card.cla();
            let read = card.send(&Command::case2(
                apdu::Header::new(cla, 0xB2, rec as u8, 0x04),
                le,
            ))?;
            if !read.status().is_some_and(StatusWord::is_normal_processing) {
                break;
            }
            if let Ok(Some(app)) = crate::ef::decode_dir_record(read.data()) {
                if app.aid.starts_with(prefix) {
                    found = Some(app.aid);
                    break;
                }
            }
        }
        // Listing the directory must not move the shell: put the old selection back on the card.
        card.chans.insert(card.channel, saved);
        if let Some(by) = Self::reselect(&card.chans[&card.channel]) {
            let _ = card.select(&by, &dialect);
        }
        found.ok_or_else(|| CmdErr::new(format!("EF.DIR lists no {name}")))
    }

    /// The SELECT that returns the card to `chan`'s selection (best effort).
    fn reselect(chan: &Chan) -> Option<SelectBy> {
        let below: Vec<FileId> = chan
            .dir
            .iter()
            .skip(if chan.adf.is_some() { 2 } else { 1 })
            .copied()
            .collect();
        let mut ids = below;
        if let Some(f) = chan.file.as_ref().filter(|f| !f.is_df) {
            ids.extend(f.fid);
        }
        match (&chan.adf, ids.is_empty()) {
            (Some(aid), _) => Some(SelectBy::Aid(aid.clone())),
            (None, true) if chan.dir.len() == 1 => Some(SelectBy::Fid(FileId::MASTER_FILE)),
            (None, true) => Some(SelectBy::AbsPath(chan.dir[1..].to_vec())),
            (None, false) => Some(SelectBy::AbsPath(ids)),
        }
    }

    fn cmd_select_adf(&mut self, arg: &str) -> CmdResult {
        let aid = match parse_segment(arg)? {
            Seg::Aid(aid) => aid,
            Seg::AdfName(name) => self.adf_aid(&name)?,
            Seg::Fid(_) => {
                return Err(CmdErr::new(
                    "select_adf takes an AID or an application name",
                ))
            }
        };
        self.run_select(&[SelectBy::Aid(aid)])
    }

    fn cmd_select(&mut self, target: &str) -> CmdResult {
        // Plain word: one segment. With a `/`: a path; a leading 3F00/MF or `/` makes it absolute.
        let (absolute, words): (bool, Vec<&str>) = if target.contains('/') {
            let t = target.trim_start_matches("./");
            let abs = t.starts_with('/');
            (abs, t.split('/').filter(|w| !w.is_empty()).collect())
        } else {
            (false, vec![target])
        };
        let mut segs = Vec::new();
        for (i, w) in words.iter().enumerate() {
            if w.eq_ignore_ascii_case("MF") || w.eq_ignore_ascii_case("3F00") {
                if i == 0 {
                    segs.push(Seg::Fid(FileId::MASTER_FILE));
                    continue;
                }
                return Err(CmdErr::new("the master file can only start a path"));
            }
            segs.push(parse_segment(w)?);
        }
        if segs.is_empty() {
            return Err(CmdErr::new("nothing to select"));
        }
        let mut plan: Vec<SelectBy> = Vec::new();
        let mut ids: Vec<FileId> = Vec::new();
        let mut abs = absolute;
        let mut iter = segs.into_iter().peekable();
        if matches!(iter.peek(), Some(Seg::Fid(f)) if *f == FileId::MASTER_FILE) && words.len() > 1
            || absolute
        {
            if matches!(iter.peek(), Some(Seg::Fid(f)) if *f == FileId::MASTER_FILE) {
                iter.next();
            }
            abs = true;
        }
        for seg in iter {
            match seg {
                Seg::Fid(f) => ids.push(f),
                Seg::Aid(aid) => {
                    if !ids.is_empty() {
                        return Err(CmdErr::new("an application can only start a path"));
                    }
                    plan.push(SelectBy::Aid(aid));
                    abs = false;
                }
                Seg::AdfName(name) => {
                    if !ids.is_empty() {
                        return Err(CmdErr::new("an application can only start a path"));
                    }
                    let aid = self.adf_aid(&name)?;
                    plan.push(SelectBy::Aid(aid));
                    abs = false;
                }
            }
        }
        if !ids.is_empty() || plan.is_empty() {
            let tail = if words.len() == 1 && plan.is_empty() {
                match ids.as_slice() {
                    [one] => SelectBy::Fid(*one),
                    _ => SelectBy::RelPath(ids),
                }
            } else if ids.is_empty() {
                SelectBy::Fid(FileId::MASTER_FILE)
            } else if abs && plan.is_empty() {
                SelectBy::AbsPath(ids)
            } else {
                SelectBy::RelPath(ids)
            };
            plan.push(tail);
        }
        self.run_select(&plan)
    }

    fn run_select(&mut self, plan: &[SelectBy]) -> CmdResult {
        let dialect = self.opts.dialect.clone();
        let card = self.equipped()?;
        let mut info = FileInfo::default();
        for by in plan {
            // A refusal names the file; the hint says where a known name lives.
            info = card.select(by, &dialect).map_err(|mut e| {
                if let SelectBy::Fid(id) = by {
                    if let Some(scope) = names::scope_of(*id) {
                        if e.message.contains("6A82") {
                            e.message.push_str(&format!(
                                " (a file of that identifier lives under {scope})"
                            ));
                        }
                    }
                }
                e
            })?;
            info = card.land(by, info);
        }
        let chan = &card.chans[&card.channel];
        let path = chan.path();
        let kind = if info.is_df {
            "directory"
        } else {
            "elementary"
        };
        let mut text = format!("{path}  {kind}");
        if let Some(st) = info.structure {
            text.push_str(&format!(" {st}"));
        }
        if let Some(sz) = info.size {
            text.push_str(&format!(", {sz} bytes"));
        }
        if let (Some(rl), Some(n)) = (info.record_length, info.records) {
            text.push_str(&format!(", {n} records of {rl}"));
        }
        if let Some(n) = &info.name {
            text.push_str(&format!(", AID {}", hex_upper(n)));
        }
        let mut data = file_json(&info);
        data["path"] = json!(path);
        Ok(Reply::ok(text, data))
    }
}

/// The interpreter. Holds the card and everything the commands share.
pub struct Shell {
    opener: Opener,
    card: Option<Equipped>,
    opts: Opts,
    /// How many commands have failed so far (the process exit code is 1 when this is not zero).
    pub failed: usize,
}

/// `AB01` -> 0xAB 0x01; `ab 01` and `0xAB01` too.
pub fn parse_hex(text: &str) -> Result<Vec<u8>, String> {
    let t: String = text
        .trim()
        .trim_start_matches("0x")
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect();
    hex::decode(&t).map_err(|_| format!("`{text}` is not hex"))
}

/// Upper-case hex.
pub fn hex_upper(bytes: &[u8]) -> String {
    hex::encode_upper(bytes)
}

/// Splits a line into words: spaces separate, `'...'` and `"..."` group, a backslash escapes.
pub fn split_words(line: &str) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut quote: Option<char> = None;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => cur.push(c),
            (None, '\'' | '"') => {
                quote = Some(c);
                in_word = true;
            }
            (None, '\\') => {
                cur.push(chars.next().ok_or("a backslash at the end of the line")?);
                in_word = true;
            }
            (None, c) if c.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            (None, c) => {
                cur.push(c);
                in_word = true;
            }
        }
    }
    if quote.is_some() {
        return Err("an unterminated quote".into());
    }
    if in_word {
        words.push(cur);
    }
    Ok(words)
}

/// Splits `a; b` into commands, leaving a `;` inside quotes alone.
pub fn split_commands(script: &str) -> Vec<String> {
    let mut out = vec![String::new()];
    let mut quote: Option<char> = None;
    for c in script.chars() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (None, '\'' | '"') => quote = Some(c),
            (None, ';') => {
                out.push(String::new());
                continue;
            }
            _ => {}
        }
        out.last_mut().expect("never empty").push(c);
    }
    out
}

fn yes_arg() -> clap::Arg {
    clap::Arg::new("yes")
        .long("yes")
        .action(clap::ArgAction::SetTrue)
        .help("Send it; without this a command that changes the card prints what it would send")
}

/// The instructions the shell sends without `--yes`: they read the card or change only the session
/// (SELECT, READ BINARY, READ RECORD, GET RESPONSE, STATUS, GET DATA, MANAGE CHANNEL).
pub const READ_ONLY_INS: [u8; 8] = [0xA4, 0xB0, 0xB2, 0xC0, 0xF2, 0xCA, 0xCB, 0x70];

/// Whether `ins` is one of [`READ_ONLY_INS`].
pub fn is_read_only(ins: u8) -> bool {
    READ_ONLY_INS.contains(&ins)
}

/// pySim's `sw_match`: `pattern` is 4 hex digits in which `x` stands for any digit.
pub fn sw_match(sw: &str, pattern: &str) -> bool {
    let (sw, pattern) = (sw.to_ascii_lowercase(), pattern.to_ascii_lowercase());
    sw.len() == pattern.len()
        && sw
            .chars()
            .zip(pattern.chars())
            .all(|(a, p)| p == 'x' || a == p)
}

/// The command grammar, one clap subcommand per shell command (`multicall`: no binary name).
pub fn grammar() -> clap::Command {
    use clap::{Arg, Command as C};
    C::new("card")
        .multicall(true)
        .disable_help_flag(true)
        .subcommand_required(true)
        .arg_required_else_help(false)
        .help_template("{subcommands}")
        .subcommand(
            C::new("equip")
                .about("(Re)open the card, optionally on another reader or command set")
                .arg(Arg::new("reader").long("reader").value_name("NAME"))
                .arg(
                    Arg::new("profile")
                        .long("profile")
                        .value_parser(["uicc", "sim"])
                        .default_value("uicc"),
                ),
        )
        .subcommand(C::new("status").about("Show the card, the channel and the selected file"))
        .subcommand(
            C::new("open_channel")
                .about("MANAGE CHANNEL open: take a supplementary logical channel and use it"),
        )
        .subcommand(
            C::new("close_channel")
                .about("MANAGE CHANNEL close (default: the channel in use)")
                .arg(Arg::new("channel").value_parser(clap::value_parser!(u8).range(1..=19))),
        )
        .subcommand(
            C::new("channel")
                .about(
                    "Use logical channel N for the commands that follow (0 is the basic channel)",
                )
                .arg(
                    Arg::new("channel")
                        .required(true)
                        .value_parser(clap::value_parser!(u8).range(0..=19)),
                ),
        )
        .subcommand(
            C::new("apdu")
                .about(
                    "Send one APDU (hex). Reads are sent; anything else is a dry run unless --yes",
                )
                .arg(
                    Arg::new("raw")
                        .long("raw")
                        .action(clap::ArgAction::SetTrue)
                        .help("Send the class byte as given (no logical channel handling)"),
                )
                .arg(
                    Arg::new("expect_sw")
                        .long("expect-sw")
                        .value_name("SW")
                        .help(
                        "Fail unless the status word matches (4 hex digits; x is a wildcard, 61xx)",
                    ),
                )
                .arg(
                    Arg::new("expect_response_regex")
                        .long("expect-response-regex")
                        .value_name("RE")
                        .help("Fail unless the response data (lower-case hex) starts with a match"),
                )
                .arg(yes_arg())
                .arg(
                    Arg::new("apdu")
                        .required(true)
                        .num_args(1..)
                        .value_name("APDU"),
                ),
        )
        .subcommand(
            C::new("select")
                .about("Select a file: a FID (6F07), a name (EF.IMSI, ADF.USIM, MF), an AID (hex) or a path (3F00/7F20/6F07, ADF.USIM/EF.IMSI)")
                .arg(Arg::new("target").required(true).value_name("NAME|FID|AID|PATH")),
        )
        .subcommand(
            C::new("select_path")
                .about("Select by path: absolute from the master file (3F00/..., MF/...), else relative to the current DF")
                .arg(Arg::new("path").required(true).value_name("PATH")),
        )
        .subcommand(
            C::new("select_adf")
                .about("Select an application by AID (5 to 16 bytes of hex) or name (ADF.USIM, ADF.ISIM, ADF.CSIM)")
                .arg(Arg::new("adf").required(true).value_name("AID|NAME")),
        )
        .subcommand(
            C::new("read_binary")
                .about("READ BINARY of the selected transparent EF (whole file by default)")
                .arg(Arg::new("offset").long("offset").value_name("N").default_value("0").value_parser(clap::value_parser!(u16).range(0..=0x7FFF)))
                .arg(Arg::new("length").long("length").value_name("N").value_parser(clap::value_parser!(u32).range(1..=0x8000))),
        )
        .subcommand(
            C::new("read_record")
                .about("READ RECORD number N (1 is the first) of the selected record EF")
                .arg(Arg::new("record").required(true).value_name("N").value_parser(clap::value_parser!(u8).range(1..=254)))
                .arg(Arg::new("length").long("length").value_name("N").value_parser(clap::value_parser!(u16).range(1..=256))),
        )
        .subcommand(
            C::new("read_records")
                .about("READ RECORD of every record (or --from .. --to) of the selected record EF")
                .arg(Arg::new("from").long("from").value_name("N").default_value("1").value_parser(clap::value_parser!(u8).range(1..=254)))
                .arg(Arg::new("to").long("to").value_name("N").value_parser(clap::value_parser!(u8).range(1..=254))),
        )
        .subcommand(
            C::new("quit")
                .visible_aliases(["exit", "eof"])
                .about("Leave the shell"),
        )
}

impl Shell {
    /// A shell with no card yet; call [`Shell::equip`] first.
    pub fn new(opener: Opener, opts: Opts) -> Self {
        Self {
            opener,
            card: None,
            opts,
            failed: 0,
        }
    }

    /// Opens the card (`reader` of `None` means the opener's default) and resets every channel.
    ///
    /// # Errors
    ///
    /// The opener's sentence.
    pub fn equip(&mut self, reader: Option<&str>, profile: Profile) -> Result<(), String> {
        let (session, reader, atr) = (self.opener)(reader)?;
        if let Some(mut old) = self.card.take() {
            let _ = old.session.disconnect();
        }
        let mut chans = BTreeMap::new();
        chans.insert(0, Chan::default());
        self.card = Some(Equipped {
            session,
            reader,
            atr,
            profile,
            chans,
            channel: 0,
        });
        Ok(())
    }

    /// The prompt: `3F00/7F20/6F07` (or `-` with no card).
    pub fn pwd(&self) -> String {
        self.card
            .as_ref()
            .map_or_else(|| "-".to_owned(), |c| c.chans[&c.channel].path())
    }

    /// The selected state of the channel in use.
    pub fn chan(&self) -> Option<&Chan> {
        self.card.as_ref().map(|c| &c.chans[&c.channel])
    }

    /// The channel in use.
    pub fn channel(&self) -> Option<u8> {
        self.card.as_ref().map(|c| c.channel)
    }

    /// Runs one command line.
    pub fn exec(&mut self, line: &str) -> Reply {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return Reply::ok("", Value::Null);
        }
        let reply = match self.run(line) {
            Ok(reply) => reply,
            Err(e) => Reply::failed(e.message, e.data),
        };
        if !reply.ok {
            self.failed += 1;
        }
        reply
    }

    fn run(&mut self, line: &str) -> CmdResult {
        let words = split_words(line).map_err(CmdErr::new)?;
        let matches = match grammar().try_get_matches_from(words) {
            Ok(m) => m,
            Err(e) => {
                let text = e.render().to_string();
                return Ok(if e.use_stderr() {
                    Reply::failed(text.trim_end(), Value::Null)
                } else {
                    Reply::ok(text.trim_end(), Value::Null)
                });
            }
        };
        let (name, args) = matches.subcommand().expect("subcommand_required");
        match name {
            "quit" => Ok(Reply {
                quit: true,
                ..Reply::ok("", Value::Null)
            }),
            "equip" => self.cmd_equip(args),
            "status" => self.cmd_status(),
            "apdu" => self.cmd_apdu(args),
            "read_binary" => self.cmd_read_binary(args),
            "read_record" => self.cmd_read_record(args),
            "read_records" => self.cmd_read_records(args),
            "select" => self.cmd_select(args.get_one::<String>("target").expect("required")),
            "select_path" => {
                self.cmd_select(&path_arg(args.get_one::<String>("path").expect("required")))
            }
            "select_adf" => self.cmd_select_adf(args.get_one::<String>("adf").expect("required")),
            "open_channel" => self.cmd_open_channel(),
            "close_channel" => self.cmd_close_channel(args),
            "channel" => self.cmd_channel(args),
            other => Err(CmdErr::new(format!("`{other}` is not implemented"))),
        }
    }

    fn equipped(&mut self) -> Result<&mut Equipped, CmdErr> {
        self.card
            .as_mut()
            .ok_or_else(|| CmdErr::new("no card: run `equip` first"))
    }

    /// Whether a command that changes the card may be sent: `--yes` on it or on the shell.
    fn may_change_card(&self, args: &clap::ArgMatches) -> bool {
        self.opts.yes
            || args
                .try_get_one::<bool>("yes")
                .ok()
                .flatten()
                .copied()
                .unwrap_or(false)
    }

    fn cmd_apdu(&mut self, args: &clap::ArgMatches) -> CmdResult {
        let text: Vec<&str> = args
            .get_many::<String>("apdu")
            .expect("required")
            .map(String::as_str)
            .collect();
        let bytes = parse_hex(&text.join("")).map_err(CmdErr::new)?;
        let raw = args.get_flag("raw");
        let send = self.may_change_card(args);
        let card = self.equipped()?;
        let mut command =
            Command::decode(&bytes).map_err(|e| CmdErr::new(format!("not an APDU: {e}")))?;
        if !raw && card.channel > 0 {
            let h = command.header();
            if let Some(cla) = apdu::class_on_channel(h.class(), card.channel) {
                command = Command::new(
                    apdu::Header::new(cla, h.instruction(), h.parameter_1(), h.parameter_2()),
                    command.body().clone(),
                );
            }
        }
        let wire = command.encode().map_err(|e| CmdErr::new(e.to_string()))?;
        let ins = command.header().instruction();
        if !send && !is_read_only(ins) {
            return Ok(Reply::ok(
                format!("dry run: would send {} (INS {ins:02X} changes the card or its state; add --yes to send)", hex_upper(&wire)),
                json!({ "sent": false, "apdu": hex_upper(&wire) }),
            ));
        }
        let ex = card.send(&command)?;
        let sw = ex.status().map(|s| s.to_string());
        let data = hex::encode(ex.data());
        let steps: Vec<Value> = ex
            .steps()
            .iter()
            .map(|s| json!({ "command": hex_upper(s.command()), "response": hex_upper(s.response()) }))
            .collect();
        let record = json!({
            "sent": true,
            "apdu": hex_upper(&wire),
            "sw": sw,
            "meaning": ex.status().map(crate::trace::sw_meaning),
            "data": data,
            "exchanges": steps,
        });
        let mut text = format!("sw {}", sw_text(ex.status()));
        if !data.is_empty() {
            text.push_str(&format!("\ndata {data}"));
        }
        if let Some(want) = args.get_one::<String>("expect_sw") {
            if !sw.as_deref().is_some_and(|got| sw_match(got, want)) {
                return Err(CmdErr {
                    message: format!(
                        "expected status word {want}, the card answered {}",
                        sw_text(ex.status())
                    ),
                    data: record,
                });
            }
        }
        if let Some(re) = args.get_one::<String>("expect_response_regex") {
            let re = regex::Regex::new(&format!("(?i)^(?:{re})"))
                .map_err(|e| CmdErr::new(format!("--expect-response-regex: {e}")))?;
            if !re.is_match(&data) {
                return Err(CmdErr {
                    message: format!("the response data {data:?} does not match {re}"),
                    data: record,
                });
            }
        }
        Ok(Reply::ok(text, record))
    }

    fn cmd_equip(&mut self, args: &clap::ArgMatches) -> CmdResult {
        let profile = match args.get_one::<String>("profile").map(String::as_str) {
            Some("sim") => Profile::Sim,
            _ => Profile::Uicc,
        };
        self.equip(
            args.get_one::<String>("reader").map(String::as_str),
            profile,
        )
        .map_err(CmdErr::new)?;
        let card = self.equipped()?;
        let atr = card.atr.as_deref().map(hex_upper);
        Ok(Reply::ok(
            format!("equipped {} ({} profile)", card.reader, profile.id()),
            json!({ "reader": card.reader, "atr": atr, "profile": profile.id() }),
        ))
    }

    fn cmd_status(&mut self) -> CmdResult {
        let yes = self.opts.yes;
        let Some(card) = self.card.as_ref() else {
            return Ok(Reply::ok(
                "no card",
                json!({ "equipped": false, "send_state_changing": yes }),
            ));
        };
        let chan = &card.chans[&card.channel];
        let channels: Vec<u8> = card.chans.keys().copied().collect();
        let file = chan.file.as_ref().map(file_json);
        let text =
            format!(
            "reader {}\nprofile {}\nchannel {} (open: {:?})\npath {}\nstate-changing commands {}",
            card.reader,
            card.profile.id(),
            card.channel,
            channels,
            chan.path(),
            if yes { "are sent (--yes)" } else { "are dry runs" },
        );
        Ok(Reply::ok(
            text,
            json!({
                "equipped": true,
                "reader": card.reader,
                "atr": card.atr.as_deref().map(hex_upper),
                "profile": card.profile.id(),
                "channel": card.channel,
                "open_channels": channels,
                "path": chan.path(),
                "file": file,
                "send_state_changing": yes,
            }),
        ))
    }

    fn cmd_open_channel(&mut self) -> CmdResult {
        let card = self.equipped()?;
        let (channel, ex) = session::open_channel(card.session.as_mut())?;
        let sw = ex.status();
        let Some(n) = channel else {
            return Err(CmdErr {
                message: format!("the card refused MANAGE CHANNEL: {}", sw_text(sw)),
                data: json!({ "sw": sw.map(|s| s.to_string()) }),
            });
        };
        card.chans.insert(n, Chan::default());
        card.channel = n;
        Ok(Reply::ok(
            format!("channel {n} opened and in use"),
            json!({ "channel": n, "sw": sw.map(|s| s.to_string()) }),
        ))
    }

    fn cmd_close_channel(&mut self, args: &clap::ArgMatches) -> CmdResult {
        let card = self.equipped()?;
        let n = args
            .get_one::<u8>("channel")
            .copied()
            .unwrap_or(card.channel);
        if n == 0 {
            return Err(CmdErr::new("the basic channel (0) cannot be closed"));
        }
        if !card.chans.contains_key(&n) {
            return Err(CmdErr::new(format!("channel {n} is not open")));
        }
        let ex = session::close_channel(card.session.as_mut(), n)?;
        let sw = ex.as_ref().and_then(session::Exchange::status);
        if !sw.is_some_and(StatusWord::is_normal_processing) {
            return Err(CmdErr {
                message: format!("the card refused closing channel {n}: {}", sw_text(sw)),
                data: json!({ "sw": sw.map(|s| s.to_string()) }),
            });
        }
        card.chans.remove(&n);
        if card.channel == n {
            card.channel = 0;
        }
        Ok(Reply::ok(
            format!("channel {n} closed; channel {} in use", card.channel),
            json!({ "closed": n, "channel": card.channel }),
        ))
    }

    fn cmd_channel(&mut self, args: &clap::ArgMatches) -> CmdResult {
        let card = self.equipped()?;
        let n = *args.get_one::<u8>("channel").expect("required");
        if !card.chans.contains_key(&n) {
            return Err(CmdErr::new(format!(
                "channel {n} is not open (open: {:?}); `open_channel` takes a new one",
                card.chans.keys().collect::<Vec<_>>()
            )));
        }
        card.channel = n;
        Ok(Reply::ok(
            format!("channel {n} in use"),
            json!({ "channel": n }),
        ))
    }
}

/// `9000 (normal processing)` or `no status word`.
pub fn sw_text(sw: Option<StatusWord>) -> String {
    sw.map_or_else(
        || "no status word".to_owned(),
        |s| format!("{s} ({})", crate::trace::sw_meaning(s)),
    )
}

/// The JSON view of a selected file.
pub fn file_json(f: &FileInfo) -> Value {
    json!({
        "fid": f.fid.map(|i| i.to_string()),
        "name": f.name.as_deref().map(hex_upper),
        "type": if f.is_df { "directory" } else { "elementary" },
        "structure": f.structure,
        "size": f.size,
        "record_length": f.record_length,
        "records": f.records,
        "fcp": f.fcp,
    })
}

/// Reads what an FCP says about a file. A body that is not a template gives an empty summary.
pub fn read_fcp(body: &[u8], dialect: &TagSet) -> FileInfo {
    let mut info = FileInfo {
        fcp: hex_upper(body),
        ..FileInfo::default()
    };
    let Ok(template) = fcp::Template::parse(body, dialect) else {
        return info;
    };
    info.fid = template.file_id().ok().flatten().map(FileId::from_bytes);
    info.size = template
        .file_size()
        .ok()
        .flatten()
        .map(fcp::FileSize::octets);
    if let Some(tag) = dialect.df_name() {
        info.name = template
            .find(tag)
            .map(|a| a.value().to_vec())
            .filter(|n| !n.is_empty());
    }
    if let Ok(Some(d)) = template.file_descriptor() {
        info.is_df = matches!(d.file_type(), fcp::FileType::Directory);
        if !info.is_df {
            info.structure = Some(match d.structure() {
                fcp::Structure::Transparent => "transparent",
                fcp::Structure::LinearFixed => "linear-fixed",
                fcp::Structure::LinearVariable => "linear-variable",
                fcp::Structure::Cyclic => "cyclic",
                fcp::Structure::Unknown(_) => "unknown",
            });
        }
        if let [_, _, hi, lo, count, ..] = d.octets() {
            if !matches!(d.structure(), fcp::Structure::Transparent) {
                info.record_length = Some(u16::from_be_bytes([*hi, *lo]));
                info.records = Some(u16::from(*count));
            }
        }
    }
    info
}

pub mod names;

#[cfg(test)]
pub(crate) mod testcard;

#[cfg(test)]
mod tests {
    use super::testcard::*;
    use super::*;

    #[test]
    fn words_group_and_escape() {
        assert_eq!(
            split_words(r#"apdu "00 A4" 'x y' a\ b"#).unwrap(),
            ["apdu", "00 A4", "x y", "a b"]
        );
        assert!(split_words("a 'b").is_err());
        assert_eq!(split_commands("a; b 'c;d' ;e"), ["a", " b 'c;d' ", "e"]);
    }

    #[test]
    fn state_persists_between_commands_and_equip_resets_it() {
        let mut sh = shell_on(TestCard::usim());
        assert!(sh.exec("status").ok);
        assert_eq!(sh.pwd(), "3F00");
        let r = sh.exec("open_channel");
        assert!(r.ok, "{}", r.text);
        assert_eq!(sh.channel(), Some(1));
        // Still channel 1 on the next command: that is the persistent state.
        let r = sh.exec("status");
        assert_eq!(r.data["channel"], 1);
        assert_eq!(r.data["open_channels"], json!([0, 1]));
        assert!(sh.exec("channel 0").ok);
        assert!(!sh.exec("channel 5").ok);
        assert!(sh.exec("close_channel 1").ok);
        assert!(!sh.exec("close_channel 1").ok, "already closed");
        sh.exec("open_channel");
        let r = sh.exec("equip");
        assert!(r.ok, "{}", r.text);
        assert_eq!(
            sh.channel(),
            Some(0),
            "a new equip starts on the basic channel"
        );
        assert_eq!(sh.failed, 2);
    }

    #[test]
    fn quit_ends_and_help_is_not_a_failure() {
        let mut sh = shell_on(TestCard::usim());
        let r = sh.exec("help");
        assert!(r.ok && r.text.contains("equip"), "{}", r.text);
        assert!(sh.exec("quit").quit);
        assert!(sh.exec("eof").quit);
        let r = sh.exec("nonsense");
        assert!(!r.ok);
        assert_eq!(sh.failed, 1);
    }

    #[test]
    fn sw_patterns_have_wildcards() {
        assert!(sw_match("6100", "61xx"));
        assert!(sw_match("9000", "9000"));
        assert!(sw_match("9F10", "9f10"));
        assert!(!sw_match("6A82", "6Axx3"));
        assert!(!sw_match("6A82", "6A83"));
    }

    #[test]
    fn apdu_sends_reads_and_follows_get_response() {
        let (mut sh, log) = shell_log();
        let r = sh.exec("apdu 00A40004022FE2");
        assert!(r.ok, "{}", r.text);
        assert_eq!(r.data["sw"], "9000");
        assert_eq!(
            r.data["exchanges"].as_array().unwrap().len(),
            2,
            "SELECT then GET RESPONSE"
        );
        assert!(r.data["data"].as_str().unwrap().starts_with("620f"));
        let r = sh.exec("apdu 00 B0 00 00 0A --expect-response-regex ^9810");
        assert!(r.ok, "{}", r.text);
        assert_eq!(r.data["data"], "98101032547698103254");
        assert!(!sh.exec("apdu 00B000000A --expect-response-regex 0000").ok);
        assert_eq!(log.borrow().len(), 4);
    }

    #[test]
    fn apdu_that_changes_the_card_is_a_dry_run_without_yes() {
        let (mut sh, log) = shell_log();
        let r = sh.exec("apdu 00D6000001AA");
        assert!(r.ok && r.data["sent"] == false, "{}", r.text);
        assert!(r.text.contains("00D6000001AA") && r.text.contains("--yes"));
        assert!(log.borrow().is_empty(), "nothing reached the card");
        let r = sh.exec("apdu --yes 00D6000001AA --expect-sw 6Dxx");
        assert!(r.ok, "{}", r.text);
        assert_eq!(r.data["sw"], "6D00");
        assert_eq!(log.borrow().len(), 1);
        let r = sh.exec("apdu --yes 00D6000001AA --expect-sw 9000");
        assert!(!r.ok);
        assert!(r.text.contains("expected status word 9000"), "{}", r.text);
        assert_eq!(
            r.data["sw"], "6D00",
            "the response is kept next to the failure"
        );
    }

    #[test]
    fn apdu_applies_the_channel_unless_raw() {
        let (mut sh, log) = shell_log();
        assert!(sh.exec("open_channel").ok);
        log.borrow_mut().clear();
        sh.exec("apdu 00A4000C022FE2");
        sh.exec("apdu --raw 00A4000C022FE2");
        let sent = log.borrow().clone();
        assert_eq!(sent[0][0], 0x01, "channel 1 in the class byte");
        assert_eq!(sent[1][0], 0x00, "--raw leaves it");
    }

    #[test]
    fn apdu_rejects_what_is_not_an_apdu() {
        let (mut sh, _) = shell_log();
        assert!(!sh.exec("apdu zz").ok);
        assert!(!sh.exec("apdu 00A4").ok);
        assert!(
            !sh.exec("apdu 00A4000C03AA").ok,
            "an Lc that disagrees with the data"
        );
    }

    #[test]
    fn select_by_fid_path_name_and_aid_tracks_the_state() {
        let (mut sh, _) = shell_log();
        let r = sh.exec("select 3F00");
        assert!(r.ok, "{}", r.text);
        assert_eq!(sh.pwd(), "3F00");
        let r = sh.exec("select 7F20");
        assert!(r.ok, "{}", r.text);
        assert_eq!(r.data["type"], "directory");
        assert_eq!(sh.pwd(), "3F00/7F20");
        let r = sh.exec("select 6F07");
        assert!(r.ok, "{}", r.text);
        assert_eq!(r.data["type"], "elementary");
        assert_eq!(r.data["structure"], "transparent");
        assert_eq!(r.data["size"], 9);
        assert_eq!(sh.pwd(), "3F00/7F20/6F07");
        // The DF is still 7F20: a sibling is reachable, the parent is too.
        assert!(
            !sh.exec("select 2FE2").ok,
            "2FE2 is under the MF, not under 7F20"
        );
        assert!(sh.exec("select 3F00").ok);
        let r = sh.exec("select 3F00/7F10/6F3A");
        assert!(r.ok, "{}", r.text);
        assert_eq!(r.data["records"], 3);
        assert_eq!(r.data["record_length"], 28);
        assert_eq!(sh.pwd(), "3F00/7F10/6F3A");
        // Relative path from the current DF (7F10).
        assert!(sh.exec("select 6F3A").ok);
        let r = sh.exec("select MF/DF.GSM/EF.IMSI");
        assert!(r.ok, "{}", r.text);
        assert_eq!(sh.pwd(), "3F00/7F20/6F07");
    }

    #[test]
    fn select_by_aid_and_adf_name_goes_through_ef_dir_and_keeps_the_state() {
        let (mut sh, log) = shell_log();
        assert!(sh.exec("select 2FE2").ok);
        let r = sh.exec("select ADF.USIM");
        assert!(r.ok, "{}", r.text);
        assert_eq!(sh.pwd(), "3F00/ADF:A0000000871002FF49FF0589");
        assert_eq!(r.data["name"], "A0000000871002FF49FF0589");
        let r = sh.exec("select EF.IMSI");
        assert!(r.ok, "{}", r.text);
        assert_eq!(sh.pwd(), "3F00/ADF:A0000000871002FF49FF0589/6F07");
        let r = sh.exec("select_adf A0000000871002");
        assert!(r.ok, "{}", r.text);
        let r = sh.exec("select_path ADF.USIM/6F07");
        assert!(r.ok, "{}", r.text);
        assert!(sh.pwd().ends_with("/6F07"));
        let r = sh.exec("select_path 6FAD");
        assert!(r.ok, "{}", r.text);
        assert!(sh.pwd().ends_with("/6FAD"), "{}", sh.pwd());
        assert!(!sh.exec("select_adf EF.IMSI").ok);
        assert!(
            log.borrow().iter().any(|c| c[1] == 0xA4 && c[2] == 0x04),
            "an AID select was sent"
        );
    }

    #[test]
    fn a_refused_select_leaves_the_state_and_hints_where_the_file_lives() {
        let (mut sh, _) = shell_log();
        assert!(sh.exec("select 7F20").ok);
        let r = sh.exec("select EF.IMSI");
        assert!(r.ok, "6F07 exists under 7F20 in the test card: {}", r.text);
        assert!(sh.exec("select 3F00").ok);
        let r = sh.exec("select EF.AD");
        assert!(!r.ok);
        assert!(
            r.text.contains("6A82") && r.text.contains("ADF.USIM"),
            "{}",
            r.text
        );
        assert_eq!(sh.pwd(), "3F00");
        assert!(!sh.exec("select nonsense").ok);
        assert!(!sh.exec("select 3F00/7F20/MF").ok);
    }

    #[test]
    fn select_on_a_second_channel_does_not_move_the_first() {
        let (mut sh, _) = shell_log();
        assert!(sh.exec("select 7F20").ok);
        assert!(sh.exec("open_channel").ok);
        assert_eq!(sh.pwd(), "3F00", "a new channel starts at the master file");
        assert!(sh.exec("select 7F10").ok);
        assert!(sh.exec("channel 0").ok);
        assert_eq!(sh.pwd(), "3F00/7F20");
    }

    #[test]
    fn read_binary_reads_whole_ranges_and_long_files_in_chunks() {
        let (mut sh, log) = shell_log();
        assert!(!sh.exec("read_binary").ok, "nothing selected");
        assert!(sh.exec("select 2FE2").ok);
        let r = sh.exec("read_binary");
        assert!(r.ok, "{}", r.text);
        assert_eq!(r.text, "98101032547698103254");
        let r = sh.exec("read_binary --offset 2 --length 3");
        assert_eq!(r.data["data"], "103254");
        assert_eq!(r.data["offset"], 2);
        // Longer than the file: the card answers 6C0A, the shell re-sends once with 10.
        log.borrow_mut().clear();
        let r = sh.exec("read_binary --length 20");
        assert!(r.ok, "{}", r.text);
        assert_eq!(r.data["length"], 10);
        assert_eq!(log.borrow().len(), 2);
        assert!(!sh.exec("read_binary --offset 10").ok, "offset at the end");
        // 300 bytes need two reads.
        assert!(sh.exec("select 3F00/7F10/6F99").ok);
        log.borrow_mut().clear();
        let r = sh.exec("read_binary");
        assert!(r.ok, "{}", r.text);
        assert_eq!(r.data["length"], 300);
        assert_eq!(log.borrow().len(), 2);
        let h = r.data["data"].as_str().unwrap();
        assert!(h.starts_with("000102") && h.ends_with(&format!("{:02x}", 299 % 251)));
        let r = sh.exec("read_binary --offset 256");
        assert_eq!(r.data["length"], 44);
    }

    #[test]
    fn read_record_and_read_records_use_the_record_length() {
        let (mut sh, _) = shell_log();
        assert!(sh.exec("select 3F00/7F10/6F3A").ok);
        let r = sh.exec("read_record 1");
        assert!(r.ok, "{}", r.text);
        assert!(r.text.starts_with("416e6e"), "{}", r.text);
        assert_eq!(r.data["length"], 28);
        assert_eq!(r.data["empty"], false);
        let r = sh.exec("read_record 2");
        assert_eq!(r.data["empty"], true);
        let r = sh.exec("read_record 4");
        assert!(!r.ok && r.text.contains("6A83"), "{}", r.text);
        let r = sh.exec("read_records");
        assert_eq!(r.data["count"], 3);
        assert_eq!(r.data["records"][2]["empty"], true);
        let r = sh.exec("read_records --from 2 --to 3");
        assert_eq!(r.data["count"], 2);
        assert!(!sh.exec("read_records --to 4").ok, "past the last record");
        // The wrong command for the structure says which one to use.
        let r = sh.exec("read_binary");
        assert!(!r.ok && r.text.contains("read_record"), "{}", r.text);
        assert!(sh.exec("select 3F00/2FE2").ok);
        let r = sh.exec("read_record 1");
        assert!(!r.ok && r.text.contains("read_binary"), "{}", r.text);
        assert!(sh.exec("select 3F00").ok);
        assert!(!sh.exec("read_binary").ok, "a directory is selected");
    }

    #[test]
    fn json_record_is_one_line() {
        let mut sh = shell_on(TestCard::usim());
        let line = sh.exec("status").record("status");
        assert!(!line.contains('\n'));
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["command"], "status");
        assert_eq!(v["ok"], true);
        assert_eq!(v["data"]["profile"], "uicc");
    }
}
