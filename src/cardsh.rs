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

use crate::aka;
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
    /// The PIN / PUK / ADM values `verify_chv` and `unblock_chv` use (from a file or an environment variable).
    pub secrets: Option<secrets::Secrets>,
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
    /// Key references verified in this session (no secret is kept).
    verified: std::collections::BTreeSet<u8>,
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

enum Which {
    Binary,
    Record(u8),
    All,
}

/// The standard file entry a decoded read is about, from the channel's path and selected file.
fn std_ef_of(chan: &Chan) -> Option<names::StdEf> {
    let fid = chan.file.as_ref().and_then(|f| f.fid)?;
    names::find(&names::scopes_of(&chan.dir, chan.adf.as_deref()), fid)
}

fn decoded_reply(std: Option<names::StdEf>, records: &[Vec<u8>], extra: Value) -> Reply {
    let (name, scope, kind) = std.map_or(("", "", "hex"), |e| (e.name, e.scope, e.kind));
    let fields = decode::decode_ef(kind, name, records);
    let mut data = json!({
        "ef": std.map(|e| e.name),
        "scope": std.map(|e| e.scope),
        "description": std.map(|e| e.desc),
        "decoder": kind,
        "structured": std.is_some() && decode::is_structured(kind),
        "decoded": fields,
    });
    if let (Some(a), Some(b)) = (data.as_object_mut(), extra.as_object()) {
        a.extend(b.clone());
    }
    let head = if name.is_empty() {
        "unknown file (no standard name here): raw hex".to_owned()
    } else {
        format!("{name} ({scope}): {}", std.map_or("", |e| e.desc))
    };
    Reply::ok(
        format!(
            "{head}\n{}",
            serde_json::to_string_pretty(&data["decoded"]).unwrap_or_default()
        ),
        data,
    )
}

/// `decode NAME HEX...`: offline.
fn cmd_decode(args: &clap::ArgMatches) -> CmdResult {
    let name = args.get_one::<String>("name").expect("required");
    let std = names::all()
        .find(|e| {
            e.name.eq_ignore_ascii_case(name)
                || e.name
                    .split_once('.')
                    .is_some_and(|(_, r)| r.eq_ignore_ascii_case(name))
        })
        .ok_or_else(|| {
            CmdErr::new(format!(
                "`{name}` is not a standard file name (see `files`)"
            ))
        })?;
    let records = args
        .get_many::<String>("hex")
        .expect("required")
        .map(|h| parse_hex(h))
        .collect::<Result<Vec<_>, _>>()
        .map_err(CmdErr::new)?;
    Ok(decoded_reply(Some(std), &records, Value::Null))
}

/// `files [TEXT]`: the standard files by name.
fn cmd_files(filter: Option<&str>) -> Reply {
    let f = filter.map(str::to_ascii_lowercase);
    let rows: Vec<names::StdEf> = names::all()
        .filter(|e| {
            f.as_deref().is_none_or(|t| {
                e.name.to_ascii_lowercase().contains(t) || e.desc.to_ascii_lowercase().contains(t)
            })
        })
        .collect();
    let text = rows
        .iter()
        .map(|e| format!("{:<14} {:<10} {}  {}", e.scope, e.fid, e.name, e.desc))
        .collect::<Vec<_>>()
        .join("\n");
    let data = json!({ "count": rows.len(), "files": rows.iter().map(|e| json!({
        "scope": e.scope, "name": e.name, "fid": e.fid.to_string(), "structure": e.structure.to_string(),
        "decoder": e.kind, "description": e.desc })).collect::<Vec<_>>() });
    Reply::ok(text, data)
}

/// A key reference (TS 102 221 table 9.3) and the names it goes by.
struct KeyTarget {
    key_ref: u8,
    label: String,
    secret: String,
}

fn key_target(args: &clap::ArgMatches) -> Result<KeyTarget, CmdErr> {
    if let Some(n) = args.try_get_one::<u8>("adm_nr").ok().flatten() {
        return Ok(KeyTarget {
            key_ref: 0x0A + n - 1,
            label: format!("ADM{n}"),
            secret: format!("adm{n}"),
        });
    }
    if args
        .try_get_one::<bool>("universal")
        .ok()
        .flatten()
        .copied()
        .unwrap_or(false)
    {
        return Ok(KeyTarget {
            key_ref: 0x11,
            label: "universal PIN".into(),
            secret: "universal".into(),
        });
    }
    if let Some(h) = args.try_get_one::<String>("key_ref").ok().flatten() {
        let b = parse_hex(h).map_err(CmdErr::new)?;
        let [k] = b[..] else {
            return Err(CmdErr::new("--key-ref is one octet of hex"));
        };
        return Ok(KeyTarget {
            key_ref: k,
            label: format!("key {k:02X}"),
            secret: format!("key-{k:02x}"),
        });
    }
    let n = args.get_one::<u8>("pin_nr").copied().unwrap_or(1);
    Ok(KeyTarget {
        key_ref: if n == 2 { 0x81 } else { n },
        label: format!("PIN{n}"),
        secret: format!("pin{n}"),
    })
}

/// `--rand HEX` (16 octets) or a fresh random one.
fn rand_arg(args: &clap::ArgMatches) -> Result<[u8; 16], CmdErr> {
    match args.get_one::<String>("rand") {
        Some(h) => {
            let b = parse_hex(h).map_err(CmdErr::new)?;
            <[u8; 16]>::try_from(b.as_slice())
                .map_err(|_| CmdErr::new("--rand is 16 octets (32 hex digits)"))
        }
        None => {
            let mut r = [0u8; 16];
            rand::fill(&mut r);
            Ok(r)
        }
    }
}

/// What the card said to a UMTS AUTHENTICATE.
enum AuthAnswer {
    /// `DB`: RES, CK, IK and (when the card sends it) Kc.
    Success {
        res: Vec<u8>,
        ck: Vec<u8>,
        ik: Vec<u8>,
        kc: Option<Vec<u8>>,
    },
    /// `DC`: the sequence number was not acceptable; AUTS comes back.
    Sync { auts: Vec<u8> },
    /// `98 62`: the MAC in AUTN did not verify.
    MacFailure,
    /// Any other status word.
    Refused(Option<StatusWord>),
    /// A success status with data of no known shape.
    Malformed(Vec<u8>),
}

/// Reads the answer of a 3G-context AUTHENTICATE (TS 31.102 7.1.2.1).
fn parse_auth(sw: Option<StatusWord>, data: &[u8]) -> AuthAnswer {
    if sw.is_some_and(|s| s.to_bytes() == [0x98, 0x62]) {
        return AuthAnswer::MacFailure;
    }
    if !sw.is_some_and(StatusWord::is_normal_processing) {
        return AuthAnswer::Refused(sw);
    }
    let take = |d: &[u8]| -> Option<(Vec<u8>, usize)> {
        let (&n, rest) = d.split_first()?;
        let v = rest.get(..usize::from(n))?;
        Some((v.to_vec(), 1 + usize::from(n)))
    };
    match data {
        [0xDC, rest @ ..] => match take(rest) {
            Some((auts, _)) if auts.len() == 14 => AuthAnswer::Sync { auts },
            _ => AuthAnswer::Malformed(data.to_vec()),
        },
        [0xDB, rest @ ..] => {
            let mut at = 0;
            let mut parts = Vec::new();
            while at < rest.len() && parts.len() < 4 {
                match take(&rest[at..]) {
                    Some((v, n)) => {
                        parts.push(v);
                        at += n;
                    }
                    None => return AuthAnswer::Malformed(data.to_vec()),
                }
            }
            match parts.as_slice() {
                [res, ck, ik] | [res, ck, ik, _]
                    if (4..=16).contains(&res.len())
                        && ck.len() == 16
                        && ik.len() == 16
                        && at == rest.len() =>
                {
                    AuthAnswer::Success {
                        res: res.clone(),
                        ck: ck.clone(),
                        ik: ik.clone(),
                        kc: parts.get(3).cloned(),
                    }
                }
                _ => AuthAnswer::Malformed(data.to_vec()),
            }
        }
        _ => AuthAnswer::Malformed(data.to_vec()),
    }
}

fn parse_sqn(text: &str) -> Result<[u8; 6], CmdErr> {
    let n = match text.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16),
        None => text.parse::<u64>(),
    }
    .map_err(|_| CmdErr::new("--sqn is a number (decimal or 0x hex)"))?;
    if n >> 48 != 0 {
        return Err(CmdErr::new("--sqn is at most 48 bits"));
    }
    <[u8; 6]>::try_from(&n.to_be_bytes()[2..]).map_err(|_| CmdErr::new("--sqn"))
}

/// How many tries a `63 Cx` leaves.
fn tries_left(sw: Option<StatusWord>) -> Option<u8> {
    sw.filter(|s| s.sw1() == 0x63 && s.sw2() & 0xF0 == 0xC0)
        .map(|s| s.sw2() & 0x0F)
}

impl Shell {
    /// Puts the card's selection back to `saved` after a lookup that had to select something else.
    fn restore_selection(&mut self, saved: Chan) {
        let dialect = self.opts.dialect.clone();
        if let Ok(card) = self.equipped() {
            card.chans.insert(card.channel, saved);
            if let Some(by) = Self::reselect(&card.chans[&card.channel]) {
                let _ = card.select(&by, &dialect);
            }
        }
    }

    /// The ICCID, read from EF.ICCID; the selection is put back.
    fn iccid(&mut self) -> Result<String, CmdErr> {
        let dialect = self.opts.dialect.clone();
        let card = self.equipped()?;
        let saved = card.chans[&card.channel].clone();
        let sel = card.select(
            &SelectBy::AbsPath(vec![FileId::from_bytes([0x2F, 0xE2])]),
            &dialect,
        );
        let read = sel.and_then(|_| card.read_binary(0, 10));
        self.restore_selection(saved);
        let bytes = read?;
        crate::ef::decode_iccid(&bytes)
            .map(|d| d.as_str().to_owned())
            .map_err(|e| CmdErr::new(format!("EF.ICCID: {e}")))
    }

    /// The secret `name` from the provider (`--chv-file` / `--chv-env`).
    fn secret(&mut self, name: &str) -> Result<[u8; 8], CmdErr> {
        let v = self.secret_bytes(name)?;
        <[u8; 8]>::try_from(v.as_slice()).map_err(|_| {
            CmdErr::new(format!(
                "`{name}` is {} octets; a PIN, PUK or ADM key is 8",
                v.len()
            ))
        })
    }

    /// The secret `name` as stored (any length the source gave).
    fn secret_bytes(&mut self, name: &str) -> Result<Vec<u8>, CmdErr> {
        let Some(sec) = self.opts.secrets.clone() else {
            return Err(CmdErr::new(
                "no PIN source: start `card` with --chv-file PATH or --chv-env VAR",
            ));
        };
        let iccid = if sec.needs_iccid() {
            Some(self.iccid()?)
        } else {
            None
        };
        sec.get(name, iccid.as_deref())
            .ok_or_else(|| CmdErr::new(format!("the PIN source has no `{name}` entry")))
    }

    /// Asks how many tries a key has left without spending one (a VERIFY or UNBLOCK with no data).
    fn tries_of(
        &mut self,
        ins: u8,
        p1: u8,
        key_ref: u8,
    ) -> Result<(Option<u8>, Option<StatusWord>), CmdErr> {
        let card = self.equipped()?;
        let cla = card.cla();
        let ex = card.send(&Command::case1(apdu::Header::new(cla, ins, p1, key_ref)))?;
        Ok((tries_left(ex.status()), ex.status()))
    }

    /// Before a secret is sent: ask the card how many tries are left (free) and refuse a blocked key or
    /// the last try. For UNBLOCK a card that does not answer the question is not an obstacle (the one
    /// attempt is made without the check). `Ok(Some(reply))` means there is nothing to send (a PIN that is already verified).
    fn guard_tries(
        &mut self,
        ins: u8,
        p1: u8,
        target: &KeyTarget,
        allow_last: bool,
        is_verify: bool,
    ) -> Result<Option<Reply>, CmdErr> {
        let key_ref = target.key_ref;
        let (left, sw) = self.tries_of(ins, p1, key_ref)?;
        let refuse = |msg: String| CmdErr {
            message: msg,
            data: json!({ "sent": false, "sw": sw.map(|s| s.to_string()), "tries_left": left }),
        };
        if is_verify && sw.is_some_and(StatusWord::is_success) {
            let card = self.equipped()?;
            card.verified.insert(key_ref);
            return Ok(Some(Reply::ok(
                format!("{} is already verified; nothing sent", target.label),
                json!({ "sent": false, "verified": true, "key_reference": format!("{key_ref:02X}") }),
            )));
        }
        match (left, sw) {
            (Some(1), _) if !allow_last => Err(refuse(format!(
                "only one try left on {}: a wrong value blocks it. Check the value, then add --allow-last-attempt",
                target.label
            ))),
            (Some(0), _) => Err(refuse(format!("{} is blocked", target.label))),
            (None, Some(s)) if s.to_bytes() == [0x69, 0x83] => Err(refuse(format!("{} is blocked", target.label))),
            (Some(_), _) => Ok(None),
            // UNBLOCK with no data is not defined by every card; it then tells nothing and the one attempt is made.
            (None, _) if !is_verify => Ok(None),
            (None, s) => Err(refuse(format!("cannot ask {}: {}", target.label, sw_text(s)))),
        }
    }

    fn cmd_run_gsm(&mut self, args: &clap::ArgMatches) -> CmdResult {
        let rand = rand_arg(args)?;
        let repeat = *args.get_one::<u8>("repeat").expect("default");
        let send = self.may_change_card(args);
        let dialect = self.opts.dialect.clone();
        let card = self.equipped()?;
        let sim = card.profile == Profile::Sim;
        // USIM: INTERNAL AUTHENTICATE in the GSM security context (TS 31.102 7.1.1: P2 = 80). SIM: RUN
        // GSM ALGORITHM (TS 51.011 9.2.16), which needs DF.GSM selected.
        let wire_head = if sim {
            "A0 88 00 00 10"
        } else {
            "00 88 00 80 11 10"
        };
        if !send {
            return Ok(Reply::ok(
                format!("dry run: would send {wire_head} {} (authentication is not a read; add --yes to send)", hex_upper(&rand)),
                json!({ "sent": false, "rand": hex_upper(&rand), "apdu": format!("{wire_head} {}", hex_upper(&rand)) }),
            ));
        }
        if sim
            && card.chans[&card.channel].dir
                != [FileId::MASTER_FILE, FileId::from_bytes([0x7F, 0x20])]
        {
            for id in [FileId::MASTER_FILE, FileId::from_bytes([0x7F, 0x20])] {
                let by = SelectBy::Fid(id);
                let info = card.select(&by, &dialect)?;
                card.land(&by, info);
            }
        }
        let mut answers: Vec<(String, String)> = Vec::new();
        let mut last = None;
        for _ in 0..repeat {
            let cla = card.cla();
            let command = if sim {
                Command::case3(apdu::Header::new(cla, 0x88, 0x00, 0x00), rand.to_vec())
            } else {
                Command::case3(
                    apdu::Header::new(cla, 0x88, 0x00, 0x80),
                    [&[0x10][..], &rand[..]].concat(),
                )
            };
            let ex = card.send(&command)?;
            let sw = ex.status();
            if !sw.is_some_and(StatusWord::is_normal_processing) {
                return Err(CmdErr {
                    message: format!("the card refused the GSM authentication: {}", sw_text(sw)),
                    data: json!({ "sent": true, "rand": hex_upper(&rand), "sw": sw.map(|s| s.to_string()) }),
                });
            }
            let d = ex.data();
            let (sres, kc) = match (sim, d) {
                (false, [0x04, sres @ .., 0x08, _, _, _, _, _, _, _, _]) if sres.len() == 4 => {
                    (&d[1..5], &d[6..14])
                }
                (true, d) if d.len() == 12 => (&d[..4], &d[4..12]),
                _ => {
                    return Err(CmdErr {
                        message: format!(
                            "the GSM authentication answer has an unexpected shape ({} octets)",
                            d.len()
                        ),
                        data: json!({ "sent": true, "sw": sw.map(|s| s.to_string()), "data": hex::encode(d) }),
                    })
                }
            };
            answers.push((hex_upper(sres), hex_upper(kc)));
            last = sw;
        }
        let deterministic = answers.windows(2).all(|w| w[0] == w[1]);
        let (sres, kc) = answers[0].clone();
        let mut text = format!("RAND {}\nSRES {sres}\nKc   {kc}", hex_upper(&rand));
        if repeat > 1 {
            text.push_str(&format!(
                "\nthe card answered {repeat} times: {}",
                if deterministic {
                    "identical answers"
                } else {
                    "DIFFERENT answers for one RAND"
                }
            ));
        }
        Ok(Reply::ok(
            text,
            json!({ "sent": true, "context": if sim { "run-gsm-algorithm" } else { "gsm" }, "rand": hex_upper(&rand), "sres": sres, "kc": kc,
                    "attempts": answers.len(), "deterministic": deterministic, "sw": last.map(|s| s.to_string()) }),
        ))
    }

    /// Ki and OP/OPc from the PIN source, when they are there.
    fn milenage_keys(&mut self) -> Result<Option<([u8; 16], aka::Operator)>, CmdErr> {
        let Some(sec) = self.opts.secrets.clone() else {
            return Ok(None);
        };
        if !(sec.has("ki") && (sec.has("opc") || sec.has("op"))) {
            return Ok(None);
        }
        let sixteen = |v: Vec<u8>, name: &str| {
            <[u8; 16]>::try_from(v.as_slice()).map_err(|_| {
                CmdErr::new(format!("`{name}` is {} octets; Milenage needs 16", v.len()))
            })
        };
        let k = sixteen(self.secret_bytes("ki")?, "ki")?;
        let op = if sec.has("opc") {
            aka::Operator::Opc(sixteen(self.secret_bytes("opc")?, "opc")?)
        } else {
            aka::Operator::Op(sixteen(self.secret_bytes("op")?, "op")?)
        };
        Ok(Some((k, op)))
    }

    fn auth_once(
        &mut self,
        rand: &[u8; 16],
        autn: &[u8; 16],
    ) -> Result<(AuthAnswer, Option<StatusWord>), CmdErr> {
        let card = self.equipped()?;
        let cla = card.cla();
        let mut data = vec![0x10];
        data.extend_from_slice(rand);
        data.push(0x10);
        data.extend_from_slice(autn);
        let ex = card.send(&Command::case3(
            apdu::Header::new(cla, 0x88, 0x00, 0x81),
            data,
        ))?;
        Ok((parse_auth(ex.status(), ex.data()), ex.status()))
    }

    fn cmd_authenticate(&mut self, args: &clap::ArgMatches) -> CmdResult {
        let rand = rand_arg(args)?;
        let keys = self.milenage_keys()?;
        let sqn = args
            .get_one::<String>("sqn")
            .map(|t| parse_sqn(t))
            .transpose()?;
        let amf = {
            let b =
                parse_hex(args.get_one::<String>("amf").expect("default")).map_err(CmdErr::new)?;
            <[u8; 2]>::try_from(b.as_slice()).map_err(|_| CmdErr::new("--amf is 2 octets"))?
        };
        let build = |sqn: &[u8; 6]| -> Result<[u8; 16], CmdErr> {
            let (k, op) = keys.ok_or_else(|| CmdErr::new("--sqn needs `ki` and `opc` (or `op`) in the PIN source (--chv-file / --chv-env)"))?;
            Ok(aka::autn(&aka::compute(k, op, &rand, sqn, &amf), sqn, &amf))
        };
        let autn: [u8; 16] = match (args.get_one::<String>("autn"), sqn) {
            (Some(h), _) => <[u8; 16]>::try_from(parse_hex(h).map_err(CmdErr::new)?.as_slice())
                .map_err(|_| CmdErr::new("--autn is 16 octets (32 hex digits)"))?,
            (None, Some(sqn)) => build(&sqn)?,
            (None, None) => {
                let mut r = [0u8; 16];
                rand::fill(&mut r);
                r
            }
        };
        let head = "00 88 00 81 22 10";
        if !self.may_change_card(args) {
            return Ok(Reply::ok(
                format!("dry run: would send {head} {} 10 {} (authentication is not a read; add --yes to send)", hex_upper(&rand), hex_upper(&autn)),
                json!({ "sent": false, "rand": hex_upper(&rand), "autn": hex_upper(&autn) }),
            ));
        }
        let (answer, sw) = self.auth_once(&rand, &autn)?;
        let mut data = json!({ "sent": true, "context": "umts", "rand": hex_upper(&rand), "autn": hex_upper(&autn), "sw": sw.map(|s| s.to_string()) });
        let mut text = format!("RAND {}\nAUTN {}", hex_upper(&rand), hex_upper(&autn));
        let expected = keys.map(|(k, op)| aka::compute(k, op, &rand, &sqn.unwrap_or([0; 6]), &amf));
        let mut ok = true;
        let mut resync_to = None;
        match answer {
            AuthAnswer::Success { res, ck, ik, kc } => {
                text.push_str(&format!(
                    "\nauthentication succeeded\nRES {}\nCK  {}\nIK  {}",
                    hex_upper(&res),
                    hex_upper(&ck),
                    hex_upper(&ik)
                ));
                data["outcome"] = json!("success");
                data["res"] = json!(hex_upper(&res));
                data["ck"] = json!(hex_upper(&ck));
                data["ik"] = json!(hex_upper(&ik));
                data["kc"] = json!(kc.as_deref().map(hex_upper));
                if let Some(e) = expected {
                    let same = res == e.res && ck == e.ck && ik == e.ik;
                    data["matches_expected"] = json!(same);
                    text.push_str(if same {
                        "\nRES, CK and IK match the Milenage values for these keys"
                    } else {
                        "\nRES, CK or IK DIFFER from the Milenage values for these keys"
                    });
                    ok = same;
                }
            }
            AuthAnswer::Sync { auts } => {
                data["outcome"] = json!("synchronisation-failure");
                data["auts"] = json!(hex_upper(&auts));
                text.push_str(&format!(
                    "\nsynchronisation failure: the card holds a newer sequence number\nAUTS {}",
                    hex_upper(&auts)
                ));
                if let Some((k, op)) = keys {
                    let auts14 =
                        <[u8; 14]>::try_from(auts.as_slice()).expect("checked by parse_auth");
                    let (sqn_ms, valid) = aka::open_auts(k, op, &rand, &auts14);
                    let n = sqn_ms.iter().fold(0u64, |a, b| (a << 8) | u64::from(*b));
                    data["sqn_ms"] = json!(n);
                    data["mac_s_valid"] = json!(valid);
                    text.push_str(&format!(
                        "\nSQNms {n} (0x{n:012X}); MAC-S {}",
                        if valid {
                            "verifies: AUTS is from this card's keys"
                        } else {
                            "does NOT verify: not this card's AUTS"
                        }
                    ));
                    if valid && args.get_flag("resync") {
                        resync_to = Some(n + 1);
                    }
                } else {
                    text.push_str("\n(give ki and opc in the PIN source to open AUTS)");
                }
            }
            AuthAnswer::MacFailure => {
                data["outcome"] = json!("mac-failure");
                text.push_str("\nMAC failure (98 62): the card rejected the AUTN");
            }
            AuthAnswer::Refused(sw) => {
                return Err(CmdErr {
                    message: format!("the card refused AUTHENTICATE: {}", sw_text(sw)),
                    data,
                })
            }
            AuthAnswer::Malformed(d) => {
                return Err(CmdErr {
                    message: format!(
                        "the AUTHENTICATE answer has an unknown shape: {}",
                        hex::encode(&d)
                    ),
                    data,
                })
            }
        }
        if let Some(next) = resync_to {
            let sqn6 = <[u8; 6]>::try_from(&next.to_be_bytes()[2..]).expect("6 octets");
            let autn2 = build(&sqn6)?;
            let (again, sw2) = self.auth_once(&rand, &autn2)?;
            let outcome = match &again {
                AuthAnswer::Success { .. } => "success",
                AuthAnswer::Sync { .. } => "synchronisation-failure",
                AuthAnswer::MacFailure => "mac-failure",
                _ => "refused",
            };
            data["resync"] = json!({ "sqn": next, "autn": hex_upper(&autn2), "outcome": outcome, "sw": sw2.map(|s| s.to_string()) });
            text.push_str(&format!("\nresynchronised with SQN {next}: {outcome}"));
            ok &= outcome == "success";
        }
        Ok(if ok {
            Reply::ok(text, data)
        } else {
            Reply::failed(text, data)
        })
    }

    fn cmd_unblock_chv(&mut self, args: &clap::ArgMatches) -> CmdResult {
        let target = key_target(args)?;
        let (puk_name, new_name, puk_label) = if target.key_ref == 0x11 {
            ("upuk".to_owned(), "new-universal".to_owned(), "UPUK")
        } else {
            let n = args.get_one::<u8>("pin_nr").copied().unwrap_or(1);
            (format!("puk{n}"), format!("new-pin{n}"), "PUK")
        };
        let puk = self.secret(&puk_name)?;
        let new_pin = self.secret(&new_name)?;
        let send = self.may_change_card(args);
        let key_ref = target.key_ref;
        let masked = format!(
            "00 2C 00 {key_ref:02X} 10 <{puk_label} redacted> <new {} redacted>",
            target.label
        );
        if !send {
            return Ok(Reply::ok(
                format!("dry run: would send {masked} (a wrong {puk_label} costs a try; add --yes to send)"),
                json!({ "sent": false, "key_reference": format!("{key_ref:02X}"), "apdu": masked }),
            ));
        }
        if let Some(done) =
            self.guard_tries(0x2C, 0x00, &target, args.get_flag("allow_last"), false)?
        {
            return Ok(done);
        }
        // One attempt, never retried.
        let card = self.equipped()?;
        let cla = card.cla();
        let data: Vec<u8> = puk.iter().chain(new_pin.iter()).copied().collect();
        let ex = card.send(&Command::case3(
            apdu::Header::new(cla, 0x2C, 0x00, key_ref),
            data,
        ))?;
        let sw = ex.status();
        if sw.is_some_and(StatusWord::is_success) {
            // Whether the card also counts the PIN as verified is the card's business: ask with verify_chv.
            card.verified.remove(&key_ref);
            return Ok(Reply::ok(
                format!(
                    "{} unblocked and set to the new value; its try counter is reset",
                    target.label
                ),
                json!({ "unblocked": true, "sent": true, "key_reference": format!("{key_ref:02X}"), "sw": "9000" }),
            ));
        }
        let why = match (tries_left(sw), sw) {
            (Some(n), _) => format!("wrong {puk_label} for {}: {n} tries left", target.label),
            (None, Some(s)) if s.to_bytes() == [0x69, 0x83] => {
                format!("the {puk_label} of {} is now blocked", target.label)
            }
            (None, s) => format!("UNBLOCK {} refused: {}", target.label, sw_text(s)),
        };
        Err(CmdErr {
            message: why,
            data: json!({ "sent": true, "key_reference": format!("{key_ref:02X}"), "sw": sw.map(|s| s.to_string()), "tries_left": tries_left(sw) }),
        })
    }

    fn cmd_verify_chv(&mut self, args: &clap::ArgMatches) -> CmdResult {
        let target = key_target(args)?;
        let value = self.secret(&target.secret)?;
        let send = self.may_change_card(args);
        let allow_last = args.get_flag("allow_last");
        let key_ref = target.key_ref;
        let masked = format!("00 20 00 {key_ref:02X} 08 <{} redacted>", target.label);
        if !send {
            return Ok(Reply::ok(
                format!(
                    "dry run: would send {masked} (a wrong value costs a try; add --yes to send)"
                ),
                json!({ "sent": false, "key_reference": format!("{key_ref:02X}"), "apdu": masked }),
            ));
        }
        if let Some(done) = self.guard_tries(0x20, 0x00, &target, allow_last, true)? {
            return Ok(done);
        }
        // One attempt, never retried.
        let card = self.equipped()?;
        let cla = card.cla();
        let ex = card.send(&Command::case3(
            apdu::Header::new(cla, 0x20, 0x00, key_ref),
            value.to_vec(),
        ))?;
        let sw = ex.status();
        let data = json!({ "sent": true, "key_reference": format!("{key_ref:02X}"), "sw": sw.map(|s| s.to_string()), "tries_left": tries_left(sw) });
        if sw.is_some_and(StatusWord::is_success) {
            card.verified.insert(key_ref);
            return Ok(Reply::ok(
                format!("{} verified", target.label),
                json!({ "verified": true, "sent": true, "key_reference": format!("{key_ref:02X}"), "sw": "9000" }),
            ));
        }
        let why = match (tries_left(sw), sw) {
            (Some(n), _) => format!("wrong value for {}: {n} tries left", target.label),
            (None, Some(s)) if s.to_bytes() == [0x69, 0x83] => {
                format!("{} is now blocked", target.label)
            }
            (None, s) => format!("VERIFY {} refused: {}", target.label, sw_text(s)),
        };
        Err(CmdErr { message: why, data })
    }

    fn cmd_read_decoded(&mut self, which: Which) -> CmdResult {
        let card = self.equipped()?;
        let ef = card.ef()?;
        let std = std_ef_of(&card.chans[&card.channel]);
        let path = card.chans[&card.channel].path();
        let records: Vec<Vec<u8>> = match which {
            Which::Binary => {
                if ef.structure.is_some_and(|st| st != "transparent") {
                    return Err(CmdErr::new("the selected file is record-structured: use read_record_decoded / read_records_decoded"));
                }
                vec![card.read_binary(0, ef.size.unwrap_or(256))?]
            }
            Which::Record(n) => {
                if ef.structure == Some("transparent") {
                    return Err(CmdErr::new(
                        "the selected file is transparent: use read_binary_decoded",
                    ));
                }
                vec![card.read(0xB2, n, 0x04, u32::from(ef.record_length.unwrap_or(256)))?]
            }
            Which::All => {
                if ef.structure == Some("transparent") {
                    return Err(CmdErr::new(
                        "the selected file is transparent: use read_binary_decoded",
                    ));
                }
                let le = u32::from(ef.record_length.unwrap_or(256));
                (1..=ef.records.unwrap_or(0).min(254) as u8)
                    .map(|n| card.read(0xB2, n, 0x04, le))
                    .collect::<Result<_, _>>()?
            }
        };
        Ok(decoded_reply(std, &records, json!({ "path": path })))
    }

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
        .subcommand(C::new("read_binary_decoded").about("Read the selected transparent EF whole and decode it by its standard name (EF.IMSI, EF.UST ...)"))
        .subcommand(
            C::new("read_record_decoded")
                .about("READ RECORD N of the selected EF and decode it by its standard name")
                .arg(Arg::new("record").required(true).value_name("N").value_parser(clap::value_parser!(u8).range(1..=254))),
        )
        .subcommand(C::new("read_records_decoded").about("Read every record of the selected EF and decode them by its standard name"))
        .subcommand(
            C::new("decode")
                .about("Decode HEX as the standard file NAME, offline (no card needed): decode EF.IMSI 0809...")
                .arg(Arg::new("name").required(true))
                .arg(Arg::new("hex").required(true).num_args(1..).help("one record per argument")),
        )
        .subcommand(
            C::new("files")
                .about("List the standard files this shell knows by name (optionally those whose name contains TEXT)")
                .arg(Arg::new("filter").value_name("TEXT")),
        )
        .subcommand(
            C::new("verify_chv")
                .about("VERIFY a PIN (default PIN1) with the value from --chv-file / --chv-env; a dry run unless --yes")
                .arg(Arg::new("pin_nr").long("pin-nr").value_name("N").value_parser(clap::value_parser!(u8).range(1..=8)).help("PIN number: 1 is PIN1, 2 is PIN2 (key reference 81), 3-8 application PINs"))
                .arg(Arg::new("universal").long("universal").action(clap::ArgAction::SetTrue).help("the universal PIN (key reference 11)"))
                .arg(Arg::new("adm_nr").long("adm-nr").value_name("N").value_parser(clap::value_parser!(u8).range(1..=5)).help("administrative key N (key reference 0A..0E)"))
                .arg(Arg::new("key_ref").long("key-ref").value_name("HEX").help("a raw key reference, one octet of hex"))
                .group(clap::ArgGroup::new("which").args(["pin_nr", "universal", "adm_nr", "key_ref"]))
                .arg(Arg::new("allow_last").long("allow-last-attempt").action(clap::ArgAction::SetTrue).help("send even when only one try is left (a wrong value then blocks the PIN)"))
                .arg(yes_arg()),
        )
        .subcommand(
            C::new("unblock_chv")
                .about("UNBLOCK PIN with the PUK and the new PIN from --chv-file / --chv-env; a dry run unless --yes")
                .arg(Arg::new("pin_nr").long("pin-nr").value_name("N").value_parser(clap::value_parser!(u8).range(1..=8)).help("PIN number: 1 is PIN1, 2 is PIN2 (key reference 81), 3-8 application PINs"))
                .arg(Arg::new("universal").long("universal").action(clap::ArgAction::SetTrue).help("the universal PIN (key reference 11, unblocked with the UPUK)"))
                .group(clap::ArgGroup::new("which").args(["pin_nr", "universal"]))
                .arg(Arg::new("allow_last").long("allow-last-attempt").action(clap::ArgAction::SetTrue).help("send even when only one PUK try is left (a wrong PUK then blocks the PIN for good)"))
                .arg(yes_arg()),
        )
        .subcommand(
            C::new("run_gsm_algorithm")
                .visible_alias("run_gsm")
                .about("GSM authentication probe: send a RAND, read SRES and Kc (USIM: GSM security context; sim profile: RUN GSM ALGORITHM). A dry run unless --yes")
                .arg(Arg::new("rand").long("rand").value_name("HEX").help("16 octets of hex (default: random)"))
                .arg(Arg::new("repeat").long("repeat").value_name("N").default_value("1").value_parser(clap::value_parser!(u8).range(1..=16)).help("send the same RAND N times and report whether the answers agree"))
                .arg(yes_arg()),
        )
        .subcommand(
            C::new("authenticate")
                .visible_alias("auth")
                .about("UMTS authentication probe (3G security context): send RAND and AUTN, read RES CK IK, or AUTS after a synchronisation failure. A dry run unless --yes")
                .arg(Arg::new("rand").long("rand").value_name("HEX").help("16 octets (default: random)"))
                .arg(Arg::new("autn").long("autn").value_name("HEX").help("16 octets, sent as given (a random AUTN probes how the card treats a token it cannot verify)"))
                .arg(Arg::new("sqn").long("sqn").value_name("N").help("build AUTN for this sequence number (decimal or 0x hex) from `ki` and `opc`/`op` of the PIN source"))
                .arg(Arg::new("amf").long("amf").value_name("HEX").default_value("8000").help("the 2-octet AMF for --sqn"))
                .arg(Arg::new("resync").long("resync").action(clap::ArgAction::SetTrue).requires("sqn").help("after a synchronisation failure whose AUTS checks out, send once more with SQN = SQNms + 1"))
                .group(clap::ArgGroup::new("token").args(["autn", "sqn"]))
                .arg(yes_arg()),
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
            verified: std::collections::BTreeSet::new(),
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
            "read_binary_decoded" => self.cmd_read_decoded(Which::Binary),
            "read_record_decoded" => self.cmd_read_decoded(Which::Record(
                *args.get_one::<u8>("record").expect("required"),
            )),
            "read_records_decoded" => self.cmd_read_decoded(Which::All),
            "decode" => cmd_decode(args),
            "files" => Ok(cmd_files(
                args.get_one::<String>("filter").map(String::as_str),
            )),
            "verify_chv" => self.cmd_verify_chv(args),
            "unblock_chv" => self.cmd_unblock_chv(args),
            "run_gsm_algorithm" => self.cmd_run_gsm(args),
            "authenticate" => self.cmd_authenticate(args),
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
                "verified_key_references": card.verified.iter().map(|k| format!("{k:02X}")).collect::<Vec<_>>(),
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

pub mod decode;
mod efs;
pub mod names;
pub mod secrets;

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
    fn decoded_reads_name_the_file_and_decode_it() {
        let (mut sh, _) = shell_log();
        assert!(sh.exec("select ADF.USIM").ok);
        assert!(sh.exec("select EF.IMSI").ok);
        let r = sh.exec("read_binary_decoded");
        assert!(r.ok, "{}", r.text);
        assert_eq!(r.data["ef"], "EF.IMSI");
        assert_eq!(r.data["scope"], "ADF.USIM");
        assert_eq!(r.data["decoded"]["imsi"], "001010123456789", "{}", r.text);
        assert!(sh.exec("select EF.AD").ok);
        assert_eq!(sh.exec("read_binary_decoded").data["decoded"]["mnc_len"], 2);
        // The same identifier under DF.GSM is the GSM file of that name.
        assert!(sh.exec("select 3F00/7F20/6F07").ok);
        let r = sh.exec("read_binary_decoded");
        assert_eq!(r.data["scope"], "DF.GSM");
        // Records: EF.ADN under DF.TELECOM.
        assert!(sh.exec("select 3F00/7F10/6F3A").ok);
        let r = sh.exec("read_record_decoded 1");
        assert!(r.ok, "{}", r.text);
        assert_eq!(r.data["ef"], "EF.ADN");
        assert_eq!(r.data["decoded"]["records"][0]["alpha"], "Ann");
        assert_eq!(r.data["decoded"]["records"][0]["number"], "0123456789");
        let r = sh.exec("read_records_decoded");
        assert_eq!(r.data["decoded"]["records"].as_array().unwrap().len(), 3);
        assert_eq!(r.data["decoded"]["records"][1]["empty"], true);
        // EF.ICCID at the MF, and a file the table does not know says so.
        assert!(sh.exec("select 3F00/2FE2").ok);
        assert_eq!(
            sh.exec("read_binary_decoded").data["decoded"]["iccid"],
            "89010123456789012345"
        );
        assert!(sh.exec("select 3F00/7F10/6F99").ok);
        let r = sh.exec("read_binary_decoded");
        assert!(
            r.ok && r.data["ef"].is_null() && r.text.contains("unknown file"),
            "{}",
            r.text
        );
        assert!(!sh.exec("read_record_decoded 1").ok, "transparent file");
    }

    #[test]
    fn decode_and_files_need_no_card() {
        let mut sh = Shell::new(
            Box::new(|_| Err("no reader".into())),
            Opts {
                yes: false,
                dialect: TagSet::ts_102_221(),
                secrets: None,
            },
        );
        let r = sh.exec("decode EF.SPN 01414253FFFF");
        assert!(r.ok, "{}", r.text);
        assert_eq!(r.data["decoded"]["name"], "ABS");
        let r = sh.exec("decode UST 0501");
        assert_eq!(r.data["decoded"]["enabled"], json!([1, 3, 9]));
        assert!(!sh.exec("decode EF.NOPE 00").ok);
        let r = sh.exec("files FPLMN");
        assert!(r.data["count"].as_u64().unwrap() >= 2, "{}", r.text);
        let r = sh.exec("files");
        assert!(r.data["count"].as_u64().unwrap() >= 250);
    }

    fn shown(r: &Reply) -> String {
        format!("{} {}", r.text, r.data)
    }

    #[test]
    fn verify_chv_is_a_dry_run_that_never_shows_the_value() {
        let (mut sh, log) = shell_with("pin1=1234", false);
        let r = sh.exec("verify_chv");
        assert!(r.ok, "{}", r.text);
        assert_eq!(r.data["sent"], false);
        assert!(
            r.text.contains("00 20 00 01 08 <PIN1 redacted>"),
            "{}",
            r.text
        );
        assert!(!shown(&r).contains("1234") && !shown(&r).contains("31323334"));
        assert!(log.borrow().is_empty(), "nothing reached the card");
        let (mut sh, _) = shell_log();
        let r = sh.exec("verify_chv");
        assert!(!r.ok && r.text.contains("--chv-file"), "{}", r.text);
        let (mut sh, _) = shell_with("pin1=1234", true);
        assert!(!sh.exec("verify_chv --pin-nr 2").ok, "no pin2 entry");
        assert!(
            !sh.exec("verify_chv --pin-nr 1 --universal").ok,
            "one selector at most"
        );
    }

    #[test]
    fn verify_chv_asks_the_tries_first_sends_once_and_remembers() {
        let (mut sh, log) = shell_with("pin1=1234; pin2=5678; universal=9999; adm1=77777777", true);
        let r = sh.exec("verify_chv");
        assert!(r.ok, "{}", r.text);
        assert_eq!(r.data["verified"], true);
        let sent = log.borrow().clone();
        assert_eq!(sent.len(), 2, "the tries query, then the VERIFY");
        assert_eq!(sent[0], [0x00, 0x20, 0x00, 0x01]);
        assert_eq!(sent[1][..5], [0x00, 0x20, 0x00, 0x01, 0x08]);
        assert!(!shown(&r).contains("1234"));
        // Verified already: nothing more is sent.
        let r = sh.exec("verify_chv");
        assert!(r.ok && r.data["sent"] == false, "{}", r.text);
        assert_eq!(log.borrow().len(), 3, "only the tries query");
        assert!(sh.exec("verify_chv --pin-nr 2").ok);
        assert!(sh.exec("verify_chv --universal").ok);
        assert!(sh.exec("verify_chv --adm-nr 1").ok);
        let keys = sh.exec("status").data["verified_key_references"].clone();
        assert_eq!(keys, json!(["01", "0A", "11", "81"]));
    }

    #[test]
    fn a_wrong_value_costs_exactly_one_try_and_the_last_try_needs_a_flag() {
        let (mut sh, log) = shell_with("pin1=0000", true);
        let r = sh.exec("verify_chv");
        assert!(!r.ok && r.text.contains("2 tries left"), "{}", r.text);
        assert_eq!(r.data["tries_left"], 2);
        let r = sh.exec("verify_chv");
        assert!(!r.ok && r.text.contains("1 tries left"), "{}", r.text);
        log.borrow_mut().clear();
        let r = sh.exec("verify_chv");
        assert!(
            !r.ok && r.text.contains("--allow-last-attempt"),
            "{}",
            r.text
        );
        assert_eq!(
            log.borrow().len(),
            1,
            "only the tries query went out: the last try was not spent"
        );
        let r = sh.exec("verify_chv --allow-last-attempt");
        assert!(!r.ok && r.text.contains("now blocked"), "{}", r.text);
        let r = sh.exec("verify_chv --allow-last-attempt");
        assert!(!r.ok && r.text.contains("is blocked"), "{}", r.text);
    }

    #[test]
    fn a_secret_bound_to_an_iccid_is_chosen_by_the_cards_iccid_and_the_selection_is_kept() {
        let (mut sh, _) = shell_with("89010123456789012345:pin1=1234; pin1=0000", true);
        assert!(sh.exec("select 3F00/7F10").ok);
        let r = sh.exec("verify_chv");
        assert!(r.ok, "the entry for this card's ICCID is used: {}", r.text);
        assert_eq!(
            sh.pwd(),
            "3F00/7F10",
            "reading EF.ICCID did not move the shell"
        );
        let (mut sh, _) = shell_with("89999:pin1=1234; pin1=0000", true);
        assert!(
            !sh.exec("verify_chv").ok,
            "another card's entry is not used"
        );
    }

    #[test]
    fn unblock_chv_sends_the_puk_and_the_new_pin_once_and_masks_both() {
        let (mut sh, log) = shell_with("pin1=0000; puk1=12345678; new-pin1=4321", false);
        let r = sh.exec("unblock_chv");
        assert!(r.ok && r.data["sent"] == false, "{}", r.text);
        assert!(
            r.text
                .contains("00 2C 00 01 10 <PUK redacted> <new PIN1 redacted>"),
            "{}",
            r.text
        );
        assert!(log.borrow().is_empty());
        for s in ["12345678", "4321", "3132333435363738"] {
            assert!(!shown(&r).contains(s));
        }
        let (mut sh, log) = shell_with("pin1=4321; puk1=12345678; new-pin1=4321", true);
        let r = sh.exec("unblock_chv");
        assert!(r.ok, "{}", r.text);
        assert_eq!(r.data["unblocked"], true);
        let sent = log.borrow().clone();
        assert_eq!(sent.len(), 2, "the tries query, then the UNBLOCK");
        assert_eq!(sent[1][..5], [0x00, 0x2C, 0x00, 0x01, 0x10]);
        assert!(!shown(&r).contains("4321"));
        // The new value is what the card holds now: PIN1 verifies with it.
        assert!(sh.exec("verify_chv").ok);
    }

    #[test]
    fn unblock_chv_wrong_puk_counts_down_and_the_last_try_needs_a_flag() {
        let (mut sh, _) = shell_with(
            "puk1=00000000; new-pin1=4321; puk2=87654321; new-pin2=1111",
            true,
        );
        let r = sh.exec("unblock_chv");
        assert!(!r.ok && r.text.contains("9 tries left"), "{}", r.text);
        // Burn it down to one try without --allow-last-attempt ever being used.
        for _ in 0..8 {
            sh.exec("unblock_chv");
        }
        let r = sh.exec("unblock_chv");
        assert!(
            !r.ok && r.text.contains("--allow-last-attempt"),
            "{}",
            r.text
        );
        assert_eq!(r.data["sent"], false);
        let r = sh.exec("unblock_chv --allow-last-attempt");
        assert!(!r.ok && r.text.contains("now blocked"), "{}", r.text);
        assert!(sh.exec("unblock_chv --pin-nr 2").ok, "PIN2 has its own PUK");
        let (mut sh, _) = shell_with("pin1=1234", true);
        let r = sh.exec("unblock_chv");
        assert!(!r.ok && r.text.contains("`puk1`"), "{}", r.text);
    }

    #[test]
    fn run_gsm_algorithm_is_a_dry_run_and_reports_sres_kc_and_repeatability() {
        let (mut sh, log) = shell_log();
        let r = sh.exec("run_gsm_algorithm --rand 000102030405060708090a0b0c0d0e0f");
        assert!(r.ok && r.data["sent"] == false, "{}", r.text);
        assert!(
            r.text
                .contains("00 88 00 80 11 10 000102030405060708090A0B0C0D0E0F"),
            "{}",
            r.text
        );
        assert!(log.borrow().is_empty());
        let (mut sh, log) = shell_log();
        sh.opts.yes = true;
        let r = sh.exec("run_gsm_algorithm --rand 000102030405060708090a0b0c0d0e0f --repeat 2");
        assert!(r.ok, "{}", r.text);
        assert_eq!(r.data["sres"], "04040404");
        assert_eq!(r.data["kc"].as_str().unwrap().len(), 16);
        assert_eq!(r.data["deterministic"], true);
        assert_eq!(r.data["attempts"], 2);
        assert_eq!(log.borrow().iter().filter(|c| c[1] == 0x88).count(), 2);
        // A random RAND by default; the wrong length is refused before anything is sent.
        let r = sh.exec("run_gsm");
        assert!(
            r.ok && r.data["rand"].as_str().unwrap().len() == 32,
            "{}",
            r.text
        );
        assert!(!sh.exec("run_gsm_algorithm --rand 00").ok);
    }

    #[test]
    fn run_gsm_algorithm_on_a_sim_profile_selects_df_gsm_first() {
        let (mut sh, log) = shell_log();
        sh.opts.yes = true;
        assert!(sh.equip(None, Profile::Sim).is_ok());
        let r = sh.exec("run_gsm_algorithm --rand 000102030405060708090a0b0c0d0e0f");
        assert!(r.ok, "{}", r.text);
        assert_eq!(r.data["context"], "run-gsm-algorithm");
        assert_eq!(sh.pwd(), "3F00/7F20", "RUN GSM ALGORITHM needs DF.GSM");
        let sent = log.borrow().clone();
        assert!(sent
            .iter()
            .any(|c| c[0] == 0xA0 && c[1] == 0x88 && c[2..4] == [0, 0]));
    }

    #[test]
    fn authenticate_builds_an_autn_and_reads_res_ck_ik() {
        let (mut sh, log) = shell_with(KEYS, false);
        let r = sh.exec("authenticate --rand 23553cbe9637a89d218ae64dae47bf35 --sqn 200");
        assert!(r.ok && r.data["sent"] == false, "{}", r.text);
        assert!(
            r.text
                .contains("00 88 00 81 22 10 23553CBE9637A89D218AE64DAE47BF35 10 "),
            "{}",
            r.text
        );
        assert!(log.borrow().is_empty(), "authentication is not a read");
        let (mut sh, log) = shell_with(KEYS, true);
        let r = sh.exec("authenticate --rand 23553cbe9637a89d218ae64dae47bf35 --sqn 200");
        assert!(r.ok, "{}", r.text);
        assert_eq!(r.data["outcome"], "success");
        assert_eq!(
            r.data["matches_expected"], true,
            "RES/CK/IK equal the host's Milenage"
        );
        assert_eq!(r.data["res"].as_str().unwrap().len(), 16);
        assert!(log
            .borrow()
            .iter()
            .any(|c| c[1] == 0x88 && c[3] == 0x81 && c.len() == 39));
    }

    #[test]
    fn authenticate_tells_a_mac_failure_from_a_sync_failure_and_resyncs() {
        let (mut sh, _) = shell_with(KEYS, true);
        // A token the card cannot verify.
        let r = sh.exec("authenticate --rand 23553cbe9637a89d218ae64dae47bf35 --autn 00112233445566778899aabbccddeeff");
        assert!(r.ok, "{}", r.text);
        assert_eq!(r.data["outcome"], "mac-failure");
        // A valid MAC but a sequence number the card has passed (SQNms is 100).
        let r = sh.exec("authenticate --rand 23553cbe9637a89d218ae64dae47bf35 --sqn 50");
        assert_eq!(r.data["outcome"], "synchronisation-failure", "{}", r.text);
        assert_eq!(r.data["sqn_ms"], 100);
        assert_eq!(r.data["mac_s_valid"], true);
        assert!(r.data["auts"].as_str().unwrap().len() == 28);
        // --resync: one more try with SQNms + 1.
        let r = sh.exec("authenticate --rand 23553cbe9637a89d218ae64dae47bf35 --sqn 50 --resync");
        assert!(r.ok, "{}", r.text);
        assert_eq!(r.data["resync"]["sqn"], 101);
        assert_eq!(r.data["resync"]["outcome"], "success");
        // The card now holds 101; the same SQN 101 is stale again.
        let r = sh.exec("authenticate --rand 23553cbe9637a89d218ae64dae47bf35 --sqn 101");
        assert_eq!(r.data["outcome"], "synchronisation-failure");
        // Without the keys AUTS cannot be opened, and --sqn cannot build a token.
        let (mut sh, _) = shell_with("pin1=1234", true);
        let r = sh.exec("authenticate --autn 00112233445566778899aabbccddeeff");
        assert!(r.ok && r.data["outcome"] == "mac-failure");
        let r = sh.exec("authenticate --sqn 5");
        assert!(!r.ok && r.text.contains("`ki`"), "{}", r.text);
        assert!(!sh.exec("authenticate --autn 00").ok);
        assert!(!sh.exec("authenticate --resync").ok, "--resync needs --sqn");
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
