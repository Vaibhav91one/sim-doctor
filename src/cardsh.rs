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

use crate::apdu::StatusWord;
use crate::fcp::{self, TagSet};
use crate::fs::FileId;
use crate::session;
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
