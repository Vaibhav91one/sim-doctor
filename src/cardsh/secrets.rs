//! The PIN / PUK / ADM key provider of the card shell (pySim's `CardKeyProvider`, here a file or an
//! environment variable). Secrets never come from the command line and never reach output: `Debug` is
//! redacted and the shell prints the APDUs that carry them with the data masked.
//!
//! Text format, one entry per line (or separated by `;` in an environment variable):
//!
//! ```text
//! pin1=1234
//! pin2=5678
//! puk1=12345678
//! adm1=hex:3737373737373737
//! 8949000000000000001:pin1=4321     # only for the card with this ICCID
//! ```
//!
//! A value is 4 to 8 ASCII digits (padded with `FF` to 8 octets as the card expects) or `hex:` and
//! exactly 8 octets. Names: `pinN` (1-8), `pukN`, `admN` (1-5), `universal`, `upuk`, `new-pinN` (the
//! PIN `unblock_chv` sets), `key-XX` (a raw key reference). `#` starts a comment.

use std::fmt;

/// Where the text comes from.
#[derive(Debug, Clone)]
pub enum Source {
    /// A file (read up to [`MAX_TEXT`] bytes).
    File(std::path::PathBuf),
    /// An environment variable.
    Env(String),
}

/// Most text read.
pub const MAX_TEXT: u64 = 4096;

#[derive(Clone)]
struct Entry {
    iccid: Option<String>,
    name: String,
    value: [u8; 8],
}

/// The parsed secrets.
#[derive(Clone, Default)]
pub struct Secrets {
    entries: Vec<Entry>,
}

impl fmt::Debug for Secrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secrets({} entries, redacted)", self.entries.len())
    }
}

fn value(text: &str) -> Result<[u8; 8], String> {
    if let Some(h) = text.strip_prefix("hex:") {
        let b = hex::decode(h).map_err(|_| "a hex: value is not hex".to_owned())?;
        return <[u8; 8]>::try_from(b.as_slice())
            .map_err(|_| "a hex: value must be 8 octets".to_owned());
    }
    if !(4..=8).contains(&text.len()) || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err("a value is 4 to 8 digits, or hex: and 8 octets".to_owned());
    }
    let mut out = [0xFF; 8];
    out[..text.len()].copy_from_slice(text.as_bytes());
    Ok(out)
}

impl Secrets {
    /// Parses the text. Errors name the line and never quote the value.
    ///
    /// # Errors
    ///
    /// A sentence naming the line number.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut entries = Vec::new();
        for (n, line) in text.split(['\n', ';']).enumerate() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let bad = |why: &str| format!("entry {}: {why}", n + 1);
            let (key, val) = line
                .split_once('=')
                .ok_or_else(|| bad("expected NAME=VALUE"))?;
            let (iccid, name) = match key.trim().split_once(':') {
                Some((i, nm)) if i.chars().all(|c| c.is_ascii_digit()) && !i.is_empty() => {
                    (Some(i.to_owned()), nm)
                }
                _ => (None, key.trim()),
            };
            let name = name.trim().to_ascii_lowercase();
            if !known(&name) {
                return Err(bad(
                    "unknown name (pinN, pukN, admN, universal, upuk, new-pinN, key-XX)",
                ));
            }
            entries.push(Entry {
                iccid,
                name,
                value: value(val.trim()).map_err(|e| bad(&e))?,
            });
        }
        Ok(Self { entries })
    }

    /// Reads and parses a source.
    ///
    /// # Errors
    ///
    /// The source is unreadable, too long or malformed.
    pub fn load(source: &Source) -> Result<Self, String> {
        use std::io::Read;
        let text = match source {
            Source::Env(name) => std::env::var(name)
                .map_err(|_| format!("environment variable {name} is not set"))?,
            Source::File(path) => {
                let mut text = String::new();
                std::fs::File::open(path)
                    .and_then(|f| f.take(MAX_TEXT + 1).read_to_string(&mut text))
                    .map_err(|e| format!("{}: {e}", path.display()))?;
                text
            }
        };
        if text.len() as u64 > MAX_TEXT {
            return Err("the secrets text is too long".into());
        }
        Self::parse(&text)
    }

    /// Whether some entry is bound to an ICCID (so the card's ICCID has to be read to choose).
    pub fn needs_iccid(&self) -> bool {
        self.entries.iter().any(|e| e.iccid.is_some())
    }

    /// The value for `name` on the card with `iccid` (when known): an entry bound to that ICCID wins
    /// over an unbound one.
    pub fn get(&self, name: &str, iccid: Option<&str>) -> Option<[u8; 8]> {
        let name = name.to_ascii_lowercase();
        let pick = |bound: bool| {
            self.entries
                .iter()
                .find(|e| {
                    e.name == name
                        && (if bound {
                            e.iccid.as_deref() == iccid && iccid.is_some()
                        } else {
                            e.iccid.is_none()
                        })
                })
                .map(|e| e.value)
        };
        pick(true).or_else(|| pick(false))
    }
}

fn known(name: &str) -> bool {
    let n = |p: &str, lo: u8, hi: u8| {
        name.strip_prefix(p)
            .and_then(|r| r.parse::<u8>().ok())
            .is_some_and(|v| (lo..=hi).contains(&v))
    };
    n("pin", 1, 8)
        || n("puk", 1, 8)
        || n("adm", 1, 5)
        || n("new-pin", 1, 8)
        || matches!(name, "universal" | "upuk")
        || name
            .strip_prefix("key-")
            .is_some_and(|h| h.len() == 2 && h.bytes().all(|b| b.is_ascii_hexdigit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pads_and_picks_by_iccid() {
        let s = Secrets::parse(
            "pin1=1234; puk1=12345678\nadm1=hex:3737373737373737 # comment\n8949001:pin1=9999",
        )
        .unwrap();
        assert_eq!(s.get("PIN1", None), Some(*b"1234\xFF\xFF\xFF\xFF"));
        assert_eq!(
            s.get("pin1", Some("8949001")),
            Some(*b"9999\xFF\xFF\xFF\xFF")
        );
        assert_eq!(s.get("pin1", Some("other")), Some(*b"1234\xFF\xFF\xFF\xFF"));
        assert_eq!(s.get("adm1", None), Some(*b"77777777"));
        assert_eq!(s.get("pin2", None), None);
        assert!(s.needs_iccid());
    }

    #[test]
    fn bad_entries_name_the_line_not_the_value() {
        for text in [
            "pin1",
            "pin1=12",
            "pin9=1234",
            "pin1=12a4",
            "adm1=hex:00",
            "nonsense=1234",
        ] {
            let e = Secrets::parse(text).unwrap_err();
            assert!(e.starts_with("entry 1:"), "{e}");
            assert!(!e.contains("12a4"), "{e}");
        }
        assert!(format!("{:?}", Secrets::parse("pin1=1234").unwrap()).contains("redacted"));
        assert!(!format!("{:?}", Secrets::parse("pin1=1234").unwrap()).contains("1234"));
    }
}
