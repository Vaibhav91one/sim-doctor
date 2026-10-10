//! Names of the standard files and where they live (ETSI TS 102 221, 3GPP TS 31.102 / 31.103 / 31.104,
//! TS 51.011). The table is in `efs.rs`: every (name, identifier) pySim defines is in it with the same
//! identifier (checked when it was generated), plus the files the specifications list that pySim does not model.

use crate::fs::FileId;

pub use super::efs::{DIRS, EFS};

/// A standard EF found by name or by identifier and place.
#[derive(Debug, Clone, Copy)]
pub struct StdEf {
    /// The directory it lives under (`ADF.USIM`, `DF.TELECOM` ...).
    pub scope: &'static str,
    /// `EF.IMSI`.
    pub name: &'static str,
    /// The identifier.
    pub fid: FileId,
    /// `T` transparent, `L` linear fixed, `C` cyclic, `B` BER-TLV.
    pub structure: char,
    /// The decoder `decode::decode_ef` uses (`hex` when only the bytes are shown).
    pub kind: &'static str,
    /// What the specification calls it.
    pub desc: &'static str,
}

fn std_ef(e: &'static (&str, &str, u16, char, &str, &str)) -> StdEf {
    StdEf {
        scope: e.0,
        name: e.1,
        fid: FileId::from_bytes(e.2.to_be_bytes()),
        structure: e.3,
        kind: e.4,
        desc: e.5,
    }
}

/// Every standard EF.
pub fn all() -> impl Iterator<Item = StdEf> {
    EFS.iter().map(std_ef)
}

/// The identifier of a file name (`EF.IMSI`, `imsi`, `df.gsm`, `MF`), case-insensitive. The `EF.` / `DF.`
/// prefix may be left out. A name that exists in several directories under different identifiers is
/// ambiguous and gives `None` (name it by identifier then).
pub fn fid_of(name: &str) -> Option<FileId> {
    let n = name.to_ascii_uppercase();
    let mut ids: Vec<u16> = Vec::new();
    let mut add = |id: u16| {
        if !ids.contains(&id) {
            ids.push(id);
        }
    };
    for (d, id, _) in DIRS {
        if d.eq_ignore_ascii_case(&n)
            || d.split_once('.')
                .is_some_and(|(_, r)| r.eq_ignore_ascii_case(&n))
        {
            add(*id);
        }
    }
    for e in EFS {
        if e.1.eq_ignore_ascii_case(&n)
            || e.1
                .split_once('.')
                .is_some_and(|(_, r)| r.eq_ignore_ascii_case(&n))
        {
            add(e.2);
        }
    }
    match ids.as_slice() {
        [one] => Some(FileId::from_bytes(one.to_be_bytes())),
        _ => None,
    }
}

/// Where a standard file with this identifier lives (the first match), for a refusal's hint.
pub fn scope_of(id: FileId) -> Option<&'static str> {
    let want = u16::from_be_bytes(id.to_bytes());
    const FIRST: [&str; 4] = ["ADF.USIM", "DF.TELECOM", "DF.GSM", "MF"];
    let rank = |s: &str| FIRST.iter().position(|f| *f == s).unwrap_or(FIRST.len());
    EFS.iter()
        .filter(|e| e.2 == want)
        .min_by_key(|e| rank(e.0))
        .map(|e| e.0)
}

/// The directory names a path through `dir` (identifiers under the MF) and application `adf` is in:
/// the scopes a file there may be listed under, innermost first.
pub fn scopes_of(dir: &[FileId], adf: Option<&[u8]>) -> Vec<&'static str> {
    let mut out = Vec::new();
    let under = |parent: &str, id: FileId| {
        DIRS.iter()
            .find(|(_, fid, p)| fid.to_be_bytes() == id.to_bytes() && (*p == parent))
            .map(|(n, _, _)| *n)
    };
    let mut parent: &str = "MF";
    let start = if let Some(aid) = adf {
        parent = if aid.starts_with(&[0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x04]) {
            "ADF.ISIM"
        } else {
            "ADF.USIM"
        };
        out.push(parent);
        2
    } else {
        1
    };
    for id in dir.iter().skip(start) {
        match under(parent, *id) {
            Some(n) => {
                out.push(n);
                parent = n;
            }
            None => break,
        }
    }
    if adf.is_none() && dir.len() == 1 {
        out.clear();
        out.push("MF");
    }
    out.reverse();
    out
}

/// The standard EF `fid` is in a place whose scopes are `scopes`.
pub fn find(scopes: &[&str], fid: FileId) -> Option<StdEf> {
    all()
        .find(|e| e.fid == fid && scopes.first().is_some_and(|s| *s == e.scope))
        .or_else(|| all().find(|e| e.fid == fid && scopes.contains(&e.scope)))
}
