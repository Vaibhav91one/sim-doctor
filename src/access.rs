//! Access conditions and PIN status, decoded from what a SELECT already says.
//!
//! **Owns.** Reading a file's security attributes - the compact (`8C`),
//! expanded (`AB`) and referenced (`8B`) forms - and the PIN status template
//! (`C6`) out of the raw values [`crate::walk`] kept, and the one read-only
//! step that makes the referenced form decodable: READ RECORD of EF.ARR.
//!
//! **Does not own.** The rules that judge what was decoded
//! ([`crate::scan`]), or the tag table ([`crate::fcp`]).
//!
//! # Sources, all ETSI TS 102 221 V17.0.0 (2021-10) unless stated
//!
//! - clause 9.2.5 and E.2: compact format. An AM byte, then one SC byte per
//!   bit set in b7..b1, in order b7 to b1. Several AM+SC groups are an OR.
//!   `b8 = 1` makes b7..b4 proprietary, so such a group is not read.
//! - clause 9.2.6 and E.3: expanded format. An AM_DO (tag `80` carries an AM
//!   byte) followed by SC_DOs; tags `81`..`8F` describe commands and are not
//!   read here. SC_DO tags are `90` ALW and `97` NEV (table 9.3), `A4` a user
//!   authentication (a key reference, so a PIN or ADM), `A0` an OR template
//!   and `AF` an AND template (clause E.3.2 and ISO/IEC 7816-4).
//! - clause 9.2.7 and 11.1.1.4.7.3: `8B` is EF.ARR file ID plus record number,
//!   or the file ID followed by SE ID and record number pairs. EF.ARR is found
//!   in the DF holding the file, then its parents up to the MF.
//! - AM byte bits for an EF: b1 READ (and SEARCH), b2 UPDATE. Read from the
//!   worked examples in clauses 9.2.5, E.2.3 and annex F/G (`01` READ, `02`
//!   UPDATE, `03` both); bits not set in the AM byte are NEVer (clause 9.2.2).
//! - clause 9.5.2 and 11.1.1.4.10: the PIN status template `C6` is a PS_DO
//!   (`90`, a bitmap whose b8 is the first following key reference), then key
//!   references (`83`), each optionally preceded by a usage qualifier (`95`).
//!   Qualifier b5 (`08`) is "use the PIN for verification". Key reference `01`
//!   is PIN Appl 1 and `11` the universal PIN (table 9.3).
//!
//! # What is not decoded
//!
//! AM_DOs other than tag `80`, the proprietary AM forms, and any SC_DO that is
//! not ALW or NEV (these are "restricted": something must be satisfied, and
//! this module does not say what). A file whose attributes do not decode has
//! no [`Access`], and a rule must treat that as "not known", never as clean.

/// This module's name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "access";

use crate::apdu::{Command, Header, Le};
use crate::fs::{self, Path};
use crate::session::{self, Policy};
use crate::tlv::{Stream, Tlv};
use crate::transport::CardSession;
use crate::walk::{Node, Tree};

/// How deep an OR/AND template may nest before it is called restricted.
const MAX_TEMPLATE_DEPTH: usize = 4;

/// The most records of one EF.ARR this module reads. READ RECORD addresses
/// records 1 to 254 in P1.
const MAX_ARR_RECORDS: usize = 254;

const AM_READ: u8 = 0b01;
const AM_UPDATE: u8 = 0b10;

/// What a security condition demands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Condition {
    /// ALWays: no verification is needed.
    Always,
    /// NEVer.
    Never,
    /// Something must be satisfied (a PIN, ADM, a secure channel), or this
    /// module cannot say what.
    Restricted,
}

impl Condition {
    /// The spelling evidence uses.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Always => "ALW",
            Self::Never => "NEV",
            Self::Restricted => "restricted",
        }
    }

    /// All must hold: any NEV wins, all ALW is ALW, otherwise restricted.
    fn and(conditions: impl IntoIterator<Item = Self>) -> Self {
        let all: Vec<Self> = conditions.into_iter().collect();
        if all.is_empty() {
            Self::Restricted
        } else if all.contains(&Self::Never) {
            Self::Never
        } else if all.iter().all(|c| *c == Self::Always) {
            Self::Always
        } else {
            Self::Restricted
        }
    }

    /// One must hold: any ALW wins, all NEV is NEV, otherwise restricted.
    fn or(conditions: impl IntoIterator<Item = Self>) -> Self {
        let all: Vec<Self> = conditions.into_iter().collect();
        if all.is_empty() {
            Self::Restricted
        } else if all.contains(&Self::Always) {
            Self::Always
        } else if all.iter().all(|c| *c == Self::Never) {
            Self::Never
        } else {
            Self::Restricted
        }
    }

    /// What holds whichever of several rules applies: ALW only if every one
    /// is, NEV only if every one is.
    fn across(conditions: impl IntoIterator<Item = Self>) -> Self {
        let all: Vec<Self> = conditions.into_iter().collect();
        if !all.is_empty() && all.iter().all(|c| *c == Self::Always) {
            Self::Always
        } else if !all.is_empty() && all.iter().all(|c| *c == Self::Never) {
            Self::Never
        } else {
            Self::Restricted
        }
    }
}

/// The READ and UPDATE conditions of one file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Access {
    /// READ (and SEARCH) of the file.
    pub read: Condition,
    /// UPDATE of the file.
    pub update: Condition,
}

impl Access {
    fn across(rules: &[Self]) -> Self {
        Self {
            read: Condition::across(rules.iter().map(|a| a.read)),
            update: Condition::across(rules.iter().map(|a| a.update)),
        }
    }
}

/// Where a `8B` points: an EF.ARR and the record numbers in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArrRef {
    /// The EF.ARR file identifier.
    pub file: [u8; 2],
    /// Record numbers, one per security environment (one when unqualified).
    pub records: Vec<u8>,
}

/// Decodes the value of tag `8B` (clause 11.1.1.4.7.3). `None` for the
/// one-octet form (an implicitly known EF.ARR) and for any other length.
pub fn parse_arr_ref(value: &[u8]) -> Option<ArrRef> {
    match value {
        [hi, lo, record] => Some(ArrRef {
            file: [*hi, *lo],
            records: vec![*record],
        }),
        [hi, lo, pairs @ ..] if !pairs.is_empty() && pairs.len() % 2 == 0 => Some(ArrRef {
            file: [*hi, *lo],
            records: pairs.chunks(2).map(|p| p[1]).collect(),
        }),
        _ => None,
    }
}

/// The EF.ARR a node's `8B` names, found the way clause 9.2.7 says: in the
/// directory holding the file, then each parent up to the MF.
pub fn arr_path(tree: &Tree, node: &Node, arr: &ArrRef) -> Option<Path> {
    let id = fs::FileId::from_bytes(arr.file);
    let mut dir = node.path().parent().or_else(|| Some(Path::master_file()));
    while let Some(current) = dir {
        if let Ok(candidate) = current.child(id) {
            if tree.at(&candidate).is_some_and(|n| n.state().is_selected()) {
                return Some(candidate);
            }
        }
        dir = current.parent();
    }
    None
}

/// The access a file's FCP states, when it states one that decodes.
///
/// `8B` needs EF.ARR to have been read by [`resolve`]; without that it is
/// `None`, which is "not known".
pub fn access_of(tree: &Tree, node: &Node) -> Option<Access> {
    let caps = node.state().capabilities()?;
    if let Some(reference) = &caps.security_reference {
        let arr = parse_arr_ref(reference)?;
        let path = arr_path(tree, node, &arr)?;
        let records = tree.access_rule_records(&path)?;
        let rules: Option<Vec<Access>> = arr
            .records
            .iter()
            .map(|n| {
                let record = records.get(usize::from(*n).checked_sub(1)?)?;
                parse_expanded(record)
            })
            .collect();
        return Some(Access::across(&rules?)).filter(|_| !arr.records.is_empty());
    }
    if let Some(expanded) = &caps.security_expanded {
        return parse_expanded(expanded);
    }
    caps.access_conditions
        .reported()
        .and_then(|v| parse_compact(v))
}

/// Decodes compact security attributes (`8C` value, clause 9.2.5).
pub fn parse_compact(value: &[u8]) -> Option<Access> {
    let mut index = 0;
    let (mut reads, mut updates) = (Vec::new(), Vec::new());
    while index < value.len() {
        let am = value[index];
        index += 1;
        if am & 0x80 != 0 {
            return None;
        }
        let count = (am & 0x7F).count_ones() as usize;
        let scs = value.get(index..index + count)?;
        index += count;
        let (mut read, mut update) = (Condition::Never, Condition::Never);
        let mut next = 0;
        for bit in (0..7).rev() {
            if am >> bit & 1 == 1 {
                let c = if scs[next] == 0x00 {
                    Condition::Always
                } else {
                    Condition::Restricted
                };
                next += 1;
                match 1u8 << bit {
                    AM_READ => read = c,
                    AM_UPDATE => update = c,
                    _ => {}
                }
            }
        }
        reads.push(read);
        updates.push(update);
    }
    if reads.is_empty() {
        return None;
    }
    Some(Access {
        read: Condition::or(reads),
        update: Condition::or(updates),
    })
}

/// Decodes an expanded access rule: an `AB` value or an EF.ARR record
/// (clause 9.2.6, E.3). Trailing `FF` padding is ignored.
pub fn parse_expanded(bytes: &[u8]) -> Option<Access> {
    let end = bytes.iter().rposition(|b| *b != 0xFF)? + 1;
    let atoms = Stream::new(&bytes[..end]).collect_atoms().ok()?;
    let mut sets: Vec<(Option<u8>, Vec<Tlv<'_>>)> = Vec::new();
    for atom in atoms {
        if (0x80..=0x8F).contains(&atom.tag().octet()) {
            let am = match (atom.tag().octet(), atom.value()) {
                (0x80, [am]) if am & 0x80 == 0 => Some(*am),
                _ => None,
            };
            sets.push((am, Vec::new()));
        } else {
            sets.last_mut()?.1.push(atom);
        }
    }
    let unread = sets.iter().any(|(am, _)| am.is_none());
    let (mut reads, mut updates) = (Vec::new(), Vec::new());
    for (am, scs) in &sets {
        let Some(am) = am else { continue };
        let condition = Condition::and(scs.iter().map(|sc| condition_of(sc, 0)));
        reads.push(if am & AM_READ != 0 {
            condition
        } else {
            Condition::Never
        });
        updates.push(if am & AM_UPDATE != 0 {
            condition
        } else {
            Condition::Never
        });
    }
    if reads.is_empty() {
        return None;
    }
    // A command-description AM_DO may grant what the AM byte does not, so a
    // NEV is only a NEV when nothing was left unread.
    let settle = |c: Condition| {
        if unread && c == Condition::Never {
            Condition::Restricted
        } else {
            c
        }
    };
    Some(Access {
        read: settle(Condition::or(reads)),
        update: settle(Condition::or(updates)),
    })
}

fn condition_of(sc: &Tlv<'_>, depth: usize) -> Condition {
    match (sc.tag().octet(), sc.value()) {
        (0x90, []) => Condition::Always,
        (0x97, []) => Condition::Never,
        (tag @ (0xA0 | 0xAF), inner) if depth < MAX_TEMPLATE_DEPTH => {
            let Ok(children) = Stream::new(inner).collect_atoms() else {
                return Condition::Restricted;
            };
            let parts = children.iter().map(|c| condition_of(c, depth + 1));
            if tag == 0xA0 {
                Condition::or(parts)
            } else {
                Condition::and(parts)
            }
        }
        _ => Condition::Restricted,
    }
}

/// One PIN a directory's PIN status template lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinEntry {
    /// The key reference (table 9.3): `01` is PIN Appl 1, `11` the universal PIN.
    pub key_reference: u8,
    /// Whether the PS_DO bitmap marks it enabled.
    pub enabled: bool,
    /// The usage qualifier that preceded it, when one did.
    pub usage_qualifier: Option<u8>,
}

/// Decodes the value of the PIN status template DO `C6` (clause 11.1.1.4.10).
/// `None` when it is not a PS_DO followed by well-formed key references.
pub fn parse_pin_status(value: &[u8]) -> Option<Vec<PinEntry>> {
    let atoms = Stream::new(value).collect_atoms().ok()?;
    let (first, rest) = atoms.split_first()?;
    if first.tag().octet() != 0x90 {
        return None;
    }
    let bitmap = first.value();
    let mut entries = Vec::new();
    let mut qualifier = None;
    for atom in rest {
        match (atom.tag().octet(), atom.value()) {
            (0x95, [q]) => qualifier = Some(*q),
            (0x83, [key]) => {
                let index = entries.len();
                let enabled = *bitmap.get(index / 8)? >> (7 - index % 8) & 1 == 1;
                entries.push(PinEntry {
                    key_reference: *key,
                    enabled,
                    usage_qualifier: qualifier.take(),
                });
            }
            _ => return None,
        }
    }
    Some(entries)
}

/// Whether PIN Appl 1 (key reference `01`) is listed and disabled, with no
/// enabled universal PIN (`11`) in use in its place (clause 9.3.1, table 9.0d).
/// `None` when the template does not list PIN Appl 1.
pub fn pin1_disabled(entries: &[PinEntry]) -> Option<bool> {
    let pin1 = entries.iter().find(|e| e.key_reference == 0x01)?;
    let universal_in_use = entries.iter().any(|e| {
        e.key_reference == 0x11 && e.enabled && e.usage_qualifier.is_some_and(|q| q & 0x08 != 0)
    });
    Some(!pin1.enabled && !universal_in_use)
}

/// Reads every EF.ARR a selected file's `8B` names, once each, so that
/// [`access_of`] can decode the references. Sends only SELECT and READ RECORD.
///
/// A short or refused read leaves that file's remaining records unread, and
/// the files that point at them undecoded: unknown, not clean.
///
/// # Errors
///
/// Whatever [`session::send`] returns.
pub fn resolve<S: CardSession + ?Sized>(
    session: &mut S,
    tree: &mut Tree,
    policy: &Policy,
) -> Result<(), session::Error> {
    let mut wanted: Vec<Path> = Vec::new();
    for node in tree.selected() {
        let Some(reference) = node
            .state()
            .capabilities()
            .and_then(|c| c.security_reference.as_deref())
            .and_then(parse_arr_ref)
        else {
            continue;
        };
        if let Some(path) = arr_path(tree, node, &reference) {
            if !wanted.contains(&path) {
                wanted.push(path);
            }
        }
    }
    for path in wanted {
        let Some(shape) = tree
            .at(&path)
            .and_then(|n| n.state().capabilities())
            .and_then(|c| c.descriptor.reported())
            .and_then(|d| match d.octets.as_slice() {
                [_, _, hi, lo, count, ..] => Some((u16::from_be_bytes([*hi, *lo]), *count)),
                _ => None,
            })
        else {
            continue;
        };
        let records = read_records(session, &path, shape, policy)?;
        tree.record_access_rules(path, records);
    }
    Ok(())
}

fn read_records<S: CardSession + ?Sized>(
    session: &mut S,
    path: &Path,
    (length, count): (u16, u8),
    policy: &Policy,
) -> Result<Vec<Vec<u8>>, session::Error> {
    let mut records = Vec::new();
    let Some(le) = Le::for_byte_count(u32::from(length)).filter(|_| length > 0) else {
        return Ok(records);
    };
    let target: Vec<u8> = path
        .segments()
        .iter()
        .skip(1)
        .flat_map(|id| id.to_bytes())
        .collect();
    let select = session::send(
        session,
        &Command::case3(fs::select_path_header(), target),
        policy,
    )?;
    if !select.status().is_some_and(|s| s.is_normal_processing()) {
        return Ok(records);
    }
    for number in 1..=usize::from(count).min(MAX_ARR_RECORDS) {
        // `number` is at most 254 here.
        let header = Header::new(0x00, 0xB2, u8::try_from(number).unwrap_or(0xFF), 0x04);
        let read = session::send(session, &Command::case2(header, le), policy)?;
        if !read.status().is_some_and(|s| s.is_normal_processing()) {
            break;
        }
        records.push(read.data().to_vec());
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expanded_rule_read_always_update_adm() {
        // ETSI TS 102 221 annex F: READ ALW, UPDATE/DEACTIVATE/ACTIVATE level 5.
        let rule = [
            0x80, 0x01, 0x01, 0x90, 0x00, 0x80, 0x01, 0x1A, 0xA4, 0x06, 0x83, 0x01, 0x0A, 0x95,
            0x01, 0x08, 0xFF, 0xFF,
        ];
        let access = parse_expanded(&rule).unwrap();
        assert_eq!(access.read, Condition::Always);
        assert_eq!(access.update, Condition::Restricted);
    }

    #[test]
    fn expanded_or_template_with_always_is_always() {
        let rule = [0x80, 0x01, 0x02, 0xA0, 0x04, 0xA4, 0x00, 0x90, 0x00];
        let access = parse_expanded(&rule).unwrap();
        assert_eq!(access.update, Condition::Always);
        assert_eq!(access.read, Condition::Never);
    }

    #[test]
    fn an_unread_command_description_never_reads_as_never() {
        let rule = [0x80, 0x01, 0x01, 0x90, 0x00, 0x84, 0x01, 0x32, 0x90, 0x00];
        assert_eq!(parse_expanded(&rule).unwrap().update, Condition::Restricted);
    }

    #[test]
    fn compact_examples_from_the_spec() {
        // 8C 03: AM 03 SC 00 00 is ALW for READ and UPDATE (clause E.2.3).
        let both = parse_compact(&[0x03, 0x00, 0x00]).unwrap();
        assert_eq!(
            (both.read, both.update),
            (Condition::Always, Condition::Always)
        );
        // AM 03 SC 10 00: UPDATE by PIN (b2 first? SCs follow b7..b1, so b2 then b1).
        let pin = parse_compact(&[0x03, 0x10, 0x00]).unwrap();
        assert_eq!(
            (pin.read, pin.update),
            (Condition::Always, Condition::Restricted)
        );
        assert_eq!(parse_compact(&[0x81, 0x00]), None);
        assert_eq!(parse_compact(&[0x03, 0x00]), None);
    }

    #[test]
    fn arr_references() {
        assert_eq!(
            parse_arr_ref(&[0x2F, 0x06, 0x03]),
            Some(ArrRef {
                file: [0x2F, 0x06],
                records: vec![3]
            })
        );
        assert_eq!(
            parse_arr_ref(&[0x6F, 0x06, 0x00, 0x01, 0x01, 0x02])
                .unwrap()
                .records,
            vec![1, 2]
        );
        assert_eq!(parse_arr_ref(&[0x03]), None);
    }

    #[test]
    fn pin_status_bitmap_pairs_with_key_references() {
        // PS_DO 80: first key reference enabled; 95 08 then 83 11 universal.
        let value = [
            0x90, 0x01, 0x80, 0x83, 0x01, 0x01, 0x95, 0x01, 0x08, 0x83, 0x01, 0x11,
        ];
        let entries = parse_pin_status(&value).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries[0].enabled && !entries[1].enabled);
        assert_eq!(pin1_disabled(&entries), Some(false));
        let off = parse_pin_status(&[0x90, 0x01, 0x00, 0x83, 0x01, 0x01]).unwrap();
        assert_eq!(pin1_disabled(&off), Some(true));
        assert_eq!(parse_pin_status(&[0x83, 0x01, 0x01]), None);
    }

    #[test]
    fn an_enabled_universal_pin_in_use_covers_a_disabled_pin1() {
        let value = [
            0x90, 0x01, 0x40, 0x83, 0x01, 0x01, 0x95, 0x01, 0x08, 0x83, 0x01, 0x11,
        ];
        let entries = parse_pin_status(&value).unwrap();
        assert_eq!(pin1_disabled(&entries), Some(false));
    }
}
