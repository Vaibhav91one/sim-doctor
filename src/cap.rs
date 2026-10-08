//! Java Card CAP files to GlobalPlatform load files, host-side only.
//!
//! **Owns.** Reading a CAP (a zip of `javacard/*.cap` components), checking each
//! component's own header, joining them in the order the Java Card VM
//! Specification (v3.x, section 6.3) gives, and checking an IJC (Interoperable
//! Java Card, the same components already concatenated) so it can be passed
//! through unchanged.
//!
//! **Does not own.** Putting anything on a card: the INSTALL and LOAD builders
//! live in [`crate::gp`] and send nothing either.
//!
//! **Order.** Header, Directory, Import, Applet, Class, Method, StaticField,
//! Export, ConstantPool, RefLocation, Descriptor. Debug is never loaded.
//! References: pySim `javacard.py` `CapFile.get_loadfile` and kaoh/globalplatform
//! `loadfile.c` (`OPGP_extract_cap_file`), which agree on this order, Descriptor
//! last and optional, Applet and Export optional.
//!
//! **Untrusted input.** A CAP is data from outside. It is read from memory, never
//! extracted to disk, never executed; entry names are only compared, never used
//! as paths; the entry count and every component's size are bounded (a
//! component's size field is 16 bits, so no component can legitimately exceed
//! 65538 bytes, and inflation stops there, which is what stops a zip bomb).

/// This module's name, as recorded in [`crate::MODULES`].
pub const NAME: &str = "cap";

use std::io::{Cursor, Read};

/// A component and its tag, in load order. Debug (tag 12) is not here: it is
/// never loaded.
const LOAD_ORDER: [(&str, u8); 11] = [
    ("Header", 1),
    ("Directory", 2),
    ("Import", 4),
    ("Applet", 3),
    ("Class", 6),
    ("Method", 7),
    ("StaticField", 8),
    ("Export", 10),
    ("ConstantPool", 5),
    ("RefLocation", 9),
    ("Descriptor", 11),
];

/// Components a load file cannot do without; the rest are optional.
const REQUIRED: [&str; 8] = [
    "Header",
    "Directory",
    "Import",
    "Class",
    "Method",
    "StaticField",
    "ConstantPool",
    "RefLocation",
];

/// Tag 12, the Debug component: allowed in a CAP, never loaded.
const DEBUG_TAG: u8 = 12;

/// Most zip entries read.
const MAX_ENTRIES: usize = 256;

/// Largest component: 1 tag byte, a 16-bit size, and 65535 bytes of body.
const MAX_COMPONENT: usize = 3 + 0xFFFF;

/// The Header component's magic.
const MAGIC: [u8; 4] = [0xDE, 0xCA, 0xFF, 0xED];

/// Why a CAP or IJC was refused.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Not a readable zip.
    #[error("not a readable zip archive: {0}")]
    Zip(String),
    /// More entries than any real CAP has.
    #[error("zip has more than {MAX_ENTRIES} entries")]
    TooManyEntries,
    /// A component appears twice (two packages in one archive).
    #[error("component {0} appears more than once")]
    Duplicate(String),
    /// A component that every load file needs is absent.
    #[error("required component {0} is missing")]
    Missing(&'static str),
    /// A component is longer than its 16-bit size field allows.
    #[error("component {0} is larger than {MAX_COMPONENT} bytes")]
    TooLarge(String),
    /// A component's tag or size field disagrees with its name or length.
    #[error("component {name} is malformed: {why}")]
    Malformed {
        /// The component.
        name: String,
        /// What was wrong.
        why: &'static str,
    },
}

/// A parsed CAP: its components, keyed by name, each the whole `.cap` file
/// (tag, size and body).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cap {
    components: Vec<(&'static str, Vec<u8>)>,
}

/// Checks one component: its tag is `tag` and its size field is the rest.
fn check_component(name: &str, tag: u8, bytes: &[u8]) -> Result<(), Error> {
    let bad = |why| Error::Malformed {
        name: name.to_owned(),
        why,
    };
    let [t, hi, lo, body @ ..] = bytes else {
        return Err(bad("shorter than its 3-byte header"));
    };
    if *t != tag {
        return Err(bad("tag does not match the component name"));
    }
    if usize::from(u16::from_be_bytes([*hi, *lo])) != body.len() {
        return Err(bad("size field does not match the length"));
    }
    Ok(())
}

impl Cap {
    /// Reads a CAP from its bytes.
    ///
    /// # Errors
    ///
    /// A zip that cannot be read, has too many entries, repeats a component,
    /// lacks a required one, or holds a component whose own header is wrong.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut zip =
            zip::ZipArchive::new(Cursor::new(bytes)).map_err(|e| Error::Zip(e.to_string()))?;
        if zip.len() > MAX_ENTRIES {
            return Err(Error::TooManyEntries);
        }
        let mut found: Vec<(&'static str, u8, Vec<u8>)> = Vec::new();
        for i in 0..zip.len() {
            let file = zip.by_index(i).map_err(|e| Error::Zip(e.to_string()))?;
            // Only compared, never used as a path.
            let entry = file.name().rsplit('/').next().unwrap_or("").to_owned();
            let Some(stem) = entry.strip_suffix(".cap") else {
                continue;
            };
            let known = LOAD_ORDER.iter().find(|(n, _)| *n == stem);
            let (name, tag) = match known {
                Some(&(n, t)) => (n, t),
                // Debug and anything unknown (e.g. the extended-format files)
                // is not part of a load file; unknown names are ignored.
                None => continue,
            };
            if found.iter().any(|(n, _, _)| *n == name) {
                return Err(Error::Duplicate(name.to_owned()));
            }
            let mut body = Vec::new();
            file.take(MAX_COMPONENT as u64 + 1)
                .read_to_end(&mut body)
                .map_err(|e| Error::Zip(e.to_string()))?;
            if body.len() > MAX_COMPONENT {
                return Err(Error::TooLarge(name.to_owned()));
            }
            check_component(name, tag, &body)?;
            found.push((name, tag, body));
        }
        let mut components = Vec::new();
        for (name, _) in LOAD_ORDER {
            match found.iter().position(|(n, _, _)| *n == name) {
                Some(at) => {
                    let (n, _, body) = found.swap_remove(at);
                    components.push((n, body));
                }
                None => {
                    if let Some(req) = REQUIRED.iter().find(|r| **r == name) {
                        return Err(Error::Missing(req));
                    }
                }
            }
        }
        let cap = Self { components };
        cap.header_package_aid()?;
        Ok(cap)
    }

    /// A component by name, whole (tag, size, body).
    pub fn component(&self, name: &str) -> Option<&[u8]> {
        self.components
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, b)| b.as_slice())
    }

    /// The names of the components that will be loaded, in load order.
    pub fn load_order(&self) -> Vec<&'static str> {
        self.components.iter().map(|(n, _)| *n).collect()
    }

    /// The executable load file: the components joined in load order.
    pub fn load_file(&self) -> Vec<u8> {
        self.components
            .iter()
            .flat_map(|(_, b)| b.iter().copied())
            .collect()
    }

    /// The package AID from the Header (the Executable Load File AID).
    ///
    /// # Errors
    ///
    /// A Header without the magic or with a package AID that overruns it.
    pub fn header_package_aid(&self) -> Result<Vec<u8>, Error> {
        let header = self.component("Header").unwrap_or_default();
        let bad = |why| Error::Malformed {
            name: "Header".to_owned(),
            why,
        };
        // tag, size(2), magic(4), minor, major, flags, pkg minor, pkg major,
        // AID length, AID.
        if header.get(3..7) != Some(&MAGIC[..]) {
            return Err(bad("magic is not DECAFFED"));
        }
        let len = usize::from(*header.get(12).ok_or(bad("no package AID"))?);
        header
            .get(13..13 + len)
            .map(<[u8]>::to_vec)
            .ok_or(bad("package AID overruns the component"))
    }

    /// The AIDs of the applets in the Applet component (empty when absent).
    ///
    /// # Errors
    ///
    /// An Applet component whose entries overrun it.
    pub fn applet_aids(&self) -> Result<Vec<Vec<u8>>, Error> {
        let Some(applet) = self.component("Applet") else {
            return Ok(Vec::new());
        };
        let bad = |why| Error::Malformed {
            name: "Applet".to_owned(),
            why,
        };
        let count = usize::from(*applet.get(3).ok_or(bad("no applet count"))?);
        let mut at = 4;
        let mut out = Vec::new();
        for _ in 0..count {
            let len = usize::from(*applet.get(at).ok_or(bad("entry overruns"))?);
            let aid = applet
                .get(at + 1..at + 1 + len)
                .ok_or(bad("AID overruns"))?;
            out.push(aid.to_vec());
            // AID, then the 16-bit install method offset.
            at += 1 + len + 2;
        }
        if at > applet.len() {
            return Err(bad("install method offset overruns"));
        }
        Ok(out)
    }
}

/// Checks an IJC file (components already concatenated: tag, 16-bit size,
/// body, repeated) and returns the bytes unchanged, which is the load file.
/// pySim `ijc_to_cap` reads the same framing.
///
/// # Errors
///
/// Anything that is not a whole number of well-framed components, or that does
/// not start with the Header.
pub fn ijc_load_file(bytes: &[u8]) -> Result<&[u8], Error> {
    let bad = |why| Error::Malformed {
        name: "IJC".to_owned(),
        why,
    };
    let mut at = 0;
    let mut first = true;
    while at < bytes.len() {
        let Some(&[tag, hi, lo]) = bytes.get(at..at + 3) else {
            return Err(bad("truncated component header"));
        };
        if first && tag != 1 {
            return Err(bad("does not start with the Header component"));
        }
        if !(1..=DEBUG_TAG).contains(&tag) {
            return Err(bad("unknown component tag"));
        }
        first = false;
        at += 3 + usize::from(u16::from_be_bytes([hi, lo]));
        if at > bytes.len() {
            return Err(bad("component overruns the file"));
        }
    }
    if first {
        return Err(bad("empty"));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// A component: tag, 16-bit size, body.
    fn comp(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        v.extend((body.len() as u16).to_be_bytes());
        v.extend(body);
        v
    }

    fn header() -> Vec<u8> {
        // magic, minor 1, major 2, flags 0, pkg minor 0, major 1, AID len 5.
        comp(
            1,
            &[0xDE, 0xCA, 0xFF, 0xED, 1, 2, 0, 0, 1, 5, 0xA0, 0, 0, 0, 1],
        )
    }

    fn applet() -> Vec<u8> {
        // one applet: AID len 6 A00000000101, install method offset 0x0010.
        comp(3, &[1, 6, 0xA0, 0, 0, 0, 1, 1, 0x00, 0x10])
    }

    /// Writes a synthetic CAP; `names` is (entry name, bytes). Stored and
    /// deflated entries are both exercised by the caller.
    fn zip_of(entries: &[(String, Vec<u8>)], deflate: bool) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let method = if deflate {
            zip::CompressionMethod::Deflated
        } else {
            zip::CompressionMethod::Stored
        };
        let opts = zip::write::SimpleFileOptions::default().compression_method(method);
        for (name, bytes) in entries {
            w.start_file(name.as_str(), opts).unwrap();
            w.write_all(bytes).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    /// All components, written in a scrambled order, plus Debug and a manifest.
    fn entries() -> Vec<(String, Vec<u8>)> {
        let p = "com/example/javacard/";
        let mut v = vec![
            ("META-INF/MANIFEST.MF".to_owned(), b"x".to_vec()),
            (format!("{p}Descriptor.cap"), comp(11, &[0xD0])),
            (format!("{p}RefLocation.cap"), comp(9, &[0x90, 0x91])),
            (format!("{p}Debug.cap"), comp(12, &[0xDD])),
            (format!("{p}ConstantPool.cap"), comp(5, &[0x50])),
            (format!("{p}Export.cap"), comp(10, &[0xA0])),
            (format!("{p}StaticField.cap"), comp(8, &[0x80])),
            (format!("{p}Method.cap"), comp(7, &[0x70])),
            (format!("{p}Class.cap"), comp(6, &[0x60])),
            (format!("{p}Applet.cap"), applet()),
            (format!("{p}Import.cap"), comp(4, &[0x40])),
            (format!("{p}Directory.cap"), comp(2, &[0x20])),
            (format!("{p}Header.cap"), header()),
        ];
        v.push(("com/example/javacard/Other.capx".to_owned(), vec![1]));
        v
    }

    fn expected() -> Vec<u8> {
        [
            header(),
            comp(2, &[0x20]),
            comp(4, &[0x40]),
            applet(),
            comp(6, &[0x60]),
            comp(7, &[0x70]),
            comp(8, &[0x80]),
            comp(10, &[0xA0]),
            comp(5, &[0x50]),
            comp(9, &[0x90, 0x91]),
            comp(11, &[0xD0]),
        ]
        .concat()
    }

    #[test]
    fn components_join_in_jcvm_order_stored_and_deflated() {
        for deflate in [false, true] {
            let cap = Cap::parse(&zip_of(&entries(), deflate)).unwrap();
            assert_eq!(
                cap.load_order(),
                [
                    "Header",
                    "Directory",
                    "Import",
                    "Applet",
                    "Class",
                    "Method",
                    "StaticField",
                    "Export",
                    "ConstantPool",
                    "RefLocation",
                    "Descriptor"
                ]
            );
            assert_eq!(cap.load_file(), expected(), "deflate={deflate}");
            assert_eq!(cap.header_package_aid().unwrap(), [0xA0, 0, 0, 0, 1]);
            assert_eq!(cap.applet_aids().unwrap(), vec![vec![0xA0, 0, 0, 0, 1, 1]]);
        }
    }

    #[test]
    fn debug_is_not_loaded_and_optional_components_may_be_absent() {
        let mut e = entries();
        e.retain(|(n, _)| !n.ends_with("Applet.cap") && !n.ends_with("Export.cap"));
        let cap = Cap::parse(&zip_of(&e, false)).unwrap();
        assert!(!cap.load_order().contains(&"Applet"));
        assert!(cap.component("Debug").is_none());
        assert!(cap.applet_aids().unwrap().is_empty());
    }

    #[test]
    fn untrusted_input_is_refused() {
        assert!(matches!(Cap::parse(b"not a zip"), Err(Error::Zip(_))));
        let mut e = entries();
        e.retain(|(n, _)| !n.ends_with("Method.cap"));
        assert_eq!(
            Cap::parse(&zip_of(&e, false)),
            Err(Error::Missing("Method"))
        );
        // a size field that lies
        let mut e = entries();
        for (n, b) in &mut e {
            if n.ends_with("Class.cap") {
                b[2] = 9;
            }
        }
        assert!(matches!(
            Cap::parse(&zip_of(&e, false)),
            Err(Error::Malformed { .. })
        ));
        // two packages
        let mut e = entries();
        e.push(("other/javacard/Class.cap".to_owned(), comp(6, &[1])));
        assert_eq!(
            Cap::parse(&zip_of(&e, false)),
            Err(Error::Duplicate("Class".into()))
        );
        // a component bigger than any size field can say
        let mut e = entries();
        for (n, b) in &mut e {
            if n.ends_with("Class.cap") {
                *b = vec![6; MAX_COMPONENT + 10];
            }
        }
        assert_eq!(
            Cap::parse(&zip_of(&e, true)),
            Err(Error::TooLarge("Class".into()))
        );
    }

    #[test]
    fn ijc_passes_through_when_framed() {
        let f = expected();
        assert_eq!(ijc_load_file(&f).unwrap(), &f[..]);
        assert!(ijc_load_file(&f[..f.len() - 1]).is_err());
        assert!(ijc_load_file(&f[header().len()..]).is_err());
        assert!(ijc_load_file(&[]).is_err());
    }
}
