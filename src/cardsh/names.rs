//! Names of the standard files and where they live (ETSI TS 102 221, 3GPP TS 31.102 / 31.103, TS 51.011).
//! Cross-checked against pySim's file system tables (`ts_102_221.py`, `ts_31_102.py`, `ts_51_011.py`);
//! the table is written here.

use crate::fs::FileId;

/// A named file: its name, identifier and the directory it lives under.
pub struct Named {
    /// `EF.IMSI`.
    pub name: &'static str,
    /// The two identifier octets.
    pub fid: u16,
    /// `MF`, `ADF.USIM`, `DF.TELECOM` ...
    pub scope: &'static str,
}

/// The files `select` knows by name.
pub const NAMES: &[Named] = &[
    Named {
        name: "MF",
        fid: 0x3F00,
        scope: "MF",
    },
    Named {
        name: "DF.TELECOM",
        fid: 0x7F10,
        scope: "MF",
    },
    Named {
        name: "DF.GSM",
        fid: 0x7F20,
        scope: "MF",
    },
    Named {
        name: "DF.PHONEBOOK",
        fid: 0x5F3A,
        scope: "DF.TELECOM",
    },
    Named {
        name: "DF.5GS",
        fid: 0x5FC0,
        scope: "ADF.USIM",
    },
    Named {
        name: "EF.DIR",
        fid: 0x2F00,
        scope: "MF",
    },
    Named {
        name: "EF.ICCID",
        fid: 0x2FE2,
        scope: "MF",
    },
    Named {
        name: "EF.PL",
        fid: 0x2F05,
        scope: "MF",
    },
    Named {
        name: "EF.ARR",
        fid: 0x2F06,
        scope: "MF",
    },
    Named {
        name: "EF.IMSI",
        fid: 0x6F07,
        scope: "ADF.USIM",
    },
    Named {
        name: "EF.AD",
        fid: 0x6FAD,
        scope: "ADF.USIM",
    },
    Named {
        name: "EF.UST",
        fid: 0x6F38,
        scope: "ADF.USIM",
    },
    Named {
        name: "EF.EST",
        fid: 0x6F56,
        scope: "ADF.USIM",
    },
    Named {
        name: "EF.SPN",
        fid: 0x6F46,
        scope: "ADF.USIM",
    },
    Named {
        name: "EF.MSISDN",
        fid: 0x6F40,
        scope: "ADF.USIM",
    },
    Named {
        name: "EF.ACC",
        fid: 0x6F78,
        scope: "ADF.USIM",
    },
    Named {
        name: "EF.FPLMN",
        fid: 0x6F7B,
        scope: "ADF.USIM",
    },
    Named {
        name: "EF.LOCI",
        fid: 0x6F7E,
        scope: "ADF.USIM",
    },
    Named {
        name: "EF.PSLOCI",
        fid: 0x6F73,
        scope: "ADF.USIM",
    },
    Named {
        name: "EF.EPSLOCI",
        fid: 0x6FE3,
        scope: "ADF.USIM",
    },
    Named {
        name: "EF.KEYS",
        fid: 0x6F08,
        scope: "ADF.USIM",
    },
    Named {
        name: "EF.KEYSPS",
        fid: 0x6F09,
        scope: "ADF.USIM",
    },
    Named {
        name: "EF.ADN",
        fid: 0x6F3A,
        scope: "DF.TELECOM",
    },
    Named {
        name: "EF.FDN",
        fid: 0x6F3B,
        scope: "DF.TELECOM",
    },
    Named {
        name: "EF.SMS",
        fid: 0x6F3C,
        scope: "DF.TELECOM",
    },
    Named {
        name: "EF.IMSI(GSM)",
        fid: 0x6F07,
        scope: "DF.GSM",
    },
];

/// The identifier of a file name (`EF.IMSI`, `imsi`, `df.gsm`), case-insensitive; the `EF.` / `DF.`
/// prefix may be left out when the rest is unique.
pub fn fid_of(name: &str) -> Option<FileId> {
    let n = name.to_ascii_uppercase();
    let hit = |f: &Named| f.name.eq_ignore_ascii_case(&n) && !f.name.contains('(');
    let by_full = NAMES.iter().find(|f| hit(f));
    let by_bare = || {
        let mut found = NAMES.iter().filter(|f| {
            f.name
                .split_once('.')
                .is_some_and(|(_, rest)| rest.eq_ignore_ascii_case(&n))
                && !f.name.contains('(')
        });
        let first = found.next()?;
        found.next().is_none().then_some(first)
    };
    by_full
        .or_else(by_bare)
        .map(|f| FileId::from_bytes(f.fid.to_be_bytes()))
}

/// Where the standard file with this identifier lives (the first match), for a refusal's hint.
pub fn scope_of(id: FileId) -> Option<&'static str> {
    NAMES
        .iter()
        .find(|f| f.fid.to_be_bytes() == id.to_bytes() && !f.name.contains('('))
        .map(|f| f.scope)
}
