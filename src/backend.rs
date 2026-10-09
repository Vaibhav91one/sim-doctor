//! Backend selection by environment variable, after lpac's `LPAC_APDU` and
//! `LPAC_HTTP` (lpac `docs/ENVVARS.md`, `docs/USAGE.md`: "If not specified, it
//! will use `pcsc` and `curl`").
//!
//! | Variable | Values | Default |
//! |---|---|---|
//! | `SIM_DOCTOR_APDU` | `pcsc` (a PC/SC reader), `replay` (a log written by `SIM_DOCTOR_RECORD`, path in `SIM_DOCTOR_REPLAY`) | `pcsc` |
//! | `SIM_DOCTOR_HTTP` | `https` (built in, verified TLS), `stdio` (lpac's JSON-lines protocol, the host does the HTTP) | `https` |
//! | `SIM_DOCTOR_CA_BUNDLE` | path of a PEM file of trust anchors, replaces the default roots | web roots |
//!
//! Not supported, unlike lpac: AT, QMI, MBIM, GBinder APDU backends, and the
//! curl and WinHTTP HTTP backends (`https` is the one built-in client). lpac's
//! curl backend turns certificate verification off; this crate never does.
//! The `SIM_DOCTOR_` prefix is this tool's own: lpac's names are not read, so
//! an lpac environment cannot silently change what this tool trusts.

use std::path::PathBuf;

use crate::es9::{Es9Transport, TransportError};
use crate::es9_https::{HttpsConfig, HttpsTransport, StdioTransport};
use crate::transport::replay::Replay;

/// Selects the APDU backend.
pub const APDU_VAR: &str = "SIM_DOCTOR_APDU";
/// Selects the HTTP backend.
pub const HTTP_VAR: &str = "SIM_DOCTOR_HTTP";
/// Trust anchors for the `https` backend.
pub const CA_BUNDLE_VAR: &str = "SIM_DOCTOR_CA_BUNDLE";
/// The log the `replay` APDU backend answers from.
pub const REPLAY_VAR: &str = "SIM_DOCTOR_REPLAY";

/// Where APDUs go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApduBackend {
    /// A PC/SC reader.
    Pcsc,
    /// A recorded log, no reader.
    Replay,
}

/// Where ES9+ HTTP goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpBackend {
    /// The built-in verified HTTPS client.
    Https,
    /// lpac's stdio protocol on this process's stdin and stdout.
    Stdio,
}

impl ApduBackend {
    /// Parses a value; `None` (variable unset) is the default.
    ///
    /// # Errors
    ///
    /// A message naming the accepted values.
    pub fn parse(value: Option<&str>) -> Result<Self, String> {
        match value {
            None | Some("pcsc") => Ok(Self::Pcsc),
            Some("replay") => Ok(Self::Replay),
            Some(other) => Err(format!("{APDU_VAR}={other:?}: expected `pcsc` or `replay`")),
        }
    }

    /// Reads [`APDU_VAR`].
    ///
    /// # Errors
    ///
    /// As [`Self::parse`].
    pub fn from_env() -> Result<Self, String> {
        Self::parse(std::env::var(APDU_VAR).ok().as_deref())
    }
}

impl HttpBackend {
    /// Parses a value; `None` (variable unset) is the default.
    ///
    /// # Errors
    ///
    /// A message naming the accepted values.
    pub fn parse(value: Option<&str>) -> Result<Self, String> {
        match value {
            None | Some("https") => Ok(Self::Https),
            Some("stdio") => Ok(Self::Stdio),
            Some(other) => Err(format!("{HTTP_VAR}={other:?}: expected `https` or `stdio`")),
        }
    }

    /// Reads [`HTTP_VAR`].
    ///
    /// # Errors
    ///
    /// As [`Self::parse`].
    pub fn from_env() -> Result<Self, String> {
        Self::parse(std::env::var(HTTP_VAR).ok().as_deref())
    }

    /// Opens the selected transport. Nothing touches the network here; the
    /// first request does.
    ///
    /// # Errors
    ///
    /// [`TransportError`] when the `https` CA bundle cannot be used.
    pub fn open(self, ca_bundle: Option<PathBuf>) -> Result<Box<dyn Es9Transport>, TransportError> {
        Ok(match self {
            Self::Https => Box::new(HttpsTransport::new(&HttpsConfig {
                ca_bundle,
                ..HttpsConfig::default()
            })?),
            Self::Stdio => Box::new(StdioTransport::new(
                std::io::BufReader::new(std::io::stdin()),
                std::io::stdout(),
            )),
        })
    }

    /// [`Self::from_env`] then [`Self::open`] with [`CA_BUNDLE_VAR`].
    ///
    /// # Errors
    ///
    /// A message for a bad selection or an unusable bundle.
    pub fn open_from_env() -> Result<Box<dyn Es9Transport>, String> {
        Self::from_env()?
            .open(std::env::var_os(CA_BUNDLE_VAR).map(PathBuf::from))
            .map_err(|e| e.to_string())
    }
}

/// Loads the log named by [`REPLAY_VAR`] for the `replay` APDU backend.
///
/// # Errors
///
/// A message when the variable is unset or the log cannot be read or parsed.
pub fn replay_from_env() -> Result<Replay, String> {
    let path = std::env::var_os(REPLAY_VAR)
        .ok_or_else(|| format!("{APDU_VAR}=replay needs {REPLAY_VAR}=<log path>"))?;
    let log = std::fs::read_to_string(&path)
        .map_err(|e| format!("{REPLAY_VAR} {}: {e}", path.to_string_lossy()))?;
    Replay::from_log(&log)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_values() {
        assert_eq!(ApduBackend::parse(None), Ok(ApduBackend::Pcsc));
        assert_eq!(ApduBackend::parse(Some("replay")), Ok(ApduBackend::Replay));
        assert_eq!(HttpBackend::parse(None), Ok(HttpBackend::Https));
        assert_eq!(HttpBackend::parse(Some("stdio")), Ok(HttpBackend::Stdio));
    }

    #[test]
    fn unknown_values_are_refused_not_defaulted() {
        // lpac's `curl` would be a silent no-verify path; it must not be accepted.
        assert!(HttpBackend::parse(Some("curl")).is_err());
        assert!(HttpBackend::parse(Some("")).is_err());
        assert!(ApduBackend::parse(Some("at")).is_err());
    }
}
