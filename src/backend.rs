//! Backend selection by environment variable, after lpac's `LPAC_APDU` and
//! `LPAC_HTTP` (lpac `docs/ENVVARS.md`, `docs/USAGE.md`: "If not specified, it
//! will use `pcsc` and `curl`").
//!
//! | Variable | Values | Default |
//! |---|---|---|
//! | `SIM_DOCTOR_HTTP` | `https` (built in, verified TLS), `stdio` (lpac's JSON-lines protocol, the host does the HTTP) | `https` |
//! | `SIM_DOCTOR_CA_BUNDLE` | path of a PEM file of trust anchors (replaces the default), or the word `webpki` for the Mozilla web roots | the bundled GSMA RSP2 Root CI1 |
//!
//! **Takes effect once a command uses ES9+ (#118).** No shipped command calls
//! the transport yet, so these variables are read only by library callers
//! ([`HttpBackend::open_from_env`]). There is no `SIM_DOCTOR_APDU`: the
//! `euicc` commands open a PC/SC session directly, and a replay selector was
//! left out rather than shipped as a variable that does nothing.
//!
//! Not supported, unlike lpac: any APDU selection, and the curl and WinHTTP
//! HTTP backends (`https` is the one built-in client). lpac's curl backend
//! turns certificate verification off; this crate never does. The
//! `SIM_DOCTOR_` prefix is this tool's own: lpac's names are not read, so an
//! lpac environment cannot silently change what this tool trusts.

use crate::es9::{Es9Transport, TransportError};
use crate::es9_https::{HttpsConfig, HttpsTransport, StdioTransport, Trust};

/// Selects the HTTP backend.
pub const HTTP_VAR: &str = "SIM_DOCTOR_HTTP";
/// Trust anchors for the `https` backend: a PEM path, or `webpki`.
pub const CA_BUNDLE_VAR: &str = "SIM_DOCTOR_CA_BUNDLE";

/// Where ES9+ HTTP goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpBackend {
    /// The built-in verified HTTPS client.
    Https,
    /// lpac's stdio protocol on this process's stdin and stdout.
    Stdio,
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
    pub fn open(self, trust: Trust) -> Result<Box<dyn Es9Transport>, TransportError> {
        Ok(match self {
            Self::Https => Box::new(HttpsTransport::new(&HttpsConfig {
                trust,
                ..HttpsConfig::default()
            })?),
            Self::Stdio => Box::new(StdioTransport::new(
                std::io::BufReader::new(std::io::stdin()),
                std::io::stdout(),
            )),
        })
    }

    /// [`Self::from_env`] then [`Self::open`] with [`CA_BUNDLE_VAR`] ([`Trust::from_env_value`]).
    ///
    /// # Errors
    ///
    /// A message for a bad selection or an unusable bundle.
    pub fn open_from_env() -> Result<Box<dyn Es9Transport>, String> {
        Self::from_env()?
            .open(Trust::from_env_value(std::env::var_os(CA_BUNDLE_VAR)))
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_values() {
        assert_eq!(HttpBackend::parse(None), Ok(HttpBackend::Https));
        assert_eq!(HttpBackend::parse(Some("stdio")), Ok(HttpBackend::Stdio));
    }

    #[test]
    fn unknown_values_are_refused_not_defaulted() {
        // lpac's `curl` would be a silent no-verify path; it must not be accepted.
        assert!(HttpBackend::parse(Some("curl")).is_err());
        assert!(HttpBackend::parse(Some("")).is_err());
    }
}
