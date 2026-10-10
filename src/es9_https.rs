//! The HTTPS [`Es9Transport`]: the only code in this crate that opens a
//! network socket. Nothing calls it unless a command explicitly needs ES9+.
//!
//! # Trust store (certificate verification is always on)
//!
//! There is no insecure option, no "skip verify" flag and no environment
//! variable that disables checking; [`HttpsConfig`] has no such field.
//!
//! * SGP.22 v2.2.2 §5.6 ("the LPA SHALL verify the received CERT.DP.TLS
//!   according to section 4.5.2.2") and §3.1.2 step 5 (verify CERT.XX.TLS or
//!   stop) require the check; §4.5.2.2 says a certificate is "Signed by a
//!   GSMA CI, or a trusted chain up to a GSMA CI". The anchor of an SM-DP+ TLS
//!   certificate is a GSMA CI, not the web PKI.
//! * Observed 2026-10-09 with a plain `openssl s_client` handshake (no ES9+
//!   request): `smdp.io` and `rsp.truphone.com` (1GLOBAL SM-DP+) present a
//!   leaf issued **directly** by `GSM Association - RSP2 Root CI1` (AKI
//!   `81370f51...ebfb`), which no web root signs, so web roots would reject
//!   it. Google's `prod.smdp-plus.rsp.goog` chains to a Symantec RSP *test*
//!   root, also not a web root.
//! * lpac (estkme-group/lpac, `driver/http/curl.c`, commit 82ada9e) sets
//!   `CURLOPT_SSL_VERIFYPEER` and `CURLOPT_SSL_VERIFYHOST` to 0: it verifies
//!   **nothing** (its WinHTTP backend sets `SECURITY_FLAG_IGNORE_UNKNOWN_CA`).
//!   That is not copied here.
//!
//! [`Trust`] therefore defaults to [`Trust::GsmaCi`]: the bundled
//! `certs/gsma-rsp2-root-ci1.pem`. Its SHA-256 is
//! [`GSMA_RSP2_ROOT_CI1_SHA256`], pinned by a test. Provenance: the PEM comes
//! from the Osmocom eUICC manual's CI bundle
//! (<https://euicc-manual.osmocom.org/docs/pki/ci/bundle.pem>, entry
//! "GSMA RSP2 Root CI1", Key ID 81370f51...ebfb, valid to 2052-02-21).
//! gsma.com refuses automated downloads (HTTP 403), so no GSMA-hosted copy was
//! compared; instead the key was checked against production: the live
//! `smdp.io` leaf verifies against this certificate with OpenSSL. Compare the
//! fingerprint with the file on GSMA's "Root Certificate Issuer for Remote SIM
//! Provisioning" page before relying on it.
//!
//! Other live CIs (for example OISTE GSMA CI G1, Key ID 4c27967a...222f) are
//! not bundled: supply them with [`Trust::Bundle`] (CLI/env
//! `SIM_DOCTOR_CA_BUNDLE=<pem>`), which **replaces** the default. The Mozilla
//! web roots are only used when asked for explicitly ([`Trust::Webpki`], env
//! value `webpki`), for test servers and public-CA hosts. Revocation (CRL) is
//! not checked, and the §2.6.6 cipher-suite rules are those of rustls, which
//! offers only TLS 1.2+ AEAD ECDHE suites.
//!
//! //! # Wire behaviour
//!
//! POST only, `https://` only, redirects never followed (a `3xx` is returned
//! as is and [`crate::es9`] refuses it), any status returned as a [`Response`]
//! (the ES9+ layer judges it), one global timeout, and a response size cap
//! (reading past it is a [`TransportError`], never a truncated body). Headers
//! are the ones [`crate::es9::Request::headers`] supplies (`Content-Type`,
//! `X-Admin-Protocol`, `User-Agent`); the client adds `Host` and
//! `Content-Length`. ureq's default proxy handling applies (it reads the
//! standard proxy environment variables); the proxy only carries the TLS
//! tunnel, verification is still end to end.
//!
//! # Why ureq
//!
//! A small blocking client with rustls: no async runtime, no OpenSSL or other
//! C TLS library to cross-build (the aarch64 CI job needs nothing extra), and
//! it can disable redirects and cap bodies. reqwest/hyper would pull tokio.

use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ureq::tls::{RootCerts, TlsConfig};

use crate::es9::{Es9Transport, Response, TransportError};

/// Default whole-request timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
/// Default response cap: 16 MiB. A BoundProfilePackage is far smaller.
pub const DEFAULT_MAX_RESPONSE: u64 = 16 * 1024 * 1024;

/// SHA-256 of the DER of the bundled GSMA RSP2 Root CI1 certificate.
pub const GSMA_RSP2_ROOT_CI1_SHA256: &str =
    "5E3E91FD454327C3AF5D32A7A73BBC59FE43AA7D85FD32D5DB44423F80A56BB3";
/// The bundled certificate, PEM.
const GSMA_RSP2_ROOT_CI1_PEM: &str = include_str!("../certs/gsma-rsp2-root-ci1.pem");

/// Which certificates the server must chain to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Trust {
    /// The bundled GSMA RSP2 Root CI1 (SGP.22 §4.5.2.2). The default.
    #[default]
    GsmaCi,
    /// These PEM trust anchors instead of the default.
    Bundle(PathBuf),
    /// The Mozilla web roots. Never implied; asked for by name.
    Webpki,
}

impl Trust {
    /// Reads the value of `SIM_DOCTOR_CA_BUNDLE`: unset is the default, the
    /// word `webpki` is [`Trust::Webpki`], anything else a PEM path.
    pub fn from_env_value(value: Option<std::ffi::OsString>) -> Self {
        match value {
            None => Self::GsmaCi,
            Some(v) if v == "webpki" => Self::Webpki,
            Some(v) => Self::Bundle(PathBuf::from(v)),
        }
    }
}

/// Settings of [`HttpsTransport`]. There is deliberately no way to turn
/// certificate verification off.
#[derive(Debug, Clone)]
pub struct HttpsConfig {
    /// The trust anchors.
    pub trust: Trust,
    /// Whole-request timeout (connect, send and receive together).
    pub timeout: Duration,
    /// Largest response body accepted, in bytes.
    pub max_response: u64,
}

impl Default for HttpsConfig {
    fn default() -> Self {
        Self {
            trust: Trust::default(),
            timeout: DEFAULT_TIMEOUT,
            max_response: DEFAULT_MAX_RESPONSE,
        }
    }
}

/// ES9+ over HTTPS with certificate verification, no redirects, a timeout and
/// a size cap. See the module documentation.
pub struct HttpsTransport {
    agent: ureq::Agent,
    max_response: u64,
}

impl HttpsTransport {
    /// Builds the client.
    ///
    /// # Errors
    ///
    /// [`TransportError`] when a [`Trust::Bundle`] cannot be read or holds no
    /// certificate (an empty bundle would otherwise trust nothing, silently).
    pub fn new(config: &HttpsConfig) -> Result<Self, TransportError> {
        let roots = match &config.trust {
            Trust::Webpki => RootCerts::WebPki,
            Trust::GsmaCi => roots_from_pem(GSMA_RSP2_ROOT_CI1_PEM.as_bytes(), "bundled GSMA CI")?,
            Trust::Bundle(path) => {
                let pem = std::fs::read(path)
                    .map_err(|e| TransportError(format!("CA bundle {}: {e}", path.display())))?;
                roots_from_pem(&pem, &format!("CA bundle {}", path.display()))?
            }
        };
        let agent = ureq::Agent::config_builder()
            .https_only(true)
            .max_redirects(0)
            .http_status_as_error(false)
            .timeout_global(Some(config.timeout))
            .tls_config(TlsConfig::builder().root_certs(roots).build())
            .build()
            .new_agent();
        Ok(Self {
            agent,
            max_response: config.max_response,
        })
    }
}

/// Trust anchors from PEM text; an empty set is an error, never "trust nothing".
fn roots_from_pem(pem: &[u8], what: &str) -> Result<RootCerts, TransportError> {
    let mut certs = Vec::new();
    for item in ureq::tls::parse_pem(pem) {
        if let ureq::tls::PemItem::Certificate(cert) =
            item.map_err(|e| TransportError(format!("{what}: {e}")))?
        {
            certs.push(cert);
        }
    }
    if certs.is_empty() {
        return Err(TransportError(format!("{what} contains no certificate")));
    }
    Ok(RootCerts::Specific(Arc::new(certs)))
}

impl Es9Transport for HttpsTransport {
    fn post(
        &mut self,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<Response, TransportError> {
        let mut request = self.agent.post(url);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let mut response = request
            .send(body)
            .map_err(|e| TransportError(e.to_string()))?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .filter_map(|(k, v)| Some((k.as_str().to_owned(), v.to_str().ok()?.to_owned())))
            .collect();
        let body = response
            .body_mut()
            .with_config()
            .limit(self.max_response)
            .read_to_vec()
            .map_err(|e| TransportError(format!("reading response: {e}")))?;
        Ok(Response {
            status,
            headers,
            body,
        })
    }
}

/// lpac's `LPAC_HTTP=stdio` protocol: one JSON line out, one in, the host does
/// the HTTP (and so the TLS verification, which this crate cannot vouch for).
///
/// Out: `{"type":"http","payload":{"url":..,"tx":"<hex>","headers":["N: V"]}}`.
/// In: `{"type":"http","payload":{"rcode":200,"rx":"<hex>"}}`. Source:
/// lpac `driver/http/stdio.c`. Response headers do not exist in this protocol.
pub struct StdioTransport<R: BufRead, W: Write> {
    input: R,
    output: W,
    max_response: u64,
}

impl<R: BufRead, W: Write> StdioTransport<R, W> {
    /// A transport over the given streams (the process's stdin/stdout in use).
    pub fn new(input: R, output: W) -> Self {
        Self {
            input,
            output,
            max_response: DEFAULT_MAX_RESPONSE,
        }
    }
}

impl<R: BufRead, W: Write> Es9Transport for StdioTransport<R, W> {
    fn post(
        &mut self,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<Response, TransportError> {
        let err = |e: &dyn std::fmt::Display| TransportError(format!("stdio http: {e}"));
        let line = serde_json::json!({"type": "http", "payload": {
            "url": url,
            "tx": hex::encode(body),
            "headers": headers.iter().map(|(k, v)| format!("{k}: {v}")).collect::<Vec<_>>(),
        }});
        writeln!(self.output, "{line}")
            .and_then(|()| self.output.flush())
            .map_err(|e| err(&e))?;
        let mut reply = String::new();
        // Bounded read: twice the cap covers the hex expansion.
        let limit = self.max_response * 2 + 1024;
        let read = std::io::Read::take(&mut self.input, limit)
            .read_line(&mut reply)
            .map_err(|e| err(&e))?;
        if read == 0 || (read as u64 >= limit && !reply.ends_with('\n')) {
            return Err(err(&"no reply line, or it exceeds the size cap"));
        }
        let value: serde_json::Value = serde_json::from_str(&reply).map_err(|e| err(&e))?;
        let payload = value
            .get("payload")
            .filter(|_| value.get("type").and_then(|t| t.as_str()) == Some("http"))
            .ok_or_else(|| err(&"reply is not a {\"type\":\"http\"} object"))?;
        let status = payload
            .get("rcode")
            .and_then(|v| v.as_u64())
            .and_then(|v| u16::try_from(v).ok())
            .ok_or_else(|| err(&"reply has no valid rcode"))?;
        let rx = payload.get("rx").and_then(|v| v.as_str()).unwrap_or("");
        let body = hex::decode(rx).map_err(|e| err(&e))?;
        Ok(Response {
            status,
            headers: Vec::new(),
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn bundled_gsma_ci_matches_its_recorded_fingerprint() {
        let RootCerts::Specific(certs) =
            roots_from_pem(GSMA_RSP2_ROOT_CI1_PEM.as_bytes(), "bundled").unwrap()
        else {
            panic!("expected specific roots");
        };
        assert_eq!(certs.len(), 1);
        let digest = Sha256::digest(certs[0].der());
        assert_eq!(hex::encode_upper(digest), GSMA_RSP2_ROOT_CI1_SHA256);
    }

    #[test]
    fn trust_env_value() {
        assert_eq!(Trust::from_env_value(None), Trust::GsmaCi);
        assert_eq!(Trust::from_env_value(Some("webpki".into())), Trust::Webpki);
        assert_eq!(
            Trust::from_env_value(Some("/x/ca.pem".into())),
            Trust::Bundle("/x/ca.pem".into())
        );
    }

    #[test]
    fn stdio_round_trip_matches_lpac_framing() {
        let reply = b"{\"type\":\"http\",\"payload\":{\"rcode\":404,\"rx\":\"333435\"}}\n";
        let mut out = Vec::new();
        let got = StdioTransport::new(&reply[..], &mut out)
            .post(
                "https://smdp.example.com/x",
                &[("Content-Type", "application/json")],
                b"{}",
            )
            .unwrap();
        assert_eq!((got.status, got.body.as_slice()), (404, &b"345"[..]));
        let sent: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(sent["payload"]["tx"], "7b7d");
        assert_eq!(
            sent["payload"]["headers"][0],
            "Content-Type: application/json"
        );
    }

    #[test]
    fn stdio_refuses_a_missing_or_malformed_reply() {
        let post =
            |input: &[u8]| StdioTransport::new(input, Vec::new()).post("https://x/", &[], b"");
        assert!(post(b"").is_err());
        assert!(post(b"{\"type\":\"apdu\",\"payload\":{}}\n").is_err());
        assert!(post(b"{\"type\":\"http\",\"payload\":{\"rcode\":200,\"rx\":\"zz\"}}\n").is_err());
    }
}
