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
//!   GSMA CI, or a trusted chain up to a GSMA CI". So the specified trust
//!   anchor of an SM-DP+ TLS certificate is a GSMA CI, **not** the web PKI.
//!   §3.1.2 also notes the LPAd may retry when several CIs exist.
//! * lpac (estkme-group/lpac, `driver/http/curl.c`, commit 82ada9e) sets
//!   `CURLOPT_SSL_VERIFYPEER` and `CURLOPT_SSL_VERIFYHOST` to 0: it verifies
//!   **nothing** (its WinHTTP backend sets `SECURITY_FLAG_IGNORE_UNKNOWN_CA`).
//!   Its `LPAC_HTTP=stdio` backend delegates the whole exchange to the host.
//!   That is not copied here.
//!
//! So: [`HttpsConfig::ca_bundle`] is a PEM file of trust anchors (the GSMA CI
//! certificate(s) a deployment trusts, or any private CA) and, when set,
//! **replaces** the default roots entirely; the CLI reads it from
//! `SIM_DOCTOR_CA_BUNDLE`. Without a bundle the default is the compiled-in
//! Mozilla web roots (`webpki-roots`), because SM-DP+ operators commonly
//! present public-CA TLS certificates in practice. That default is a
//! convenience and a deviation from the §4.5.2.2 text; a deployment that wants
//! the spec's trust model supplies the GSMA CI bundle. Revocation (CRL) is not
//! checked, and the §2.6.6 cipher-suite rules are those of rustls, which
//! offers only TLS 1.2+ AEAD ECDHE suites (the §2.6.6 CBC suite is not
//! offered, the GCM one is).
//!
//! # Wire behaviour
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

/// Settings of [`HttpsTransport`]. There is deliberately no way to turn
/// certificate verification off.
#[derive(Debug, Clone)]
pub struct HttpsConfig {
    /// PEM file of trust anchors that replaces the default web roots.
    pub ca_bundle: Option<PathBuf>,
    /// Whole-request timeout (connect, send and receive together).
    pub timeout: Duration,
    /// Largest response body accepted, in bytes.
    pub max_response: u64,
}

impl Default for HttpsConfig {
    fn default() -> Self {
        Self {
            ca_bundle: None,
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
    /// [`TransportError`] when `ca_bundle` cannot be read or holds no
    /// certificate (an empty bundle would otherwise trust nothing, silently).
    pub fn new(config: &HttpsConfig) -> Result<Self, TransportError> {
        let roots = match &config.ca_bundle {
            None => RootCerts::WebPki,
            Some(path) => {
                let pem = std::fs::read(path)
                    .map_err(|e| TransportError(format!("CA bundle {}: {e}", path.display())))?;
                let mut certs = Vec::new();
                for item in ureq::tls::parse_pem(&pem) {
                    if let ureq::tls::PemItem::Certificate(cert) =
                        item.map_err(|e| TransportError(format!("CA bundle: {e}")))?
                    {
                        certs.push(cert);
                    }
                }
                if certs.is_empty() {
                    return Err(TransportError(format!(
                        "CA bundle {} contains no certificate",
                        path.display()
                    )));
                }
                RootCerts::Specific(Arc::new(certs))
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
