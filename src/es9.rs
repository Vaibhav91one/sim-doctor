//! ES9+, the LPA to SM-DP+ interface of SGP.22: the JSON-over-HTTPS message
//! layer for InitiateAuthentication, AuthenticateClient,
//! GetBoundProfilePackage, HandleNotification and CancelSession. Library
//! only: **nothing here opens a socket**. A caller supplies an
//! [`Es9Transport`]; the CLI never calls this module.
//!
//! **Owns.** SM-DP+ address validation ([`SmdpAddress`]), request bodies and
//! headers ([`Request`]), response checking (HTTP status, redirects,
//! `header.functionExecutionStatus`) and base64 decoding of the ASN.1
//! payloads into the types [`crate::es10`] consumes.
//!
//! **Does not own.** TLS, certificate checks (5.6: the LPA SHALL verify
//! CERT.DP.TLS, which is the transport's job), any HTTP client, signature
//! checks, or splitting a BoundProfilePackage into STORE DATA segments.
//!
//! # Provenance
//!
//! `[V] SGP.22 v2.5` public PDF, checked 2026-10-07 (page numbers per the PDF).
//!
//! | Function | Function clause | JSON binding | Path (6.5.2, Table 57) |
//! |---|---|---|---|
//! | InitiateAuthentication | 5.6.1 | 6.5.2.6 | `/gsma/rsp2/es9plus/initiateAuthentication` |
//! | GetBoundProfilePackage | 5.6.2 | 6.5.2.7 | `/gsma/rsp2/es9plus/getBoundProfilePackage` |
//! | AuthenticateClient | 5.6.3 | 6.5.2.8 | `/gsma/rsp2/es9plus/authenticateClient` |
//! | HandleNotification | 5.6.4 | 6.5.2.9 | `/gsma/rsp2/es9plus/handleNotification` |
//! | CancelSession | 5.6.5 | 6.5.2.10 | `/gsma/rsp2/es9plus/cancelSession` |
//!
//! HTTP rules: 6.2 (POST; `User-Agent: gsma-rsp-lpad`; `X-Admin-Protocol:
//! gsma/rsp/v<x.y.z>` = highest SGP.22 version supported; `Content-Type:
//! application/json`), 6.3 (a normal answer is `200` whether the function
//! succeeded or failed; a notification is answered `204` with an empty body;
//! "other 2xx SHALL not be used"), 6.5.1.1 (ES9+ bodies carry no request
//! header), 6.5.1.4 (response `header.functionExecutionStatus`).
//!
//! # Redirects
//!
//! 6.3 says only that `3xx` "MAY be used" by the server and defines `200`
//! (and `204`) as the normal statuses. It gives **no rule for following a
//! redirect**, and an ES9+ body carries the transactionId and eUICC-signed
//! material for one specific, TLS-authenticated SM-DP+ (5.6). So this layer
//! treats any status other than the one expected as an error, `3xx` included,
//! reports it as [`Error::Redirect`] with the `Location` it saw, and a
//! transport MUST NOT follow redirects on its own (see [`Es9Transport`]).
//! This is a decision, not a spec rule. Do not confuse it with the SM-DS
//! "redirect" of 3.6 (an event naming another SM-DP+ address, ES11), which is
//! a different mechanism and is not implemented here.
//!
//! # Wire quirks seen in other implementations (not adopted)
//!
//! lpac (`euicc/es9p.c`) sends `X-Admin-Protocol: gsma/rsp/v2.2.2`, treats any
//! `2xx` as success and trims whitespace out of the base64 it receives; pySim
//! (`pySim/esim/http_json_api.py`) sends `v2.5.0` and, with Python `requests`,
//! follows redirects. This module sends `v2.5.0` (what it implements), accepts
//! only the exact status, and accepts ASCII whitespace inside base64 (as lpac
//! does) but nothing else outside the standard alphabet.
//!
//! # Not implemented
//!
//! A real HTTPS backend and the lpac `LPAC_HTTP`-style backend selection (a
//! follow-up: no HTTP client is a dependency yet), ES11 and ES2+, the
//! `Executed-WithWarning` detail (treated as success, the warning is not
//! surfaced), checks on response headers (`Content-Type`, `X-Admin-Protocol`),
//! a `host:port` SM-DP+ address (the spec type is a bare FQDN), and splitting
//! the returned BoundProfilePackage into STORE DATA segments.

use serde_json::Value;

use crate::es10::{self, AuthenticateServerRequest, PrepareDownloadRequest};

/// `X-Admin-Protocol` value this layer sends: the highest SGP.22 version it
/// implements ([SGP.22 v2.5 §6.2]).
pub const ADMIN_PROTOCOL: &str = "gsma/rsp/v2.5.0";
/// `User-Agent` value of an LPAd ([SGP.22 v2.5 §6.2]).
pub const USER_AGENT: &str = "gsma-rsp-lpad";
/// `Content-Type` of the JSON binding ([SGP.22 v2.5 §6.2]).
pub const CONTENT_TYPE: &str = "application/json";

/// Which ES9+ function a request is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Function {
    /// 5.6.1.
    InitiateAuthentication,
    /// 5.6.2.
    GetBoundProfilePackage,
    /// 5.6.3.
    AuthenticateClient,
    /// 5.6.4.
    HandleNotification,
    /// 5.6.5.
    CancelSession,
}

impl Function {
    /// The path of Table 57.
    pub const fn path(self) -> &'static str {
        match self {
            Self::InitiateAuthentication => "/gsma/rsp2/es9plus/initiateAuthentication",
            Self::GetBoundProfilePackage => "/gsma/rsp2/es9plus/getBoundProfilePackage",
            Self::AuthenticateClient => "/gsma/rsp2/es9plus/authenticateClient",
            Self::HandleNotification => "/gsma/rsp2/es9plus/handleNotification",
            Self::CancelSession => "/gsma/rsp2/es9plus/cancelSession",
        }
    }

    /// The HTTP status of a normal answer: `204` for the notification MEP,
    /// `200` otherwise ([SGP.22 v2.5 §6.3]).
    pub const fn expected_status(self) -> u16 {
        match self {
            Self::HandleNotification => 204,
            _ => 200,
        }
    }
}

/// Everything that can go wrong in the ES9+ layer.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The SM-DP+ address is not an FQDN.
    #[error("SM-DP+ address {address:?}: {reason}")]
    Address {
        /// The address as given.
        address: String,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// A transaction id that is not 1 to 16 bytes / 2 to 32 hex digits.
    #[error("transactionId must be 1 to 16 bytes, got {0}")]
    TransactionIdLength(usize),
    /// The transport failed (no HTTP response).
    #[error("transport: {0}")]
    Transport(#[from] TransportError),
    /// A `3xx` answer. Not followed ([module documentation](self)).
    #[error("HTTP {status} redirect (Location: {location:?}) refused, redirects are not followed")]
    Redirect {
        /// The `3xx` status.
        status: u16,
        /// The `Location` header, when there was one.
        location: Option<String>,
    },
    /// Any other status than the one the function's MEP defines.
    #[error("HTTP status {got}, expected {expected}")]
    HttpStatus {
        /// The status received.
        got: u16,
        /// The status 6.3 defines for this function.
        expected: u16,
    },
    /// The body is not JSON, or not a JSON object.
    #[error("response body is not a JSON object: {0}")]
    Json(String),
    /// A mandatory member is missing or has the wrong JSON type.
    #[error("response member {0} is missing or not a string")]
    MissingField(&'static str),
    /// A member's value is not what its schema allows.
    #[error("response member {field}: {reason}")]
    BadField {
        /// The JSON member.
        field: &'static str,
        /// What is wrong.
        reason: String,
    },
    /// `functionExecutionStatus` is `Failed` or `Expired`.
    #[error("SM-DP+ function status {status}: subject {subject_code:?} reason {reason_code:?} ({message:?})")]
    Function {
        /// `Failed` or `Expired`.
        status: String,
        /// `statusCodeData.subjectCode`, an OID-style string such as `8.2.5`.
        subject_code: Option<String>,
        /// `statusCodeData.reasonCode`, such as `3.7`.
        reason_code: Option<String>,
        /// `statusCodeData.subjectIdentifier`.
        subject_identifier: Option<String>,
        /// `statusCodeData.message`.
        message: Option<String>,
    },
    /// `functionExecutionStatus.status` is not one of the four of 6.5.1.4.
    #[error("unknown functionExecutionStatus {0:?}")]
    UnknownStatus(String),
    /// A payload is not the ASN.1 object its member promises.
    #[error("{field} payload: {source}")]
    Asn1 {
        /// The JSON member.
        field: &'static str,
        /// What the TLV reader said.
        source: es10::DecodeError,
    },
}

/// A transport failure: DNS, TLS (including CERT.DP.TLS rejection), I/O.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct TransportError(pub String);

/// An HTTP response as the transport hands it up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// The status code.
    pub status: u16,
    /// Header fields, names in any case.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// The HTTPS half, supplied by the caller.
///
/// `url` is the full `https://...` URL. `headers` are the ones 6.2 requires;
/// the transport adds `Host` and `Content-Length`. The implementation MUST
/// verify the server certificate (5.6) and MUST NOT follow redirects: return
/// the `3xx` response as it is. Tests use recorded responses and never a
/// network.
pub trait Es9Transport {
    /// POSTs `body` and returns the response, whatever its status.
    ///
    /// # Errors
    ///
    /// [`TransportError`] when no HTTP response was obtained.
    fn post(
        &mut self,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<Response, TransportError>;
}

// ---------------------------------------------------------------------------
// SM-DP+ address
// ---------------------------------------------------------------------------

/// A validated SM-DP+ address: a bare FQDN ([SGP.22 v2.5 §4.1, Table 5
/// "FQDN"], 5.6 (`smdpAddress`)): at least two dot-separated labels of
/// letters, digits and hyphens. No port, scheme, path, userinfo or trailing
/// dot, which also means it cannot smuggle anything into the URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmdpAddress(String);

impl SmdpAddress {
    /// Validates `address`. Case is kept (the spec's note about SNI and `Host`
    /// is the transport's concern).
    ///
    /// # Errors
    ///
    /// [`Error::Address`].
    pub fn parse(address: &str) -> Result<Self, Error> {
        let bad = |reason| Error::Address {
            address: address.to_owned(),
            reason,
        };
        if address.len() > 253 {
            return Err(bad("longer than 253 characters"));
        }
        let labels: Vec<&str> = address.split('.').collect();
        if labels.len() < 2 {
            return Err(bad("not a fully qualified domain name (no dot)"));
        }
        for label in &labels {
            if label.is_empty() || label.len() > 63 {
                return Err(bad("empty label or label longer than 63 characters"));
            }
            if !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            {
                return Err(bad("labels may hold only letters, digits and '-'"));
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(bad("label starts or ends with '-'"));
            }
        }
        if labels[labels.len() - 1].bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad("looks like an IP address, not a domain name"));
        }
        Ok(Self(address.to_owned()))
    }

    /// The address as given.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// `https://<addr>/gsma/rsp2/es9plus/<function>`.
    pub fn url(&self, function: Function) -> String {
        format!("https://{}{}", self.0, function.path())
    }
}

// ---------------------------------------------------------------------------
// Base64 (RFC 4648 section 4, padded), kept in-tree: no dependency for 40 lines
// ---------------------------------------------------------------------------

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(B64[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn b64_decode(text: &str) -> Result<Vec<u8>, String> {
    let chars: Vec<u8> = text
        .bytes()
        .filter(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        .collect();
    if chars.len() % 4 != 0 {
        return Err("length is not a multiple of 4 (padding missing)".into());
    }
    let mut out = Vec::with_capacity(chars.len() / 4 * 3);
    let last = chars.len().saturating_sub(4);
    for (at, quad) in chars.chunks(4).enumerate() {
        let pad = quad.iter().rev().take_while(|b| **b == b'=').count();
        if pad > 2 || (pad > 0 && at * 4 != last) {
            return Err("misplaced '=' padding".into());
        }
        let mut n = 0u32;
        for b in &quad[..4 - pad] {
            let v = B64
                .iter()
                .position(|c| c == b)
                .ok_or("character outside the base64 alphabet")?;
            n = n << 6 | v as u32;
        }
        n <<= 6 * pad as u32;
        // Non-zero bits under the padding would make two texts one value.
        if n & ((1 << (8 * pad)) - 1) != 0 {
            return Err("non-zero bits under the padding".into());
        }
        out.extend_from_slice(&n.to_be_bytes()[1..4 - pad]);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

/// One POST, ready for a transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The function.
    pub function: Function,
    /// The full URL.
    pub url: String,
    /// The JSON body, compact, members in the order of the 6.5.2 schema.
    pub body: String,
}

impl Request {
    /// The headers 6.2 requires, in the order of 6.5.1.
    pub fn headers() -> [(&'static str, &'static str); 3] {
        [
            ("User-Agent", USER_AGENT),
            ("X-Admin-Protocol", ADMIN_PROTOCOL),
            ("Content-Type", CONTENT_TYPE),
        ]
    }
}

fn hex_upper(bytes: &[u8]) -> Result<String, Error> {
    if !(1..=16).contains(&bytes.len()) {
        return Err(Error::TransactionIdLength(bytes.len()));
    }
    Ok(bytes.iter().map(|b| format!("{b:02X}")).collect())
}

/// `{"k":"v",...}` with members in the given order. Strings go through
/// serde_json, which escapes exactly what 6.5 says to (quote, backslash,
/// control characters) and nothing else.
fn object(members: &[(&str, String)]) -> String {
    let parts: Vec<String> = members
        .iter()
        .map(|(k, v)| format!("{}:{}", Value::from(*k), Value::from(v.as_str())))
        .collect();
    format!("{{{}}}", parts.join(","))
}

fn expect_tag(field: &'static str, data: &[u8], tag: u32) -> Result<(), Error> {
    es10::single_value(data, tag)
        .map(|_| ())
        .map_err(|source| Error::Asn1 { field, source })
}

/// 6.5.2.6: `euiccChallenge`, `euiccInfo1`, `smdpAddress`. `euicc_challenge`
/// is the value of GetEUICCChallenge (16 bytes on a real eUICC; not
/// length-checked here), `euicc_info1` the whole `BF20` the eUICC returned.
///
/// # Errors
///
/// [`Error::Asn1`] when `euicc_info1` is not one `BF20` TLV.
pub fn initiate_authentication(
    smdp: &SmdpAddress,
    euicc_challenge: &[u8],
    euicc_info1: &[u8],
) -> Result<Request, Error> {
    expect_tag("euiccInfo1", euicc_info1, 0xBF20)?;
    Ok(Request {
        function: Function::InitiateAuthentication,
        url: smdp.url(Function::InitiateAuthentication),
        body: object(&[
            ("euiccChallenge", b64_encode(euicc_challenge)),
            ("euiccInfo1", b64_encode(euicc_info1)),
            ("smdpAddress", smdp.as_str().to_owned()),
        ]),
    })
}

/// 6.5.2.8: `transactionId`, `authenticateServerResponse` (the whole `BF38`
/// the eUICC returned from ES10b.AuthenticateServer).
///
/// # Errors
///
/// [`Error::TransactionIdLength`]; [`Error::Asn1`] when the response is not
/// one `BF38` TLV.
pub fn authenticate_client(
    smdp: &SmdpAddress,
    transaction_id: &[u8],
    authenticate_server_response: &[u8],
) -> Result<Request, Error> {
    expect_tag(
        "authenticateServerResponse",
        authenticate_server_response,
        0xBF38,
    )?;
    Ok(Request {
        function: Function::AuthenticateClient,
        url: smdp.url(Function::AuthenticateClient),
        body: object(&[
            ("transactionId", hex_upper(transaction_id)?),
            (
                "authenticateServerResponse",
                b64_encode(authenticate_server_response),
            ),
        ]),
    })
}

/// 6.5.2.7: `transactionId`, `prepareDownloadResponse` (the whole `BF21` the
/// eUICC returned from ES10b.PrepareDownload).
///
/// # Errors
///
/// [`Error::TransactionIdLength`]; [`Error::Asn1`] when the response is not
/// one `BF21` TLV.
pub fn get_bound_profile_package(
    smdp: &SmdpAddress,
    transaction_id: &[u8],
    prepare_download_response: &[u8],
) -> Result<Request, Error> {
    expect_tag("prepareDownloadResponse", prepare_download_response, 0xBF21)?;
    Ok(Request {
        function: Function::GetBoundProfilePackage,
        url: smdp.url(Function::GetBoundProfilePackage),
        body: object(&[
            ("transactionId", hex_upper(transaction_id)?),
            (
                "prepareDownloadResponse",
                b64_encode(prepare_download_response),
            ),
        ]),
    })
}

/// 6.5.2.9: `pendingNotification` (the encoded PendingNotification of 5.7.10,
/// passed through).
pub fn handle_notification(smdp: &SmdpAddress, pending_notification: &[u8]) -> Request {
    Request {
        function: Function::HandleNotification,
        url: smdp.url(Function::HandleNotification),
        body: object(&[("pendingNotification", b64_encode(pending_notification))]),
    }
}

/// 6.5.2.10: `transactionId`, `cancelSessionResponse` (the whole `BF41` the
/// eUICC returned from ES10b.CancelSession).
///
/// # Errors
///
/// [`Error::TransactionIdLength`]; [`Error::Asn1`] when the response is not
/// one `BF41` TLV.
pub fn cancel_session(
    smdp: &SmdpAddress,
    transaction_id: &[u8],
    cancel_session_response: &[u8],
) -> Result<Request, Error> {
    expect_tag("cancelSessionResponse", cancel_session_response, 0xBF41)?;
    Ok(Request {
        function: Function::CancelSession,
        url: smdp.url(Function::CancelSession),
        body: object(&[
            ("transactionId", hex_upper(transaction_id)?),
            ("cancelSessionResponse", b64_encode(cancel_session_response)),
        ]),
    })
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

/// Checks the HTTP status of `response` for `function`: the exact status, and
/// a `3xx` is [`Error::Redirect`].
fn check_http(function: Function, response: &Response) -> Result<(), Error> {
    let expected = function.expected_status();
    match response.status {
        s if s == expected => Ok(()),
        s @ 300..=399 => Err(Error::Redirect {
            status: s,
            location: response.header("Location").map(str::to_owned),
        }),
        got => Err(Error::HttpStatus { got, expected }),
    }
}

/// Parses the body as a JSON object and applies 6.5.1.4: `header` and
/// `header.functionExecutionStatus.status` must be present; `Failed` and
/// `Expired` become [`Error::Function`].
fn parse_body(response: &Response) -> Result<Value, Error> {
    let value: Value =
        serde_json::from_slice(&response.body).map_err(|e| Error::Json(e.to_string()))?;
    if !value.is_object() {
        return Err(Error::Json("top level is not an object".into()));
    }
    let status = &value["header"]["functionExecutionStatus"];
    let name = status["status"]
        .as_str()
        .ok_or(Error::MissingField("header.functionExecutionStatus.status"))?;
    match name {
        // ponytail: a warning is accepted and not surfaced; add a field when a caller needs it
        "Executed-Success" | "Executed-WithWarning" => Ok(value),
        "Failed" | "Expired" => {
            let data = &status["statusCodeData"];
            let text = |k: &str| data[k].as_str().map(str::to_owned);
            Err(Error::Function {
                status: name.to_owned(),
                subject_code: text("subjectCode"),
                reason_code: text("reasonCode"),
                subject_identifier: text("subjectIdentifier"),
                message: text("message"),
            })
        }
        other => Err(Error::UnknownStatus(other.to_owned())),
    }
}

fn string<'a>(body: &'a Value, field: &'static str) -> Result<&'a str, Error> {
    body[field].as_str().ok_or(Error::MissingField(field))
}

fn bytes(body: &Value, field: &'static str) -> Result<Vec<u8>, Error> {
    b64_decode(string(body, field)?).map_err(|reason| Error::BadField { field, reason })
}

/// A base64 member that is one whole TLV with the given tag; returns the
/// whole TLV.
fn whole(body: &Value, field: &'static str, tag: u32) -> Result<Vec<u8>, Error> {
    let data = bytes(body, field)?;
    expect_tag(field, &data, tag)?;
    Ok(data)
}

/// A base64 member that is one TLV with the given tag; returns its value.
fn inner(body: &Value, field: &'static str, tag: u32) -> Result<Vec<u8>, Error> {
    let data = bytes(body, field)?;
    es10::single_value(&data, tag)
        .map(<[u8]>::to_vec)
        .map_err(|source| Error::Asn1 { field, source })
}

/// `transactionId`: `^[0-9,A-F]{2,32}$` in the schema (the comma is in the
/// character class as printed; it is never valid here), even length, decoded
/// to 1 to 16 bytes.
fn transaction_id(body: &Value) -> Result<Vec<u8>, Error> {
    let text = string(body, "transactionId")?;
    let bad = |reason: &str| Error::BadField {
        field: "transactionId",
        reason: reason.to_owned(),
    };
    if !(2..=32).contains(&text.len()) || text.len() % 2 != 0 {
        return Err(bad("must be 2 to 32 hex digits, an even number"));
    }
    if !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'A'..=b'F')) {
        return Err(bad("must be upper-case hexadecimal"));
    }
    Ok((0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("checked hex"))
        .collect())
}

/// Response of ES9+.InitiateAuthentication (6.5.2.6): the inputs of
/// ES10b.AuthenticateServer except `ctxParams1`, which the LPA owns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitiateAuthenticationOk {
    /// `transactionId`, 1 to 16 bytes.
    pub transaction_id: Vec<u8>,
    /// `serverSigned1`, complete DER (the `30` TLV the signature covers).
    pub server_signed1: Vec<u8>,
    /// `serverSignature1`, the value of tag `5F37`.
    pub server_signature1: Vec<u8>,
    /// `euiccCiPKIdToBeUsed`, the value of the `04` SubjectKeyIdentifier.
    pub euicc_ci_pk_id_to_be_used: Vec<u8>,
    /// `serverCertificate` (CERT.DPauth.ECDSA), complete DER.
    pub server_certificate: Vec<u8>,
}

impl InitiateAuthenticationOk {
    /// The ES10b.AuthenticateServer request, with the LPA's `ctxParams1`
    /// (complete DER, `A0` header included). Encode it with
    /// [`AuthenticateServerRequest::encode`].
    pub fn authenticate_server_request<'a>(
        &'a self,
        ctx_params1: &'a [u8],
    ) -> AuthenticateServerRequest<'a> {
        AuthenticateServerRequest {
            server_signed1: &self.server_signed1,
            server_signature1: &self.server_signature1,
            euicc_ci_pk_id_to_be_used: &self.euicc_ci_pk_id_to_be_used,
            server_certificate: &self.server_certificate,
            ctx_params1,
        }
    }
}

/// Parses the answer to [`initiate_authentication`].
///
/// # Errors
///
/// Any [`Error`] of the transport-level and body-level checks.
pub fn parse_initiate_authentication(
    response: &Response,
) -> Result<InitiateAuthenticationOk, Error> {
    check_http(Function::InitiateAuthentication, response)?;
    let body = parse_body(response)?;
    Ok(InitiateAuthenticationOk {
        transaction_id: transaction_id(&body)?,
        server_signed1: whole(&body, "serverSigned1", 0x30)?,
        server_signature1: inner(&body, "serverSignature1", 0x5F37)?,
        euicc_ci_pk_id_to_be_used: inner(&body, "euiccCiPKIdToBeUsed", 0x04)?,
        server_certificate: whole(&body, "serverCertificate", 0x30)?,
    })
}

/// Response of ES9+.AuthenticateClient (6.5.2.8): the inputs of
/// ES10b.PrepareDownload, plus the profile metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticateClientOk {
    /// `transactionId`, 1 to 16 bytes.
    pub transaction_id: Vec<u8>,
    /// `profileMetadata`, the whole `BF25` StoreMetadataRequest (5.5.3).
    pub profile_metadata: Vec<u8>,
    /// `smdpSigned2`, complete DER.
    pub smdp_signed2: Vec<u8>,
    /// `smdpSignature2`, the value of tag `5F37`.
    pub smdp_signature2: Vec<u8>,
    /// `smdpCertificate` (CERT.DPpb.ECDSA), complete DER.
    pub smdp_certificate: Vec<u8>,
}

impl AuthenticateClientOk {
    /// The ES10b.PrepareDownload request. `hash_cc` is the 32-byte confirmation
    /// code hash when `smdpSigned2` says one is required; encode with
    /// [`PrepareDownloadRequest::encode`].
    pub fn prepare_download_request<'a>(
        &'a self,
        hash_cc: Option<&'a [u8]>,
    ) -> PrepareDownloadRequest<'a> {
        PrepareDownloadRequest {
            smdp_signed2: &self.smdp_signed2,
            smdp_signature2: &self.smdp_signature2,
            hash_cc,
            smdp_certificate: &self.smdp_certificate,
        }
    }
}

/// Parses the answer to [`authenticate_client`]. (An ES11 server answers this
/// path with `eventEntries` instead; that shape is not handled and reports
/// the first missing member.)
///
/// # Errors
///
/// Any [`Error`] of the transport-level and body-level checks.
pub fn parse_authenticate_client(response: &Response) -> Result<AuthenticateClientOk, Error> {
    check_http(Function::AuthenticateClient, response)?;
    let body = parse_body(response)?;
    Ok(AuthenticateClientOk {
        transaction_id: transaction_id(&body)?,
        profile_metadata: whole(&body, "profileMetadata", 0xBF25)?,
        smdp_signed2: whole(&body, "smdpSigned2", 0x30)?,
        smdp_signature2: inner(&body, "smdpSignature2", 0x5F37)?,
        smdp_certificate: whole(&body, "smdpCertificate", 0x30)?,
    })
}

/// Response of ES9+.GetBoundProfilePackage (6.5.2.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetBoundProfilePackageOk {
    /// `transactionId`, 1 to 16 bytes.
    pub transaction_id: Vec<u8>,
    /// `boundProfilePackage`, the whole `BF36`. Cutting it into the STORE DATA
    /// segments of 2.5.5 for [`es10::bpp_blocks`] is not done here.
    pub bound_profile_package: Vec<u8>,
}

/// Parses the answer to [`get_bound_profile_package`].
///
/// # Errors
///
/// Any [`Error`] of the transport-level and body-level checks.
pub fn parse_get_bound_profile_package(
    response: &Response,
) -> Result<GetBoundProfilePackageOk, Error> {
    check_http(Function::GetBoundProfilePackage, response)?;
    let body = parse_body(response)?;
    Ok(GetBoundProfilePackageOk {
        transaction_id: transaction_id(&body)?,
        bound_profile_package: whole(&body, "boundProfilePackage", 0xBF36)?,
    })
}

/// Checks the answer to [`handle_notification`]: `204`, nothing else to read
/// (5.6.4: "No additional output data"; 6.3: empty body).
///
/// # Errors
///
/// [`Error::Redirect`] or [`Error::HttpStatus`].
pub fn parse_handle_notification(response: &Response) -> Result<(), Error> {
    check_http(Function::HandleNotification, response)
}

/// Checks the answer to [`cancel_session`]: `200` with only a `header`
/// (6.5.2.10: no body part) that says success.
///
/// # Errors
///
/// Any [`Error`] of the transport-level and body-level checks.
pub fn parse_cancel_session(response: &Response) -> Result<(), Error> {
    check_http(Function::CancelSession, response)?;
    parse_body(response).map(|_| ())
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// The five functions over an [`Es9Transport`], for one SM-DP+.
pub struct Es9Client<T: Es9Transport> {
    transport: T,
    smdp: SmdpAddress,
}

impl<T: Es9Transport> Es9Client<T> {
    /// A client for `smdp` over `transport`.
    pub fn new(transport: T, smdp: SmdpAddress) -> Self {
        Self { transport, smdp }
    }

    fn send(&mut self, request: &Request) -> Result<Response, Error> {
        Ok(self
            .transport
            .post(&request.url, &Request::headers(), request.body.as_bytes())?)
    }

    /// ES9+.InitiateAuthentication.
    ///
    /// # Errors
    ///
    /// Any [`Error`].
    pub fn initiate_authentication(
        &mut self,
        euicc_challenge: &[u8],
        euicc_info1: &[u8],
    ) -> Result<InitiateAuthenticationOk, Error> {
        let request = initiate_authentication(&self.smdp, euicc_challenge, euicc_info1)?;
        parse_initiate_authentication(&self.send(&request)?)
    }

    /// ES9+.AuthenticateClient.
    ///
    /// # Errors
    ///
    /// Any [`Error`].
    pub fn authenticate_client(
        &mut self,
        transaction_id: &[u8],
        authenticate_server_response: &[u8],
    ) -> Result<AuthenticateClientOk, Error> {
        let request =
            authenticate_client(&self.smdp, transaction_id, authenticate_server_response)?;
        parse_authenticate_client(&self.send(&request)?)
    }

    /// ES9+.GetBoundProfilePackage.
    ///
    /// # Errors
    ///
    /// Any [`Error`].
    pub fn get_bound_profile_package(
        &mut self,
        transaction_id: &[u8],
        prepare_download_response: &[u8],
    ) -> Result<GetBoundProfilePackageOk, Error> {
        let request =
            get_bound_profile_package(&self.smdp, transaction_id, prepare_download_response)?;
        parse_get_bound_profile_package(&self.send(&request)?)
    }

    /// ES9+.HandleNotification.
    ///
    /// # Errors
    ///
    /// Any [`Error`].
    pub fn handle_notification(&mut self, pending_notification: &[u8]) -> Result<(), Error> {
        let request = handle_notification(&self.smdp, pending_notification);
        parse_handle_notification(&self.send(&request)?)
    }

    /// ES9+.CancelSession.
    ///
    /// # Errors
    ///
    /// Any [`Error`].
    pub fn cancel_session(
        &mut self,
        transaction_id: &[u8],
        cancel_session_response: &[u8],
    ) -> Result<(), Error> {
        let request = cancel_session(&self.smdp, transaction_id, cancel_session_response)?;
        parse_cancel_session(&self.send(&request)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn smdp() -> SmdpAddress {
        SmdpAddress::parse("smdp.gsma.com").unwrap()
    }

    fn ok(status: u16, body: &str) -> Response {
        Response {
            status,
            headers: vec![
                ("X-Admin-Protocol".into(), ADMIN_PROTOCOL.into()),
                ("Content-Type".into(), CONTENT_TYPE.into()),
            ],
            body: body.as_bytes().to_vec(),
        }
    }

    // --- base64: RFC 4648 section 10 test vectors --------------------------

    #[test]
    fn base64_rfc4648_vectors() {
        for (plain, enc) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(b64_encode(plain.as_bytes()), enc);
            assert_eq!(b64_decode(enc).unwrap(), plain.as_bytes());
        }
    }

    #[test]
    fn base64_rejects_malformed() {
        for bad in [
            "Zg", "Zg=", "Zm9v=", "Zg==Zm9v", "Zm9!", "=AAA", "Zh==", "Zm9=",
        ] {
            assert!(b64_decode(bad).is_err(), "{bad}");
        }
        assert_eq!(b64_decode("Zm9v\r\nYmFy").unwrap(), b"foobar");
    }

    // --- addressing ---------------------------------------------------------

    #[test]
    fn address_and_url() {
        // 'smdp.gsma.com' is the FQDN example of SGP.22 v2.5 Table 5 and Annex I.
        let a = smdp();
        assert_eq!(
            a.url(Function::InitiateAuthentication),
            "https://smdp.gsma.com/gsma/rsp2/es9plus/initiateAuthentication"
        );
        assert_eq!(
            a.url(Function::HandleNotification),
            "https://smdp.gsma.com/gsma/rsp2/es9plus/handleNotification"
        );
        assert!(SmdpAddress::parse("SMDP.GSMA.COM").is_ok());
        assert!(SmdpAddress::parse("a-b.c1.example").is_ok());
    }

    #[test]
    fn address_rejects_non_fqdn() {
        for bad in [
            "",
            "localhost",
            "smdp.gsma.com:8443",
            "smdp.gsma.com/",
            "https://smdp.gsma.com",
            "user@smdp.gsma.com",
            "smdp.gsma.com.",
            ".smdp.gsma.com",
            "smdp..gsma.com",
            "-smdp.gsma.com",
            "smdp$gsma.com",
            "smdp.gsma.com ",
            "smdp.gsma.com\n",
            "10.0.0.1",
            "smdp.gsm_a.com",
            "smdp.gsmä.com",
        ] {
            assert!(SmdpAddress::parse(bad).is_err(), "{bad:?}");
        }
        assert!(SmdpAddress::parse(&format!("{}.com", "a".repeat(64))).is_err());
    }

    // --- request bodies, byte-exact ----------------------------------------

    /// SGP.22 v2.5 Annex I (page 267) gives an ES9+.InitiateAuthentication
    /// request with members `euiccChallenge`, `euiccInfo1`, `smdpAddress` and
    /// `smdpAddress` = `smdp.gsma.com`; this body has exactly those members in
    /// that order and that address. The example's two base64 values cannot be
    /// reproduced byte for byte: "...VE5D" (49 characters) and "...WRTU" (39)
    /// are not valid base64 at all. So the values here are 16 zero bytes
    /// (`AAAAAAAAAAAAAAAAAAAAAA==`) and the 3-byte `BF 20 00` (`vyAA`).
    #[test]
    fn annex_i_initiate_authentication_request_shape() {
        let r = initiate_authentication(&smdp(), &[0; 16], &[0xBF, 0x20, 0]).unwrap();
        assert_eq!(
            r.body,
            "{\"euiccChallenge\":\"AAAAAAAAAAAAAAAAAAAAAA==\",\"euiccInfo1\":\"vyAA\",\
             \"smdpAddress\":\"smdp.gsma.com\"}"
        );
        assert!(b64_decode("ZVVpY2NDaGFsbGVuZ2VFeGFtcGxlQmFzZTY0oUFZuQnNZVE5D").is_err());
        assert!(b64_decode("RmVHRnRjR3hsUW1GelpUWTBvVUZadVFuTlpWRTU").is_err());
    }

    /// The members of the other requests are the 6.5.2.7 to 6.5.2.10 schemas;
    /// no source publishes a recorded body for them (checked: SGP.22 Annex I,
    /// pySim 3c437d4, lpac 82ada9e), so the base64 here is RFC 4648 vectors
    /// carried inside TLVs whose encoding is spelled out, and the transaction
    /// id is the Annex I one.
    #[test]
    fn other_request_bodies() {
        let tid = hex::decode("0123456789ABCDEF").unwrap();
        // BF38 03 80 01 00  ->  "vzgDgAEA"
        let r = authenticate_client(&smdp(), &tid, &[0xBF, 0x38, 3, 0x80, 1, 0]).unwrap();
        assert_eq!(
            r.body,
            "{\"transactionId\":\"0123456789ABCDEF\",\"authenticateServerResponse\":\"vzgDgAEA\"}"
        );
        assert_eq!(
            r.url,
            "https://smdp.gsma.com/gsma/rsp2/es9plus/authenticateClient"
        );
        let r = get_bound_profile_package(&smdp(), &tid, &[0xBF, 0x21, 3, 0x80, 1, 0]).unwrap();
        assert_eq!(
            r.body,
            "{\"transactionId\":\"0123456789ABCDEF\",\"prepareDownloadResponse\":\"vyEDgAEA\"}"
        );
        let r = cancel_session(&smdp(), &tid, &[0xBF, 0x41, 3, 0x80, 1, 0]).unwrap();
        assert_eq!(
            r.body,
            "{\"transactionId\":\"0123456789ABCDEF\",\"cancelSessionResponse\":\"v0EDgAEA\"}"
        );
        let r = handle_notification(&smdp(), b"foobar");
        assert_eq!(r.body, "{\"pendingNotification\":\"Zm9vYmFy\"}");
        assert_eq!(r.function.expected_status(), 204);
    }

    #[test]
    fn request_validation() {
        let good = [0xBF, 0x38, 3, 0x80, 1, 0];
        assert!(matches!(
            authenticate_client(&smdp(), &[], &good),
            Err(Error::TransactionIdLength(0))
        ));
        assert!(matches!(
            authenticate_client(&smdp(), &[0; 17], &good),
            Err(Error::TransactionIdLength(17))
        ));
        assert!(matches!(
            authenticate_client(&smdp(), &[1], &[0xBF, 0x21, 0]),
            Err(Error::Asn1 { .. })
        ));
        assert!(matches!(
            initiate_authentication(&smdp(), &[0; 16], &[0xBF, 0x22, 0]),
            Err(Error::Asn1 { .. })
        ));
        let r = initiate_authentication(&smdp(), &[0; 16], &[0xBF, 0x20, 0]).unwrap();
        assert!(r
            .body
            .starts_with("{\"euiccChallenge\":\"AAAAAAAAAAAAAAAAAAAAAA==\","));
    }

    #[test]
    fn headers_follow_6_2() {
        assert_eq!(
            Request::headers(),
            [
                ("User-Agent", "gsma-rsp-lpad"),
                ("X-Admin-Protocol", "gsma/rsp/v2.5.0"),
                ("Content-Type", "application/json"),
            ]
        );
    }

    // --- responses ---------------------------------------------------------

    const SIGNED1: &str = "MAOAAao="; // 30 03 80 01 AA
    const SIG: &str = "XzcCESI="; // 5F37 02 11 22
    const CI: &str = "BAKquw=="; // 04 02 AA BB
    const CERT: &str = "MAA="; // 30 00

    fn init_ok_body() -> String {
        format!(
            "{{\"header\":{{\"functionExecutionStatus\":{{\"status\":\"Executed-Success\"}}}},\
             \"transactionId\":\"0123456789ABCDEF\",\"serverSigned1\":\"{SIGNED1}\",\
             \"serverSignature1\":\"{SIG}\",\"euiccCiPKIdToBeUsed\":\"{CI}\",\
             \"serverCertificate\":\"{CERT}\"}}"
        )
    }

    #[test]
    fn parses_initiate_authentication() {
        let ok = parse_initiate_authentication(&ok(200, &init_ok_body())).unwrap();
        assert_eq!(ok.transaction_id, hex::decode("0123456789ABCDEF").unwrap());
        assert_eq!(ok.server_signed1, [0x30, 3, 0x80, 1, 0xAA]);
        assert_eq!(ok.server_signature1, [0x11, 0x22]);
        assert_eq!(ok.euicc_ci_pk_id_to_be_used, [0xAA, 0xBB]);
        assert_eq!(ok.server_certificate, [0x30, 0]);
        // Hands straight to the es10 encoder, with the LPA's ctxParams1.
        let ctx = [0xA0, 0];
        let wire = ok.authenticate_server_request(&ctx).encode();
        assert_eq!(
            wire,
            hex::decode("BF381230038001AA5F370211220402AABB3000A000").unwrap()
        );
    }

    #[test]
    fn parses_authenticate_client() {
        // BF25 03 80 01 01 / 30 03 80 01 BB / 5F37 02 01 02 / 30 00
        let body = "{\"header\":{\"functionExecutionStatus\":{\"status\":\"Executed-Success\"}},\
             \"transactionId\":\"0123456789ABCDEF\",\"profileMetadata\":\"vyUDgAEB\",\
             \"smdpSigned2\":\"MAOAAbs=\",\"smdpSignature2\":\"XzcCAQI=\",\
             \"smdpCertificate\":\"MAA=\"}";
        let ok = parse_authenticate_client(&ok(200, body)).unwrap();
        assert_eq!(ok.profile_metadata, [0xBF, 0x25, 3, 0x80, 1, 1]);
        assert_eq!(ok.smdp_signed2, [0x30, 3, 0x80, 1, 0xBB]);
        assert_eq!(ok.smdp_signature2, [1, 2]);
        let wire = ok.prepare_download_request(None).encode().unwrap();
        assert_eq!(wire, hex::decode("BF210C30038001BB5F370201023000").unwrap());
    }

    #[test]
    fn parses_get_bound_profile_package() {
        let body = "{\"header\":{\"functionExecutionStatus\":{\"status\":\"Executed-Success\"}},\
             \"transactionId\":\"AB\",\"boundProfilePackage\":\"vzYDgAEB\"}";
        let ok = parse_get_bound_profile_package(&ok(200, body)).unwrap();
        assert_eq!(ok.transaction_id, [0xAB]);
        assert_eq!(ok.bound_profile_package, [0xBF, 0x36, 3, 0x80, 1, 1]);
        // A BoundProfilePackage under another tag is not one.
        let wrong = body.replace("vzYDgAEB", "vzgDgAEA");
        assert!(matches!(
            parse_get_bound_profile_package(&ok_resp(&wrong)),
            Err(Error::Asn1 {
                field: "boundProfilePackage",
                ..
            })
        ));
    }

    fn ok_resp(body: &str) -> Response {
        ok(200, body)
    }

    /// The failed-execution example of SGP.22 v2.5 Annex I (page 268) is for
    /// ES2+.DownloadOrder; 6.5.1.4 gives every function the same header, so it
    /// stands for the ES9+ error path.
    #[test]
    fn failed_status_carries_codes() {
        let body = "{\"header\":{\"functionExecutionStatus\":{\"status\":\"Failed\",\
             \"statusCodeData\":{\"subjectCode\":\"8.2.5\",\"reasonCode\":\"3.7\",\
             \"message\":\"No more Profile\"}}}}";
        for r in [
            parse_initiate_authentication(&ok(200, body)).map(|_| ()),
            parse_authenticate_client(&ok(200, body)).map(|_| ()),
            parse_get_bound_profile_package(&ok(200, body)).map(|_| ()),
            parse_cancel_session(&ok(200, body)),
        ] {
            match r {
                Err(Error::Function {
                    status,
                    subject_code,
                    reason_code,
                    subject_identifier,
                    message,
                }) => {
                    assert_eq!(status, "Failed");
                    assert_eq!(subject_code.as_deref(), Some("8.2.5"));
                    assert_eq!(reason_code.as_deref(), Some("3.7"));
                    assert_eq!(subject_identifier, None);
                    assert_eq!(message.as_deref(), Some("No more Profile"));
                }
                other => panic!("{other:?}"),
            }
        }
        let expired = "{\"header\":{\"functionExecutionStatus\":{\"status\":\"Expired\"}}}";
        assert!(matches!(
            parse_cancel_session(&ok(200, expired)),
            Err(Error::Function { status, .. }) if status == "Expired"
        ));
    }

    #[test]
    fn status_and_header_edge_cases() {
        let warn = "{\"header\":{\"functionExecutionStatus\":{\"status\":\"Executed-WithWarning\",\
             \"statusCodeData\":{\"subjectCode\":\"1.1\",\"reasonCode\":\"2.2\"}}}}";
        assert!(parse_cancel_session(&ok(200, warn)).is_ok());
        for (body, want) in [
            ("{}", "header.functionExecutionStatus.status"),
            ("{\"header\":{}}", "header.functionExecutionStatus.status"),
            (
                "{\"header\":{\"functionExecutionStatus\":{}}}",
                "header.functionExecutionStatus.status",
            ),
        ] {
            assert!(
                matches!(parse_cancel_session(&ok(200, body)), Err(Error::MissingField(f)) if f == want),
                "{body}"
            );
        }
        assert!(matches!(
            parse_cancel_session(&ok(
                200,
                "{\"header\":{\"functionExecutionStatus\":{\"status\":\"Maybe\"}}}"
            )),
            Err(Error::UnknownStatus(s)) if s == "Maybe"
        ));
        assert!(matches!(
            parse_cancel_session(&ok(200, "[]")),
            Err(Error::Json(_))
        ));
        assert!(matches!(
            parse_cancel_session(&ok(200, "not json")),
            Err(Error::Json(_))
        ));
    }

    #[test]
    fn rejects_bad_members() {
        let good = init_ok_body();
        // missing member
        let no_cert = good.replace("serverCertificate", "serverCert");
        assert!(matches!(
            parse_initiate_authentication(&ok(200, &no_cert)),
            Err(Error::MissingField("serverCertificate"))
        ));
        // lower-case / odd / over-long / non-hex transaction ids
        for bad in ["0123456789abcdef", "ABC", "A", "ZZ", &"AA".repeat(17), ""] {
            let body = good.replace("0123456789ABCDEF", bad);
            assert!(
                matches!(
                    parse_initiate_authentication(&ok(200, &body)),
                    Err(Error::BadField {
                        field: "transactionId",
                        ..
                    })
                ),
                "{bad:?}"
            );
        }
        // bad base64
        let body = good.replace(SIG, "XzcCESI");
        assert!(matches!(
            parse_initiate_authentication(&ok(200, &body)),
            Err(Error::BadField {
                field: "serverSignature1",
                ..
            })
        ));
        // right base64, wrong TLV (signature under tag 04)
        let body = good.replace(SIG, CI);
        assert!(matches!(
            parse_initiate_authentication(&ok(200, &body)),
            Err(Error::Asn1 {
                field: "serverSignature1",
                ..
            })
        ));
    }

    /// The Annex I InitiateAuthentication response example is not decodable
    /// (`serverSigned1` is 19 base64 characters; the member is spelled
    /// `euiccCiPKIdTobeUsed`, the schema says `euiccCiPKIdToBeUsed`). The
    /// parser follows the schema and says so rather than guessing.
    #[test]
    fn annex_i_response_example_is_refused() {
        let body = "{\"header\":{\"functionExecutionStatus\":{\"status\":\"Executed-Success\"}},\
            \"transactionId\":\"0123456789ABCDEF\",\"serverSigned1\":\"RKNFZsbFVUa05qUm14e\",\
            \"serverSignature1\":\"RKNFZsbFVUa05qUm14e\",\"euiccCiPKIdTobeUsed\":\"MDM=\",\
            \"serverCertificate\":\"RUU2NTQ0ODQ5NDA0RlpSRUZERA==\"}";
        assert!(matches!(
            parse_initiate_authentication(&ok(200, body)),
            Err(Error::BadField {
                field: "serverSigned1",
                ..
            })
        ));
    }

    // --- HTTP status and redirects -----------------------------------------

    #[test]
    fn redirects_are_refused_not_followed() {
        for status in [301, 302, 303, 307, 308] {
            let mut r = ok(status, "");
            r.headers
                .push(("location".into(), "https://evil.example/x".into()));
            for f in [
                parse_initiate_authentication(&r).map(|_| ()),
                parse_authenticate_client(&r).map(|_| ()),
                parse_get_bound_profile_package(&r).map(|_| ()),
                parse_cancel_session(&r),
                parse_handle_notification(&r),
            ] {
                match f {
                    Err(Error::Redirect {
                        status: s,
                        location,
                    }) => {
                        assert_eq!(s, status);
                        assert_eq!(location.as_deref(), Some("https://evil.example/x"));
                    }
                    other => panic!("{other:?}"),
                }
            }
        }
        // a redirect without Location is still a redirect
        assert!(matches!(
            parse_cancel_session(&ok(302, "")),
            Err(Error::Redirect { location: None, .. })
        ));
    }

    #[test]
    fn only_the_defined_status_is_normal() {
        // 6.3: 200 for request/response, 204 for the notification; other 2xx not used.
        assert!(matches!(
            parse_initiate_authentication(&ok(201, &init_ok_body())),
            Err(Error::HttpStatus {
                got: 201,
                expected: 200
            })
        ));
        assert!(matches!(
            parse_initiate_authentication(&ok(204, "")),
            Err(Error::HttpStatus {
                got: 204,
                expected: 200
            })
        ));
        assert!(matches!(
            parse_initiate_authentication(&ok(500, "{}")),
            Err(Error::HttpStatus {
                got: 500,
                expected: 200
            })
        ));
        assert!(matches!(
            parse_handle_notification(&ok(200, "")),
            Err(Error::HttpStatus {
                got: 200,
                expected: 204
            })
        ));
        assert!(parse_handle_notification(&ok(204, "")).is_ok());
    }

    // --- client over a recorded transport ----------------------------------

    type Seen = (String, Vec<(String, String)>, Vec<u8>);

    struct Recorded {
        replies: Vec<Result<Response, TransportError>>,
        seen: Vec<Seen>,
    }

    impl Es9Transport for Recorded {
        fn post(
            &mut self,
            url: &str,
            headers: &[(&str, &str)],
            body: &[u8],
        ) -> Result<Response, TransportError> {
            self.seen.push((
                url.to_owned(),
                headers
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                    .collect(),
                body.to_vec(),
            ));
            self.replies.remove(0)
        }
    }

    #[test]
    fn client_posts_and_parses() {
        let t = Recorded {
            replies: vec![Ok(ok(200, &init_ok_body())), Ok(ok(204, ""))],
            seen: vec![],
        };
        let mut c = Es9Client::new(t, smdp());
        let got = c
            .initiate_authentication(&[0u8; 16], &[0xBF, 0x20, 0])
            .unwrap();
        assert_eq!(got.server_signature1, [0x11, 0x22]);
        c.handle_notification(b"foobar").unwrap();
        let seen = &c.transport.seen;
        assert_eq!(
            seen[0].0,
            "https://smdp.gsma.com/gsma/rsp2/es9plus/initiateAuthentication"
        );
        assert_eq!(
            seen[0].1[1],
            ("X-Admin-Protocol".into(), ADMIN_PROTOCOL.into())
        );
        assert_eq!(
            seen[1].0,
            "https://smdp.gsma.com/gsma/rsp2/es9plus/handleNotification"
        );
        assert_eq!(seen[1].2, b"{\"pendingNotification\":\"Zm9vYmFy\"}");
    }

    #[test]
    fn client_surfaces_transport_and_redirect() {
        let t = Recorded {
            replies: vec![
                Err(TransportError("tls: certificate rejected".into())),
                Ok(ok(302, "")),
            ],
            seen: vec![],
        };
        let mut c = Es9Client::new(t, smdp());
        let info = [0xBF, 0x20, 0];
        assert!(matches!(
            c.initiate_authentication(&[0; 16], &info),
            Err(Error::Transport(_))
        ));
        assert!(matches!(
            c.initiate_authentication(&[0; 16], &info),
            Err(Error::Redirect { status: 302, .. })
        ));
        // each call is one POST; nothing was retried or followed
        assert_eq!(c.transport.seen.len(), 2);
    }
}
