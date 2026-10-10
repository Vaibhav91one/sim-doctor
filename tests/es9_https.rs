//! The HTTPS transport against a local TLS server on 127.0.0.1. No real
//! network: the CA and the server certificate are made at test time.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sim_doctor::es9::{self, Es9Client, Es9Transport, Request, SmdpAddress};
use sim_doctor::es9_https::{HttpsConfig, HttpsTransport, Trust};

struct Ca {
    cert: rcgen::Certificate,
    issuer: Issuer<'static, KeyPair>,
}

fn make_ca() -> Ca {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec![]).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let cert = params.self_signed(&key).unwrap();
    Ca {
        cert,
        issuer: Issuer::new(params, key),
    }
}

fn bundle_file(name: &str, ca: &Ca) -> PathBuf {
    let path = std::env::temp_dir().join(format!("sim-doctor-{}-{name}.pem", std::process::id()));
    std::fs::write(&path, ca.cert.pem()).unwrap();
    path
}

/// What the server saw of one request.
struct Seen {
    head: String,
    body: Vec<u8>,
}

/// Serves `reply(request)` raw HTTP bytes for each of `connections`
/// connections, with a certificate for 127.0.0.1 signed by `ca`.
fn serve(
    ca: &Ca,
    connections: usize,
    reply: impl Fn(&Seen) -> Vec<u8> + Send + 'static,
) -> (u16, mpsc::Receiver<Seen>) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec![]).unwrap();
    params.subject_alt_names = vec![SanType::IpAddress("127.0.0.1".parse().unwrap())];
    let leaf = params.signed_by(&key, &ca.issuer).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from(leaf.der().to_vec())],
        PrivateKeyDer::Pkcs8(key.serialize_der().into()),
    )
    .unwrap();
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for _ in 0..connections {
            let Ok((mut tcp, _)) = listener.accept() else {
                return;
            };
            let mut conn = rustls::ServerConnection::new(config.clone()).unwrap();
            let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
            // Read head then Content-Length bytes. A failed handshake (the
            // client rejecting our certificate) ends this connection quietly.
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            let head_end = loop {
                if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break i + 4;
                }
                match tls.read(&mut chunk) {
                    Ok(0) | Err(_) => break usize::MAX,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
            };
            if head_end == usize::MAX {
                continue;
            }
            let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
            let want = head
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|v| v.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            while buf.len() < head_end + want {
                match tls.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
            }
            let seen = Seen {
                head,
                body: buf[head_end..].to_vec(),
            };
            let _ = tls.write_all(&reply(&seen));
            let _ = tls.flush();
            conn.send_close_notify();
            let _ = conn.complete_io(&mut tcp);
            let _ = tx.send(seen);
        }
    });
    (port, rx)
}

fn http(status: &str, extra: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

fn transport(bundle: &Path) -> HttpsTransport {
    HttpsTransport::new(&HttpsConfig {
        trust: Trust::Bundle(bundle.to_path_buf()),
        timeout: Duration::from_secs(5),
        max_response: 1000,
    })
    .unwrap()
}

fn url(port: u16) -> String {
    format!("https://127.0.0.1:{port}/gsma/rsp2/es9plus/initiateAuthentication")
}

#[test]
fn successful_exchange_sends_the_es9_headers() {
    let ca = make_ca();
    let bundle = bundle_file("ok", &ca);
    let (port, seen) = serve(&ca, 1, |_| {
        http(
            "200 OK",
            "Content-Type: application/json;charset=UTF-8\r\n",
            b"{\"a\":1}",
        )
    });
    let got = transport(&bundle)
        .post(&url(port), &Request::headers(), b"{\"x\":2}")
        .unwrap();
    assert_eq!(got.status, 200);
    assert_eq!(got.body, b"{\"a\":1}");
    assert!(got
        .headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("content-type") && v.starts_with("application/json")));
    let seen = seen.recv_timeout(Duration::from_secs(5)).unwrap();
    let head = seen.head.to_ascii_lowercase();
    assert!(head.starts_with("post /gsma/rsp2/es9plus/initiateauthentication http/1.1"));
    assert!(head.contains("content-type: application/json\r\n"));
    assert!(head.contains(&format!("x-admin-protocol: {}\r\n", es9::ADMIN_PROTOCOL)));
    assert!(head.contains("user-agent: gsma-rsp-lpad\r\n"));
    assert_eq!(seen.body, b"{\"x\":2}");
}

#[test]
fn wrong_ca_is_rejected() {
    let ca = make_ca();
    let other = make_ca();
    let bundle = bundle_file("wrong", &other);
    let (port, _seen) = serve(&ca, 1, |_| http("200 OK", "", b"{}"));
    let err = transport(&bundle)
        .post(&url(port), &Request::headers(), b"{}")
        .unwrap_err();
    assert!(!err.0.is_empty());
}

#[test]
fn default_anchor_is_gsma_ci_and_rejects_a_private_ca() {
    assert_eq!(HttpsConfig::default().trust, Trust::GsmaCi);
    let ca = make_ca();
    let (port, _seen) = serve(&ca, 1, |_| http("200 OK", "", b"{}"));
    let mut t = HttpsTransport::new(&HttpsConfig::default()).unwrap();
    assert!(t.post(&url(port), &Request::headers(), b"{}").is_err());
}

#[test]
fn explicit_webpki_also_rejects_a_private_ca() {
    let ca = make_ca();
    let (port, _seen) = serve(&ca, 1, |_| http("200 OK", "", b"{}"));
    let mut t = HttpsTransport::new(&HttpsConfig {
        trust: Trust::Webpki,
        ..HttpsConfig::default()
    })
    .unwrap();
    assert!(t.post(&url(port), &Request::headers(), b"{}").is_err());
}

#[test]
fn plain_http_is_refused_without_a_connection() {
    let ca = make_ca();
    let bundle = bundle_file("plain", &ca);
    let err = transport(&bundle)
        .post("http://127.0.0.1:9/x", &Request::headers(), b"{}")
        .unwrap_err();
    assert!(!err.0.is_empty());
}

#[test]
fn bad_bundles_are_refused() {
    let missing = HttpsConfig {
        trust: Trust::Bundle("/nonexistent/ca.pem".into()),
        ..HttpsConfig::default()
    };
    assert!(HttpsTransport::new(&missing).is_err());
    let empty = std::env::temp_dir().join(format!("sim-doctor-{}-empty.pem", std::process::id()));
    std::fs::write(&empty, "not a certificate\n").unwrap();
    let cfg = HttpsConfig {
        trust: Trust::Bundle(empty),
        ..HttpsConfig::default()
    };
    assert!(HttpsTransport::new(&cfg).is_err());
}

#[test]
fn redirect_is_returned_and_refused_by_the_client() {
    let ca = make_ca();
    let bundle = bundle_file("redir", &ca);
    // One connection only: following the redirect would find nobody listening.
    let (port, _seen) = serve(&ca, 1, |_| {
        http(
            "302 Found",
            "Location: https://127.0.0.1:1/elsewhere\r\n",
            b"",
        )
    });
    let mut raw = transport(&bundle);
    let got = raw.post(&url(port), &Request::headers(), b"{}").unwrap();
    assert_eq!(got.status, 302);
    // Through the client: the ES9+ layer reports Error::Redirect.
    let smdp = SmdpAddress::parse("smdp.example.com").unwrap();
    let (port, _seen) = serve(&ca, 1, |_| {
        http(
            "302 Found",
            "Location: https://127.0.0.1:1/elsewhere\r\n",
            b"",
        )
    });
    let mut client = Es9Client::new(
        Redirecting {
            inner: transport(&bundle),
            port,
        },
        smdp,
    );
    assert!(matches!(
        client.initiate_authentication(&[0u8; 16], &[0xBF, 0x20, 0]),
        Err(es9::Error::Redirect { status: 302, .. })
    ));
}

/// Points the client's URL (a bare FQDN, no port) at the test server.
struct Redirecting {
    inner: HttpsTransport,
    port: u16,
}

impl Es9Transport for Redirecting {
    fn post(
        &mut self,
        _url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<es9::Response, es9::TransportError> {
        self.inner.post(&url(self.port), headers, body)
    }
}

#[test]
fn non_200_status_is_an_http_status_error() {
    let ca = make_ca();
    let bundle = bundle_file("500", &ca);
    let (port, _seen) = serve(&ca, 1, |_| http("500 Internal Server Error", "", b"oops"));
    let smdp = SmdpAddress::parse("smdp.example.com").unwrap();
    let mut client = Es9Client::new(
        Redirecting {
            inner: transport(&bundle),
            port,
        },
        smdp,
    );
    assert!(matches!(
        client.initiate_authentication(&[0u8; 16], &[0xBF, 0x20, 0]),
        Err(es9::Error::HttpStatus { got: 500, .. })
    ));
}

#[test]
fn oversized_response_is_an_error_not_a_truncation() {
    let ca = make_ca();
    let bundle = bundle_file("big", &ca);
    let (port, _seen) = serve(&ca, 1, |_| http("200 OK", "", &[b'a'; 5000]));
    let err = transport(&bundle)
        .post(&url(port), &Request::headers(), b"{}")
        .unwrap_err();
    assert!(err.0.contains("response"), "{err}");
}

#[test]
fn slow_server_times_out() {
    let ca = make_ca();
    let bundle = bundle_file("slow", &ca);
    let (port, _seen) = serve(&ca, 1, |_| {
        std::thread::sleep(Duration::from_secs(3));
        http("200 OK", "", b"{}")
    });
    let mut t = HttpsTransport::new(&HttpsConfig {
        trust: Trust::Bundle(bundle),
        timeout: Duration::from_millis(500),
        max_response: 1000,
    })
    .unwrap();
    let started = std::time::Instant::now();
    assert!(t.post(&url(port), &Request::headers(), b"{}").is_err());
    assert!(started.elapsed() < Duration::from_secs(3));
}

/// Rewrites the FQDN host of the URL to the local test server, keeping the
/// path, and remembers the URL it was asked for.
struct HostRewrite {
    inner: HttpsTransport,
    port: u16,
    asked: Vec<String>,
}

impl Es9Transport for HostRewrite {
    fn post(
        &mut self,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<es9::Response, es9::TransportError> {
        self.asked.push(url.to_owned());
        let local = url.replace("smdp.example.com", &format!("127.0.0.1:{}", self.port));
        self.inner.post(&local, headers, body)
    }
}

/// A dump of one notification addressed to smdp.example.com
/// (`30 { BF2F { 80 01, 81 04 80, 0C smdp.example.com } }`).
fn replay_dump() -> String {
    let meta = "800105810204800C10736D64702E6578616D706C652E636F6D";
    let raw = format!(
        "30{:02X}BF2F{:02X}{meta}",
        meta.len() / 2 + 3,
        meta.len() / 2
    );
    format!(
        r#"{{"format":"{}","eid":"89","notifications":[{{"pending_notification_hex":"{raw}"}}]}}"#,
        sim_doctor::euicc::DUMP_FORMAT
    )
}

#[test]
fn replay_posts_the_notification_to_its_address_over_verified_tls() {
    let ca = make_ca();
    let bundle = bundle_file("replay", &ca);
    let (port, seen) = serve(&ca, 1, |_| http("204 No Content", "", b""));
    let mut t = HostRewrite {
        inner: transport(&bundle),
        port,
        asked: Vec::new(),
    };
    let data = sim_doctor::notif::replay(&replay_dump(), Some(&mut t)).unwrap();
    assert_eq!(data["notifications"][0]["sent"], true);
    assert_eq!(
        t.asked,
        ["https://smdp.example.com/gsma/rsp2/es9plus/handleNotification"]
    );
    let seen = seen.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(
        seen.head
            .starts_with("POST /gsma/rsp2/es9plus/handleNotification HTTP/1.1"),
        "{}",
        seen.head
    );
    let body = String::from_utf8(seen.body).unwrap();
    assert!(body.starts_with(r#"{"pendingNotification":""#), "{body}");
}

#[test]
fn replay_dry_run_opens_no_connection() {
    // No transport is passed, and nothing listens: a dry run cannot send.
    let data = sim_doctor::notif::replay(&replay_dump(), None).unwrap();
    assert_eq!(data["dry_run"], true);
    assert_eq!(data["notifications"][0]["sent"], false);
}
