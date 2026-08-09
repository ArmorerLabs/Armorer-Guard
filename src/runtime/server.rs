use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::Arc;
use std::thread;

use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};

use super::Runtime;

const MAX_REQUEST_BYTES: usize = 2 * 1_048_576;

#[cfg(unix)]
pub(super) fn serve(socket: &Path, runtime: Arc<Runtime>) -> Result<(), String> {
    if socket.exists() {
        let metadata = fs::symlink_metadata(socket)
            .map_err(|error| format!("failed to inspect existing socket: {error}"))?;
        if !metadata.file_type().is_socket() {
            return Err(format!(
                "refusing to replace non-socket path: {}",
                socket.display()
            ));
        }
        fs::remove_file(socket)
            .map_err(|error| format!("failed to remove stale Guard socket: {error}"))?;
    }
    if let Some(parent) = socket.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create socket directory: {error}"))?;
    }
    let listener = UnixListener::bind(socket)
        .map_err(|error| format!("failed to bind Guard Unix socket: {error}"))?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("failed to restrict Guard socket permissions: {error}"))?;
    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                let runtime = Arc::clone(&runtime);
                thread::spawn(move || {
                    let _ = handle_connection(stream, &runtime);
                });
            }
            Err(error) => return Err(format!("Guard socket accept failed: {error}")),
        }
    }
    Ok(())
}

#[cfg(not(unix))]
#[cfg(windows)]
pub(super) fn serve(pipe: &Path, runtime: Arc<Runtime>) -> Result<(), String> {
    let listener = winpipe::WinListener::bind(pipe.to_string_lossy().as_ref())
        .map_err(|error| format!("failed to bind Guard named pipe: {error}"))?;
    loop {
        let (stream, _) = listener
            .accept()
            .map_err(|error| format!("Guard named-pipe accept failed: {error}"))?;
        let runtime = Arc::clone(&runtime);
        thread::spawn(move || {
            let _ = handle_connection(stream, &runtime);
        });
    }
}

#[cfg(not(any(unix, windows)))]
pub(super) fn serve(_endpoint: &Path, _runtime: Arc<Runtime>) -> Result<(), String> {
    Err("local Guard transport is unsupported on this platform".to_string())
}

pub(super) fn serve_mtls(
    endpoint: &str,
    certificate_file: &Path,
    private_key_file: &Path,
    client_ca_file: &Path,
    runtime: Arc<Runtime>,
) -> Result<(), String> {
    let configuration = Arc::new(mtls_configuration(
        certificate_file,
        private_key_file,
        client_ca_file,
    )?);
    let listener = TcpListener::bind(endpoint)
        .map_err(|error| format!("failed to bind Guard mTLS endpoint: {error}"))?;
    for connection in listener.incoming() {
        let tcp = connection.map_err(|error| format!("Guard mTLS accept failed: {error}"))?;
        let tls = ServerConnection::new(Arc::clone(&configuration))
            .map_err(|error| format!("failed to create Guard TLS session: {error}"))?;
        let runtime = Arc::clone(&runtime);
        thread::spawn(move || {
            let stream = StreamOwned::new(tls, tcp);
            let _ = handle_connection(stream, &runtime);
        });
    }
    Ok(())
}

fn mtls_configuration(
    certificate_file: &Path,
    private_key_file: &Path,
    client_ca_file: &Path,
) -> Result<ServerConfig, String> {
    let certificate_bytes = fs::read(certificate_file)
        .map_err(|error| format!("failed to read Guard server certificate: {error}"))?;
    let certificates = rustls_pemfile::certs(&mut certificate_bytes.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("failed to parse Guard server certificate: {error}"))?;
    if certificates.is_empty() {
        return Err("Guard server certificate chain is empty".to_string());
    }
    let private_key_bytes = fs::read(private_key_file)
        .map_err(|error| format!("failed to read Guard server private key: {error}"))?;
    let private_key = rustls_pemfile::private_key(&mut private_key_bytes.as_slice())
        .map_err(|error| format!("failed to parse Guard server private key: {error}"))?
        .ok_or_else(|| "Guard server private key is missing".to_string())?;
    let client_ca_bytes = fs::read(client_ca_file)
        .map_err(|error| format!("failed to read Guard client CA: {error}"))?;
    let client_cas = rustls_pemfile::certs(&mut client_ca_bytes.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("failed to parse Guard client CA: {error}"))?;
    let mut roots = RootCertStore::empty();
    let (accepted, rejected) = roots.add_parsable_certificates(client_cas);
    if accepted == 0 || rejected > 0 {
        return Err("Guard client CA contains no usable trust anchor".to_string());
    }
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|error| format!("failed to configure Guard client verification: {error}"))?;
    ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(certificates, private_key)
        .map_err(|error| format!("failed to configure Guard server identity: {error}"))
}

fn handle_connection<S: Read + Write>(mut stream: S, runtime: &Runtime) -> Result<(), String> {
    let request = read_request(&mut stream)?;
    let response = route(runtime, &request.method, &request.path, &request.body);
    write_response(&mut stream, response.0, &response.1)
}

struct Request {
    method: String,
    path: String,
    body: Vec<u8>,
}

fn read_request(stream: &mut impl Read) -> Result<Request, String> {
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end;
    loop {
        let count = stream
            .read(&mut chunk)
            .map_err(|error| format!("failed to read request: {error}"))?;
        if count == 0 {
            return Err("connection closed before request completed".to_string());
        }
        bytes.extend_from_slice(&chunk[..count]);
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err("request exceeds maximum size".to_string());
        }
        if let Some(index) = find_bytes(&bytes, b"\r\n\r\n") {
            header_end = index + 4;
            break;
        }
    }
    let header = std::str::from_utf8(&bytes[..header_end])
        .map_err(|_| "request headers are not UTF-8".to_string())?;
    let mut lines = header.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| "missing request line".to_string())?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or_else(|| "missing HTTP method".to_string())?
        .to_string();
    let path = request_parts
        .next()
        .ok_or_else(|| "missing HTTP path".to_string())?
        .to_string();
    let content_length = lines
        .filter_map(|line| line.split_once(':'))
        .find_map(|(name, value)| {
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    if header_end + content_length > MAX_REQUEST_BYTES {
        return Err("request body exceeds maximum size".to_string());
    }
    while bytes.len() < header_end + content_length {
        let count = stream
            .read(&mut chunk)
            .map_err(|error| format!("failed to read request body: {error}"))?;
        if count == 0 {
            return Err("connection closed before request body completed".to_string());
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    Ok(Request {
        method,
        path,
        body: bytes[header_end..header_end + content_length].to_vec(),
    })
}

pub(super) fn route(runtime: &Runtime, method: &str, path: &str, body: &[u8]) -> (u16, String) {
    let result = match (method, path) {
        ("GET", "/v1/health") => return (200, runtime.health_json()),
        ("GET", "/v1/readiness") if runtime.ready() => {
            return (200, "{\"status\":\"ready\"}".to_string())
        }
        ("GET", "/v1/readiness") => {
            return (
                503,
                "{\"status\":\"not_ready\",\"reason_code\":\"runtime:action_guard_unconfigured\"}"
                    .to_string(),
            )
        }
        ("GET", "/v1/operations/status") => runtime.operational_status_json(),
        ("GET", "/v1/policies/effective") => runtime.effective_policy_json().map_err(|message| {
            super::ApiError::unavailable(&message, "runtime:policy_unavailable")
        }),
        ("GET", "/v1/policies/history") => runtime.policy_history_json(),
        ("POST", "/v1/policies/simulate") => runtime.simulate_policy(body),
        ("POST", "/v1/policies/proposals") => runtime.propose_policy(body),
        ("POST", "/v1/policies/activate") => runtime.activate_policy(body),
        ("POST", "/v1/policies/rollback") => runtime.rollback_policy(body),
        ("POST", "/v1/policies/observe") => runtime.observe_rollout(body),
        ("POST", "/v1/telemetry/query") => runtime.query_telemetry(body),
        ("POST", "/v1/replay/traces") => runtime.replay_trace(body),
        ("POST", "/v1/evidence/access") => runtime.access_evidence(body),
        ("GET", "/v1/capabilities") => runtime.capabilities_json(),
        ("GET", "/v1/features") => runtime.feature_manifest_json(),
        ("GET", "/v1/enforcement/coverage") => runtime.enforcement_coverage_json(),
        ("POST", "/v1/approvals/challenges") => runtime.create_approval_challenge(body),
        ("POST", "/v1/approvals/consume") => runtime.consume_approval(body),
        ("POST", "/v1/executions/authorize") => runtime.authorize_dispatch(body),
        ("POST", "/v1/executions/receipts") => runtime.record_execution(body),
        ("POST", "/v1/gateway/http") => runtime.broker_http(body),
        ("POST", "/v1/gateway/filesystem") => runtime.broker_filesystem(body),
        ("POST", "/v1/input/evaluate") => runtime.evaluate_content("input", body),
        ("POST", "/v1/context/evaluate") => runtime.evaluate_content("context", body),
        ("POST", "/v1/model/request/evaluate") => runtime.evaluate_content("model_request", body),
        ("POST", "/v1/model/response/evaluate") => runtime.evaluate_content("model_response", body),
        ("POST", "/v1/tool/result/evaluate") => runtime.evaluate_content("tool_result", body),
        ("POST", "/v1/memory/write/evaluate") => runtime.evaluate_content("memory_write", body),
        ("POST", "/v1/memory/read/evaluate") => runtime.evaluate_content("memory_read", body),
        ("POST", "/v1/inter-agent/evaluate") => runtime.evaluate_content("inter_agent", body),
        ("POST", "/v1/action/evaluate") => runtime.evaluate_action(body),
        ("POST", "/v1/output/evaluate") => runtime.evaluate_content("output", body),
        _ => return (404, "{\"error\":\"route not found\"}".to_string()),
    };
    match result {
        Ok(body) => (200, body),
        Err(error) => (error.status, error.json()),
    }
}

fn write_response(stream: &mut impl Write, status: u16, body: &str) -> Result<(), String> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .map_err(|error| format!("failed to write response: {error}"))
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
    use rustls::{ClientConfig, ClientConnection};
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn runtime() -> Runtime {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        Runtime::load(
            std::env::temp_dir().join(format!("guard-runtime-test-{nonce}")),
            super::super::RuntimeLoadOptions {
                policy_path: None,
                delegation_key_path: None,
                policy_key_path: None,
                gateway_key_path: None,
                approval_key_path: None,
                evidence_key_path: None,
                evidence_authorization_key_path: None,
                manifest: None,
            },
        )
        .unwrap()
    }

    #[test]
    fn health_and_readiness_are_distinct() {
        let runtime = runtime();
        assert_eq!(route(&runtime, "GET", "/v1/health", b"").0, 200);
        assert_eq!(route(&runtime, "GET", "/v1/readiness", b"").0, 503);
    }

    #[test]
    fn unknown_fields_fail_closed() {
        let runtime = runtime();
        let response = route(
            &runtime,
            "POST",
            "/v1/input/evaluate",
            br#"{"schema_version":"armorer-guard-content-evaluation/v1","unknown":true}"#,
        );
        assert_eq!(response.0, 400);
        assert!(response.1.contains("contract:invalid_json"));
    }

    #[test]
    fn mtls_requires_a_client_certificate_signed_by_the_configured_ca() {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();

        let server_key = KeyPair::generate().unwrap();
        let server = CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .signed_by(&server_key, &ca, &ca_key)
            .unwrap();
        let client_key = KeyPair::generate().unwrap();
        let client = CertificateParams::new(vec!["guard-client".to_string()])
            .unwrap()
            .signed_by(&client_key, &ca, &ca_key)
            .unwrap();

        let directory = std::env::temp_dir().join(format!(
            "guard-mtls-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&directory).unwrap();
        let cert_path = directory.join("server.pem");
        let key_path = directory.join("server.key");
        let ca_path = directory.join("ca.pem");
        fs::write(&cert_path, server.pem()).unwrap();
        fs::write(&key_path, server_key.serialize_pem()).unwrap();
        fs::write(&ca_path, ca.pem()).unwrap();
        let server_config = Arc::new(mtls_configuration(&cert_path, &key_path, &ca_path).unwrap());

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let accepted_config = Arc::clone(&server_config);
        let guarded_runtime = runtime();
        let server_thread = thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let connection = ServerConnection::new(accepted_config).unwrap();
            handle_connection(StreamOwned::new(connection, tcp), &guarded_runtime).unwrap();
        });

        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(ca.der().to_vec())).unwrap();
        let client_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(
                vec![CertificateDer::from(client.der().to_vec())],
                PrivateKeyDer::try_from(client_key.serialize_der()).unwrap(),
            )
            .unwrap();
        let connection = ClientConnection::new(
            Arc::new(client_config),
            ServerName::try_from("localhost").unwrap().to_owned(),
        )
        .unwrap();
        let mut tls = StreamOwned::new(connection, TcpStream::connect(endpoint).unwrap());
        tls.write_all(
            b"GET /v1/health HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
        tls.flush().unwrap();
        let mut response = String::new();
        let _ = tls.read_to_string(&mut response);
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("\"status\":\"healthy\""));
        server_thread.join().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let rejected_config = Arc::clone(&server_config);
        let rejected_thread = thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let connection = ServerConnection::new(rejected_config).unwrap();
            let mut tls = StreamOwned::new(connection, tcp);
            let mut message = [0u8; 2];
            tls.read_exact(&mut message)
        });
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(ca.der().to_vec())).unwrap();
        let client_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connection = ClientConnection::new(
            Arc::new(client_config),
            ServerName::try_from("localhost").unwrap().to_owned(),
        )
        .unwrap();
        let mut unauthenticated =
            StreamOwned::new(connection, TcpStream::connect(endpoint).unwrap());
        let _ = unauthenticated.write_all(b"no");
        let _ = unauthenticated.flush();
        drop(unauthenticated);
        assert!(rejected_thread.join().unwrap().is_err());
    }
}
