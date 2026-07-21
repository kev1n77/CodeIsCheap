use codeischeap_capture_ipc::{
    CAPTURE_ENVELOPE_VERSION, CaptureEnvelope, CaptureOutcome, CaptureSource, CaptureTransport,
    CapturedBody, CapturedBodyState, CapturedField, CapturedRequest, CapturedResponse,
    IPC_ORIGIN_MITMPROXY, IPC_PROTOCOL, IPC_PROTOCOL_VERSION, IpcError, MAX_AUTH_FRAME_BYTES,
    ResponseCompleteness, receive_from_reader, receive_from_reader_with_transport,
    receive_one_with_deadline, receive_one_with_transport_verified,
};
#[cfg(unix)]
use codeischeap_capture_ipc::{
    receive_one_unix_with_transport_deadline, receive_one_unix_with_transport_verified,
};
use schemars::schema_for;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

use std::time::Duration;

const CHECKED_IN_SCHEMA: &str = include_str!("../../../schemas/capture-envelope/v0.1.schema.json");
const MITMPROXY_FIXTURE: &str = include_str!("fixtures/mitmproxy-request.json");

fn sample_envelope() -> CaptureEnvelope {
    CaptureEnvelope {
        version: CAPTURE_ENVELOPE_VERSION.to_owned(),
        capture_id: "flow_test_1".to_owned(),
        observed_at_unix_ms: 1_721_000_000_000,
        source: CaptureSource::Mitmproxy,
        attribution: None,
        request: CapturedRequest {
            method: "POST".to_owned(),
            scheme: "https".to_owned(),
            host: "api.openai.com".to_owned(),
            port: 443,
            path: "/v1/chat/completions".to_owned(),
            query: Vec::new(),
            headers: Vec::new(),
            body: CapturedBody {
                state: CapturedBodyState::Json,
                content: Some(
                    serde_json::json!({"messages": [{"role": "user", "content": "hello"}]}),
                ),
            },
        },
        outcome: None,
        redactions: Vec::new(),
    }
}

async fn framed_reader(
    token: &str,
    envelope: &CaptureEnvelope,
) -> BufReader<tokio::io::DuplexStream> {
    framed_reader_with_origin(token, IPC_ORIGIN_MITMPROXY, envelope).await
}

async fn framed_reader_with_origin(
    token: &str,
    origin: &str,
    envelope: &CaptureEnvelope,
) -> BufReader<tokio::io::DuplexStream> {
    framed_reader_with_transport(token, origin, envelope, None).await
}

async fn framed_reader_with_transport(
    token: &str,
    origin: &str,
    envelope: &CaptureEnvelope,
    transport: Option<CaptureTransport>,
) -> BufReader<tokio::io::DuplexStream> {
    framed_reader_with_auth(token, origin, IPC_PROTOCOL_VERSION, envelope, transport).await
}

async fn framed_reader_with_auth(
    token: &str,
    origin: &str,
    version: &str,
    envelope: &CaptureEnvelope,
    transport: Option<CaptureTransport>,
) -> BufReader<tokio::io::DuplexStream> {
    let (mut writer, reader) = tokio::io::duplex(16 * 1024);
    let auth = serde_json::json!({
        "protocol": IPC_PROTOCOL,
        "version": version,
        "origin": origin,
        "token": token,
        "transport": transport,
    });
    let mut frames = serde_json::to_vec(&auth).expect("auth frame must serialize");
    frames.push(b'\n');
    frames.extend(serde_json::to_vec(envelope).expect("envelope must serialize"));
    frames.push(b'\n');
    tokio::spawn(async move {
        writer
            .write_all(&frames)
            .await
            .expect("frames must be writable");
    });
    BufReader::new(reader)
}

#[tokio::test]
async fn rejects_the_previous_transport_protocol() {
    let expected = sample_envelope();
    let mut reader = framed_reader_with_auth(
        "synthetic-token",
        IPC_ORIGIN_MITMPROXY,
        "0.4",
        &expected,
        None,
    )
    .await;

    let error = receive_from_reader(&mut reader, "synthetic-token")
        .await
        .expect_err("old sidecars must be rejected");

    assert!(matches!(error, IpcError::UnsupportedProtocol));
}

#[tokio::test]
async fn accepts_ephemeral_loopback_transport_context() {
    let expected = sample_envelope();
    let transport = CaptureTransport {
        client_addr: "127.0.0.1:53110".parse().unwrap(),
        server_addr: "127.0.0.1:8787".parse().unwrap(),
    };
    let mut reader = framed_reader_with_transport(
        "synthetic-token",
        IPC_ORIGIN_MITMPROXY,
        &expected,
        Some(transport),
    )
    .await;

    let received = receive_from_reader_with_transport(&mut reader, "synthetic-token")
        .await
        .expect("valid transport context must be accepted");

    assert_eq!(received.envelope, expected);
    assert_eq!(received.transport, Some(transport));
}

#[tokio::test]
async fn rejects_non_loopback_transport_context() {
    let expected = sample_envelope();
    let transport = CaptureTransport {
        client_addr: "192.0.2.10:53110".parse().unwrap(),
        server_addr: "127.0.0.1:8787".parse().unwrap(),
    };
    let mut reader = framed_reader_with_transport(
        "synthetic-token",
        IPC_ORIGIN_MITMPROXY,
        &expected,
        Some(transport),
    )
    .await;

    let error = receive_from_reader_with_transport(&mut reader, "synthetic-token")
        .await
        .expect_err("non-loopback transport context must be rejected");

    assert!(matches!(error, IpcError::InvalidTransport));
}

#[tokio::test]
async fn accepts_an_authenticated_envelope() {
    let expected = sample_envelope();
    let mut reader = framed_reader("synthetic-token", &expected).await;

    let received = receive_from_reader(&mut reader, "synthetic-token")
        .await
        .expect("valid frames must be accepted");

    assert_eq!(received, expected);
}

#[tokio::test]
async fn response_outcomes_round_trip_through_authenticated_ipc() {
    let mut expected = sample_envelope();
    expected.outcome = Some(CaptureOutcome::Response(CapturedResponse {
        status: 200,
        headers: vec![CapturedField {
            name: "content-type".to_owned(),
            value: "text/event-stream".to_owned(),
        }],
        body: CapturedBody {
            state: CapturedBodyState::Text,
            content: Some(serde_json::Value::String(
                "data: {\"type\":\"done\"}\n\n".to_owned(),
            )),
        },
        duration_ms: 73,
        completeness: ResponseCompleteness::Complete,
    }));
    let mut reader = framed_reader("synthetic-token", &expected).await;

    let received = receive_from_reader(&mut reader, "synthetic-token")
        .await
        .expect("response outcome must be accepted");

    assert_eq!(received, expected);
}

#[tokio::test]
async fn rejects_an_invalid_token_without_echoing_it() {
    let mut reader = framed_reader("wrong-token", &sample_envelope()).await;

    let error = receive_from_reader(&mut reader, "expected-token")
        .await
        .expect_err("invalid tokens must be rejected");

    assert!(matches!(error, IpcError::Unauthorized));
    assert!(!error.to_string().contains("wrong-token"));
}

#[tokio::test]
async fn rejects_an_unexpected_origin() {
    let mut reader =
        framed_reader_with_origin("synthetic-token", "unknown-plugin", &sample_envelope()).await;

    let error = receive_from_reader(&mut reader, "synthetic-token")
        .await
        .expect_err("unexpected origins must be rejected");

    assert!(matches!(error, IpcError::UnsupportedOrigin));
}

#[tokio::test]
async fn rejects_oversized_auth_before_reading_an_envelope() {
    let (mut writer, reader) = tokio::io::duplex(MAX_AUTH_FRAME_BYTES * 2);
    let mut oversized = vec![b'a'; MAX_AUTH_FRAME_BYTES + 1];
    oversized.push(b'\n');
    tokio::spawn(async move {
        writer
            .write_all(&oversized)
            .await
            .expect("oversized frame must be writable");
    });
    let mut reader = BufReader::new(reader);

    let error = receive_from_reader(&mut reader, "synthetic-token")
        .await
        .expect_err("oversized auth must be rejected");

    assert!(matches!(error, IpcError::AuthFrameTooLarge));
}

#[tokio::test]
async fn stalled_connection_expires_and_the_next_sidecar_can_deliver() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener must bind");
    let address = listener.local_addr().expect("listener address");
    let stalled = TcpStream::connect(address)
        .await
        .expect("stalled client must connect");

    let error = receive_one_with_deadline(&listener, "synthetic-token", Duration::from_millis(20))
        .await
        .expect_err("stalled client must expire");
    assert!(matches!(error, IpcError::ConnectionDeadlineExceeded));
    drop(stalled);

    let expected = sample_envelope();
    let expected_for_sender = expected.clone();
    let sender = tokio::spawn(async move {
        let mut stream = TcpStream::connect(address)
            .await
            .expect("sidecar must connect after timeout");
        let auth = serde_json::json!({
            "protocol": IPC_PROTOCOL,
            "version": IPC_PROTOCOL_VERSION,
            "origin": IPC_ORIGIN_MITMPROXY,
            "token": "synthetic-token",
        });
        stream
            .write_all(
                format!(
                    "{auth}\n{}\n",
                    serde_json::to_string(&expected_for_sender).expect("envelope must encode")
                )
                .as_bytes(),
            )
            .await
            .expect("sidecar frames must write");
        let mut acknowledgement = String::new();
        BufReader::new(stream)
            .read_line(&mut acknowledgement)
            .await
            .expect("acknowledgement must read");
        assert_eq!(acknowledgement, "{\"status\":\"accepted\"}\n");
    });

    let received = receive_one_with_deadline(&listener, "synthetic-token", Duration::from_secs(1))
        .await
        .expect("next sidecar delivery must be accepted");
    sender.await.expect("sidecar sender must complete");
    assert_eq!(received, expected);
}

#[tokio::test]
async fn rejects_an_unauthorized_peer_before_reading_auth() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener must bind");
    let address = listener.local_addr().expect("listener address");
    let sender = tokio::spawn(async move {
        TcpStream::connect(address)
            .await
            .expect("unauthorized peer must connect")
    });

    let error = receive_one_with_transport_verified(
        &listener,
        "synthetic-token",
        |peer, server| async move {
            assert!(peer.ip().is_loopback());
            assert_eq!(server, address);
            false
        },
    )
    .await
    .expect_err("unauthorized peer must be rejected");
    let _stream = sender.await.expect("sender task must complete");

    assert!(matches!(error, IpcError::UnauthorizedPeer));
}

#[cfg(unix)]
#[tokio::test]
async fn unix_socket_transport_preserves_auth_frames_and_acknowledgement() {
    let directory = tempfile::tempdir().expect("temporary directory must exist");
    let path = directory.path().join("capture.sock");
    let listener = UnixListener::bind(&path).expect("Unix listener must bind");
    let expected = sample_envelope();
    let expected_for_sender = expected.clone();
    let sender = tokio::spawn(async move {
        let mut stream = UnixStream::connect(path)
            .await
            .expect("Unix sidecar must connect");
        let auth = serde_json::json!({
            "protocol": IPC_PROTOCOL,
            "version": IPC_PROTOCOL_VERSION,
            "origin": IPC_ORIGIN_MITMPROXY,
            "token": "synthetic-token",
        });
        stream
            .write_all(
                format!(
                    "{auth}\n{}\n",
                    serde_json::to_string(&expected_for_sender).expect("envelope must encode")
                )
                .as_bytes(),
            )
            .await
            .expect("Unix frames must write");
        let mut acknowledgement = String::new();
        BufReader::new(stream)
            .read_line(&mut acknowledgement)
            .await
            .expect("Unix acknowledgement must read");
        assert_eq!(acknowledgement, "{\"status\":\"accepted\"}\n");
    });

    let received = receive_one_unix_with_transport_deadline(
        &listener,
        "synthetic-token",
        Duration::from_secs(1),
    )
    .await
    .expect("Unix capture must be accepted");
    sender.await.expect("Unix sender must complete");
    assert_eq!(received.envelope, expected);
    assert_eq!(received.transport, None);
}

#[cfg(unix)]
#[tokio::test]
async fn unix_socket_rejects_an_unexpected_peer_before_reading_auth() {
    let directory = tempfile::tempdir().expect("temporary directory must exist");
    let path = directory.path().join("capture.sock");
    let listener = UnixListener::bind(&path).expect("Unix listener must bind");
    let sender = tokio::spawn(async move {
        UnixStream::connect(path)
            .await
            .expect("unauthorized Unix peer must connect")
    });

    let expected_pid = i32::try_from(std::process::id()).expect("test PID must fit in i32");
    let error = receive_one_unix_with_transport_verified(
        &listener,
        "synthetic-token",
        move |_, process_id| {
            assert_eq!(process_id, Some(expected_pid));
            false
        },
    )
    .await
    .expect_err("unexpected Unix peer must be rejected");
    let _stream = sender.await.expect("Unix sender must complete");
    assert!(matches!(error, IpcError::UnauthorizedPeer));
}

#[test]
fn mitmproxy_fixture_matches_the_rust_contract() {
    let envelope: CaptureEnvelope =
        serde_json::from_str(MITMPROXY_FIXTURE).expect("mitmproxy fixture must deserialize");

    assert_eq!(envelope.source, CaptureSource::Mitmproxy);
    assert_eq!(envelope.request.host, "api.openai.com");
    assert_eq!(
        envelope.request.body.content,
        Some(serde_json::json!({
            "messages": [{"role": "user", "content": "keep this prompt"}],
            "metadata": {"trace": "keep"}
        }))
    );
    assert_eq!(envelope.redactions.len(), 5);
}

#[test]
fn checked_in_schema_matches_the_rust_contract() {
    let generated =
        serde_json::to_value(schema_for!(CaptureEnvelope)).expect("schema must serialize");
    let checked_in: serde_json::Value =
        serde_json::from_str(CHECKED_IN_SCHEMA).expect("checked-in schema must be valid JSON");

    assert_eq!(
        checked_in, generated,
        "schema drifted; run `cargo run -p codeischeap-capture-ipc --bin export-capture-schema -- schemas/capture-envelope/v0.1.schema.json`"
    );
}
