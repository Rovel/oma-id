//! P3-a enrollment transaction tests (plan §7.2, §7.3): the agent's
//! device-side flow against a local mock issuer — hardware identity
//! collection with DMI fallbacks, idempotent request posting, signed status
//! polls, and adoption of the server-assigned device id.

#![cfg(target_os = "linux")]

use ed25519_dalek::SigningKey;
use oma_id_agent::enrollment::{
    ensure_enrolled, ensure_enrolled_with_interval, read_hardware_identity, EnrollError,
};
use std::time::Duration;
use oma_id_agent::DeviceIdentity;
use std::io::{Read, Write};

/// A tiny blocking HTTP server: routes /api/v1/enrollment-requests to the
/// closure, one request per connection. Returns the bound port.
fn spawn_mock(handler: impl Fn(&str) -> String + Send + 'static) -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 8192];
            let mut raw = String::new();
            // Read headers, then exactly content-length body bytes (ureq
            // keeps the connection open, so read-to-EOF would deadlock).
            loop {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        raw.push_str(&String::from_utf8_lossy(&buf[..n]));
                        if let Some(headers_end) = raw.find("\r\n\r\n") {
                            let headers = &raw[..headers_end];
                            let content_length = headers
                                .to_ascii_lowercase()
                                .split("content-length:")
                                .nth(1)
                                .and_then(|v| v.split('\r').next())
                                .and_then(|v| v.trim().parse::<usize>().ok());
                            let body_start = headers_end + 4;
                            match content_length {
                                Some(len) if raw.len() >= body_start + len => break,
                                None => break,
                                _ => {}
                            }
                        }
                    }
                }
            }
            let response = handler(&raw);
            let http = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response.len(),
                response
            );
            let _ = stream.write_all(http.as_bytes());
            let _ = stream.flush();
        }
    });
    port
}

fn request_body(raw: &str) -> serde_json::Value {
    let body = raw.split("\r\n\r\n").nth(1).unwrap_or("");
    serde_json::from_str(body).unwrap_or(serde_json::Value::Null)
}

#[test]
fn hardware_identity_falls_back_cleanly_without_dmi() {
    // In a container or any non-DMI environment every field may be missing;
    // the identity must still produce a usable display name.
    let hardware = read_hardware_identity();
    assert!(hardware.device_name.is_some(), "device_name always present");
    if hardware.manufacturer.is_none() && hardware.model.is_none() {
        assert!(hardware
            .device_name
            .as_deref()
            .expect("name")
            .starts_with("Device (machine-id"));
    }
}

#[test]
fn enrollment_flow_posts_then_polls_until_accepted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let identity = DeviceIdentity::load_or_create(&dir.path().join("device.key")).expect("identity");

    // A separate SigningKey instance over the SAME seed (the identity's
    // signing key is moved into the mock closure for signature checks).
    let mock_signing = SigningKey::from_bytes(&identity.signing_key.to_bytes());

    let polls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let polls_reader = polls.clone();
    let port = spawn_mock(move |raw| {
        if raw.starts_with("POST /api/v1/enrollment-requests") {
            let body = request_body(raw);
            assert_eq!(
                body["public_key_hex"].as_str().expect("key").len(),
                64,
                "the enrollment request carries the device public key"
            );
            assert!(body["device_name"].is_string(), "hardware identity sent");
            r#"{"id": 7, "state": "pending", "nonce": "abc"}"#.to_string()
        } else if raw.starts_with("GET /api/v1/enrollment-requests/7") {
            // The signed poll must cover "enrollment-status|<id>|<timestamp>".
            let query = raw.split_whitespace().nth(1).expect("path");
            let timestamp = query.split("timestamp=").nth(1).and_then(|t| {
                t.split('&').next().and_then(|t| t.parse::<u64>().ok())
            });
            let signature_hex = query
                .split("signature_hex=")
                .nth(1)
                .and_then(|s| s.split('&').next())
                .unwrap_or("")
                .to_string();
            let ts = timestamp.expect("timestamp");
            let message = format!("enrollment-status|7|{ts}");
            let sig: Vec<u8> = hex::decode(&signature_hex).expect("sig hex");
            mock_signing
                .verify_strict(message.as_bytes(), &ed25519_dalek::Signature::from_slice(&sig).expect("sig"))
                .expect("the status poll signature must verify");
            // First poll: pending. Second poll: accepted with the device id.
            if polls_reader.fetch_add(1, std::sync::atomic::Ordering::SeqCst) >= 1 {
                r#"{"state": "accepted", "device": {"device_id": "workstation-7"}}"#.to_string()
            } else {
                r#"{"state": "pending", "nonce": "abc"}"#.to_string()
            }
        } else {
            format!("{{\"error\": \"unrouted: {}\"}}", raw.split_whitespace().next().unwrap_or("?"))
        }
    });

    let state_dir = dir.path().join("state");
    std::fs::create_dir_all(&state_dir).expect("state dir");
    let assigned = ensure_enrolled_with_interval(
        &format!("http://127.0.0.1:{port}"),
        &identity,
        &state_dir,
        "proposed-1",
        Duration::from_millis(100),
    )
    .expect("enrollment must complete");
    assert_eq!(assigned, "workstation-7", "the server-assigned device id is adopted");

    // The enrollment record persisted (0600) and short-circuits a re-run.
    let record_path = state_dir.join("enrollment.json");
    let record = std::fs::read(&record_path).expect("enrollment record");
    assert!(serde_json::from_slice::<oma_id_agent::enrollment::EnrollmentRecord>(&record).is_ok());
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&record_path).expect("meta").permissions().mode() & 0o777,
        0o600,
        "the enrollment record is 0600"
    );
    let second = ensure_enrolled(&format!("http://127.0.0.1:{port}"), &identity, &state_dir, "proposed-1")
        .expect("re-run");
    assert_eq!(second, "workstation-7", "a previously accepted record short-circuits");
}

#[test]
fn enrollment_rejection_is_terminal_and_fails_closed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let identity = DeviceIdentity::load_or_create(&dir.path().join("device.key")).expect("identity");

    let port = spawn_mock(|raw| {
        if raw.starts_with("POST") {
            r#"{"id": 3, "state": "pending", "nonce": "abc"}"#.to_string()
        } else {
            r#"{"state": "rejected"}"#.to_string()
        }
    });

    let state_dir = dir.path().join("state");
    std::fs::create_dir_all(&state_dir).expect("state dir");
    let error = ensure_enrolled_with_interval(
        &format!("http://127.0.0.1:{port}"),
        &identity,
        &state_dir,
        "d",
        Duration::from_millis(100),
    )
    .expect_err("rejection must fail");
    assert!(
        matches!(error, EnrollError::RejectedByAdmin(3)),
        "an admin rejection is a distinct terminal error: {error:?}"
    );
    assert!(
        !state_dir.join("enrollment.json").exists(),
        "nothing is recorded on rejection (fail closed, §7.3)"
    );
}

#[test]
fn unreachable_server_during_enrollment_fails_cleanly() {
    let dir = tempfile::tempdir().expect("tempdir");
    let identity = DeviceIdentity::load_or_create(&dir.path().join("device.key")).expect("identity");
    let state_dir = dir.path().join("state");
    std::fs::create_dir_all(&state_dir).expect("state dir");
    let error =
        ensure_enrolled("http://127.0.0.1:9", &identity, &state_dir, "d").expect_err("must fail");
    assert!(
        matches!(error, EnrollError::Rejected { .. } | EnrollError::Http(_)),
        "unreachable server is a clean error: {error:?}"
    );
}
