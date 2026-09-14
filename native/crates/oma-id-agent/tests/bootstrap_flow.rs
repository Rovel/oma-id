#![cfg(target_os = "linux")]
//! Reserve-then-activate bootstrap tests (docs/p0/installer-enrollment.md,
//! §7.2 step 5): the agent retries its signed check-in until the admin
//! accepts (401 → 200), then surfaces the POSIX mapping + the one-time
//! bootstrap credential. Provisioning/password/ack side effects require
//! root, so those are container-tested; here we verify the resolve logic.

use oma_id_agent::{bootstrap_checkin_until_accepted, DeviceIdentity};
use std::io::{Read, Write};
use std::time::Duration;

fn spawn_mock(mut handler: impl FnMut(&str) -> String + Send + 'static) -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 8192];
            let mut raw = String::new();
            loop {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        raw.push_str(&String::from_utf8_lossy(&buf[..n]));
                        if let Some(h) = raw.find("\r\n\r\n") {
                            let cl = raw[..h]
                                .to_ascii_lowercase()
                                .split("content-length:")
                                .nth(1)
                                .and_then(|v| v.split('\r').next())
                                .and_then(|v| v.trim().parse::<usize>().ok());
                            let body_start = h + 4;
                            match cl {
                                Some(len) if raw.len() >= body_start + len => break,
                                None => break,
                                _ => {}
                            }
                        }
                    }
                }
            }
            let resp = handler(&raw);
            let http = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                resp.len(), resp
            );
            let _ = stream.write_all(http.as_bytes());
        }
    });
    port
}

const OK_RESPONSE: &str = r#"{
  "version": 2,
  "high_water_revocation_epoch": 1,
  "leases": [],
  "key_id": "k1",
  "issuer_keys": [],
  "posix": {"username":"owner","uid":10000,"gid":10000,"home":"/home/owner","shell":"/bin/zsh","full_name":"Owner"},
  "bootstrap": {"credential":"ABC123bootstrap","rotate":true}
}"#;

#[test]
fn bootstrap_retries_until_the_reservation_is_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let identity = DeviceIdentity::load_or_create(&dir.path().join("device.key")).unwrap();

    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let c = calls.clone();
    let port = spawn_mock(move |_raw: &str| {
        // First 3 calls: not accepted (401). 4th: accepted with bootstrap.
        let n = c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if n < 3 {
            "{\"error\":\"unauthorized\"}".to_string()
        } else {
            OK_RESPONSE.to_string()
        }
    });

    let b = bootstrap_checkin_until_accepted(
        &format!("http://127.0.0.1:{port}"),
        "workstation-1",
        &identity,
        Duration::from_millis(10),
    )
    .expect("bootstrap resolves once accepted");

    assert_eq!(b.posix.username, "owner");
    assert_eq!(b.posix.uid, 10000);
    assert_eq!(b.bootstrap_credential.as_deref(), Some("ABC123bootstrap"));
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 4, "3 rejects + 1 accept");
}

#[test]
fn bootstrap_without_bootstrap_credential_is_fine() {
    let dir = tempfile::tempdir().unwrap();
    let identity = DeviceIdentity::load_or_create(&dir.path().join("device.key")).unwrap();
    let port = spawn_mock(|_| {
        r#"{"version":2,"high_water_revocation_epoch":1,"leases":[],"key_id":"k1","issuer_keys":[],
             "posix":{"username":"owner","uid":10000,"gid":10000,"home":"/home/owner","shell":"/bin/zsh","full_name":""}}"#
        .to_string()
    });
    let b = bootstrap_checkin_until_accepted(
        &format!("http://127.0.0.1:{port}"),
        "workstation-1",
        &identity,
        Duration::from_millis(10),
    )
    .unwrap();
    assert_eq!(b.posix.username, "owner");
    assert_eq!(b.bootstrap_credential, None);
}

#[test]
fn unreachable_server_during_bootstrap_keeps_retrying_not_failing() {
    let dir = tempfile::tempdir().unwrap();
    let identity = DeviceIdentity::load_or_create(&dir.path().join("device.key")).unwrap();
    // A port with a listener that accepts but never answers → connection
    // kept open → ureq blocks; use a closed port instead (immediate refuse).
    // Bind then drop to get a closed port.
    let dead_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    }; // dropped → closed
    // Run bootstrap in a thread; it must NOT return quickly (it retries), so
    // we just verify it is still retrying by checking it does not produce an
    // immediate Err within a short window. We assert the loop is live by
    // running for 150ms and expecting no completion.
    let handle = std::thread::spawn(move || {
        bootstrap_checkin_until_accepted(
            &format!("http://127.0.0.1:{dead_port}"),
            "workstation-1",
            &identity,
            Duration::from_millis(30),
        )
    });
    std::thread::sleep(Duration::from_millis(150));
    assert!(!handle.is_finished(), "bootstrap keeps retrying on reachability errors");
    // it never resolves (server never comes up); leave it retrying in this
    // detached thread — the test binary detaches, harmless.
}
