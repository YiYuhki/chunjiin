mod common;

use std::path::PathBuf;
use std::time::Duration;

use cdr::audit::{AuditConfig, Auditor};
use cdr::{Engine, Policy, Status};

fn temp_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("cdr-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

#[test]
fn audit_log_and_quarantine() {
    let dir = temp_dir("audit");
    let log = dir.join("logs/audit.jsonl");
    let q = dir.join("quarantine");
    let auditor = Auditor::open(&AuditConfig {
        log_path: Some(log.clone()),
        quarantine_dir: Some(q.clone()),
        quarantine_clean: false,
    })
    .unwrap();
    let engine = Engine::default();

    let bad = common::malicious_docm();
    let r = engine.process(&bad, "보고서.docm");
    let rec = auditor
        .record(
            &r,
            &bad,
            "/inbox/보고서.docm",
            &engine.policy,
            Duration::from_millis(5),
        )
        .unwrap();
    assert_eq!(rec.status, Status::Sanitized);
    assert_eq!(rec.event_id.len(), 16);
    let qpath = q.join(rec.quarantine.as_ref().expect("재조합된 파일은 격리 보관"));
    assert_eq!(std::fs::read(&qpath).unwrap(), bad, "격리본은 원본 그대로");
    assert!(qpath.extension().unwrap() == "bin");
    assert!(qpath.with_extension("json").exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&qpath).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    let clean = common::clean_pdf();
    let r2 = engine.process(&clean, "ok.pdf");
    let rec2 = auditor
        .record(&r2, &clean, "/inbox/ok.pdf", &engine.policy, Duration::ZERO)
        .unwrap();
    assert_eq!(rec2.status, Status::Clean);
    assert!(
        rec2.quarantine.is_none(),
        "정상 파일은 기본적으로 보관하지 않음"
    );

    let blocked = b"MZ\x90\x00 not a document".to_vec();
    let r3 = engine.process(&blocked, "a.exe");
    let rec3 = auditor
        .record(
            &r3,
            &blocked,
            "/inbox/a.exe",
            &engine.policy,
            Duration::ZERO,
        )
        .unwrap();
    assert!(rec3.quarantine.is_some(), "차단 파일은 격리 보관");

    let lines: Vec<serde_json::Value> = std::fs::read_to_string(&log)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0]["status"], "sanitized");
    assert_eq!(lines[0]["source"], "/inbox/보고서.docm");
    assert_eq!(lines[0]["max_severity"], "critical");
    assert!(lines[0]["categories"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c == "macro"));
    assert_eq!(lines[0]["input_sha256"], r.input_sha256);
    assert!(lines[0]["ts"].as_str().unwrap().ends_with('Z'));
    assert_eq!(lines[1]["status"], "clean");
    assert_eq!(lines[2]["status"], "blocked");
    assert_eq!(lines[2]["policy"]["strip_metadata"], true);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn server_writes_audit_and_returns_event_id() {
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    let dir = temp_dir("server");
    let log = dir.join("audit.jsonl");
    let auditor = Auditor::open(&AuditConfig {
        log_path: Some(log.clone()),
        quarantine_dir: Some(dir.join("q")),
        quarantine_clean: false,
    })
    .unwrap();
    let app = cdr::server::router(
        cdr::server::AppState::new(Policy::default(), 2, Duration::from_secs(60))
            .with_auditor(auditor),
    );

    let boundary = "b0undary";
    let mut body = format!("--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.docm\"\r\n\r\n").into_bytes();
    body.extend(common::malicious_docm());
    body.extend(format!("\r\n--{boundary}--\r\n").into_bytes());
    let req = Request::post("/api/v1/sanitize")
        .header(
            "content-type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), 200);
    let id = res.headers()["x-cdr-event-id"]
        .to_str()
        .unwrap()
        .to_string();
    let _ = res.into_body().collect().await.unwrap();

    let line: serde_json::Value = serde_json::from_str(
        std::fs::read_to_string(&log)
            .unwrap()
            .lines()
            .next()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(line["event_id"], id);
    assert_eq!(line["source"], "api");
    assert!(line["quarantine"].as_str().is_some());
    let _ = std::fs::remove_dir_all(&dir);
}
