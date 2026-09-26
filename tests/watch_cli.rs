mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use cdr::audit::{AuditConfig, Auditor};
use cdr::watch::{Event, WatchConfig, Watcher};
use cdr::Engine;

fn temp_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("cdr-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn files_under(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d).unwrap().flatten() {
            if e.file_type().unwrap().is_dir() {
                stack.push(e.path());
            } else {
                out.push(
                    e.path()
                        .strip_prefix(root)
                        .unwrap()
                        .to_string_lossy()
                        .to_string(),
                );
            }
        }
    }
    out.sort();
    out
}

#[test]
fn watcher_waits_for_stable_files_and_moves_results() {
    let dir = temp_dir("watch");
    let (inbox, outbox, blocked) = (dir.join("in"), dir.join("out"), dir.join("blocked"));
    fs::create_dir_all(inbox.join("부서/팀")).unwrap();
    fs::write(inbox.join("부서/팀/보고서.docm"), common::malicious_docm()).unwrap();
    fs::write(inbox.join("ok.pdf"), common::clean_pdf()).unwrap();
    fs::write(inbox.join("setup.exe"), b"MZ\x90\x00 payload").unwrap();
    fs::write(inbox.join("copying.docx.part"), b"partial").unwrap();
    fs::write(inbox.join(".hidden.pdf"), common::clean_pdf()).unwrap();

    let engine = Engine::default();
    let auditor = Auditor::open(&AuditConfig {
        log_path: Some(dir.join("audit.jsonl")),
        quarantine_dir: Some(dir.join("q")),
        quarantine_clean: false,
    })
    .unwrap();
    let cfg = WatchConfig {
        inbox: inbox.clone(),
        outbox: outbox.clone(),
        blocked: Some(blocked.clone()),
        interval: Duration::from_millis(10),
        settle: Duration::ZERO,
        jobs: 4,
        once: false,
    };
    let mut w = Watcher::new(cfg, &engine, &auditor).unwrap();
    let noop = |_: Event| {};

    // 첫 주기에는 처음 본 파일이라 처리하지 않는다 (안정화 확인)
    assert_eq!(w.cycle(&noop), 0);
    assert_eq!(w.cycle(&noop), 3);

    assert_eq!(files_under(&outbox), vec!["ok.pdf", "부서/팀/보고서.docx"]);
    assert_eq!(files_under(&blocked), vec!["setup.exe.blocked.json"]);
    // 처리된 원본은 수신 폴더에서 지워지고, 빈 하위 폴더도 정리된다. 쓰는 중/숨김 파일은 그대로
    assert_eq!(
        files_under(&inbox),
        vec![".hidden.pdf", "copying.docx.part"]
    );
    let log = fs::read_to_string(dir.join("audit.jsonl")).unwrap();
    assert_eq!(log.lines().count(), 3);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn watcher_rejects_nested_folders() {
    let dir = temp_dir("watch-nested");
    let engine = Engine::default();
    let auditor = Auditor::disabled();
    let cfg = WatchConfig {
        inbox: dir.clone(),
        outbox: dir.join("out"),
        blocked: None,
        interval: Duration::from_secs(1),
        settle: Duration::ZERO,
        jobs: 1,
        once: true,
    };
    assert!(
        Watcher::new(cfg, &engine, &auditor).is_err(),
        "송신 폴더가 수신 폴더 안에 있으면 무한 재처리 위험"
    );
    let _ = fs::remove_dir_all(&dir);
}

fn cdr() -> Command {
    Command::new(env!("CARGO_BIN_EXE_cdr"))
}

#[test]
fn cli_policy_file_and_parallel_sanitize() {
    let dir = temp_dir("cli");
    let inbox = dir.join("in");
    fs::create_dir_all(&inbox).unwrap();
    for i in 0..6 {
        fs::write(inbox.join(format!("doc{i}.docm")), common::malicious_docm()).unwrap();
    }
    fs::write(inbox.join("a.pdf"), common::malicious_pdf()).unwrap();

    // 기본 정책 파일은 그대로 다시 읽을 수 있어야 한다
    let tmpl = cdr().arg("policy").output().unwrap();
    assert!(tmpl.status.success());
    let text = String::from_utf8(tmpl.stdout).unwrap();
    assert!(text.contains("[links]"));

    // 정책 파일: 링크 제거 + 래스터화
    let cfg = dir.join("cdr.toml");
    fs::write(
        &cfg,
        "[links]\nremove_hyperlinks = true\n[pdf]\nrasterize = true\nraster_dpi = 72\n",
    )
    .unwrap();
    let report = dir.join("report.json");
    let out = cdr()
        .args([
            "sanitize",
            inbox.to_str().unwrap(),
            "-o",
            dir.join("out").to_str().unwrap(),
            "--jobs",
            "4",
            "--config",
            cfg.to_str().unwrap(),
            "--report",
            report.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let results: Vec<serde_json::Value> =
        serde_json::from_str(&fs::read_to_string(&report).unwrap()).unwrap();
    assert_eq!(results.len(), 7);
    assert_eq!(results[0]["filename"], "a.pdf", "보고서는 입력 순서대로");
    assert!(
        results[0]["stats"]["pages_rasterized"].as_u64().is_some(),
        "정책 파일의 래스터화 적용"
    );
    assert!(
        results[1]["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["category"] == "hyperlink"),
        "정책 파일의 링크 제거 적용"
    );
    assert_eq!(files_under(&dir.join("out")).len(), 7);

    // 오타가 있는 정책 파일은 거부
    fs::write(&cfg, "[links]\nremove_hyperlink = true\n").unwrap();
    let bad = cdr()
        .args([
            "scan",
            inbox.to_str().unwrap(),
            "--config",
            cfg.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&bad.stderr).contains("정책 파일"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn cli_watch_once() {
    let dir = temp_dir("cli-watch");
    let inbox = dir.join("in");
    fs::create_dir_all(&inbox).unwrap();
    fs::write(inbox.join("x.xlsm"), common::malicious_xlsm()).unwrap();
    let out = cdr()
        .args([
            "watch",
            "--inbox",
            inbox.to_str().unwrap(),
            "--outbox",
            dir.join("out").to_str().unwrap(),
            "--once",
            "--quarantine",
            dir.join("q").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("[재조합] x.xlsm"));
    assert_eq!(files_under(&dir.join("out")), vec!["x.xlsx"]);
    assert!(files_under(&inbox).is_empty());
    assert_eq!(
        files_under(&dir.join("q")).len(),
        2,
        "원본(.bin)과 보고서(.json) 격리"
    );
    let _ = fs::remove_dir_all(&dir);
}
