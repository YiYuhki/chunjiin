//! 전자우편(EML) 재조합

mod common;

use base64::Engine as _;
use cdr::{Engine, Status};
use common::*;
use mail_parser::{MessageParser, MimeHeaders};

fn b64(d: &[u8]) -> String {
    let s = base64::engine::general_purpose::STANDARD.encode(d);
    s.as_bytes()
        .chunks(76)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("\r\n")
}

fn malicious_mail() -> Vec<u8> {
    let html = r#"<html><head><script>steal()</script><style>body{}</style></head><body onload="x()">
<p onclick="evil()">안녕하세요 <b>본문</b></p>
<img src="http://tracker.example/pixel.gif?id=1"><img src="cid:logo@x">
<a href="javascript:alert(1)">나쁜링크</a> <a href="https://example.com/">좋은링크</a>
<form action="http://evil/"><input name=p></form><iframe src="http://evil/"></iframe>
<div style="background:url(http://evil/bg.png)">배경</div><div style="color:red">빨강</div>
</body></html>"#;
    let subject = format!(
        "=?UTF-8?B?{}?=",
        base64::engine::general_purpose::STANDARD.encode("분기 보고서")
    );
    let mut m = String::new();
    m.push_str("Received: from evil.example (1.2.3.4)\r\n");
    m.push_str("From: 홍길동 <hong@example.com>\r\nTo: kim@example.com\r\n");
    m.push_str(&format!("Subject: {subject}\r\n"));
    m.push_str("Date: Sat, 26 Sep 2026 10:00:00 +0900\r\nMessage-ID: <abc@example.com>\r\n");
    m.push_str("X-Mailer: EvilMailer\r\nX-Originating-IP: 10.0.0.1\r\nMIME-Version: 1.0\r\n");
    m.push_str("Content-Type: multipart/mixed; boundary=\"MIX\"\r\n\r\n");
    m.push_str("--MIX\r\nContent-Type: multipart/related; boundary=\"REL\"\r\n\r\n");
    m.push_str("--REL\r\nContent-Type: multipart/alternative; boundary=\"ALT\"\r\n\r\n");
    m.push_str("--ALT\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n");
    m.push_str("안녕하세요\u{202E}fdp.exe 본문\r\n");
    m.push_str("--ALT\r\nContent-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n");
    m.push_str(&b64(html.as_bytes()));
    m.push_str("\r\n--ALT--\r\n");
    m.push_str("--REL\r\nContent-Type: image/png\r\nContent-ID: <logo@x>\r\nContent-Disposition: inline; filename=\"logo.png\"\r\nContent-Transfer-Encoding: base64\r\n\r\n");
    m.push_str(&b64(&png_with_payload()));
    m.push_str("\r\n--REL--\r\n");
    for (name, ct, data) in [
        (
            "보고서.docm",
            "application/vnd.ms-word.document.macroEnabled.12",
            malicious_docm(),
        ),
        (
            "setup.exe",
            "application/octet-stream",
            b"MZ\x90\x00 evil".to_vec(),
        ),
        ("report.pdf", "application/pdf", clean_pdf()),
    ] {
        let enc: String = name.bytes().map(|b| format!("%{b:02X}")).collect();
        m.push_str(&format!(
            "--MIX\r\nContent-Type: {ct}\r\nContent-Disposition: attachment; filename*=UTF-8''{enc}\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n",
            b64(&data)
        ));
    }
    m.push_str("--MIX--\r\n");
    m.into_bytes()
}

#[test]
fn mail_is_reassembled() {
    let r = Engine::default().process(&malicious_mail(), "받은메일.eml");
    assert_eq!(
        r.status,
        Status::Sanitized,
        "{} {:#?}",
        r.reason,
        r.findings
    );
    assert_eq!(r.output_filename.as_deref(), Some("받은메일.eml"));
    let cats: Vec<&str> = r.findings.iter().map(|f| f.category.as_str()).collect();
    for want in [
        "active-content",
        "external-resource",
        "archive-member",
        "macro",
        "text-spoofing",
    ] {
        assert!(cats.contains(&want), "{want}: {cats:?}");
    }
    assert!(r
        .findings
        .iter()
        .any(|f| f.location.starts_with("첨부:보고서.docm")));

    let out = r.output.clone().unwrap();
    let raw = String::from_utf8_lossy(&out);
    for gone in ["X-Mailer", "X-Originating-IP", "Received", "EvilMailer"] {
        assert!(!raw.contains(gone), "{gone}");
    }
    let msg = MessageParser::default()
        .parse(&out)
        .expect("재조합된 메일 해석");
    assert_eq!(msg.subject(), Some("분기 보고서"));
    assert_eq!(
        msg.from().unwrap().first().unwrap().address(),
        Some("hong@example.com")
    );

    let text = msg.body_text(0).unwrap();
    assert!(text.contains("안녕하세요fdp.exe 본문"), "{text}");
    assert!(text.contains("setup.exe"), "제거 안내: {text}");
    let html = msg.body_html(0).unwrap();
    for gone in [
        "<script",
        "steal()",
        "onload",
        "onclick",
        "tracker.example",
        "javascript:",
        "<form",
        "<iframe",
        "url(",
    ] {
        assert!(!html.contains(gone), "{gone}: {html}");
    }
    for kept in [
        "본문",
        "https://example.com/",
        "cid:logo@x",
        "color:red",
        "좋은링크",
    ] {
        assert!(html.contains(kept), "{kept}: {html}");
    }

    let names: Vec<String> = msg
        .attachments()
        .filter_map(|a| a.attachment_name().map(str::to_string))
        .collect();
    assert!(names.contains(&"보고서.docx".to_string()), "{names:?}");
    assert!(names.contains(&"report.pdf".to_string()), "{names:?}");
    assert!(!names.iter().any(|n| n.contains("setup")), "{names:?}");
    // 인라인 이미지는 재인코딩되어 Content-ID 로 남는다
    let logo = msg
        .attachments()
        .find(|a| a.content_id() == Some("logo@x"))
        .expect("인라인 이미지");
    assert!(!logo.contents().windows(5).any(|w| w == b"<?php"));
    image::load_from_memory(logo.contents()).unwrap();

    // 다시 넣으면 더 제거할 것이 없다
    let again = Engine::default().process(&out, "받은메일.eml");
    assert_ne!(again.status, Status::Blocked, "{}", again.reason);
    assert!(
        again
            .findings
            .iter()
            .all(|f| f.severity < cdr::report::Severity::Medium),
        "{:#?}",
        again.findings
    );
}

#[test]
fn mail_detection_needs_eml_extension_and_headers() {
    let e = Engine::default();
    assert_eq!(
        e.process(b"From: a@b\r\nSubject: x\r\n\r\nhello", "a.eml")
            .detected_type,
        "eml"
    );
    // 메일 헤더가 없는 .eml 은 차단
    assert_eq!(e.process(b"just text", "a.eml").status, Status::Blocked);
}
