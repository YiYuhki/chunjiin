mod common;

use cdr::{Engine, Status};
use common::msg::{malicious_msg, rtf_bomb_msg, rtf_html_msg};
use mail_parser::MimeHeaders;

fn parse(eml: &[u8]) -> mail_parser::Message<'_> {
    mail_parser::MessageParser::default().parse(eml).unwrap()
}

#[test]
fn msg_is_rebuilt_as_eml() {
    let r = Engine::default().process(&malicious_msg(), "보고서.msg");
    assert_eq!(
        r.status,
        Status::Sanitized,
        "{} {:#?}",
        r.reason,
        r.findings
    );
    assert_eq!(r.output_filename.as_deref(), Some("보고서.eml"));
    let out = r.output.clone().unwrap();
    let text = String::from_utf8_lossy(&out);
    for bad in [
        "<script",
        "onload",
        "javascript",
        "evil.example",
        "refresh",
        "Bcc:",
        "hidden@example.com",
        "MZ\u{90}",
        "calc.exe",
        "iframe",
        "\u{202E}",
    ] {
        assert!(!text.contains(bad), "{bad} 가 남아 있음:\n{text}");
    }
    let m = parse(&out);
    assert_eq!(m.subject(), Some("분기 보고서 Bcc: victim@evil.example"));
    let from = m.from().unwrap().first().unwrap();
    assert_eq!(from.name(), Some("김철수"));
    assert_eq!(from.address(), Some("kim@example.com"));
    let to = m.to().unwrap().first().unwrap();
    assert_eq!(to.address(), Some("lee@example.com"));
    assert_eq!(to.name(), Some("Lee, Younghee"));
    // 주소가 없는 Exchange 내부 수신자는 이름만 남는다
    assert!(text.contains("Cc: =?UTF-8?B?"), "{text}");
    assert!(m
        .date()
        .unwrap()
        .to_rfc3339()
        .starts_with("2024-01-02T03:04:05"));
    assert!(m.body_text(0).unwrap().contains("본문입니다."));
    let html = m.body_html(0).unwrap();
    assert!(
        html.contains("본문입니다.") && html.contains("cid:logo@x"),
        "{html}"
    );

    // 첨부: 그림(재인코딩, 본문 안), 내장 메시지(.eml, 정제됨). 실행 파일·참조·OLE 는 빠지고 안내가 붙는다
    let names: Vec<String> = m
        .attachments()
        .map(|a| a.attachment_name().unwrap_or("").to_string())
        .collect();
    assert!(names.contains(&"logo.png".to_string()), "{names:?}");
    assert!(names.contains(&"전달된 메일.eml".to_string()), "{names:?}");
    assert_eq!(names.len(), 2, "{names:?}");
    let logo = m
        .attachments()
        .find(|a| a.attachment_name() == Some("logo.png"))
        .unwrap();
    assert!(!logo.contents().windows(5).any(|w| w == b"<?php"));
    image::load_from_memory(logo.contents()).unwrap();
    let body = m.body_text(0).unwrap();
    for n in ["invoice.exe", "payload.lnk", "Package.bin"] {
        assert!(body.contains(n), "제거 안내에 {n} 없음: {body}");
    }
    let inner = m
        .attachments()
        .find(|a| a.attachment_name() == Some("전달된 메일.eml"))
        .unwrap();
    let inner = String::from_utf8_lossy(inner.contents());
    assert!(
        inner.contains("park@example.com") && !inner.contains("script"),
        "{inner}"
    );

    let cats: Vec<&str> = r.findings.iter().map(|f| f.category.as_str()).collect();
    for c in [
        "active-content",
        "external-resource",
        "ole",
        "archive-member",
        "format-conversion",
    ] {
        assert!(cats.contains(&c), "{c} 없음: {cats:?}");
    }

    // 결과물(.eml)은 다시 넣어도 그대로
    let again = Engine::default().process(&out, "보고서.eml");
    assert_eq!(again.status, Status::Clean, "{:#?}", again.findings);
    assert_eq!(again.output.as_deref(), Some(out.as_slice()), "고정점");
}

#[test]
fn rtf_encapsulated_html_body() {
    let r = Engine::default().process(&rtf_html_msg(), "a.msg");
    assert_eq!(
        r.status,
        Status::Sanitized,
        "{} {:#?}",
        r.reason,
        r.findings
    );
    let out = r.output.unwrap();
    let m = parse(&out);
    assert_eq!(m.subject(), Some("RTF 본문"));
    let html = m.body_html(0).unwrap();
    assert!(
        html.contains("한글 본문") && !html.contains("script"),
        "{html}"
    );
}

#[test]
fn msg_inside_zip_and_disguised() {
    // 확장자를 바꾼 .msg 도 내용으로 판별한다
    let r = Engine::default().process(&malicious_msg(), "문서.doc");
    assert_eq!(r.status, Status::Sanitized, "{}", r.reason);
    assert_eq!(r.output_filename.as_deref(), Some("문서.eml"));
    // 압축 파일 안의 .msg 도 .eml 로 바뀐다
    let zip = common::make_zip(&[("mail/a.msg", &malicious_msg())]);
    let r = Engine::default().process(&zip, "a.zip");
    assert_eq!(r.status, Status::Sanitized, "{}", r.reason);
    let files = common::unzip(r.output.as_ref().unwrap());
    assert!(
        files.iter().any(|(n, _)| n == "mail/a.eml"),
        "{:?}",
        files.iter().map(|f| &f.0).collect::<Vec<_>>()
    );
}

#[test]
fn compressed_rtf_bomb_is_blocked() {
    // 3MB 가 약 25MB 로 풀린다 (예산: 파일 크기의 2배 + 16MB)
    let r = Engine::default().process(&rtf_bomb_msg(3 << 20), "a.msg");
    assert_eq!(r.status, Status::Blocked, "{:#?}", r.findings);
    assert!(r.reason.contains("총량"), "{}", r.reason);
    // 작은 메시지의 압축 RTF 는 여유분 안에서 풀린다
    let r = Engine::default().process(&rtf_bomb_msg(64 << 10), "a.msg");
    assert_ne!(r.status, Status::Blocked, "{}", r.reason);
}
