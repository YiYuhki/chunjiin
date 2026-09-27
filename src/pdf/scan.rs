//! 원본 PDF 분석: 재조합 과정에서 새 문서에 포함되지 않는 위험 요소를 보고한다.
//! (재조합은 허용 목록 방식이므로 이 분석 결과와 무관하게 안전성이 보장된다.)

use std::collections::BTreeMap;

use lopdf::{Document, Object};

use crate::detect::{find, rfind};
use crate::policy::Policy;
use crate::report::{Findings, Severity};

pub fn report_threats(data: &[u8], doc: &Document, policy: &Policy, findings: &mut Findings) {
    let mut notes: BTreeMap<(&'static str, Severity, String), u32> = BTreeMap::new();
    let mut note = |cat: &'static str, sev: Severity, desc: String| {
        *notes.entry((cat, sev, desc)).or_default() += 1;
    };

    // 파일 구조
    if let Some(pos) = find(&data[..data.len().min(1024)], b"%PDF-") {
        if pos > 0 {
            note(
                "polyglot",
                Severity::Medium,
                format!("PDF 헤더 앞 {pos} bytes 데이터"),
            );
        }
    }
    if let Some(eof) = rfind(data, b"%%EOF") {
        let tail = &data[eof + 5..];
        let trailing = tail
            .iter()
            .filter(|b| !b.is_ascii_whitespace() && **b != 0)
            .count();
        if trailing > 0 {
            note(
                "hidden-data",
                Severity::Medium,
                format!("%%EOF 이후 덧붙은 데이터 {} bytes", tail.len()),
            );
        }
    }
    let eofs = data.windows(5).filter(|w| *w == b"%%EOF").count();
    if eofs > 1 {
        note(
            "incremental-update",
            Severity::Info,
            format!("증분 업데이트 {}회(이전 버전 데이터 잔존 가능)", eofs - 1),
        );
    }

    if let Ok(catalog) = doc.catalog() {
        if catalog.has(b"OpenAction") {
            note(
                "auto-exec",
                Severity::Medium,
                "문서 열기 동작(OpenAction)".into(),
            );
        }
        if catalog.has(b"AA") {
            note("auto-exec", Severity::High, "문서 추가 액션(/AA)".into());
        }
        if catalog.has(b"AcroForm") {
            note(
                "form",
                Severity::Info,
                "대화형 폼 필드(AcroForm, 외형은 본문에 평면화하여 보존)".into(),
            );
        }
        if catalog.has(b"Collection") {
            note("embedded-file", Severity::Medium, "PDF 포트폴리오".into());
        }
        let has_info = doc
            .trailer
            .get(b"Info")
            .ok()
            .map(|o| deref(doc, o))
            .and_then(|o| o.as_dict().ok())
            .is_some_and(|d| !d.is_empty());
        if has_info && policy.strip_metadata {
            note("metadata", Severity::Info, "문서 정보(작성자 등)".into());
        }
        if catalog.has(b"Metadata") && policy.strip_metadata {
            note("metadata", Severity::Info, "XMP 메타데이터".into());
        }
        if let Ok(names) = catalog.get(b"Names").and_then(|o| deref(doc, o).as_dict()) {
            if names.has(b"JavaScript") {
                note(
                    "javascript",
                    Severity::Critical,
                    "문서 수준 JavaScript".into(),
                );
            }
            if names.has(b"EmbeddedFiles") {
                note(
                    "embedded-file",
                    Severity::High,
                    "첨부 파일(EmbeddedFiles)".into(),
                );
            }
        }
        if let Ok(form) = catalog
            .get(b"AcroForm")
            .and_then(|o| deref(doc, o).as_dict())
        {
            if form.has(b"XFA") {
                note("xfa", Severity::High, "XFA 폼(스크립트 실행 가능)".into());
            }
        }
    }

    // 간접 객체와 그 안에 중첩된 직접 사전까지 모두 검사한다
    let mut stack: Vec<(&Object, usize)> = doc.objects.values().map(|o| (o, 0)).collect();
    while let Some((obj, depth)) = stack.pop() {
        let dict = match obj {
            Object::Dictionary(d) => d,
            Object::Stream(s) => &s.dict,
            Object::Array(a) if depth < 32 => {
                stack.extend(a.iter().map(|o| (o, depth + 1)));
                continue;
            }
            _ => continue,
        };
        if depth < 32 {
            stack.extend(dict.iter().map(|(_, v)| (v, depth + 1)));
        }
        if dict.has(b"JS") {
            note("javascript", Severity::Critical, "JavaScript 코드".into());
        }
        if dict.has(b"AA") && !dict.has(b"Pages") {
            note(
                "auto-exec",
                Severity::High,
                "추가 액션(/AA, 이벤트 트리거)".into(),
            );
        }
        match dict.get(b"S").and_then(Object::as_name).unwrap_or(b"") {
            b"JavaScript" => note("javascript", Severity::Critical, "JavaScript 액션".into()),
            b"Launch" => note(
                "launch",
                Severity::Critical,
                "외부 프로그램 실행(Launch) 액션".into(),
            ),
            b"SubmitForm" => note(
                "data-exfiltration",
                Severity::High,
                "폼 데이터 전송(SubmitForm) 액션".into(),
            ),
            b"ImportData" => note(
                "external-resource",
                Severity::High,
                "외부 데이터 가져오기(ImportData) 액션".into(),
            ),
            b"GoToR" | b"GoToE" => note(
                "external-resource",
                Severity::Medium,
                "외부/임베디드 문서 이동 액션".into(),
            ),
            b"RichMediaExecute" | b"Rendition" | b"Movie" | b"Sound" => {
                note("rich-media", Severity::High, "멀티미디어 실행 액션".into())
            }
            b"URI" => {
                let uri = dict
                    .get(b"URI")
                    .ok()
                    .map(|o| deref(doc, o))
                    .and_then(|o| o.as_str().ok())
                    .unwrap_or(b"");
                let uri = String::from_utf8_lossy(uri);
                if !policy.uri_allowed(&uri) {
                    note(
                        "dangerous-link",
                        Severity::High,
                        format!(
                            "허용되지 않은 URI: {}",
                            uri.chars().take(120).collect::<String>()
                        ),
                    );
                } else if policy.remove_hyperlinks {
                    note(
                        "hyperlink",
                        Severity::Low,
                        "하이퍼링크(정책에 따라 제외)".into(),
                    );
                }
            }
            _ => {}
        }
        if dict.get(b"Type").and_then(Object::as_name).ok() == Some(b"EmbeddedFile") {
            note(
                "embedded-file",
                Severity::High,
                "임베디드 파일 스트림".into(),
            );
        }
        match dict
            .get(b"Subtype")
            .and_then(Object::as_name)
            .unwrap_or(b"")
        {
            b"FileAttachment" => note("embedded-file", Severity::High, "파일 첨부 주석".into()),
            b"RichMedia" | b"Screen" | b"Movie" | b"Sound" | b"3D" => {
                note("rich-media", Severity::Medium, "멀티미디어/3D 주석".into())
            }
            _ => {}
        }
    }

    for ((cat, sev, desc), n) in notes {
        let desc = if n > 1 {
            format!("{desc} ({n}건)")
        } else {
            desc
        };
        findings.add(cat, sev, format!("{desc} - 새 문서에 포함하지 않음"), "");
    }
    findings.count("source_objects", doc.objects.len() as u64);
}

fn deref<'a>(doc: &'a Document, o: &'a Object) -> &'a Object {
    match o {
        Object::Reference(id) => doc.get_object(*id).unwrap_or(o),
        _ => o,
    }
}
