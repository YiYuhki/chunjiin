//! PowerPoint 97-2003(.ppt) 재조합.
//!
//! - 새 OLE 복합 파일에 PowerPoint Document, Current User, Pictures, CompObj 만 조립한다.
//! - PowerPoint Document 의 레코드 트리를 순회한다.
//!   - 차단: 암호화(CryptSession10Container), 임베디드 OLE/VBA 저장소(ExOleObjStg),
//!     ActiveX(ExControl) — 영구 객체 디렉터리 오프셋과 얽혀 있어 안전하게 떼어낼 수 없음
//!   - 제자리 무력화(길이 불변): 매크로·프로그램 실행·OLE 동작(InteractiveInfoAtom)을
//!     "동작 없음"으로, 허용되지 않은 하이퍼링크 대상 문자열을 공백으로 바꾸고 해당 링크 동작을 끈다.

use std::collections::HashSet;

use super::cfbx::{self, utf16le, Node};
use crate::error::{blocked, Result};
use crate::ooxml::content::truncate;
use crate::policy::Policy;
use crate::report::{Findings, Severity};

const RT_EX_OLE_OBJ_STG: u16 = 0x1011;
const RT_EX_CONTROL: u16 = 0x0FEE;
const RT_VBA_INFO_ATOM: u16 = 0x0400;
const RT_CRYPT_SESSION: u16 = 0x2F14;
const RT_INTERACTIVE_INFO_ATOM: u16 = 0x0FF3;
const RT_EX_HYPERLINK: u16 = 0x0FD7;
const RT_EX_HYPERLINK_ATOM: u16 = 0x0FD3;
const RT_CSTRING: u16 = 0x0FBA;

struct Rec {
    ver: u16,
    instance: u16,
    rtype: u16,
    body: usize,
    len: usize,
}

fn header(d: &[u8], at: usize) -> Option<Rec> {
    let vi = u16::from_le_bytes(d.get(at..at + 2)?.try_into().ok()?);
    let rtype = u16::from_le_bytes(d.get(at + 2..at + 4)?.try_into().ok()?);
    let len = u32::from_le_bytes(d.get(at + 4..at + 8)?.try_into().ok()?) as usize;
    let body = at + 8;
    d.get(body..body.checked_add(len)?)?;
    Some(Rec {
        ver: vi & 0xF,
        instance: vi >> 4,
        rtype,
        body,
        len,
    })
}

/// 레코드 트리를 방문한다 (깊이 제한). 레코드처럼 표시되었지만 내용이 레코드가 아닌
/// 컨테이너(PowerPoint 2007 라운드트립 데이터 등)를 만나면 그 컨테이너는 건너뛴다.
/// 보안 판정은 이 순회에 의존하지 않고 [`find_headers`] 전수 검색으로 한다.
/// 반환값: 방문한 레코드 수
fn walk(
    d: &[u8],
    start: usize,
    end: usize,
    depth: usize,
    f: &mut dyn FnMut(&Rec) -> bool,
) -> usize {
    if depth > 32 {
        return 0;
    }
    let mut pos = start;
    let mut n = 0;
    while pos + 8 <= end {
        let Some(r) = header(d, pos).filter(|r| r.body + r.len <= end) else {
            break;
        };
        n += 1;
        if !f(&r) {
            return n;
        }
        if r.ver == 0xF {
            n += walk(d, r.body, r.body + r.len, depth + 1, f);
        }
        pos = r.body + r.len;
    }
    n
}

/// 스트림 전체에서 지정한 레코드 헤더(형식, 버전) 모양을 모두 찾는다.
/// 비정상 컨테이너 속에 숨겨 트리 순회를 피하는 경우까지 잡기 위한 전수 검색이다.
fn find_headers(d: &[u8], rtype: u16, ver: Option<u16>) -> Vec<Rec> {
    let pat = rtype.to_le_bytes();
    let mut out = Vec::new();
    let mut p = 0;
    while p + 8 <= d.len() {
        if d[p + 2] == pat[0] && d[p + 3] == pat[1] {
            if let Some(r) = header(d, p) {
                if ver.is_none_or(|v| r.ver == v) {
                    out.push(r);
                }
            }
        }
        p += 1;
    }
    out
}

pub fn reassemble(data: &[u8], policy: &Policy, findings: &mut Findings) -> Result<Vec<u8>> {
    let c = cfbx::read(data, policy)?;
    findings.count("input_parts", c.nodes.len() as u64);
    let Some(src) = c.stream("PowerPoint Document") else {
        return blocked("structure", "PowerPoint Document 스트림 없음");
    };
    if c.stream("Current User").is_none() {
        return blocked("structure", "Current User 스트림 없음");
    }
    if c.has("PP97_DUALSTORAGE") || c.has("Header") {
        return blocked(
            "structure",
            "PowerPoint 95 (또는 95/97 이중 저장) 형식은 지원하지 않아 차단합니다",
        );
    }
    if c.has("EncryptedSummary") {
        return blocked(
            "encrypted",
            "암호화된 PowerPoint 문서는 검사할 수 없어 차단합니다",
        );
    }
    let mut doc = src.to_vec();

    // 1차: 위험 요소 판별 (전수 검색)
    if !find_headers(&doc, RT_CRYPT_SESSION, Some(0xF)).is_empty() {
        return blocked(
            "encrypted",
            "암호화된 PowerPoint 문서는 검사할 수 없어 차단합니다",
        );
    }
    // ExOleObjStg: instance 0 = 비압축(본문이 OLE 복합 파일), 1 = 압축(4바이트 원본 크기 + zlib)
    let is_ole_storage = |r: &Rec| {
        r.ver == 0
            && match r.instance {
                0 => doc.get(r.body..r.body + 8) == Some(crate::detect::OLE_MAGIC),
                1 => r.len > 6 && doc[r.body + 4] == 0x78,
                _ => false,
            }
    };
    if find_headers(&doc, RT_EX_OLE_OBJ_STG, None)
        .iter()
        .any(is_ole_storage)
    {
        return blocked(
            "embedded-object",
            "임베디드 OLE 개체/VBA 저장소가 포함된 PPT 는 안전하게 재조합할 수 없어 차단합니다",
        );
    }
    if !find_headers(&doc, RT_EX_CONTROL, Some(0xF)).is_empty() {
        return blocked(
            "activex",
            "ActiveX 컨트롤이 포함된 PPT 는 안전하게 재조합할 수 없어 차단합니다",
        );
    }
    // VBAInfoContainer 는 대부분 문서에 있으며, 실제 매크로 유무는 원자 레코드의 fHasMacros 로 판단
    if find_headers(&doc, RT_VBA_INFO_ATOM, None)
        .iter()
        .any(|r| r.len >= 8 && doc[r.body + 4..r.body + 8] == [1, 0, 0, 0])
    {
        return blocked(
            "macro",
            "VBA 매크로가 포함된 PPT 는 안전하게 재조합할 수 없어 차단합니다",
        );
    }

    // 하이퍼링크 대상 수집 (트리 순회)
    let mut bad_links: HashSet<u32> = HashSet::new();
    let mut bad_strings: Vec<(usize, usize, String)> = Vec::new();
    let d = &doc;
    let records = walk(d, 0, d.len(), 0, &mut |r| {
        if r.rtype == RT_EX_HYPERLINK && r.ver == 0xF {
            let mut id = None;
            let mut target = None;
            walk(d, r.body, r.body + r.len, 1, &mut |c| {
                if c.rtype == RT_EX_HYPERLINK_ATOM && c.len >= 4 {
                    id = Some(u32::from_le_bytes(
                        d[c.body..c.body + 4].try_into().unwrap(),
                    ));
                }
                if c.rtype == RT_CSTRING && c.instance == 1 {
                    target = Some((c.body, c.len, utf16le(&d[c.body..c.body + c.len])));
                }
                true
            });
            if let (Some(id), Some((at, len, url))) = (id, target) {
                let internal = url.trim().is_empty() || url.starts_with('#');
                if !internal && (!policy.uri_allowed(&url) || policy.remove_hyperlinks) {
                    bad_links.insert(id);
                    bad_strings.push((at, len, url));
                }
            }
        }
        true
    });
    if records == 0 {
        return blocked("structure", "PowerPoint 레코드 구조 해석 실패");
    }
    findings.count("records", records as u64);

    // 2차: 제자리 무력화
    for (at, len, url) in &bad_strings {
        for b in doc[*at..*at + *len].chunks_exact_mut(2) {
            b.copy_from_slice(&[0x20, 0]);
        }
        let (cat, sev) = if policy.uri_allowed(url) {
            ("hyperlink", Severity::Low)
        } else {
            ("dangerous-link", Severity::High)
        };
        findings.add(
            cat,
            sev,
            format!("하이퍼링크 대상 제거: {}", truncate(url, 120)),
            "PowerPoint Document",
        );
    }
    let mut actions: Vec<(usize, u8)> = Vec::new();
    for r in find_headers(&doc, RT_INTERACTIVE_INFO_ATOM, Some(0)) {
        if r.len == 16 {
            let link = u32::from_le_bytes(doc[r.body + 4..r.body + 8].try_into().unwrap());
            let action = doc[r.body + 8];
            if matches!(action, 1 | 2 | 5) || (action == 4 && bad_links.contains(&link)) {
                actions.push((r.body + 8, action));
            }
        }
    }
    for (at, action) in actions {
        doc[at] = 0;
        let desc = match action {
            1 => "매크로 실행 동작",
            2 => "프로그램 실행 동작",
            5 => "OLE 개체 동작",
            _ => "하이퍼링크 동작",
        };
        let (cat, sev) = if action == 4 {
            ("dangerous-link", Severity::Info)
        } else {
            ("auto-exec", Severity::High)
        };
        findings.add(cat, sev, format!("{desc} 제거"), "PowerPoint Document");
    }

    // 새 컨테이너 조립
    let mut out = vec![Node {
        path: "PowerPoint Document".into(),
        is_storage: false,
        clsid: [0; 16],
        data: doc,
    }];
    for keep in ["Current User", "Pictures", "\u{1}CompObj"] {
        if let Some(d) = c.stream(keep) {
            out.push(Node {
                path: keep.into(),
                is_storage: false,
                clsid: [0; 16],
                data: d.to_vec(),
            });
        }
    }
    let summaries = ["\u{5}SummaryInformation", "\u{5}DocumentSummaryInformation"];
    for s in summaries {
        if let Some(d) = c.stream(s) {
            if policy.strip_metadata {
                findings.add(
                    "metadata",
                    Severity::Info,
                    "문서 요약 정보(작성자 등) 제거",
                    s.trim_start_matches('\u{5}'),
                );
            } else {
                out.push(Node {
                    path: s.into(),
                    is_storage: false,
                    clsid: [0; 16],
                    data: d.to_vec(),
                });
            }
        }
    }
    let mut seen = HashSet::new();
    for n in &c.nodes {
        let top = n.path.split('/').next().unwrap_or("").to_string();
        if out.iter().any(|o| o.path.eq_ignore_ascii_case(&top))
            || summaries.contains(&top.as_str())
            || !seen.insert(top.clone())
        {
            continue;
        }
        findings.add(
            "orphan-part",
            Severity::Low,
            "허용 목록 외 항목 - 새 문서에 조립하지 않음",
            top.replace(['\u{1}', '\u{5}'], "").as_str(),
        );
    }
    findings.count("output_parts", out.len() as u64);
    cfbx::write(c.version, c.root_clsid, &out)
}
