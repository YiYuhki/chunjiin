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

/// 최상위 레코드 목록
fn top_level(d: &[u8]) -> Vec<Rec> {
    let mut out = Vec::new();
    let mut pos = 0;
    while let Some(r) = header(d, pos) {
        pos = r.body + r.len;
        out.push(r);
    }
    out
}

struct EmptyStorage {
    raw: Vec<u8>,
    compressed: Vec<u8>,
}

/// 내용이 없는 OLE 복합 파일 (비압축 / "원본 크기 + zlib" 압축 형태)
fn empty_storage() -> Result<EmptyStorage> {
    let raw = cfbx::write(cfb::Version::V3, [0; 16], &[])?;
    let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    let _ = std::io::Write::write_all(&mut e, &raw);
    let mut compressed = (raw.len() as u32).to_le_bytes().to_vec();
    compressed.extend(e.finish().unwrap_or_default());
    Ok(EmptyStorage { raw, compressed })
}

/// 이미 비어 있는(스트림이 하나도 없는) OLE 저장소인지 - 재검증 시 중복 보고 방지
fn storage_is_empty(d: &[u8], r: &Rec, policy: &Policy) -> bool {
    let body = &d[r.body..r.body + r.len];
    let data = if r.instance == 1 {
        let mut out = Vec::new();
        let dec = flate2::read::ZlibDecoder::new(&body[4..]);
        if std::io::Read::read_to_end(&mut std::io::Read::take(dec, 1 << 20), &mut out).is_err() {
            return false;
        }
        out
    } else {
        body.to_vec()
    };
    matches!(cfbx::read(&data, policy), Ok(c) if c.nodes.is_empty())
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
    let storages: Vec<Rec> = find_headers(&doc, RT_EX_OLE_OBJ_STG, None)
        .into_iter()
        .filter(|r| is_ole_storage(r) && !storage_is_empty(&doc, r, policy))
        .collect();
    if !find_headers(&doc, RT_EX_CONTROL, Some(0xF)).is_empty() {
        return blocked(
            "activex",
            "ActiveX 컨트롤이 포함된 PPT 는 안전하게 재조합할 수 없어 차단합니다",
        );
    }
    // VBAInfoContainer 는 대부분 문서에 있으며, 실제 매크로 유무는 원자 레코드의 fHasMacros 로 판단
    let vba_flags: Vec<usize> = find_headers(&doc, RT_VBA_INFO_ATOM, None)
        .iter()
        .filter(|r| r.len >= 8 && doc[r.body + 4..r.body + 8] == [1, 0, 0, 0])
        .map(|r| r.body + 4)
        .collect();
    if !storages.is_empty() || !vba_flags.is_empty() {
        if !policy.neutralize_embedded_ole {
            let (cat, why) = if vba_flags.is_empty() {
                ("embedded-object", "임베디드 OLE 개체가 포함된 PPT 는 차단합니다 (--neutralize-ole 로 빈 개체 대체 가능)")
            } else {
                (
                    "macro",
                    "VBA 매크로가 포함된 PPT 는 차단합니다 (--neutralize-ole 로 빈 개체 대체 가능)",
                )
            };
            return blocked(cat, why);
        }
        // 정상 트리의 최상위 영구 객체만 덮어쓴다. 비정상 위치에서만 발견되면 은닉 시도로 보고 차단
        let top: HashSet<usize> = top_level(&doc)
            .into_iter()
            .filter(|r| r.rtype == RT_EX_OLE_OBJ_STG)
            .map(|r| r.body)
            .collect();
        let replacement = empty_storage()?;
        for r in &storages {
            if !top.contains(&r.body) {
                return blocked(
                    "embedded-object",
                    "레코드 구조 밖에 숨겨진 OLE 저장소가 있어 차단합니다",
                );
            }
            let body = if r.instance == 1 {
                replacement.compressed.clone()
            } else {
                replacement.raw.clone()
            };
            if body.len() > r.len {
                return blocked(
                    "embedded-object",
                    "OLE 개체 자리가 작아 빈 개체로 대체할 수 없어 차단합니다",
                );
            }
            doc[r.body..r.body + body.len()].copy_from_slice(&body);
            doc[r.body + body.len()..r.body + r.len].fill(0);
        }
        for at in &vba_flags {
            doc[*at..*at + 4].copy_from_slice(&[0; 4]);
        }
        if !storages.is_empty() {
            findings.add(
                "embedded-object",
                Severity::High,
                format!(
                    "임베디드 OLE/VBA 저장소 {}개를 빈 개체로 대체(미리보기 그림 유지)",
                    storages.len()
                ),
                "PowerPoint Document",
            );
        }
        if !vba_flags.is_empty() {
            findings.add(
                "macro",
                Severity::Critical,
                "VBA 매크로 제거(매크로 표시 해제, 저장소는 빈 개체로 대체)",
                "PowerPoint Document",
            );
        }
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
        for b in doc[*at..*at + *len].as_chunks_mut::<2>().0 {
            *b = [0x20, 0];
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
