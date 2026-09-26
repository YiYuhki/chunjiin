//! HWP 5.x(한글 바이너리) 재조합.
//!
//! 새 OLE 복합 파일을 만들어 허용된 스트림만 조립한다.
//! - 조립: FileHeader(속성 비트 정리), DocInfo, BodyText/Section*, 래스터 이미지 BinData
//!   (재인코딩), 미리보기(PrvText/PrvImage)
//! - 조립하지 않음: 문서 스크립트(Scripts), OLE·EPS/PostScript 등 비래스터 BinData,
//!   DocOptions(외부 연결 문서·DRM·전자 서명), XMLTemplate, 문서 이력(DocHistory),
//!   요약 정보(정책)
//! - 레코드 재구성: DocInfo 의 외부 파일 연결(BIN_DATA LINK) 경로 제거,
//!   본문 하이퍼링크 필드 중 허용되지 않은 대상 제거
//! - 차단: 암호 설정, 배포용 문서, DRM, 인증서 암호화 문서

use std::collections::BTreeMap;

use super::blip::PixelBudget;
use super::cfbx::{self, deflate_raw, inflate_raw, utf16le, Node};
use crate::detect::OLE_MAGIC;
use crate::error::{blocked, Result};
use crate::hwpx::{normalize_link, report_script_text};
use crate::imaging::{self, ImageKind};
use crate::metafile;
use crate::ooxml::content::truncate;
use crate::policy::Policy;
use crate::report::{Findings, Severity};

const SIGNATURE: &[u8] = b"HWP Document File";
const HWPTAG_BEGIN: u16 = 0x10;
const HWPTAG_BIN_DATA: u16 = HWPTAG_BEGIN + 2;
const HWPTAG_CTRL_HEADER: u16 = HWPTAG_BEGIN + 55;
const HWPTAG_SHAPE_COMPONENT_OLE: u16 = HWPTAG_BEGIN + 84;

// FileHeader 속성 비트
const F_COMPRESSED: u32 = 1 << 0;
const F_PASSWORD: u32 = 1 << 1;
const F_DISTRIBUTION: u32 = 1 << 2;
const F_SCRIPT: u32 = 1 << 3;
const F_DRM: u32 = 1 << 4;
const F_XML_TEMPLATE: u32 = 1 << 5;
const F_HISTORY: u32 = 1 << 6;
const F_SIGNATURE: u32 = 1 << 7;
const F_CERT_ENCRYPT: u32 = 1 << 8;
const F_SIGNATURE_RESERVE: u32 = 1 << 9;
const F_CERT_DRM: u32 = 1 << 10;

pub struct Record {
    pub tag: u16,
    pub level: u16,
    pub data: Vec<u8>,
}

/// 한 스트림에서 허용하는 최대 레코드 수 (빈 레코드 남발로 인한 메모리 증폭 방지)
const MAX_RECORDS: usize = 4_000_000;

pub fn parse_records(buf: &[u8]) -> Option<Vec<Record>> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < buf.len() {
        if out.len() >= MAX_RECORDS {
            return None;
        }
        let h = u32::from_le_bytes(buf.get(pos..pos + 4)?.try_into().ok()?);
        pos += 4;
        let tag = (h & 0x3FF) as u16;
        let level = ((h >> 10) & 0x3FF) as u16;
        let mut size = (h >> 20) as usize;
        if size == 0xFFF {
            size = u32::from_le_bytes(buf.get(pos..pos + 4)?.try_into().ok()?) as usize;
            pos += 4;
        }
        let data = buf.get(pos..pos.checked_add(size)?)?.to_vec();
        pos += size;
        out.push(Record { tag, level, data });
    }
    Some(out)
}

pub fn write_records(recs: &[Record]) -> Vec<u8> {
    let mut out = Vec::new();
    for r in recs {
        let size = r.data.len();
        let head = (r.tag as u32 & 0x3FF) | ((r.level as u32 & 0x3FF) << 10);
        if size >= 0xFFF {
            out.extend_from_slice(&(head | (0xFFF << 20)).to_le_bytes());
            out.extend_from_slice(&(size as u32).to_le_bytes());
        } else {
            out.extend_from_slice(&(head | ((size as u32) << 20)).to_le_bytes());
        }
        out.extend_from_slice(&r.data);
    }
    out
}

pub fn reassemble(data: &[u8], policy: &Policy, findings: &mut Findings) -> Result<Vec<u8>> {
    let c = cfbx::read(data, policy)?;
    findings.count("input_parts", c.nodes.len() as u64);
    let Some(header) = c.stream("FileHeader") else {
        return blocked("structure", "FileHeader 없음 - HWP 5 문서가 아님");
    };
    if header.len() < 40 || !header.starts_with(SIGNATURE) {
        return blocked("structure", "HWP 파일 서명 불일치");
    }
    let props = u32::from_le_bytes(header[36..40].try_into().unwrap());
    for (bit, why) in [
        (
            F_PASSWORD,
            "암호가 설정된 HWP 문서는 검사할 수 없어 차단합니다",
        ),
        (
            F_DISTRIBUTION,
            "배포용(암호화) HWP 문서는 검사할 수 없어 차단합니다",
        ),
        (F_DRM, "DRM 보안 HWP 문서는 검사할 수 없어 차단합니다"),
        (
            F_CERT_ENCRYPT,
            "공인 인증서 암호화 HWP 문서는 검사할 수 없어 차단합니다",
        ),
        (
            F_CERT_DRM,
            "공인 인증서 DRM HWP 문서는 검사할 수 없어 차단합니다",
        ),
    ] {
        if props & bit != 0 {
            return blocked("encrypted", why);
        }
    }
    let compressed = props & F_COMPRESSED != 0;
    let limit = policy.max_stream_size;

    let decode = |raw: &[u8], name: &str| -> Result<Vec<u8>> {
        if !compressed {
            return Ok(raw.to_vec());
        }
        match inflate_raw(raw, limit) {
            Some(d) => Ok(d),
            None => blocked("structure", format!("{name} 스트림 압축 해제 실패")),
        }
    };
    let encode = |plain: Vec<u8>| {
        if compressed {
            deflate_raw(&plain)
        } else {
            plain
        }
    };

    let mut out: Vec<Node> = Vec::new();
    let mut notes: BTreeMap<(&'static str, Severity, String), u32> = BTreeMap::new();
    let mut note = |cat: &'static str, sev: Severity, desc: String| {
        *notes.entry((cat, sev, desc)).or_default() += 1;
    };

    // FileHeader: 제거하는 저장소에 해당하는 속성 비트를 끈다
    let mut new_header = header.to_vec();
    let cleared =
        props & !(F_SCRIPT | F_XML_TEMPLATE | F_HISTORY | F_SIGNATURE | F_SIGNATURE_RESERVE);
    new_header[36..40].copy_from_slice(&cleared.to_le_bytes());
    out.push(Node {
        path: "FileHeader".into(),
        is_storage: false,
        clsid: [0; 16],
        data: new_header,
    });

    // DocInfo: 외부 파일 연결 제거
    let Some(docinfo) = c.stream("DocInfo") else {
        return blocked("structure", "DocInfo 없음");
    };
    let plain = decode(docinfo, "DocInfo")?;
    let Some(mut recs) = parse_records(&plain) else {
        return blocked("structure", "DocInfo 레코드 해석 실패");
    };
    for r in recs.iter_mut().filter(|r| r.tag == HWPTAG_BIN_DATA) {
        if r.data.len() >= 2 && u16::from_le_bytes([r.data[0], r.data[1]]) & 0xF == 0 {
            let path = read_wstr(&r.data, 2).unwrap_or_default();
            if !path.is_empty() || r.data.len() > 6 {
                note(
                    "external-resource",
                    Severity::Medium,
                    format!("외부 파일 연결 제거: {}", truncate(&path, 120)),
                );
            }
            let prop = [r.data[0], r.data[1]];
            r.data = vec![prop[0], prop[1], 0, 0, 0, 0];
        }
    }
    out.push(Node {
        path: "DocInfo".into(),
        is_storage: false,
        clsid: [0; 16],
        data: encode(write_records(&recs)),
    });

    // 본문 섹션
    let mut sections = 0u64;
    for n in c
        .nodes
        .iter()
        .filter(|n| !n.is_storage && n.path.to_ascii_lowercase().starts_with("bodytext/"))
    {
        let plain = decode(&n.data, &n.path)?;
        let Some(mut recs) = parse_records(&plain) else {
            return blocked("structure", format!("{} 레코드 해석 실패", n.path));
        };
        for r in recs.iter_mut() {
            if r.tag == HWPTAG_SHAPE_COMPONENT_OLE {
                note(
                    "embedded-object",
                    Severity::Info,
                    "OLE 개체 틀(내장 데이터는 조립하지 않음)".into(),
                );
            }
            if r.tag == HWPTAG_CTRL_HEADER && r.data.len() >= 11 && &r.data[0..4] == b"klh%" {
                let len = u16::from_le_bytes([r.data[9], r.data[10]]) as usize;
                let end = 11 + len * 2;
                if end > r.data.len() {
                    continue;
                }
                let target = normalize_link(&utf16le(&r.data[11..end]));
                if target.is_empty() || target.starts_with('#') {
                    continue;
                }
                if !policy.uri_allowed(&target) || policy.remove_hyperlinks {
                    let (cat, sev) = if policy.uri_allowed(&target) {
                        ("hyperlink", Severity::Low)
                    } else {
                        ("dangerous-link", Severity::High)
                    };
                    note(
                        cat,
                        sev,
                        format!("하이퍼링크 대상 제거: {}", truncate(&target, 120)),
                    );
                    let mut d = r.data[..9].to_vec();
                    d.extend_from_slice(&0u16.to_le_bytes());
                    d.extend_from_slice(&r.data[end..]);
                    r.data = d;
                }
            }
        }
        out.push(Node {
            path: n.path.clone(),
            is_storage: false,
            clsid: [0; 16],
            data: encode(write_records(&recs)),
        });
        sections += 1;
    }
    if sections == 0 {
        return blocked("structure", "본문(BodyText) 없음");
    }

    // BinData: 래스터 이미지는 재인코딩, 메타파일은 재조합
    let mut budget = PixelBudget::new(policy);
    let mut metafiles = metafile::Stats::default();
    for n in c
        .nodes
        .iter()
        .filter(|n| !n.is_storage && n.path.to_ascii_lowercase().starts_with("bindata/"))
    {
        let (plain, was_compressed) = match inflate_raw(&n.data, limit) {
            Some(d)
                if !d.is_empty()
                    && (ImageKind::sniff(&d).is_some()
                        || metafile::sniff(&d).is_some()
                        || !is_known_raw(&n.data)) =>
            {
                (d, true)
            }
            _ => (n.data.clone(), false),
        };
        match ImageKind::sniff(&plain) {
            Some(k) => match imaging::reencode_same(&plain, k, policy) {
                Ok(img) => {
                    findings.count("images_reencoded", 1);
                    let data = if was_compressed {
                        deflate_raw(&img)
                    } else {
                        img
                    };
                    out.push(Node {
                        path: n.path.clone(),
                        is_storage: false,
                        clsid: [0; 16],
                        data,
                    });
                }
                Err(e) => findings.add(
                    "image",
                    Severity::Medium,
                    format!("이미지 제외: {e}"),
                    n.path.as_str(),
                ),
            },
            None if metafile::sniff(&plain).is_some() => {
                match metafile::rebuild(&plain, policy, &mut budget, &mut metafiles) {
                    Ok((mf, _)) => out.push(Node {
                        path: n.path.clone(),
                        is_storage: false,
                        clsid: [0; 16],
                        data: if was_compressed { deflate_raw(&mf) } else { mf },
                    }),
                    Err(e) => findings.add(
                        "metafile",
                        Severity::Medium,
                        format!("메타파일 제외: {e}"),
                        n.path.as_str(),
                    ),
                }
            }
            None => {
                let (cat, sev, desc) = classify_bin(&plain);
                findings.add(
                    cat,
                    sev,
                    format!("{desc} - 새 문서에 조립하지 않음"),
                    n.path.as_str(),
                );
            }
        }
    }

    metafiles.report(findings, "BinData");

    // 미리보기
    if let Some(t) = c.stream("PrvText") {
        let text: String = utf16le(t)
            .chars()
            .filter(|c| !c.is_control() || matches!(c, '\r' | '\n' | '\t'))
            .collect();
        let data: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        out.push(Node {
            path: "PrvText".into(),
            is_storage: false,
            clsid: [0; 16],
            data,
        });
    }
    if let Some(img) = c.stream("PrvImage") {
        if let Some(k) = ImageKind::sniff(img) {
            if let Ok(b) = imaging::reencode_same(img, k, policy) {
                out.push(Node {
                    path: "PrvImage".into(),
                    is_storage: false,
                    clsid: [0; 16],
                    data: b,
                });
            }
        }
    }
    let summary = "\u{5}HwpSummaryInformation";
    if let Some(s) = c.stream(summary) {
        if policy.strip_metadata {
            findings.add(
                "metadata",
                Severity::Info,
                "문서 요약 정보(작성자 등) 제거",
                "",
            );
        } else {
            out.push(Node {
                path: summary.into(),
                is_storage: false,
                clsid: [0; 16],
                data: s.to_vec(),
            });
        }
    }

    // 조립하지 않은 저장소/스트림 보고
    for n in &c.nodes {
        let lower = n.path.to_ascii_lowercase();
        let top = lower.split('/').next().unwrap_or("");
        if out.iter().any(|o| o.path.eq_ignore_ascii_case(&n.path))
            || lower.starts_with("bindata/")
            || lower.starts_with("bodytext")
            || lower == "bindata"
            || lower == summary.to_ascii_lowercase()
            || lower == "prvimage"
        {
            continue;
        }
        if n.is_storage && top == lower && top != "scripts" && top != "docoptions" {
            continue; // 저장소 자체는 하위 스트림에서 보고
        }
        match top {
            "scripts" if lower.ends_with("jscriptversion") => findings.add(
                "script",
                Severity::Info,
                "스크립트 버전 정보 - 새 문서에 조립하지 않음",
                n.path.as_str(),
            ),
            "scripts" if !n.is_storage => {
                // [u32 길이][UTF-16 문자열] 묶음을 (문서 압축 시) raw deflate 한 형식
                let plain = if compressed {
                    inflate_raw(&n.data, limit).unwrap_or_else(|| n.data.clone())
                } else {
                    n.data.clone()
                };
                let mut text = String::new();
                let mut p = 0;
                while p + 4 <= plain.len() {
                    let len = u32::from_le_bytes(plain[p..p + 4].try_into().unwrap()) as usize;
                    let Some(chunk) = plain.get(p + 4..p + 4 + len.saturating_mul(2)) else {
                        break;
                    };
                    text.push_str(&utf16le(chunk));
                    text.push('\n');
                    p += 4 + len * 2;
                }
                report_script_text(findings, &n.path, &text)
            }
            "scripts" | "docoptions" => {}
            _ if lower.starts_with("docoptions/_linkdoc") => findings.add(
                "external-resource",
                Severity::Medium,
                "연결 문서 정보 - 새 문서에 조립하지 않음",
                n.path.as_str(),
            ),
            _ if lower.starts_with("docoptions/") => findings.add(
                "hwp-option",
                Severity::Low,
                "문서 옵션(DRM·전자 서명 등) - 새 문서에 조립하지 않음",
                n.path.as_str(),
            ),
            "xmltemplate" => findings.add(
                "custom-xml",
                Severity::Info,
                "XML 템플릿 - 새 문서에 조립하지 않음",
                n.path.as_str(),
            ),
            "dochistory" => findings.add(
                "hidden-data",
                Severity::Low,
                "문서 이력(이전 버전 데이터) - 새 문서에 조립하지 않음",
                n.path.as_str(),
            ),
            _ => findings.add(
                "orphan-part",
                Severity::Low,
                "허용 목록 외 스트림 - 새 문서에 조립하지 않음",
                n.path.as_str(),
            ),
        }
    }
    for ((cat, sev, desc), n) in notes {
        let desc = if n > 1 {
            format!("{desc} ({n}건)")
        } else {
            desc
        };
        findings.add(cat, sev, desc, "");
    }

    // 원본과 같은 순서의 저장소 구성
    out.push(Node {
        path: "BodyText".into(),
        is_storage: true,
        clsid: [0; 16],
        data: vec![],
    });
    findings.count(
        "output_parts",
        out.iter().filter(|n| !n.is_storage).count() as u64,
    );
    cfbx::write(c.version, c.root_clsid, &out)
}

fn read_wstr(data: &[u8], at: usize) -> Option<String> {
    let len = u16::from_le_bytes(data.get(at..at + 2)?.try_into().ok()?) as usize;
    Some(utf16le(data.get(at + 2..at + 2 + len * 2)?))
}

/// 압축되지 않은 상태로 알아볼 수 있는 형식인지 (압축 여부 판단 보조)
fn is_known_raw(data: &[u8]) -> bool {
    ImageKind::sniff(data).is_some()
        || metafile::sniff(data).is_some()
        || data.starts_with(OLE_MAGIC)
        || data.starts_with(b"%!PS")
        || data.starts_with(b"\xc5\xd0\xd3\xc6")
}

fn classify_bin(data: &[u8]) -> (&'static str, Severity, &'static str) {
    let head = &data[..data.len().min(16)];
    if head.windows(8).any(|w| w == OLE_MAGIC) {
        ("embedded-object", Severity::High, "OLE 개체 데이터")
    } else if data.starts_with(b"%!PS") || data.starts_with(b"\xc5\xd0\xd3\xc6") {
        (
            "postscript",
            Severity::Critical,
            "EPS/PostScript 이미지(고스트스크립트 취약점 악용 경로)",
        )
    } else if data.starts_with(b"MZ") {
        ("executable", Severity::Critical, "실행 파일")
    } else {
        (
            "binary-part",
            Severity::Medium,
            "재조합할 수 없는 바이너리 데이터",
        )
    }
}
