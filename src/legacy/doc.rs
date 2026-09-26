//! Word 97-2003(.doc) 재조합.
//!
//! - 새 OLE 복합 파일에 WordDocument, 사용 중인 테이블 스트림(0Table/1Table 중 하나),
//!   Data, CompObj 만 조립한다. 매크로(Macros/_VBA_PROJECT), OLE 개체(ObjectPool),
//!   사용자 정의 XML(MsoDataStore), 사용하지 않는 테이블 스트림(이전 편집 잔재)은
//!   조립하지 않는다. OLE 개체는 본문에 저장된 미리보기 그림이 남는다.
//! - FIB: 매크로 명령 사용자 지정·매크로 이름·첨부 템플릿 연결(SttbfAssoc) 위치를
//!   비우고, 서식 파일(.dot) 표시를 끈다.
//! - 본문: 조각 테이블을 따라 필드 코드를 읽어 DDE/INCLUDE*/LINK/허용되지 않은 HYPERLINK
//!   필드의 코드를 같은 길이의 공백으로 덮어쓴다(오프셋 불변, 필드 결과 텍스트는 유지).
//! - 차단: 암호화/난독화 문서

use std::collections::BTreeMap;

use super::cfbx::{self, Node};
use crate::error::{blocked, Result};
use crate::ooxml::content::{truncate, word_field_is_dangerous};
use crate::policy::Policy;
use crate::report::{Findings, Severity};

// FibRgFcLcb97 의 (fc, lcb) 쌍 번호
const FC_CMDS: usize = 24;
const FC_PLCF_MCR: usize = 25;
const FC_STTBF_MCR: usize = 26;
const FC_STTBF_ASSOC: usize = 32;
const FC_CLX: usize = 33;

const MAX_CHARS: usize = 64 * 1024 * 1024;

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}
fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

struct Fib {
    rg_fc_lcb: usize,
    count: usize,
}

impl Fib {
    fn parse(doc: &[u8]) -> Option<Fib> {
        let mut off = 32;
        let csw = u16_at(doc, off)? as usize;
        off += 2 + csw * 2;
        let cslw = u16_at(doc, off)? as usize;
        off += 2 + cslw * 4;
        let count = u16_at(doc, off)? as usize;
        off += 2;
        doc.get(off..off + count * 8)?;
        Some(Fib {
            rg_fc_lcb: off,
            count,
        })
    }

    fn pair(&self, doc: &[u8], i: usize) -> Option<(usize, usize)> {
        if i >= self.count {
            return None;
        }
        let at = self.rg_fc_lcb + i * 8;
        Some((u32_at(doc, at)? as usize, u32_at(doc, at + 4)? as usize))
    }

    fn clear_lcb(&self, doc: &mut [u8], i: usize) -> bool {
        if i >= self.count {
            return false;
        }
        let at = self.rg_fc_lcb + i * 8 + 4;
        let had = doc[at..at + 4] != [0, 0, 0, 0];
        doc[at..at + 4].copy_from_slice(&[0; 4]);
        had
    }
}

/// 본문 문자와 그 저장 위치
struct Char {
    code: u16,
    offset: usize,
    wide: bool,
}

fn read_chars(doc: &[u8], table: &[u8], fc_clx: usize, lcb_clx: usize) -> Option<Vec<Char>> {
    let clx = table.get(fc_clx..fc_clx.checked_add(lcb_clx)?)?;
    let mut pos = 0;
    let plc = loop {
        match *clx.get(pos)? {
            1 => {
                let cb = i16::from_le_bytes(clx.get(pos + 1..pos + 3)?.try_into().ok()?);
                pos += 3 + usize::try_from(cb).ok()?;
            }
            2 => {
                let lcb = u32_at(clx, pos + 1)? as usize;
                break clx.get(pos + 5..pos + 5 + lcb)?;
            }
            _ => return None,
        }
    };
    if plc.len() < 4 || (plc.len() - 4) % 12 != 0 {
        return None;
    }
    let n = (plc.len() - 4) / 12;
    let mut chars = Vec::new();
    for i in 0..n {
        let cp0 = u32_at(plc, i * 4)? as usize;
        let cp1 = u32_at(plc, (i + 1) * 4)? as usize;
        let pcd = 4 * (n + 1) + i * 8;
        let fc_raw = u32_at(plc, pcd + 2)?;
        let compressed = fc_raw & 0x4000_0000 != 0;
        let fc = (fc_raw & 0x3FFF_FFFF) as usize;
        let (base, width) = if compressed { (fc / 2, 1) } else { (fc, 2) };
        let len = cp1.checked_sub(cp0)?;
        // 정상 문서에서 문자 수는 WordDocument 크기를 넘지 않는다(조각 중복으로 인한 증폭 방지)
        if chars.len() + len > MAX_CHARS.min(doc.len()) {
            return None;
        }
        for k in 0..len {
            let off = base + k * width;
            let code = if compressed {
                *doc.get(off)? as u16
            } else {
                u16_at(doc, off)?
            };
            chars.push(Char {
                code,
                offset: off,
                wide: !compressed,
            });
        }
    }
    Some(chars)
}

struct Frame {
    code: String,
    starts_nested: bool,
    in_instr: bool,
    positions: Vec<usize>,
}

/// 위험 필드 코드의 문자 위치를 찾는다.
fn dangerous_fields(chars: &[Char], policy: &Policy, reports: &mut Vec<String>) -> Vec<usize> {
    let mut stack: Vec<Frame> = Vec::new();
    let mut out = Vec::new();
    for (i, ch) in chars.iter().enumerate() {
        match ch.code {
            0x13 => {
                if let Some(top) = stack.last_mut() {
                    if top.in_instr && top.code.trim().is_empty() {
                        top.starts_nested = true;
                    }
                }
                stack.push(Frame {
                    code: String::new(),
                    starts_nested: false,
                    in_instr: true,
                    positions: Vec::new(),
                });
            }
            0x14 => {
                if let Some(top) = stack.last_mut() {
                    top.in_instr = false;
                }
            }
            0x15 => {
                if let Some(f) = stack.pop() {
                    if word_field_is_dangerous(&f.code, f.starts_nested, policy) {
                        reports.push(if f.code.trim().is_empty() {
                            "(중첩 필드로 생성된 필드 코드)".into()
                        } else {
                            f.code.trim().to_string()
                        });
                        out.extend(f.positions.iter().copied());
                    }
                    if let Some(parent) = stack.last_mut() {
                        if parent.in_instr {
                            parent.positions.extend(f.positions);
                        }
                    }
                }
            }
            c => {
                if let Some(top) = stack.last_mut() {
                    if top.in_instr {
                        top.code.push(char::from_u32(c as u32).unwrap_or(' '));
                        top.positions.push(i);
                    }
                }
            }
        }
    }
    out
}

/// SttbfAssoc 의 첨부 서식 파일 경로(ibstAssocDot = 1)
fn attached_template(table: &[u8], fc: usize, lcb: usize) -> Option<String> {
    let sttb = table.get(fc..fc.checked_add(lcb)?)?;
    let extended = u16_at(sttb, 0)? == 0xFFFF;
    let mut pos = if extended { 6 } else { 4 };
    let count = u16_at(sttb, if extended { 2 } else { 0 })? as usize;
    let extra = u16_at(sttb, if extended { 4 } else { 2 })? as usize;
    for i in 0..count.min(2) {
        let (len, text) = if extended {
            let n = u16_at(sttb, pos)? as usize;
            (
                2 + n * 2,
                super::cfbx::utf16le(sttb.get(pos + 2..pos + 2 + n * 2)?),
            )
        } else {
            let n = *sttb.get(pos)? as usize;
            (
                1 + n,
                sttb.get(pos + 1..pos + 1 + n)?
                    .iter()
                    .map(|&b| b as char)
                    .collect(),
            )
        };
        if i == 1 {
            return Some(text);
        }
        pos += len + extra;
    }
    None
}

pub fn reassemble(data: &[u8], policy: &Policy, findings: &mut Findings) -> Result<Vec<u8>> {
    let c = cfbx::read(data, policy)?;
    findings.count("input_parts", c.nodes.len() as u64);
    let Some(word) = c.stream("WordDocument") else {
        return blocked("structure", "WordDocument 스트림 없음");
    };
    let mut doc = word.to_vec();
    if u16_at(&doc, 0) != Some(0xA5EC) {
        let why = if u16_at(&doc, 0) == Some(0xA5DC) {
            "Word 6.0/95 형식은 지원하지 않아 차단합니다"
        } else {
            "Word 문서 서명(FIB) 불일치"
        };
        return blocked("structure", why);
    }
    let flags = u16_at(&doc, 0x0A).unwrap_or(0);
    if flags & (1 << 8) != 0 || flags & (1 << 15) != 0 {
        return blocked(
            "encrypted",
            "암호화된 Word 문서는 검사할 수 없어 차단합니다",
        );
    }
    let table_name = if flags & (1 << 9) != 0 {
        "1Table"
    } else {
        "0Table"
    };
    let Some(table) = c.stream(table_name) else {
        return blocked("structure", format!("{table_name} 스트림 없음"));
    };
    let Some(fib) = Fib::parse(&doc) else {
        return blocked("structure", "FIB 해석 실패");
    };

    // 서식 파일(.dot) → 문서
    if flags & 1 != 0 {
        doc[0x0A..0x0C].copy_from_slice(&(flags & !1).to_le_bytes());
        findings.add(
            "macro-enabled-format",
            Severity::Low,
            "서식 파일(.dot)을 일반 문서로 변환",
            "",
        );
    }
    if fib.clear_lcb(&mut doc, FC_CMDS)
        | fib.clear_lcb(&mut doc, FC_PLCF_MCR)
        | fib.clear_lcb(&mut doc, FC_STTBF_MCR)
    {
        findings.add(
            "macro",
            Severity::Info,
            "명령 사용자 지정/매크로 이름 목록 제거",
            "WordDocument",
        );
    }
    let template = fib
        .pair(&doc, FC_STTBF_ASSOC)
        .and_then(|(fc, lcb)| attached_template(table, fc, lcb));
    if fib.clear_lcb(&mut doc, FC_STTBF_ASSOC) {
        match template.filter(|t| !t.trim().is_empty()) {
            Some(t) => {
                let remote = t.starts_with("\\\\") || t.contains("://");
                let sev = if remote {
                    Severity::Critical
                } else {
                    Severity::Medium
                };
                findings.add(
                    "template-injection",
                    sev,
                    format!("첨부 서식 파일 연결 제거: {}", truncate(&t, 120)),
                    "WordDocument",
                );
            }
            None => findings.add(
                "metadata",
                Severity::Info,
                "문서 연결 정보(SttbfAssoc) 제거",
                "WordDocument",
            ),
        }
    }

    // 필드 코드 무력화
    let Some((fc_clx, lcb_clx)) = fib.pair(&doc, FC_CLX) else {
        return blocked("structure", "조각 테이블(CLX) 위치 없음");
    };
    let Some(chars) = read_chars(&doc, table, fc_clx, lcb_clx) else {
        return blocked("structure", "조각 테이블(CLX) 해석 실패");
    };
    findings.count("characters", chars.len() as u64);
    let mut reports = Vec::new();
    let positions = dangerous_fields(&chars, policy, &mut reports);
    for i in positions {
        let ch = &chars[i];
        if ch.wide {
            doc[ch.offset..ch.offset + 2].copy_from_slice(&[0x20, 0]);
        } else {
            doc[ch.offset] = 0x20;
        }
    }
    let mut counts: BTreeMap<String, u32> = BTreeMap::new();
    for r in reports {
        *counts.entry(truncate(&r, 100)).or_default() += 1;
    }
    for (code, n) in counts {
        let suffix = if n > 1 {
            format!(" ({n}건)")
        } else {
            String::new()
        };
        findings.add(
            "dde",
            Severity::High,
            format!("위험 필드 코드 무력화: {code}{suffix}"),
            "WordDocument",
        );
    }

    // 새 컨테이너 조립
    let mut out = vec![
        Node {
            path: "WordDocument".into(),
            is_storage: false,
            clsid: [0; 16],
            data: doc,
        },
        Node {
            path: table_name.into(),
            is_storage: false,
            clsid: [0; 16],
            data: table.to_vec(),
        },
    ];
    for keep in ["Data", "\u{1}CompObj"] {
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

    // 조립하지 않은 항목 보고 (최상위 저장소/스트림 단위)
    let mut seen = std::collections::HashSet::new();
    for n in &c.nodes {
        let top = n.path.split('/').next().unwrap_or("").to_string();
        if out.iter().any(|o| o.path.eq_ignore_ascii_case(&top))
            || summaries.contains(&top.as_str())
            || !seen.insert(top.clone())
        {
            continue;
        }
        let (cat, sev, desc) = match top.as_str() {
            "Macros" | "_VBA_PROJECT" | "_VBA_PROJECT_CUR" => {
                ("macro", Severity::Critical, "VBA 매크로")
            }
            "ObjectPool" => (
                "embedded-object",
                Severity::High,
                "OLE 개체(미리보기 그림은 유지)",
            ),
            "MsoDataStore" => ("custom-xml", Severity::Info, "사용자 정의 XML 데이터"),
            "0Table" | "1Table" => (
                "hidden-data",
                Severity::Low,
                "사용하지 않는 테이블 스트림(이전 편집 잔재)",
            ),
            "\u{1}Ole" => ("embedded-object", Severity::Info, "OLE 링크 정보"),
            _ => ("orphan-part", Severity::Low, "허용 목록 외 항목"),
        };
        findings.add(
            cat,
            sev,
            format!("{desc} - 새 문서에 조립하지 않음"),
            top.replace(['\u{1}', '\u{5}'], "").as_str(),
        );
    }

    findings.count("output_parts", out.len() as u64);
    cfbx::write(c.version, c.root_clsid, &out)
}
