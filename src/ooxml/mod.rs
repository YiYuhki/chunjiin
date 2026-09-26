//! OOXML(docx/xlsx/pptx 및 매크로·템플릿·쇼 변형) 재조합.
//!
//! 원본 패키지를 수정하지 않는다. 패키지 루트 관계(`_rels/.rels`)에서 출발해
//! **허용 목록에 있는 관계만** 따라가며 파트를 수집하고, 각 파트를 허용된
//! 네임스페이스/요소만으로 다시 구성한 뒤 `[Content_Types].xml` 과 모든 `.rels`
//! 를 새로 생성하여 새 패키지를 조립한다.
//!
//! 따라서 매크로(vbaProject), XLM 매크로 시트, ActiveX, OLE 임베딩, 외부 템플릿,
//! 데이터 연결, customUI, 사용자 정의 XML, 참조되지 않은 은닉 파트 등은
//! "제거"되는 것이 아니라 애초에 새 문서에 조립되지 않는다.

mod content;
pub mod rules;

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use crate::detect::FileType;
use crate::error::{blocked, CdrError, Result};
use crate::imaging::{self, ImageKind};
use crate::policy::Policy;
use crate::report::{Findings, Severity};
use crate::xml::{self, Node};
use crate::zipsafe::{self, Entry};

use rules::{DocKind, PartType, CT_NS, PKG_REL_NS};

const REL_CT: &str = "application/vnd.openxmlformats-package.relationships+xml";

#[derive(Debug, Clone)]
enum Target {
    Internal(String),
    External(String),
}

#[derive(Debug, Clone)]
struct Rel {
    id: String,
    rtype: String,
    target: Target,
    /// 내부 관계의 대상 파트 형식
    ptype: Option<PartType>,
}

struct Part {
    ptype: PartType,
    rels: Vec<Rel>,
    /// 재조합 결과 파트 이름
    out_name: String,
    xml: Option<xml::Document>,
    binary: Option<Vec<u8>>,
}

pub fn reassemble(
    data: &[u8],
    ftype: FileType,
    policy: &Policy,
    findings: &mut Findings,
) -> Result<Vec<u8>> {
    reassemble_at(data, ftype, policy, findings, 0)
}

fn reassemble_at(
    data: &[u8],
    ftype: FileType,
    policy: &Policy,
    findings: &mut Findings,
    depth: usize,
) -> Result<Vec<u8>> {
    let kind = match ftype {
        FileType::Docx => DocKind::Word,
        FileType::Xlsx => DocKind::Excel,
        FileType::Pptx => DocKind::PowerPoint,
        _ => return blocked("unsupported", "OOXML 이 아님"),
    };
    let entries = zipsafe::read_entries(data, policy, findings)?;
    findings.count("input_parts", entries.len() as u64);
    let files: HashMap<String, Entry> = entries
        .into_iter()
        .map(|e| (e.name.to_ascii_lowercase(), e))
        .collect();

    // ---------------------------------------------------------------- 1. 관계 그래프 탐색
    let mut reported: HashSet<String> = HashSet::new();
    let root_rels = read_rels(&files, "", None, kind, policy, findings, &mut reported)?;
    let main: Vec<&Rel> = root_rels
        .iter()
        .filter(|r| rules::rel_short_name(&r.rtype).map(|s| s.0) == Some("officeDocument"))
        .collect();
    let main_name = match main.as_slice() {
        [r] => match &r.target {
            Target::Internal(n) => n.clone(),
            Target::External(_) => return blocked("structure", "메인 문서가 외부 경로를 가리킴"),
        },
        [] => return blocked("structure", "메인 문서(officeDocument) 관계 없음"),
        _ => return blocked("structure", "메인 문서 관계가 둘 이상"),
    };

    let mut parts: BTreeMap<String, Part> = BTreeMap::new();
    let mut queue: VecDeque<(String, PartType)> = VecDeque::new();
    for r in &root_rels {
        if let Target::Internal(n) = &r.target {
            queue.push_back((n.clone(), r.ptype.expect("검증된 관계")));
        }
    }
    while let Some((name, ptype)) = queue.pop_front() {
        if parts.contains_key(&name) {
            continue;
        }
        if parts.len() >= policy.max_zip_entries {
            return blocked("structure", "파트 수 제한 초과");
        }
        let rels = if matches!(ptype, PartType::Image | PartType::Package) {
            Vec::new()
        } else {
            match read_rels(
                &files,
                &name,
                Some(ptype),
                kind,
                policy,
                findings,
                &mut reported,
            ) {
                Ok(r) => r,
                Err(e) if e.category() == "xxe" => return Err(e),
                Err(e) => {
                    findings.add(
                        "structure",
                        Severity::Medium,
                        format!("관계 파일 무시: {e}"),
                        name.as_str(),
                    );
                    Vec::new()
                }
            }
        };
        for r in &rels {
            if let Target::Internal(n) = &r.target {
                if !parts.contains_key(n) {
                    queue.push_back((n.clone(), r.ptype.expect("검증된 관계")));
                }
            }
        }
        parts.insert(
            name.clone(),
            Part {
                ptype,
                rels,
                out_name: name,
                xml: None,
                binary: None,
            },
        );
    }

    // ---------------------------------------------------------------- 2. 파트 내용 해석/재인코딩
    let mut dropped: HashSet<String> = HashSet::new();
    for (name, part) in parts.iter_mut() {
        let data = &files[&name.to_ascii_lowercase()].data;
        match part.ptype {
            PartType::Image => match ImageKind::sniff(data) {
                None => {
                    findings.add(
                        "unsupported-media",
                        Severity::Low,
                        "재조합 불가 이미지 형식(EMF/WMF/SVG/TIFF 등) 제외",
                        name.as_str(),
                    );
                    dropped.insert(name.clone());
                }
                Some(k) => match imaging::reencode(data, k, policy) {
                    Ok((bytes, out_kind)) => {
                        findings.count("images_reencoded", 1);
                        if out_kind != k
                            || !name
                                .to_ascii_lowercase()
                                .ends_with(&format!(".{}", ext_alias(out_kind)))
                        {
                            part.out_name = replace_ext(name, out_kind.extension());
                        }
                        part.binary = Some(bytes);
                    }
                    Err(e) => {
                        findings.add(
                            "image",
                            Severity::Medium,
                            format!("이미지 제외: {e}"),
                            name.as_str(),
                        );
                        dropped.insert(name.clone());
                    }
                },
            },
            PartType::Package => {
                let inner_type = crate::detect::detect(data);
                if depth > 0
                    || !matches!(inner_type, FileType::Docx | FileType::Xlsx | FileType::Pptx)
                {
                    findings.add(
                        "embedded-object",
                        Severity::Medium,
                        "재조합할 수 없는 내장 패키지 제외",
                        name.as_str(),
                    );
                    dropped.insert(name.clone());
                    continue;
                }
                let mut inner = Findings::default();
                match reassemble_at(data, inner_type, policy, &mut inner, depth + 1) {
                    Ok(bytes) => {
                        for f in inner.items {
                            let loc = format!("{name}!{}", f.location);
                            findings.add(&f.category, f.severity, f.description, loc);
                        }
                        findings.count("packages_reassembled", 1);
                        if let Some(ext) = inner_type.output_extension() {
                            part.out_name = replace_ext(name, ext);
                        }
                        part.binary = Some(bytes);
                    }
                    Err(e) => {
                        findings.add(
                            "embedded-object",
                            Severity::Medium,
                            format!("내장 패키지 제외: {e}"),
                            name.as_str(),
                        );
                        dropped.insert(name.clone());
                    }
                }
            }
            PartType::Xml(_) | PartType::Vml => match xml::parse(data, name, policy) {
                Ok(doc) if rules::namespace_allowed(&doc.root.ns) => part.xml = Some(doc),
                Ok(doc) => {
                    findings.add(
                        "foreign-xml",
                        Severity::Low,
                        format!("허용되지 않은 루트 네임스페이스({}) 파트 제외", doc.root.ns),
                        name.as_str(),
                    );
                    dropped.insert(name.clone());
                }
                Err(e) if e.category() == "xxe" => return Err(e),
                Err(e) if *name == main_name => return Err(e),
                Err(e) => {
                    findings.add(
                        "structure",
                        Severity::Medium,
                        format!("파트 제외: {e}"),
                        name.as_str(),
                    );
                    dropped.insert(name.clone());
                }
            },
        }
    }
    if dropped.contains(&main_name) {
        return blocked("structure", "메인 문서 파트를 재조합할 수 없음");
    }

    // ---------------------------------------------------------------- 3. 제외된 파트 정리 및 도달성 재계산
    let root_rels: Vec<Rel> = root_rels
        .into_iter()
        .filter(|r| keep_rel(r, &dropped))
        .collect();
    for part in parts.values_mut() {
        part.rels.retain(|r| keep_rel(r, &dropped));
    }
    let mut reachable: HashSet<String> = HashSet::new();
    let mut stack: Vec<String> = root_rels.iter().filter_map(internal_target).collect();
    while let Some(n) = stack.pop() {
        if dropped.contains(&n) || !reachable.insert(n.clone()) {
            continue;
        }
        if let Some(p) = parts.get(&n) {
            stack.extend(p.rels.iter().filter_map(internal_target));
        }
    }
    parts.retain(|n, _| reachable.contains(n));

    // ---------------------------------------------------------------- 4. 파트 XML 재구성
    for (name, part) in parts.iter_mut() {
        if let Some(doc) = part.xml.as_mut() {
            let valid: HashSet<String> = part.rels.iter().map(|r| r.id.clone()).collect();
            let mut ctx = content::Ctx::new(kind, name, &valid, policy);
            content::sanitize_part(&mut doc.root, &mut ctx);
            ctx.flush(findings);
        }
    }

    // 조립되지 않은 원본 파트 보고 (관계 단계에서 보고된 것 제외)
    for (lower, e) in &files {
        let used = parts.keys().any(|n| n.to_ascii_lowercase() == *lower);
        if used
            || lower == "[content_types].xml"
            || lower.ends_with(".rels")
            || reported.contains(lower)
        {
            continue;
        }
        let (cat, sev, desc) = classify_orphan(lower);
        findings.add(
            cat,
            sev,
            format!("{desc} - 새 문서에 조립하지 않음"),
            e.name.as_str(),
        );
    }

    // ---------------------------------------------------------------- 5. 새 패키지 조립
    let out_names: HashMap<&str, &str> = parts
        .iter()
        .map(|(k, p)| (k.as_str(), p.out_name.as_str()))
        .collect();
    let mut out: Vec<Entry> = Vec::new();
    let mut overrides: Vec<(String, &'static str)> = Vec::new();

    out.push(Entry {
        name: "_rels/.rels".into(),
        data: build_rels("", &root_rels, &out_names),
    });
    for (name, part) in &parts {
        let bytes = match (&part.xml, &part.binary) {
            (Some(doc), _) => xml::serialize(doc),
            (None, Some(b)) => b.clone(),
            _ => continue,
        };
        let ct = match part.ptype {
            PartType::Xml(_) if *name == main_name => rules::main_content_type(kind),
            PartType::Xml(ct) => ct,
            PartType::Vml => rules::VML_CT,
            PartType::Image => ImageKind::sniff(&bytes)
                .map(|k| k.mime())
                .unwrap_or("application/octet-stream"),
            PartType::Package => package_content_type(&bytes),
        };
        overrides.push((part.out_name.clone(), ct));
        out.push(Entry {
            name: part.out_name.clone(),
            data: bytes,
        });
        if !part.rels.is_empty() {
            out.push(Entry {
                name: rels_path(&part.out_name),
                data: build_rels(&part.out_name, &part.rels, &out_names),
            });
        }
    }
    let content_types = build_content_types(&overrides);
    out.insert(
        0,
        Entry {
            name: "[Content_Types].xml".into(),
            data: content_types,
        },
    );

    findings.count("output_parts", out.len() as u64);
    zipsafe::write_entries(&out)
}

fn keep_rel(r: &Rel, dropped: &HashSet<String>) -> bool {
    match &r.target {
        Target::Internal(n) => !dropped.contains(n),
        Target::External(_) => true,
    }
}

fn internal_target(r: &Rel) -> Option<String> {
    match &r.target {
        Target::Internal(n) => Some(n.clone()),
        Target::External(_) => None,
    }
}

/// 소스 파트의 관계 파일을 읽고 허용 목록으로 걸러낸다.
fn read_rels(
    files: &HashMap<String, Entry>,
    source: &str,
    source_type: Option<PartType>,
    kind: DocKind,
    policy: &Policy,
    findings: &mut Findings,
    reported: &mut HashSet<String>,
) -> Result<Vec<Rel>> {
    let from_root = source.is_empty();
    let path = rels_path(source);
    let Some(entry) = files.get(&path.to_ascii_lowercase()) else {
        if from_root {
            return blocked("structure", "_rels/.rels 없음 - 올바른 OOXML 패키지가 아님");
        }
        return Ok(Vec::new());
    };
    let doc = xml::parse(&entry.data, &path, policy)?;
    if !(doc.root.local == "Relationships" && doc.root.ns == PKG_REL_NS) {
        return Err(CdrError::Blocked {
            category: "structure",
            reason: format!("관계 파일 형식 오류: {path}"),
        });
    }

    let mut ids = HashSet::new();
    let mut rels = Vec::new();
    for el in doc.root.child_elements() {
        if el.local != "Relationship" {
            continue;
        }
        let id = el.attr("Id").unwrap_or("").to_string();
        let rtype = el.attr("Type").unwrap_or("").to_string();
        let target = el.attr("Target").unwrap_or("").to_string();
        let external = el.attr("TargetMode") == Some("External");
        if id.is_empty()
            || !id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "_-.".contains(c))
            || !ids.insert(id.clone())
        {
            findings.add(
                "structure",
                Severity::Low,
                format!("잘못되었거나 중복된 관계 ID 제외: {id}"),
                path.as_str(),
            );
            continue;
        }
        let short = rules::rel_short_name(&rtype)
            .map(|s| s.0)
            .unwrap_or("unknown");

        if external {
            if short == "hyperlink"
                && !from_root
                && policy.uri_allowed(&target)
                && !target.chars().any(char::is_control)
            {
                if policy.remove_hyperlinks {
                    findings.add(
                        "hyperlink",
                        Severity::Low,
                        format!("하이퍼링크 제외(정책): {}", content::truncate(&target, 120)),
                        path.as_str(),
                    );
                    continue;
                }
                rels.push(Rel {
                    id,
                    rtype,
                    target: Target::External(target),
                    ptype: None,
                });
                continue;
            }
            let (cat, sev, desc) = rules::classify_dropped(short, true);
            findings.add(
                cat,
                sev,
                format!("{desc} 제외: {}", content::truncate(&target, 160)),
                path.as_str(),
            );
            continue;
        }

        let resolved = resolve_target(source, &target);
        let Some(entry) = resolved
            .as_ref()
            .and_then(|r| files.get(&r.to_ascii_lowercase()))
        else {
            findings.add(
                "structure",
                Severity::Info,
                format!("존재하지 않는 파트를 가리키는 관계 제외: {target}"),
                path.as_str(),
            );
            continue;
        };
        let Some(ptype) = rules::allowed_rel(kind, &rtype, from_root, source_type) else {
            let (cat, sev, desc) = rules::classify_dropped(short, false);
            findings.add(
                cat,
                sev,
                format!("{desc} - 새 문서에 조립하지 않음"),
                entry.name.as_str(),
            );
            mark_dependents(files, &entry.name, reported, 0);
            continue;
        };
        rels.push(Rel {
            id,
            rtype,
            target: Target::Internal(entry.name.clone()),
            ptype: Some(ptype),
        });
    }
    Ok(rels)
}

/// 제외된 파트와 그 하위 파트를 "보고됨" 으로 표시한다 (중복/오탐 보고 방지).
fn mark_dependents(
    files: &HashMap<String, Entry>,
    part: &str,
    reported: &mut HashSet<String>,
    depth: usize,
) {
    if depth > 16 || !reported.insert(part.to_ascii_lowercase()) {
        return;
    }
    let Some(entry) = files.get(&rels_path(part).to_ascii_lowercase()) else {
        return;
    };
    let Ok(text) = std::str::from_utf8(&entry.data) else {
        return;
    };
    // 관계 파일은 이미 검증 전이므로 Target 속성만 가볍게 추출한다
    for chunk in text.split("Target=\"").skip(1) {
        let Some(target) = chunk.split('"').next() else {
            continue;
        };
        if let Some(resolved) = resolve_target(part, target) {
            if let Some(e) = files.get(&resolved.to_ascii_lowercase()) {
                mark_dependents(files, &e.name, reported, depth + 1);
            }
        }
    }
}

fn package_content_type(bytes: &[u8]) -> &'static str {
    match crate::detect::detect(bytes) {
        FileType::Docx => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        FileType::Xlsx => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        FileType::Pptx => {
            "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        }
        _ => "application/octet-stream",
    }
}

fn classify_orphan(lower: &str) -> (&'static str, Severity, &'static str) {
    if lower.ends_with("vbaproject.bin") || lower.ends_with("vbadata.xml") {
        ("macro", Severity::Critical, "VBA 매크로")
    } else if lower.contains("macrosheets/") {
        ("xlm-macro", Severity::Critical, "Excel 4.0 매크로 시트")
    } else if lower.contains("embeddings/") {
        ("embedded-object", Severity::High, "임베디드 개체")
    } else if lower.contains("activex/") {
        ("activex", Severity::High, "ActiveX 컨트롤")
    } else {
        (
            "orphan-part",
            Severity::Low,
            "참조되지 않은 파트(은닉 데이터 가능)",
        )
    }
}

// ----------------------------------------------------------------------------- 경로 유틸리티

fn rels_path(part: &str) -> String {
    if part.is_empty() {
        return "_rels/.rels".into();
    }
    match part.rsplit_once('/') {
        Some((dir, file)) => format!("{dir}/_rels/{file}.rels"),
        None => format!("_rels/{part}.rels"),
    }
}

fn dir_of(part: &str) -> &str {
    part.rsplit_once('/').map(|(d, _)| d).unwrap_or("")
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let hex = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// 관계 대상 경로를 패키지 내 파트 이름으로 해석한다. 패키지 밖을 가리키면 None.
fn resolve_target(source: &str, target: &str) -> Option<String> {
    let target = percent_decode(target.trim()).replace('\\', "/");
    let target = target.split('#').next().unwrap_or("");
    let (base, rel) = match target.strip_prefix('/') {
        Some(abs) => ("", abs),
        None => (dir_of(source), target),
    };
    let mut segs: Vec<&str> = if base.is_empty() {
        Vec::new()
    } else {
        base.split('/').collect()
    };
    for seg in rel.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                segs.pop()?;
            }
            s => segs.push(s),
        }
    }
    if segs.is_empty() {
        None
    } else {
        Some(segs.join("/"))
    }
}

fn relative_path(from_part: &str, to_part: &str) -> String {
    let from: Vec<&str> = if from_part.is_empty() {
        Vec::new()
    } else {
        dir_of(from_part)
            .split('/')
            .filter(|s| !s.is_empty())
            .collect()
    };
    let to: Vec<&str> = to_part.split('/').collect();
    let common = from.iter().zip(&to).take_while(|(a, b)| a == b).count();
    let mut out: Vec<&str> = vec![".."; from.len() - common];
    out.extend(&to[common..]);
    out.join("/")
}

fn replace_ext(name: &str, ext: &str) -> String {
    match name.rsplit_once('.') {
        Some((stem, _)) if !stem.ends_with('/') => format!("{stem}.{ext}"),
        _ => format!("{name}.{ext}"),
    }
}

fn ext_alias(kind: ImageKind) -> &'static str {
    match kind {
        ImageKind::Jpeg => "jp", // .jpg / .jpeg 모두 허용
        k => k.extension(),
    }
}

// ----------------------------------------------------------------------------- 새 패키지 XML

fn build_rels(source_out: &str, rels: &[Rel], out_names: &HashMap<&str, &str>) -> Vec<u8> {
    let mut children = Vec::new();
    for r in rels {
        let el = match &r.target {
            Target::Internal(n) => {
                let out = out_names.get(n.as_str()).copied().unwrap_or(n);
                xml::element(
                    "Relationship",
                    &[
                        ("Id", &r.id),
                        ("Type", &r.rtype),
                        ("Target", &relative_path(source_out, out)),
                    ],
                    vec![],
                )
            }
            Target::External(url) => xml::element(
                "Relationship",
                &[
                    ("Id", &r.id),
                    ("Type", &r.rtype),
                    ("Target", url),
                    ("TargetMode", "External"),
                ],
                vec![],
            ),
        };
        children.push(Node::Element(el));
    }
    let root = xml::element("Relationships", &[("xmlns", PKG_REL_NS)], children);
    xml::serialize(&xml::Document { root })
}

fn build_content_types(overrides: &[(String, &'static str)]) -> Vec<u8> {
    let mut children = vec![
        Node::Element(xml::element(
            "Default",
            &[("Extension", "rels"), ("ContentType", REL_CT)],
            vec![],
        )),
        Node::Element(xml::element(
            "Default",
            &[("Extension", "xml"), ("ContentType", "application/xml")],
            vec![],
        )),
    ];
    for (name, ct) in overrides {
        let part_name = format!("/{name}");
        children.push(Node::Element(xml::element(
            "Override",
            &[("PartName", &part_name), ("ContentType", ct)],
            vec![],
        )));
    }
    let root = xml::element("Types", &[("xmlns", CT_NS)], children);
    xml::serialize(&xml::Document { root })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        assert_eq!(rels_path(""), "_rels/.rels");
        assert_eq!(
            rels_path("word/document.xml"),
            "word/_rels/document.xml.rels"
        );
        assert_eq!(
            resolve_target("word/document.xml", "media/a%20b.png").as_deref(),
            Some("word/media/a b.png")
        );
        assert_eq!(
            resolve_target("word/document.xml", "/xl/x.xml").as_deref(),
            Some("xl/x.xml")
        );
        assert_eq!(
            resolve_target("xl/worksheets/sheet1.xml", "../drawings/d.xml").as_deref(),
            Some("xl/drawings/d.xml")
        );
        assert_eq!(
            resolve_target("word/document.xml", "../../etc/passwd"),
            None
        );
        assert_eq!(
            relative_path("xl/worksheets/sheet1.xml", "xl/drawings/d.xml"),
            "../drawings/d.xml"
        );
        assert_eq!(relative_path("", "word/document.xml"), "word/document.xml");
        assert_eq!(
            relative_path("word/document.xml", "word/media/a.png"),
            "media/a.png"
        );
    }
}
