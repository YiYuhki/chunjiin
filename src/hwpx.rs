//! HWPX(한컴오피스 OWPML, KS X 6101) 재조합.
//!
//! 패키지 매니페스트(`Contents/content.hpf`)에 등록된 항목 중 허용된 것만 골라
//! 새 패키지를 조립한다. 문서 스크립트(`Scripts/`, JScript 매크로), OLE 개체,
//! 외부 링크 이미지, 실행 파일 등 비이미지 바이너리, 매니페스트에 없는 은닉 파일은
//! 새 문서에 조립되지 않는다. 각 XML 은 허용 네임스페이스만으로 재구성하며
//! 허용되지 않은 하이퍼링크 필드를 무력화한다.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::error::{blocked, Result};
use crate::imaging::{self, ImageKind};
use crate::legacy::blip::PixelBudget;
use crate::metafile;
use crate::ooxml::content::truncate;
use crate::policy::Policy;
use crate::report::{Findings, Severity};
use crate::svg;
use crate::xml::{self, value_is_external, Element, Node, XML_NS};
use crate::zipsafe::{self, Entry};

const MIMETYPE: &[u8] = b"application/hwp+zip";

/// 매니페스트와 무관하게 패키지 구조상 허용하는 파트
const FIXED_PARTS: &[&str] = &[
    "version.xml",
    "settings.xml",
    "META-INF/container.xml",
    "META-INF/manifest.xml",
    "META-INF/container.rdf",
];

fn namespace_allowed(ns: &str) -> bool {
    ns.is_empty()
        || ns.starts_with("http://www.hancom.co.kr/")
        || ns.starts_with("urn:oasis:names:tc:opendocument:")
        || ns.starts_with("http://www.idpf.org/2007/")
        || ns.starts_with("http://purl.org/dc/")
        || ns.starts_with("http://schemas.openxmlformats.org/") // 차트(DrawingML)
        || ns.starts_with("http://schemas.microsoft.com/office/")
        || ns.starts_with("http://schemas.haansoft.com/")
        || ns == "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
        || ns == "http://www.w3.org/2001/XMLSchema-instance"
        || ns == "http://www.w3.org/1999/xlink"
        || ns == XML_NS
        || ns == xml::XMLNS_NS
}

enum Kind {
    Xml,
    /// 이미 재인코딩된 이미지 바이트
    Image(Vec<u8>),
    /// 재조합된 벡터 그림(EMF/WMF/SVG) 바이트
    Metafile(Vec<u8>),
    Text,
}

pub fn reassemble(data: &[u8], policy: &Policy, findings: &mut Findings) -> Result<Vec<u8>> {
    let entries = zipsafe::read_entries(data, policy, findings)?;
    findings.count("input_parts", entries.len() as u64);
    let files: HashMap<String, Entry> = entries
        .into_iter()
        .map(|e| (e.name.to_ascii_lowercase(), e))
        .collect();
    match files.get("mimetype") {
        Some(m) if m.data.trim_ascii() == MIMETYPE => {}
        _ => return blocked("structure", "mimetype 이 application/hwp+zip 이 아님"),
    }

    // ------------------------------------------------------------ 1. 매니페스트 해석
    let manifest_name = "Contents/content.hpf";
    let Some(manifest_entry) = files.get(&manifest_name.to_ascii_lowercase()) else {
        return blocked(
            "structure",
            "Contents/content.hpf 없음 - 올바른 HWPX 가 아님",
        );
    };
    // 패키지 전체가 공유하는 XML 노드 예산
    let mut xml_nodes = 0usize;
    let mut manifest =
        xml::parse_counted(&manifest_entry.data, manifest_name, policy, &mut xml_nodes)?;

    // 조립할 파트: 원본 이름 → (출력 이름, 종류)
    let mut keep: BTreeMap<String, (String, Kind)> = BTreeMap::new();
    let mut dropped_ids: HashSet<String> = HashSet::new();
    let mut renamed: HashMap<String, String> = HashMap::new();
    let mut reported: HashSet<String> = HashSet::new();

    let mut budget = PixelBudget::new(policy);
    let mut metafiles = metafile::Stats::default();
    let mut items: Vec<(String, String, String, bool)> = Vec::new(); // id, href, media-type, embedded
    collect_items(&manifest.root, &mut items);
    for (id, href, media, embedded) in items {
        let resolved = resolve_href(&files, &href);
        let lower_href = href.to_ascii_lowercase();
        // 한컴은 내장 OLE 에도 isEmbeded="0" 을 쓰므로 속성보다 경로 형태와 존재 여부로 판단한다
        let _ = embedded;
        if value_is_external(&href) || href.contains("://") || looks_like_local_path(&href) {
            findings.add(
                "external-resource",
                Severity::Medium,
                format!("외부 링크 항목 제외: {}", truncate(&href, 120)),
                manifest_name,
            );
            dropped_ids.insert(id);
            continue;
        }
        let Some(name) = resolved else {
            findings.add(
                "structure",
                Severity::Info,
                format!("존재하지 않는 매니페스트 항목 제외: {href}"),
                manifest_name,
            );
            dropped_ids.insert(id);
            continue;
        };
        let lower = name.to_ascii_lowercase();
        reported.insert(lower.clone());
        let data = &files[&lower].data;
        if lower.starts_with("scripts/") || media.contains("script") || lower_href.ends_with(".js")
        {
            report_script(findings, &name, data);
            dropped_ids.insert(id);
            continue;
        }
        if lower.ends_with(".xml") {
            keep.insert(name.clone(), (name.clone(), Kind::Xml));
            continue;
        }
        if let Some(k) = ImageKind::sniff(data) {
            match imaging::reencode(data, k, policy) {
                Ok((bytes, out_kind)) => {
                    let out = if out_kind != k {
                        replace_ext(&name, out_kind.extension())
                    } else {
                        name.clone()
                    };
                    if out != name {
                        renamed.insert(name.clone(), out.clone());
                    }
                    keep.insert(name.clone(), (out, Kind::Image(bytes)));
                }
                Err(e) => {
                    findings.add(
                        "image",
                        Severity::Medium,
                        format!("이미지 제외: {e}"),
                        name.as_str(),
                    );
                    dropped_ids.insert(id);
                }
            }
            continue;
        }
        if (lower.ends_with(".svg") || media.contains("svg")) && svg::looks_like_svg(data) {
            match svg::rebuild(data, policy, &mut budget, findings, &name) {
                Ok(bytes) => {
                    keep.insert(name.clone(), (name.clone(), Kind::Metafile(bytes)));
                }
                Err(e) => {
                    findings.add(
                        "svg",
                        Severity::Medium,
                        format!("SVG 제외: {e}"),
                        name.as_str(),
                    );
                    dropped_ids.insert(id);
                }
            }
            continue;
        }
        if metafile::sniff(data).is_some() {
            match metafile::rebuild(data, policy, &mut budget, &mut metafiles) {
                Ok((bytes, _)) => {
                    keep.insert(name.clone(), (name.clone(), Kind::Metafile(bytes)));
                }
                Err(e) => {
                    findings.add(
                        "metafile",
                        Severity::Medium,
                        format!("메타파일 제외: {e}"),
                        name.as_str(),
                    );
                    dropped_ids.insert(id);
                }
            }
            continue;
        }
        let (cat, sev, desc) = if data.starts_with(crate::detect::OLE_MAGIC) {
            ("embedded-object", Severity::High, "OLE 개체")
        } else if data.starts_with(b"MZ") || data.starts_with(b"\x7fELF") {
            ("executable", Severity::Critical, "실행 파일")
        } else if lower.starts_with("bindata/") {
            (
                "binary-part",
                Severity::Medium,
                "재조합할 수 없는 바이너리 데이터(글꼴·OLE 등)",
            )
        } else {
            ("unlisted-part", Severity::Low, "허용 목록 외 항목")
        };
        findings.add(
            cat,
            sev,
            format!("{desc} - 새 문서에 조립하지 않음"),
            name.as_str(),
        );
        dropped_ids.insert(id);
    }

    metafiles.report(findings, manifest_name);

    for fixed in FIXED_PARTS {
        if let Some(e) = files.get(&fixed.to_ascii_lowercase()) {
            keep.insert(e.name.clone(), (e.name.clone(), Kind::Xml));
            reported.insert(e.name.to_ascii_lowercase());
        }
    }
    for (lower, e) in &files {
        if lower.starts_with("chart/") && lower.ends_with(".xml") {
            keep.insert(e.name.clone(), (e.name.clone(), Kind::Xml));
            reported.insert(lower.clone());
        }
        if lower.starts_with("preview/") {
            reported.insert(lower.clone());
            if lower.ends_with(".txt") {
                keep.insert(e.name.clone(), (e.name.clone(), Kind::Text));
            } else if let Some(k) = ImageKind::sniff(&e.data) {
                // 재인코딩 결과 형식(BMP → PNG 등)에 맞춰 확장자를 정한다
                if let Ok((bytes, out_kind)) = imaging::reencode(&e.data, k, policy) {
                    keep.insert(
                        e.name.clone(),
                        (
                            replace_ext(&e.name, out_kind.extension()),
                            Kind::Image(bytes),
                        ),
                    );
                }
            }
        }
    }
    if !keep
        .keys()
        .any(|k| k.to_ascii_lowercase().starts_with("contents/section"))
    {
        return blocked("structure", "본문 섹션(Contents/section*.xml) 없음");
    }

    // 조립하지 않은 원본 파일 보고
    for (lower, e) in &files {
        if lower == "mimetype" || lower == "contents/content.hpf" || reported.contains(lower) {
            continue;
        }
        if lower.starts_with("scripts/") {
            report_script(findings, &e.name, &e.data);
            continue;
        }
        if lower.starts_with("chart/") && lower.ends_with(".xml") {
            continue; // 차트는 매니페스트가 아닌 본문에서 참조되며 아래에서 조립된다
        }
        let (cat, sev, desc) = {
            (
                "orphan-part",
                Severity::Low,
                "매니페스트에 없는 파일(은닉 데이터 가능)",
            )
        };
        findings.add(
            cat,
            sev,
            format!("{desc} - 새 문서에 조립하지 않음"),
            e.name.as_str(),
        );
    }

    // ------------------------------------------------------------ 2. 파트 재구성
    let kept_names: HashSet<String> = keep.values().map(|(o, _)| o.clone()).collect();
    let mut out: Vec<Entry> = vec![Entry {
        name: "mimetype".into(),
        data: MIMETYPE.to_vec(),
    }];

    let mut ctx = Ctx {
        policy,
        dropped_ids: &dropped_ids,
        notes: BTreeMap::new(),
        ancestors: Vec::new(),
    };
    rebuild_manifest(&mut manifest.root, &dropped_ids, &renamed, policy, &mut ctx);
    sanitize_root(&mut manifest.root, &mut ctx);
    ctx.flush(findings, manifest_name);
    out.push(Entry {
        name: manifest_name.into(),
        data: xml::serialize(&manifest),
    });

    for (name, (out_name, kind)) in &keep {
        let data = &files[&name.to_ascii_lowercase()].data;
        let bytes = match kind {
            Kind::Image(bytes) => {
                findings.count("images_reencoded", 1);
                bytes.clone()
            }
            Kind::Metafile(bytes) => bytes.clone(),
            Kind::Text => {
                let text = String::from_utf8_lossy(data);
                text.chars()
                    .filter(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
                    .collect::<String>()
                    .into_bytes()
            }
            Kind::Xml => {
                let mut doc = match xml::parse_counted(data, name, policy, &mut xml_nodes) {
                    Ok(d) => d,
                    Err(e)
                        if matches!(e.category(), "xxe" | "resource")
                            || name.to_ascii_lowercase().starts_with("contents/") =>
                    {
                        return Err(e)
                    }
                    Err(e) => {
                        findings.add(
                            "structure",
                            Severity::Medium,
                            format!("파트 제외: {e}"),
                            name.as_str(),
                        );
                        continue;
                    }
                };
                if !namespace_allowed(&doc.root.ns) {
                    findings.add(
                        "foreign-xml",
                        Severity::Low,
                        "허용되지 않은 네임스페이스 파트 제외",
                        name.as_str(),
                    );
                    continue;
                }
                let mut ctx = Ctx {
                    policy,
                    dropped_ids: &dropped_ids,
                    notes: BTreeMap::new(),
                    ancestors: Vec::new(),
                };
                let lower = name.to_ascii_lowercase();
                if lower == "meta-inf/manifest.xml" || lower == "meta-inf/container.xml" {
                    prune_file_entries(&mut doc.root, &kept_names);
                }
                sanitize_root(&mut doc.root, &mut ctx);
                ctx.flush(findings, name);
                xml::serialize(&doc)
            }
        };
        out.push(Entry {
            name: out_name.clone(),
            data: bytes,
        });
    }

    findings.count("output_parts", out.len() as u64);
    zipsafe::write_entries_with(&out, &["mimetype"])
}

fn collect_items(el: &Element, out: &mut Vec<(String, String, String, bool)>) {
    for c in el.child_elements() {
        if c.local == "item" {
            if let (Some(id), Some(href)) = (c.attr("id"), c.attr("href")) {
                let media = c.attr("media-type").unwrap_or("").to_ascii_lowercase();
                // 한컴 스키마의 철자(isEmbeded)와 올바른 철자 모두 확인
                let embedded = c
                    .attr("isEmbeded")
                    .or(c.attr("isEmbedded"))
                    .map(|v| v != "0")
                    .unwrap_or(true);
                out.push((id.to_string(), href.to_string(), media, embedded));
            }
        }
        collect_items(c, out);
    }
}

fn resolve_href(files: &HashMap<String, Entry>, href: &str) -> Option<String> {
    let href = href.trim().trim_start_matches('/');
    if href.split('/').any(|s| s == "..") {
        return None;
    }
    for cand in [href.to_string(), format!("Contents/{href}")] {
        if let Some(e) = files.get(&cand.to_ascii_lowercase()) {
            return Some(e.name.clone());
        }
    }
    None
}

fn replace_ext(name: &str, ext: &str) -> String {
    match name.rsplit_once('.') {
        Some((stem, _)) if !stem.ends_with('/') => format!("{stem}.{ext}"),
        _ => format!("{name}.{ext}"),
    }
}

/// 매니페스트에서 제외 항목을 지우고, 이름이 바뀐 항목의 경로와 메타데이터를 정리한다.
fn rebuild_manifest(
    root: &mut Element,
    dropped: &HashSet<String>,
    renamed: &HashMap<String, String>,
    policy: &Policy,
    ctx: &mut Ctx,
) {
    fn walk(
        el: &mut Element,
        dropped: &HashSet<String>,
        renamed: &HashMap<String, String>,
        strip: bool,
        ctx: &mut Ctx,
    ) {
        el.children.retain(|n| match n {
            Node::Element(c) if c.local == "item" => {
                !c.attr("id").is_some_and(|id| dropped.contains(id))
            }
            Node::Element(c) if c.local == "itemref" => {
                !c.attr("idref").is_some_and(|id| dropped.contains(id))
            }
            _ => true,
        });
        for n in el.children.iter_mut() {
            let Node::Element(c) = n else { continue };
            if c.local == "item" {
                if let Some(href) = c.attr("href").map(str::to_string) {
                    if let Some((_, new)) = renamed
                        .iter()
                        .find(|(old, _)| old.ends_with(href.trim_start_matches('/')))
                    {
                        c.set_attr("href", new);
                    }
                }
            }
            let is_author = (c.local == "meta"
                && matches!(c.attr("name"), Some("creator") | Some("lastsaveby")))
                || (c.local == "creator" && c.ns.starts_with("http://purl.org/dc/"));
            if strip && is_author && !c.text().is_empty() {
                ctx.note(
                    "metadata",
                    Severity::Info,
                    format!("문서 속성 제거({})", c.attr("name").unwrap_or(&c.local)),
                );
                c.set_text("");
            }
            walk(c, dropped, renamed, strip, ctx);
        }
    }
    walk(root, dropped, renamed, policy.strip_metadata, ctx);
}

/// META-INF 의 파일 목록에서 새 패키지에 없는 경로를 지운다.
fn prune_file_entries(root: &mut Element, kept: &HashSet<String>) {
    root.children.retain(|n| match n {
        Node::Element(c) if c.local == "file-entry" || c.local == "rootfile" => {
            let path = c.attr("full-path").unwrap_or("");
            path == "/"
                || path.is_empty()
                || path.eq_ignore_ascii_case("Contents/content.hpf")
                || kept.iter().any(|k| k.eq_ignore_ascii_case(path))
        }
        _ => true,
    });
    for n in root.children.iter_mut() {
        if let Node::Element(c) = n {
            prune_file_entries(c, kept);
        }
    }
}

// ----------------------------------------------------------------------------- 요소 재구성

struct Ctx<'a> {
    policy: &'a Policy,
    dropped_ids: &'a HashSet<String>,
    notes: BTreeMap<(&'static str, Severity, String), u32>,
    ancestors: Vec<String>,
}

impl Ctx<'_> {
    fn note(&mut self, cat: &'static str, sev: Severity, desc: impl Into<String>) {
        *self.notes.entry((cat, sev, desc.into())).or_default() += 1;
    }

    fn flush(&mut self, findings: &mut Findings, part: &str) {
        for ((cat, sev, desc), n) in std::mem::take(&mut self.notes) {
            let desc = if n > 1 {
                format!("{desc} ({n}건)")
            } else {
                desc
            };
            findings.add(cat, sev, desc, part);
        }
    }
}

enum Action {
    Keep,
    Remove,
    RemoveAncestor(&'static str),
}

fn sanitize_root(root: &mut Element, ctx: &mut Ctx) {
    sanitize_attrs(root, ctx);
    ctx.ancestors.push(root.local.clone());
    let children = std::mem::take(&mut root.children);
    root.children = rebuild(root, children, ctx).unwrap_or_default();
    ctx.ancestors.pop();
}

fn rebuild(
    parent: &Element,
    children: Vec<Node>,
    ctx: &mut Ctx,
) -> std::result::Result<Vec<Node>, &'static str> {
    let mut out = Vec::with_capacity(children.len());
    for node in children {
        match node {
            Node::Text(t) => out.push(Node::Text(t)),
            Node::Element(mut el) => match sanitize_element(&mut el, ctx) {
                Action::Keep => out.push(Node::Element(el)),
                Action::Remove => {}
                Action::RemoveAncestor(name) if parent.local == name => return Err(""),
                Action::RemoveAncestor(name) => return Err(name),
            },
        }
    }
    Ok(out)
}

/// 제거 대상이 특정 조상 안에 있으면 그 조상째, 아니면 자신만 제거한다.
fn remove_up_to(ctx: &Ctx, ancestor: &'static str) -> Action {
    if ctx.ancestors.iter().any(|a| a == ancestor) {
        Action::RemoveAncestor(ancestor)
    } else {
        Action::Remove
    }
}

fn sanitize_element(el: &mut Element, ctx: &mut Ctx) -> Action {
    if !namespace_allowed(&el.ns) {
        ctx.note(
            "foreign-xml",
            Severity::Low,
            format!("허용되지 않은 네임스페이스 요소 제거 ({})", el.ns),
        );
        return Action::Remove;
    }
    match el.local.as_str() {
        "ole" => {
            ctx.note("embedded-object", Severity::High, "OLE 개체 요소 제거");
            return Action::Remove;
        }
        "video" => {
            ctx.note("rich-media", Severity::Medium, "동영상 개체 제거");
            return Action::Remove;
        }
        _ => {}
    }

    // 제외된 바이너리 항목 참조
    if let Some(id) = el.attr("binaryItemIDRef").map(str::to_string) {
        if ctx.dropped_ids.contains(&id) {
            if el.local == "font" {
                el.remove_attr_if(|a| a.local == "binaryItemIDRef");
                el.set_attr("isEmbedded", "0");
                ctx.note("embedded-font", Severity::Low, "임베디드 글꼴 참조 제거");
            } else {
                return remove_up_to(ctx, "pic");
            }
        }
    }

    if el.local == "fieldBegin"
        && el
            .attr("type")
            .is_some_and(|t| t.eq_ignore_ascii_case("HYPERLINK"))
    {
        neutralize_hyperlink(el, ctx);
    }

    sanitize_attrs(el, ctx);

    ctx.ancestors.push(el.local.clone());
    let children = std::mem::take(&mut el.children);
    let result = rebuild(el, children, ctx);
    ctx.ancestors.pop();
    match result {
        Ok(c) => el.children = c,
        Err("") => return Action::Remove,
        Err(name) => return Action::RemoveAncestor(name),
    }
    Action::Keep
}

/// 하이퍼링크 필드의 대상(Path/Command 매개변수)이 허용되지 않으면 비운다.
fn neutralize_hyperlink(el: &mut Element, ctx: &mut Ctx) {
    fn params<'e>(el: &'e mut Element, out: &mut Vec<&'e mut Element>) {
        for n in el.children.iter_mut() {
            if let Node::Element(c) = n {
                if c.local == "stringParam"
                    && matches!(c.attr("name"), Some("Path") | Some("Command"))
                {
                    out.push(c);
                } else {
                    params(c, out);
                }
            }
        }
    }
    let mut found = Vec::new();
    params(el, &mut found);
    // Path 와 Command 를 모두 검사한다 (한글은 Command 를 따라가므로 Path 만 보면 우회된다)
    let mut worst: Option<(String, bool)> = None;
    for p in &found {
        let target = normalize_link(&p.text());
        if target.is_empty() || target.starts_with('#') {
            continue; // 문서 내 책갈피 이동
        }
        let permitted = ctx.policy.uri_allowed(&target);
        if !permitted || ctx.policy.remove_hyperlinks {
            let dangerous = !permitted;
            if worst.as_ref().is_none_or(|(_, d)| dangerous && !d) {
                worst = Some((target, dangerous));
            }
        }
    }
    if let Some((target, dangerous)) = worst {
        let (cat, sev) = if dangerous {
            ("dangerous-link", Severity::High)
        } else {
            ("hyperlink", Severity::Low)
        };
        for p in found {
            p.set_text("");
        }
        ctx.note(
            cat,
            sev,
            format!("하이퍼링크 대상 제거: {}", truncate(&target, 120)),
        );
    }
}

fn sanitize_attrs(el: &mut Element, ctx: &mut Ctx) {
    let mut removed = Vec::new();
    el.attrs.retain(|a| {
        if a.is_xmlns() {
            return true;
        }
        if !namespace_allowed(&a.ns) {
            removed.push(format!(
                "허용되지 않은 네임스페이스 속성 제거 ({})",
                a.qname
            ));
            return false;
        }
        if a.ns == XML_NS && a.local == "base" {
            removed.push("xml:base 속성 제거".into());
            return false;
        }
        // 네임스페이스 식별자 URI(hp:required-namespace, rdf:resource 등)는 자원 참조가 아니다
        let identifier =
            !a.value.is_empty() && namespace_allowed(a.value.split('#').next().unwrap_or(""));
        if a.local != "href" && !identifier && value_is_external(&a.value) {
            removed.push(format!(
                "외부 경로를 가리키는 속성 제거 ({}={})",
                a.qname,
                truncate(&a.value, 80)
            ));
            return false;
        }
        true
    });
    for r in removed {
        ctx.note("external-resource", Severity::Medium, r);
    }
}

/// 한컴 하이퍼링크 경로("http\\://x;1;0;0;", "www.daum.net|-")를 URI 로 정규화한다.
pub(crate) fn normalize_link(raw: &str) -> String {
    let v = raw.replace("\\:", ":");
    let v = v.split([';', '|']).next().unwrap_or("").trim().to_string();
    if v.is_empty() || v.contains(':') || v.starts_with('#') {
        return v;
    }
    // 스킴 없이 저장된 웹 주소 (예: www.daum.net/path)
    let host = v.split(['/', '?', '#']).next().unwrap_or("");
    let is_domain = host.contains('.')
        && !host.starts_with('.')
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
    if is_domain {
        format!("http://{v}")
    } else {
        v
    }
}

/// C:\ 경로, UNC, 상대 상위 경로 등 패키지 밖 로컬 경로인지
fn looks_like_local_path(href: &str) -> bool {
    let b = href.as_bytes();
    (b.len() > 2 && b[0].is_ascii_alphabetic() && b[1] == b':')
        || href.starts_with("\\\\")
        || href.contains('\\')
}

/// 스크립트를 보고한다. 한컴이 모든 문서에 넣는 빈 기본 템플릿은 Info 로 구분한다.
pub(crate) fn report_script(findings: &mut Findings, name: &str, data: &[u8]) {
    report_script_text(findings, name, &decode_script(data));
}

pub(crate) fn report_script_text(findings: &mut Findings, name: &str, text: &str) {
    if text_is_default_script(text) {
        findings.add(
            "script",
            Severity::Info,
            "기본 스크립트 템플릿(실행 코드 없음) - 새 문서에 조립하지 않음",
            name,
        );
    } else {
        findings.add(
            "macro",
            Severity::Critical,
            "문서 스크립트(JScript 매크로) - 새 문서에 조립하지 않음",
            name,
        );
    }
}

fn decode_script(data: &[u8]) -> String {
    let utf16 = |bytes: &[u8], le: bool| {
        let units: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| {
                if le {
                    u16::from_le_bytes(*c)
                } else {
                    u16::from_be_bytes(*c)
                }
            })
            .collect();
        String::from_utf16_lossy(&units)
    };
    if let Some(rest) = data.strip_prefix(b"\xff\xfe") {
        utf16(rest, true)
    } else if let Some(rest) = data.strip_prefix(b"\xfe\xff") {
        utf16(rest, false)
    } else if data.len() >= 2 && data[1] == 0 {
        utf16(data, true)
    } else {
        String::from_utf8_lossy(data.strip_prefix(b"\xef\xbb\xbf").unwrap_or(data)).into_owned()
    }
}

fn text_is_default_script(text: &str) -> bool {
    // 주석 제거
    let mut code = String::new();
    let mut rest = text;
    while !rest.is_empty() {
        if let Some(r) = rest.strip_prefix("//") {
            rest = r.find('\n').map(|i| &r[i..]).unwrap_or("");
        } else if let Some(r) = rest.strip_prefix("/*") {
            rest = r.find("*/").map(|i| &r[i + 2..]).unwrap_or("");
        } else {
            let c = rest.chars().next().unwrap();
            if !c.is_whitespace() {
                code.push(c);
            }
            rest = &rest[c.len_utf8()..];
        }
    }
    let mut code = code.replace(
        "varDocuments=XHwpDocuments;varDocument=Documents.Active_XHwpDocument;",
        "",
    );
    // 빈 이벤트 처리기 function OnXxx(){} 제거
    while let Some(start) = code.find("function") {
        let after = &code[start + "function".len()..];
        let name_len = after
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .count();
        if name_len > 0 && after[name_len..].starts_with("(){}") {
            code.replace_range(start..start + "function".len() + name_len + 4, "");
        } else {
            break;
        }
    }
    code.is_empty()
}
