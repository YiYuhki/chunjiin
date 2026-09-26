//! OOXML 파트 XML 재조합: 허용 네임스페이스·요소·관계 ID 만으로 트리를 다시 구성한다.

use std::collections::{BTreeMap, HashSet};

use super::rules::{self, DocKind};
use crate::policy::Policy;
use crate::report::{Findings, Severity};
use crate::xml::{Element, Node, XML_NS};

enum Action {
    Keep,
    Remove,
    Unwrap,
    /// 지정한 이름의 조상 요소까지 통째로 제거
    RemoveAncestor(&'static str),
}

/// 자식 요소가 모두 사라지면 함께 제거할 컨테이너
const EMPTY_CONTAINERS: &[&str] = &[
    "externalReferences",
    "hyperlinks",
    "oleObjects",
    "controls",
    "AlternateContent",
    "Choice",
    "Fallback",
    "definedNames",
    "embeddedFontLst",
    "custDataLst",
    "webPublishItems",
];

const DANGEROUS_FIELDS: &[&str] = &[
    "DDE",
    "DDEAUTO",
    "INCLUDETEXT",
    "INCLUDEPICTURE",
    "INCLUDE",
    "IMPORT",
    "LINK",
    // MACROBUTTON 은 표시 텍스트가 필드 코드 안에 있고 매크로를 모두 제거한 뒤에는
    // 실행할 대상이 없으므로 무력화하지 않는다
];

const DANGEROUS_FORMULA_FUNCS: &[&str] = &[
    "CALL",
    "REGISTER",
    "REGISTER.ID",
    "EXEC",
    "WEBSERVICE",
    "FILTERXML",
    "RTD",
];

use crate::xml::value_is_external as attr_is_external;

pub struct Ctx<'a> {
    pub kind: DocKind,
    pub part: &'a str,
    pub valid_ids: &'a HashSet<String>,
    pub policy: &'a Policy,
    notes: BTreeMap<(&'static str, Severity, String), u32>,
    /// 현재 요소의 조상 이름 (조상 제거 요청이 실제 조상이 있을 때만 올라가도록)
    ancestors: Vec<String>,
}

impl<'a> Ctx<'a> {
    pub fn new(
        kind: DocKind,
        part: &'a str,
        valid_ids: &'a HashSet<String>,
        policy: &'a Policy,
    ) -> Self {
        Ctx {
            kind,
            part,
            valid_ids,
            policy,
            notes: BTreeMap::new(),
            ancestors: Vec::new(),
        }
    }

    fn note(&mut self, cat: &'static str, sev: Severity, desc: impl Into<String>) {
        *self.notes.entry((cat, sev, desc.into())).or_default() += 1;
    }

    pub fn flush(self, findings: &mut Findings) {
        for ((cat, sev, desc), n) in self.notes {
            let desc = if n > 1 {
                format!("{desc} ({n}건)")
            } else {
                desc
            };
            findings.add(cat, sev, desc, self.part);
        }
    }
}

pub fn sanitize_part(root: &mut Element, ctx: &mut Ctx) {
    if ctx.kind == DocKind::Word {
        neutralize_word_fields(root, ctx);
    }
    // 루트는 제거하지 않는다 (필요 시 파트 단위로 제외됨)
    let children = std::mem::take(&mut root.children);
    root.children = rebuild_children(root, children, ctx).unwrap_or_default();
    sanitize_attrs(root, ctx);
    let lower = ctx.part.to_ascii_lowercase();
    if ctx.policy.strip_metadata || lower.ends_with("app.xml") {
        strip_metadata(root, &lower, ctx);
    }
}

/// 자식 목록을 재구성한다. 조상 제거 요청이 올라오면 Err 로 전달한다.
fn rebuild_children(
    parent: &Element,
    children: Vec<Node>,
    ctx: &mut Ctx,
) -> Result<Vec<Node>, &'static str> {
    let mut out = Vec::with_capacity(children.len());
    for node in children {
        match node {
            Node::Text(t) => out.push(Node::Text(t)),
            Node::Element(mut el) => match sanitize_element(&mut el, ctx) {
                Action::Keep => out.push(Node::Element(el)),
                Action::Remove => {}
                Action::Unwrap => out.extend(el.children),
                Action::RemoveAncestor(name) => {
                    if parent.local == name {
                        return Err("__remove_self__");
                    }
                    return Err(name);
                }
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
    // 1) 네임스페이스 허용 목록
    if !rules::namespace_allowed(&el.ns) {
        ctx.note(
            "foreign-xml",
            Severity::Low,
            format!("허용되지 않은 네임스페이스 요소 제거 ({})", el.ns),
        );
        return Action::Remove;
    }

    // 2) 위험 요소
    if let Some(action) = deny_rule(el, ctx) {
        return action;
    }

    // 3) 관계 ID 참조 확인: 재조합에 포함되지 않은 대상을 가리키면 요소를 정리한다
    let mut dangling = false;
    el.attrs.retain(|a| {
        if rules::is_rel_attr_ns(&a.ns) && !a.value.is_empty() && !ctx.valid_ids.contains(&a.value)
        {
            if el.local == "blip" {
                return false; // 이미지 참조만 제거하고 요소는 유지
            }
            dangling = true;
        }
        true
    });
    if dangling {
        return match el.local.as_str() {
            "hyperlink" if el.has_element_children() => Action::Unwrap,
            "oleObj" => remove_up_to(ctx, "graphicFrame"),
            _ => Action::Remove,
        };
    }

    // 4) 형식별 규칙
    if ctx.kind == DocKind::Word && rules::is_word_ns(&el.ns) && el.local == "fldSimple" {
        let code = el.attr("instr").unwrap_or("").to_string();
        if field_is_dangerous(&code, false) {
            ctx.note(
                "dde",
                Severity::High,
                format!("위험 필드 코드 무력화: {}", truncate(code.trim(), 100)),
            );
            return Action::Unwrap;
        }
    }
    if ctx.kind == DocKind::Excel && rules::is_sheet_ns(&el.ns) {
        if el.local == "f" && formula_is_dangerous(&el.text()) {
            ctx.note(
                "dde",
                Severity::High,
                format!(
                    "위험 수식 제거(캐시 값 유지): ={}",
                    truncate(&el.text(), 100)
                ),
            );
            return Action::Remove;
        }
        if el.local == "definedName" {
            let name = el.attr("name").unwrap_or("").to_ascii_lowercase();
            let name = name.trim_start_matches("_xlnm.");
            if [
                "auto_open",
                "auto_close",
                "auto_activate",
                "auto_deactivate",
            ]
            .iter()
            .any(|p| name.starts_with(p))
            {
                ctx.note(
                    "auto-exec",
                    Severity::High,
                    format!("자동 실행 이름 제거: {}", el.attr("name").unwrap_or("")),
                );
                return Action::Remove;
            }
        }
    }
    if let Some(action) = el.attr("action") {
        let a = action.to_ascii_lowercase();
        if ["ppaction://program", "ppaction://macro", "ppaction://ole"]
            .iter()
            .any(|p| a.starts_with(p))
        {
            ctx.note(
                "auto-exec",
                Severity::High,
                format!("프로그램/매크로 실행 액션 제거: {}", truncate(action, 80)),
            );
            return Action::Remove;
        }
    }

    // 5) 속성
    sanitize_attrs(el, ctx);

    // 6) 자식 재구성
    let children = std::mem::take(&mut el.children);
    ctx.ancestors.push(el.local.clone());
    let rebuilt = rebuild_children(el, children, ctx);
    ctx.ancestors.pop();
    match rebuilt {
        Ok(c) => el.children = c,
        Err("__remove_self__") => return Action::Remove,
        Err(name) => return Action::RemoveAncestor(name),
    }

    // 7) 빈 컨테이너 정리
    if EMPTY_CONTAINERS.contains(&el.local.as_str()) && !el.has_element_children() {
        return Action::Remove;
    }
    Action::Keep
}

fn deny_rule(el: &Element, ctx: &mut Ctx) -> Option<Action> {
    let l = el.local.as_str();
    if rules::is_word_ns(&el.ns) {
        let (sev, desc) = match l {
            "altChunk" => (Severity::Medium, "altChunk 삽입 콘텐츠"),
            "subDoc" => (Severity::High, "하위 문서 참조"),
            "attachedTemplate" => (Severity::High, "첨부 템플릿 참조"),
            "docVars" => (Severity::Low, "문서 변수(docVars)"),
            "mailMerge" => (Severity::Medium, "메일 병합 데이터 원본(외부 쿼리)"),
            "control" => (Severity::High, "ActiveX 컨트롤"),
            "objectEmbed" | "objectLink" => (Severity::High, "OLE 개체"),
            "movie" => (Severity::Medium, "동영상 개체"),
            "frameset" => (Severity::High, "프레임셋"),
            "embedRegular" | "embedBold" | "embedItalic" | "embedBoldItalic" => {
                (Severity::Low, "임베디드 글꼴 참조")
            }
            _ => return None,
        };
        ctx.note("active-content", sev, format!("{desc} 요소 제거"));
        return Some(Action::Remove);
    }
    if el.ns == rules::VML_OFFICE_NS && l == "OLEObject" {
        ctx.note(
            "embedded-object",
            Severity::High,
            "OLE 개체 요소 제거(미리보기 그림 유지)",
        );
        return Some(Action::Remove);
    }
    if rules::is_pres_ns(&el.ns) {
        return match l {
            "oleObj" => {
                ctx.note("embedded-object", Severity::High, "OLE 개체 프레임 제거");
                Some(remove_up_to(ctx, "graphicFrame"))
            }
            "control" | "controls" => {
                ctx.note("activex", Severity::High, "ActiveX 컨트롤 제거");
                Some(Action::Remove)
            }
            "embeddedFont" | "embeddedFontLst" => {
                ctx.note("embedded-font", Severity::Low, "임베디드 글꼴 제거");
                Some(Action::Remove)
            }
            _ => None,
        };
    }
    if rules::is_sheet_ns(&el.ns) {
        let (cat, sev, desc) = match l {
            "oleObjects" | "oleObject" => ("embedded-object", Severity::High, "OLE 개체"),
            "controls" | "control" => ("activex", Severity::High, "ActiveX 컨트롤"),
            "webPublishItems" => ("external-resource", Severity::Low, "웹 게시 항목"),
            "externalReferences" => ("external-link", Severity::Medium, "외부 통합 문서 참조"),
            _ => return None,
        };
        ctx.note(cat, sev, format!("{desc} 요소 제거"));
        return Some(Action::Remove);
    }
    None
}

fn sanitize_attrs(el: &mut Element, ctx: &mut Ctx) {
    let mut removed: Vec<String> = Vec::new();
    el.attrs.retain(|a| {
        if a.is_xmlns() {
            return true;
        }
        if !rules::namespace_allowed(&a.ns) {
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
        // 확장 요소의 식별자(ext uri="...")는 자원 참조가 아니다
        if a.local != "uri" && attr_is_external(&a.value) {
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

fn strip_metadata(root: &mut Element, lower_part: &str, ctx: &mut Ctx) {
    let targets: &[&str] = if lower_part.ends_with("core.xml") {
        &["creator", "lastModifiedBy", "lastPrinted"]
    } else if lower_part.ends_with("app.xml") {
        if ctx.policy.strip_metadata {
            &["Company", "Manager", "HyperlinkBase"]
        } else {
            &["HyperlinkBase"]
        }
    } else {
        return;
    };
    for node in root.children.iter_mut() {
        if let Node::Element(e) = node {
            if targets.contains(&e.local.as_str()) && !e.text().is_empty() {
                ctx.note(
                    "metadata",
                    Severity::Info,
                    format!("문서 속성 제거({})", e.local),
                );
                e.set_text("");
            }
        }
    }
    root.children
        .retain(|n| !matches!(n, Node::Element(e) if e.local == "HyperlinkBase"));
}

// ----------------------------------------------------------------------------- Word 필드

struct FieldFrame {
    own_code: String,
    starts_with_nested: bool,
    instr_ids: Vec<usize>,
}

/// 복합 필드(fldChar begin/separate/end)를 문서 순서로 추적하여 위험 필드의 코드를 비운다.
/// 필드 코드가 여러 run 으로 쪼개지거나(DD + EAUTO) 중첩 필드로 키워드를 만드는 난독화도 처리한다.
fn neutralize_word_fields(root: &mut Element, ctx: &mut Ctx) {
    let mut stack: Vec<FieldFrame> = Vec::new();
    let mut dangerous: HashSet<usize> = HashSet::new();
    let mut counter = 0usize;
    let mut reports: Vec<String> = Vec::new();
    scan_fields(root, &mut stack, &mut dangerous, &mut counter, &mut reports);
    if dangerous.is_empty() {
        return;
    }
    for r in reports {
        ctx.note(
            "dde",
            Severity::High,
            format!("위험 필드 코드 무력화: {}", truncate(r.trim(), 100)),
        );
    }
    let mut counter = 0usize;
    blank_fields(root, &dangerous, &mut counter);
}

fn scan_fields(
    el: &Element,
    stack: &mut Vec<FieldFrame>,
    dangerous: &mut HashSet<usize>,
    counter: &mut usize,
    reports: &mut Vec<String>,
) {
    for node in &el.children {
        let Node::Element(c) = node else { continue };
        if rules::is_word_ns(&c.ns) {
            match c.local.as_str() {
                "fldChar" => match c.attr("fldCharType") {
                    Some("begin") => {
                        if let Some(top) = stack.last_mut() {
                            if top.own_code.trim().is_empty() {
                                top.starts_with_nested = true;
                            }
                        }
                        stack.push(FieldFrame {
                            own_code: String::new(),
                            starts_with_nested: false,
                            instr_ids: Vec::new(),
                        });
                    }
                    Some("end") => {
                        if let Some(frame) = stack.pop() {
                            if field_is_dangerous(&frame.own_code, frame.starts_with_nested) {
                                reports.push(if frame.own_code.trim().is_empty() {
                                    "(중첩 필드로 생성된 필드 코드)".to_string()
                                } else {
                                    frame.own_code.clone()
                                });
                                dangerous.extend(frame.instr_ids.iter().copied());
                            }
                            // 바깥 필드도 안쪽 instrText 를 함께 비울 수 있도록 전달
                            if let Some(parent) = stack.last_mut() {
                                parent.instr_ids.extend(frame.instr_ids);
                            }
                        }
                    }
                    _ => {}
                },
                "instrText" | "delInstrText" => {
                    let id = *counter;
                    *counter += 1;
                    if let Some(top) = stack.last_mut() {
                        top.own_code.push_str(&c.text());
                        top.instr_ids.push(id);
                    }
                    continue;
                }
                _ => {}
            }
        }
        scan_fields(c, stack, dangerous, counter, reports);
    }
}

fn blank_fields(el: &mut Element, dangerous: &HashSet<usize>, counter: &mut usize) {
    for node in el.children.iter_mut() {
        let Node::Element(c) = node else { continue };
        if rules::is_word_ns(&c.ns) && (c.local == "instrText" || c.local == "delInstrText") {
            if dangerous.contains(counter) {
                c.set_text("");
            }
            *counter += 1;
            continue;
        }
        blank_fields(c, dangerous, counter);
    }
}

pub(crate) fn field_is_dangerous(code: &str, starts_with_nested: bool) -> bool {
    if starts_with_nested {
        return true;
    }
    let first = code
        .split(|c: char| !c.is_ascii_alphanumeric())
        .find(|t| !t.is_empty())
        .unwrap_or("")
        .to_ascii_uppercase();
    DANGEROUS_FIELDS.contains(&first.as_str())
}

// ----------------------------------------------------------------------------- Excel 수식

fn formula_is_dangerous(formula: &str) -> bool {
    // 문자열 리터럴 제거
    let mut plain = String::with_capacity(formula.len());
    let mut in_str = false;
    for c in formula.chars() {
        if c == '"' {
            in_str = !in_str;
            continue;
        }
        if !in_str {
            plain.push(c.to_ascii_uppercase());
        }
    }
    // DDE: 앱|'토픽'!항목
    if plain.contains('|') {
        return true;
    }
    for func in DANGEROUS_FORMULA_FUNCS {
        let mut start = 0;
        while let Some(pos) = plain[start..].find(func) {
            let idx = start + pos;
            let before = plain[..idx].chars().last();
            let after = plain[idx + func.len()..].trim_start().chars().next();
            let boundary =
                before.is_none_or(|b| !(b.is_ascii_alphanumeric() || b == '_' || b == '.'));
            if boundary && after == Some('(') {
                return true;
            }
            start = idx + func.len();
        }
    }
    false
}

pub fn truncate(s: &str, max: usize) -> String {
    let mut out: String = s.chars().take(max).collect();
    if s.chars().count() > max {
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formulas() {
        assert!(formula_is_dangerous("cmd|'/c calc'!A0"));
        assert!(formula_is_dangerous("WEBSERVICE(\"http://x\")"));
        assert!(formula_is_dangerous("CALL (\"x\")"));
        assert!(!formula_is_dangerous("SUM(A1:A3)"));
        assert!(!formula_is_dangerous("\"a|b\"&A1"));
        assert!(!formula_is_dangerous("RECALL(1)"));
    }

    #[test]
    fn fields() {
        assert!(field_is_dangerous(" DDEAUTO c:\\x", false));
        assert!(field_is_dangerous("includePicture \"http://x\"", false));
        assert!(!field_is_dangerous(" HYPERLINK \"http://x/link\" ", false));
        assert!(!field_is_dangerous(" PAGE ", false));
        assert!(field_is_dangerous("  \"c:\\cmd\" ", true));
    }

    #[test]
    fn external_attrs() {
        assert!(attr_is_external("file:///c:/x"));
        assert!(attr_is_external("\\\\10.0.0.1\\share"));
        assert!(attr_is_external("ms-msdt:/id x"));
        assert!(!attr_is_external("MS Gothic"));
        assert!(!attr_is_external("ppaction://hlinkshowjump?jump=nextslide"));
        assert!(!attr_is_external("image1.png"));
    }
}
