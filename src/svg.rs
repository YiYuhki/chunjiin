//! SVG 재조합.
//!
//! SVG 는 XML 로 된 벡터 그림이지만 스크립트(`<script>`, `onload` 등 이벤트 처리기), 외부 자원
//! (`href`, CSS `url()`·`@import`), HTML 삽입(`<foreignObject>`), 애니메이션으로 속성을 바꾸는
//! 우회(`<set attributeName="href">`)를 담을 수 있다. XML 로 해석한 뒤 **허용 목록의 요소·속성만**
//! 새 문서에 다시 쓴다.
//!
//! - 참조(`href`, `url()`)는 문서 안(`#id`)만 허용한다. 내장 래스터 그림(`data:image/...`)은
//!   픽셀만 재인코딩하고, 그 밖의 `<image>` 는 옮기지 않는다
//! - CSS(`style` 속성, `<style>`)는 외부 참조·확장 문법이 없을 때만 옮긴다
//! - 알 수 없는 네임스페이스(편집기 정보 등)의 요소·속성, 주석·처리 명령은 옮기지 않는다
//! - DOCTYPE 은 내부 부분 집합(엔터티 선언)이 없을 때만 무시하고, 있으면 차단한다

use std::collections::{HashMap, HashSet};

use base64::Engine as _;

use crate::error::{blocked, Result};
use crate::imaging::{self, ImageKind};
use crate::legacy::blip::PixelBudget;
use crate::policy::Policy;
use crate::report::{Findings, Severity};
use crate::xml::{self, Attr, Document, Element, Node};

pub const SVG_NS: &str = "http://www.w3.org/2000/svg";
const XLINK_NS: &str = "http://www.w3.org/1999/xlink";

/// 옮기는 요소
const ELEMENTS: &[&str] = &[
    "svg",
    "g",
    "defs",
    "symbol",
    "use",
    "title",
    "desc",
    "path",
    "rect",
    "circle",
    "ellipse",
    "line",
    "polyline",
    "polygon",
    "text",
    "tspan",
    "textPath",
    "linearGradient",
    "radialGradient",
    "stop",
    "pattern",
    "clipPath",
    "mask",
    "marker",
    "image",
    "style",
    "filter",
    "feBlend",
    "feColorMatrix",
    "feComponentTransfer",
    "feFuncR",
    "feFuncG",
    "feFuncB",
    "feFuncA",
    "feComposite",
    "feFlood",
    "feGaussianBlur",
    "feMerge",
    "feMergeNode",
    "feMorphology",
    "feOffset",
    "feDropShadow",
    "feTile",
    "feImage",
    "switch",
];

/// 자식만 남기고 요소 자체는 옮기지 않는 것 (링크)
const UNWRAP: &[&str] = &["a"];

/// 옮기는 속성 (네임스페이스 없음)
const ATTRS: &[&str] = &[
    "id",
    "class",
    "style",
    "transform",
    "x",
    "y",
    "x1",
    "y1",
    "x2",
    "y2",
    "cx",
    "cy",
    "r",
    "rx",
    "ry",
    "fx",
    "fy",
    "fr",
    "width",
    "height",
    "d",
    "points",
    "pathLength",
    "viewBox",
    "preserveAspectRatio",
    "version",
    "baseProfile",
    "fill",
    "fill-opacity",
    "fill-rule",
    "stroke",
    "stroke-width",
    "stroke-linecap",
    "stroke-linejoin",
    "stroke-miterlimit",
    "stroke-dasharray",
    "stroke-dashoffset",
    "stroke-opacity",
    "opacity",
    "color",
    "display",
    "visibility",
    "overflow",
    "clip-path",
    "clip-rule",
    "mask",
    "filter",
    "marker-start",
    "marker-mid",
    "marker-end",
    "font-family",
    "font-size",
    "font-weight",
    "font-style",
    "font-variant",
    "font-stretch",
    "text-anchor",
    "dominant-baseline",
    "alignment-baseline",
    "baseline-shift",
    "letter-spacing",
    "word-spacing",
    "text-decoration",
    "writing-mode",
    "direction",
    "unicode-bidi",
    "dx",
    "dy",
    "rotate",
    "textLength",
    "lengthAdjust",
    "startOffset",
    "method",
    "spacing",
    "side",
    "offset",
    "stop-color",
    "stop-opacity",
    "gradientUnits",
    "gradientTransform",
    "spreadMethod",
    "patternUnits",
    "patternContentUnits",
    "patternTransform",
    "clipPathUnits",
    "maskUnits",
    "maskContentUnits",
    "markerUnits",
    "markerWidth",
    "markerHeight",
    "refX",
    "refY",
    "orient",
    "image-rendering",
    "shape-rendering",
    "text-rendering",
    "color-interpolation",
    "color-interpolation-filters",
    "paint-order",
    "vector-effect",
    "mix-blend-mode",
    "isolation",
    "filterUnits",
    "primitiveUnits",
    "in",
    "in2",
    "result",
    "stdDeviation",
    "mode",
    "operator",
    "k1",
    "k2",
    "k3",
    "k4",
    "values",
    "type",
    "tableValues",
    "slope",
    "intercept",
    "amplitude",
    "exponent",
    "flood-color",
    "flood-opacity",
    "radius",
    "requiredFeatures",
    "systemLanguage",
    "media",
];

/// 참조 속성(`href`)을 허용하는 요소: 문서 안 참조만
const LOCAL_HREF: &[&str] = &[
    "use",
    "textPath",
    "linearGradient",
    "radialGradient",
    "pattern",
    "filter",
    "feImage",
];

#[derive(Default)]
struct Stats {
    scripts: u64,
    external: u64,
    removed_elements: u64,
    removed_attrs: u64,
    images: u64,
    styles: u64,
}

struct Ctx<'a> {
    policy: &'a Policy,
    budget: &'a mut PixelBudget,
    stats: Stats,
    xlink_used: bool,
    error: Option<crate::error::CdrError>,
}

/// SVG 로 보이는지 (앞부분에 `<svg` 루트가 있는지)
pub fn looks_like_svg(data: &[u8]) -> bool {
    let data = data.strip_prefix(b"\xef\xbb\xbf").unwrap_or(data);
    let head = &data[..data.len().min(4096)];
    let Some(first) = head.iter().position(|c| !c.is_ascii_whitespace()) else {
        return false;
    };
    head[first] == b'<' && crate::detect::find(head, b"<svg").is_some()
}

/// DOCTYPE 선언을 걷어낸다. 내부 부분 집합(`[...]`, 엔터티 선언)이 있으면 차단.
fn strip_doctype(data: &[u8]) -> Result<Vec<u8>> {
    let Some(at) = crate::detect::find(data, b"<!DOCTYPE") else {
        return Ok(data.to_vec());
    };
    let Some(root) = crate::detect::find(data, b"<svg").filter(|&r| r > at) else {
        return blocked("xxe", "SVG 루트 뒤의 DOCTYPE");
    };
    let decl = &data[at..root];
    let Some(end) = decl.iter().position(|&c| c == b'>') else {
        return blocked("structure", "닫히지 않은 DOCTYPE");
    };
    if decl[..end].contains(&b'[') {
        return blocked("xxe", "DOCTYPE 내부 선언(엔터티) 포함");
    }
    let mut out = data[..at].to_vec();
    out.extend(&data[at + end + 1..]);
    Ok(out)
}

/// SVG 를 재조합한다. `budget` 은 내장 래스터 그림의 화소 예산.
pub fn rebuild(
    data: &[u8],
    policy: &Policy,
    budget: &mut PixelBudget,
    findings: &mut Findings,
    location: &str,
) -> Result<Vec<u8>> {
    let data = strip_doctype(data)?;
    let doc = xml::parse(&data, location, policy)?;
    let root = &doc.root;
    if root.local != "svg" || !(root.ns == SVG_NS || root.ns.is_empty()) {
        return blocked("structure", "SVG 루트 요소가 아님");
    }
    let mut ctx = Ctx {
        policy,
        budget,
        stats: Stats::default(),
        xlink_used: false,
        error: None,
    };
    let mut out = element(root, &mut ctx).expect("루트는 허용 요소");
    if let Some(e) = ctx.error.take() {
        return Err(e);
    }
    check_expansion(&out, policy)?;
    // 네임스페이스 선언은 새로 붙인다
    out.attrs.retain(|a| !a.is_xmlns());
    out.attrs.insert(0, attr_xmlns("xmlns", SVG_NS));
    if ctx.xlink_used {
        out.attrs.insert(1, attr_xmlns("xmlns:xlink", XLINK_NS));
    }
    report(&ctx.stats, findings, location);
    Ok(xml::serialize(&Document { root: out }))
}

/// 단독 SVG 파일 재조합 (엔진 진입점)
pub fn reassemble(data: &[u8], policy: &Policy, findings: &mut Findings) -> Result<Vec<u8>> {
    let mut budget = PixelBudget::new(policy);
    rebuild(data, policy, &mut budget, findings, "/")
}

fn attr_xmlns(qname: &str, value: &str) -> Attr {
    let local = qname.split_once(':').map_or("", |(_, l)| l);
    Attr {
        qname: qname.into(),
        ns: xml::XMLNS_NS.into(),
        local: local.into(),
        value: value.into(),
    }
}

fn report(s: &Stats, findings: &mut Findings, location: &str) {
    if s.scripts > 0 {
        findings.add(
            "script",
            Severity::High,
            format!("SVG 스크립트·이벤트 처리기 {}개 제거", s.scripts),
            location,
        );
    }
    if s.external > 0 {
        findings.add(
            "external-resource",
            Severity::Medium,
            format!("SVG 외부 참조 {}개 제거 (href·CSS url·@import)", s.external),
            location,
        );
    }
    if s.removed_elements + s.removed_attrs + s.styles > 0 {
        findings.add(
            "svg",
            Severity::Low,
            format!(
                "SVG 허용 목록 밖 요소 {}개·속성 {}개·스타일 {}개를 옮기지 않음",
                s.removed_elements, s.removed_attrs, s.styles
            ),
            location,
        );
    }
    if s.images > 0 {
        findings.count("images_reencoded", s.images);
    }
}

fn is_svg(el: &Element) -> bool {
    el.ns == SVG_NS || el.ns.is_empty()
}

/// 요소를 재조합한다. 옮기지 않으면 None (링크처럼 자식만 남기는 요소는 `children` 이 처리)
fn element(el: &Element, ctx: &mut Ctx) -> Option<Element> {
    let local = el.local.as_str();
    if !is_svg(el) || !ELEMENTS.contains(&local) {
        return None;
    }
    let mut out = Element {
        qname: local.to_string(),
        ns: SVG_NS.to_string(),
        local: local.to_string(),
        attrs: Vec::new(),
        children: Vec::new(),
    };
    for a in &el.attrs {
        if a.is_xmlns() {
            continue;
        }
        if let Some(v) = attribute(el, a, ctx) {
            out.attrs.push(v);
        }
    }
    if local == "image" {
        // 문서 안 래스터 그림만: 없으면 요소를 옮기지 않는다
        if !out.attrs.iter().any(|a| a.local == "href") {
            ctx.stats.removed_elements += 1;
            return None;
        }
        return Some(out);
    }
    if local == "style" {
        let css = el.text();
        if !css_is_safe(&css) {
            ctx.stats.styles += 1;
            if css_is_external(&css) {
                ctx.stats.external += 1;
            }
            return None;
        }
        out.children.push(Node::Text(css));
        return Some(out);
    }
    out.children = children(&el.children, ctx);
    Some(out)
}

fn children(nodes: &[Node], ctx: &mut Ctx) -> Vec<Node> {
    let mut out = Vec::with_capacity(nodes.len());
    for n in nodes {
        match n {
            Node::Text(t) => out.push(Node::Text(t.clone())),
            Node::Element(c) => {
                if is_svg(c) && UNWRAP.contains(&c.local.as_str()) {
                    if c.attrs.iter().any(|a| a.local == "href") {
                        ctx.stats.external += 1;
                    }
                    out.extend(children(&c.children, ctx));
                    continue;
                }
                match element(c, ctx) {
                    Some(e) => out.push(Node::Element(e)),
                    None if is_svg(c) && c.local == "script" => ctx.stats.scripts += 1,
                    None if matches!(c.local.as_str(), "image" | "style") && is_svg(c) => {}
                    None => ctx.stats.removed_elements += 1,
                }
            }
        }
    }
    out
}

/// 속성 하나를 검증한다. 옮기지 않으면 None.
fn attribute(el: &Element, a: &Attr, ctx: &mut Ctx) -> Option<Attr> {
    let local = a.local.as_str();
    if a.ns.is_empty() && local.to_ascii_lowercase().starts_with("on") {
        ctx.stats.scripts += 1;
        return None;
    }
    let plain = |value: String| Attr {
        qname: local.to_string(),
        ns: String::new(),
        local: local.to_string(),
        value,
    };
    if local == "href" && (a.ns.is_empty() || a.ns == XLINK_NS) {
        let value = a.value.trim();
        let kept = if matches!(el.local.as_str(), "image" | "feImage") && value.starts_with("data:")
        {
            embedded_image(value, ctx)
        } else if LOCAL_HREF.contains(&el.local.as_str()) && value.starts_with('#') {
            Some(value.to_string())
        } else {
            None
        };
        let Some(value) = kept else {
            if !value.starts_with('#') {
                ctx.stats.external += 1;
            } else {
                ctx.stats.removed_attrs += 1;
            }
            return None;
        };
        return Some(if a.ns == XLINK_NS {
            ctx.xlink_used = true;
            Attr {
                qname: "xlink:href".into(),
                ns: XLINK_NS.into(),
                local: "href".into(),
                value,
            }
        } else {
            plain(value)
        });
    }
    if a.ns == xml::XML_NS && local == "space" {
        return Some(a.clone());
    }
    if !a.ns.is_empty() || !ATTRS.contains(&local) {
        ctx.stats.removed_attrs += 1;
        return None;
    }
    if local == "style" {
        if css_is_safe(&a.value) {
            return Some(plain(a.value.clone()));
        }
        ctx.stats.styles += 1;
        if css_is_external(&a.value) {
            ctx.stats.external += 1;
        }
        return None;
    }
    if !value_is_safe(&a.value) {
        ctx.stats.external += 1;
        return None;
    }
    Some(plain(a.value.clone()))
}

/// 참조 사슬(use → use → …)을 따라가는 최대 깊이
const MAX_REF_DEPTH: usize = 16;

/// 값 안의 문서 안 참조 `url(#id)` 들
fn url_refs(v: &str, out: &mut Vec<String>) {
    let lower = v.to_ascii_lowercase();
    let mut at = 0;
    while let Some(i) = lower[at..].find("url(") {
        let start = at + i + 4;
        let arg = v[start..].trim_start().trim_start_matches(['"', '\'']);
        if let Some(id) = arg.strip_prefix('#') {
            let end = id.find(['"', '\'', ')', ' ']).unwrap_or(id.len());
            out.push(id[..end].to_string());
        }
        at = start;
    }
}

/// 요소 자신이 가리키는 id 들 (`href="#id"`, 속성·style 의 `url(#id)`)
fn element_refs(el: &Element, out: &mut Vec<String>) {
    for a in &el.attrs {
        if a.local == "href" {
            if let Some(id) = a.value.strip_prefix('#') {
                out.push(id.to_string());
            }
        } else {
            url_refs(&a.value, out);
        }
    }
}

struct Expansion<'a> {
    ids: HashMap<&'a str, &'a Element>,
    /// `<style>` 규칙이 가리키는 id: class 가 있는 요소마다 적용된다고 보고 넉넉히 센다
    style_refs: Vec<String>,
    memo: HashMap<&'a str, u64>,
    active: HashSet<&'a str>,
    depth: usize,
    too_deep: bool,
}

impl<'a> Expansion<'a> {
    fn collect(&mut self, el: &'a Element) {
        if let Some(id) = el.attr("id") {
            self.ids.entry(id).or_insert(el);
        }
        if el.local == "style" {
            url_refs(&el.text(), &mut self.style_refs);
        }
        for c in el.child_elements() {
            self.collect(c);
        }
    }

    /// 렌더러가 펼쳐 그리는 요소 수 (참조한 대상은 가리킬 때마다 다시 센다)
    fn weight(&mut self, el: &'a Element) -> u64 {
        // id 가 붙은 요소는 한 번만 센다 (중첩된 id 를 여러 번 다시 걷지 않도록)
        let key = el
            .attr("id")
            .and_then(|id| self.ids.get_key_value(id))
            .filter(|(_, &t)| std::ptr::eq(t, el))
            .map(|(&k, _)| k);
        if let Some(w) = key.and_then(|k| self.memo.get(k)) {
            return *w;
        }
        let mut total: u64 = 1;
        let mut refs = Vec::new();
        element_refs(el, &mut refs);
        if el.attr("class").is_some() {
            refs.extend(self.style_refs.iter().cloned());
        }
        for r in refs {
            total = total.saturating_add(self.target(&r));
        }
        for c in el.child_elements() {
            total = total.saturating_add(self.weight(c));
        }
        if let Some(k) = key {
            self.memo.insert(k, total);
        }
        total
    }

    fn target(&mut self, id: &str) -> u64 {
        let Some((&key, &el)) = self.ids.get_key_value(id) else {
            return 0;
        };
        if let Some(&w) = self.memo.get(key) {
            return w;
        }
        // 순환 참조는 렌더러가 그리지 않으므로 세지 않는다
        if !self.active.insert(key) {
            return 0;
        }
        if self.depth >= MAX_REF_DEPTH {
            self.too_deep = true;
            self.active.remove(key);
            return 0;
        }
        self.depth += 1;
        let w = self.weight(el);
        self.depth -= 1;
        self.active.remove(key);
        w
    }
}

/// `<use>`·무늬·마커 등 참조를 겹겹이 펼치면 요소 수가 기하급수로 늘어나는 구조를 막는다
/// (XML 의 billion laughs 와 같은 원리로 작은 파일이 렌더러를 멈추게 함)
fn check_expansion(root: &Element, policy: &Policy) -> Result<()> {
    let mut x = Expansion {
        ids: HashMap::new(),
        style_refs: Vec::new(),
        memo: HashMap::new(),
        active: HashSet::new(),
        depth: 0,
        too_deep: false,
    };
    x.collect(root);
    x.style_refs.sort();
    x.style_refs.dedup();
    let total = x.weight(root);
    if x.too_deep {
        return blocked(
            "resource",
            format!("SVG 참조 사슬이 너무 깊음(최대 {MAX_REF_DEPTH}단계)"),
        );
    }
    let limit = policy.max_xml_nodes as u64;
    if total > limit {
        return blocked(
            "resource",
            format!("SVG 참조를 펼친 요소 수가 한도({limit})를 넘음 (use 폭탄 의심)"),
        );
    }
    Ok(())
}

/// `url(...)` 참조가 모두 문서 안(`#id`)을 가리키는지
fn urls_are_local(v: &str) -> bool {
    let lower = v.to_ascii_lowercase();
    let mut rest = lower.as_str();
    while let Some(i) = rest.find("url(") {
        let arg = rest[i + 4..].trim_start().trim_start_matches(['"', '\'']);
        if !arg.starts_with('#') {
            return false;
        }
        rest = &rest[i + 4..];
    }
    true
}

fn value_is_safe(v: &str) -> bool {
    let lower = v.to_ascii_lowercase();
    urls_are_local(v) && !lower.contains("javascript:") && !lower.contains("data:")
}

/// CSS 가 외부 자원을 부르는지 (보고용 구분)
fn css_is_external(css: &str) -> bool {
    let lower = css.to_ascii_lowercase();
    lower.contains("@import") || !urls_are_local(css)
}

/// 옮겨도 되는 CSS 인지: 외부 참조(`@import`, 문서 밖 `url()`), 글꼴 내장(`@font-face`),
/// 스크립트 표현식, 이스케이프(난독화), 확장 바인딩이 없어야 한다
fn css_is_safe(css: &str) -> bool {
    let lower = css.to_ascii_lowercase();
    !css.contains('\\')
        && !css.contains('<')
        && !lower.contains("@import")
        && !lower.contains("@font-face")
        && !lower.contains("expression")
        && !lower.contains("javascript:")
        && !lower.contains("behavior")
        && !lower.contains("-moz-binding")
        && !lower.contains("data:")
        && urls_are_local(css)
}

/// `<image href="data:image/...;base64,...">`: 픽셀만 재인코딩한 data URI 로 바꾼다
fn embedded_image(value: &str, ctx: &mut Ctx) -> Option<String> {
    let rest = value.strip_prefix("data:")?;
    let (meta, payload) = rest.split_once(',')?;
    if !meta.to_ascii_lowercase().ends_with(";base64") {
        return None;
    }
    let clean: String = payload
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(clean.as_bytes())
        .ok()?;
    let kind = ImageKind::sniff(&bytes)?;
    if let Err(e) = ctx.budget.charge(&bytes, kind) {
        ctx.error = Some(e);
        return None;
    }
    let (img, out_kind) = imaging::reencode(&bytes, kind, ctx.policy).ok()?;
    ctx.stats.images += 1;
    Some(format!(
        "data:{};base64,{}",
        out_kind.mime(),
        base64::engine::general_purpose::STANDARD.encode(img)
    ))
}

/// 그림 파트로 쓰이는 SVG 의 MIME 형식
pub const MIME: &str = "image/svg+xml";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn css_checks() {
        assert!(css_is_safe("fill:url(#g);stroke:#000"));
        assert!(css_is_safe(".a{fill:url( '#g' )}"));
        assert!(!css_is_safe("fill:url(http://x/y)"));
        assert!(!css_is_safe("@import 'x.css';"));
        assert!(!css_is_safe("@font-face{font-family:x}"));
        assert!(css_is_safe("@media print {rect{fill:red}}"));
        assert!(!css_is_safe("fill:u\\72l(http://x)"));
        assert!(!css_is_safe("background:url(data:image/png;base64,AAAA)"));
        assert!(value_is_safe("url(#a) none"));
        assert!(!value_is_safe("url(file:///etc/passwd)"));
    }
}
