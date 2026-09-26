//! 재조합용 최소 XML DOM.
//!
//! - DTD/DOCTYPE 를 허용하지 않는다 (XXE, Billion laughs 차단)
//! - 사전 정의 엔터티와 문자 참조만 해석한다
//! - 주석과 처리 명령(PI)은 버린다
//! - 요소/속성의 네임스페이스 URI 를 해석해 두어 허용 목록 판정에 사용한다
//! - 출력은 원래 접두어(qname)를 그대로 사용해 Office 호환성을 유지한다

use quick_xml::events::Event;
use quick_xml::Reader;

use crate::error::{blocked, Result};
use crate::policy::Policy;

pub const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";
pub const XMLNS_NS: &str = "http://www.w3.org/2000/xmlns/";

#[derive(Debug, Clone)]
pub struct Attr {
    pub qname: String,
    pub ns: String,
    pub local: String,
    pub value: String,
}

impl Attr {
    pub fn is_xmlns(&self) -> bool {
        self.ns == XMLNS_NS
    }
}

#[derive(Debug, Clone)]
pub enum Node {
    Element(Element),
    Text(String),
}

#[derive(Debug, Clone)]
pub struct Element {
    pub qname: String,
    pub ns: String,
    pub local: String,
    pub attrs: Vec<Attr>,
    pub children: Vec<Node>,
}

impl Element {
    pub fn is(&self, ns: &str, local: &str) -> bool {
        self.local == local && self.ns == ns
    }

    pub fn attr(&self, local: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|a| a.local == local && !a.is_xmlns())
            .map(|a| a.value.as_str())
    }

    pub fn attr_ns(&self, ns: &str, local: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|a| a.local == local && a.ns == ns)
            .map(|a| a.value.as_str())
    }

    pub fn set_attr(&mut self, qname: &str, value: &str) {
        if let Some(a) = self.attrs.iter_mut().find(|a| a.qname == qname) {
            a.value = value.to_string();
        }
    }

    pub fn remove_attr_if(&mut self, f: impl Fn(&Attr) -> bool) {
        self.attrs.retain(|a| !f(a));
    }

    pub fn child_elements(&self) -> impl Iterator<Item = &Element> {
        self.children.iter().filter_map(|n| match n {
            Node::Element(e) => Some(e),
            Node::Text(_) => None,
        })
    }

    pub fn has_element_children(&self) -> bool {
        self.child_elements().next().is_some()
    }

    /// 텍스트 자식 전체
    pub fn text(&self) -> String {
        let mut s = String::new();
        for n in &self.children {
            if let Node::Text(t) = n {
                s.push_str(t);
            }
        }
        s
    }

    pub fn set_text(&mut self, text: &str) {
        self.children.retain(|n| matches!(n, Node::Element(_)));
        if !text.is_empty() {
            self.children.insert(0, Node::Text(text.to_string()));
        }
    }
}

pub struct Document {
    pub root: Element,
}

struct Scope {
    decls: Vec<(String, String)>,
}

fn resolve(scopes: &[Scope], prefix: &str) -> Option<String> {
    if prefix == "xml" {
        return Some(XML_NS.to_string());
    }
    for s in scopes.iter().rev() {
        for (p, u) in s.decls.iter().rev() {
            if p == prefix {
                return Some(u.clone());
            }
        }
    }
    if prefix.is_empty() {
        Some(String::new())
    } else {
        None
    }
}

fn split_qname(q: &str) -> (&str, &str) {
    match q.split_once(':') {
        Some((p, l)) => (p, l),
        None => ("", q),
    }
}

fn predefined_entity(name: &str) -> Option<char> {
    Some(match name {
        "lt" => '<',
        "gt" => '>',
        "amp" => '&',
        "apos" => '\'',
        "quot" => '"',
        _ => return None,
    })
}

/// 속성 값의 엔터티를 해석한다(사전 정의 엔터티와 문자 참조만 허용).
fn unescape_attr(raw: &str, name: &str) -> Result<String> {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(idx) = rest.find('&') {
        out.push_str(&rest[..idx]);
        let after = &rest[idx + 1..];
        let Some(end) = after.find(';') else {
            return blocked("structure", format!("잘못된 엔터티 참조: {name}"));
        };
        let ent = &after[..end];
        let ch = if let Some(num) = ent.strip_prefix('#') {
            let code = if let Some(hex) = num.strip_prefix('x').or_else(|| num.strip_prefix('X')) {
                u32::from_str_radix(hex, 16).ok()
            } else {
                num.parse::<u32>().ok()
            };
            code.and_then(char::from_u32).filter(|c| *c != '\0')
        } else {
            predefined_entity(ent)
        };
        match ch {
            Some(c) => out.push(c),
            None => return blocked("xxe", format!("허용되지 않은 엔터티 참조(&{ent};): {name}")),
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    // 속성 값 정규화: 공백 문자를 공백으로
    Ok(out.replace(['\t', '\n', '\r'], " "))
}

pub fn parse(data: &[u8], name: &str, policy: &Policy) -> Result<Document> {
    let data = data.strip_prefix(b"\xef\xbb\xbf").unwrap_or(data);
    let Ok(text) = std::str::from_utf8(data) else {
        return blocked("structure", format!("UTF-8 이 아닌 XML: {name}"));
    };
    let mut reader = Reader::from_str(text);
    reader.config_mut().trim_text(false);
    reader.config_mut().check_end_names = true;

    let mut stack: Vec<Element> = Vec::new();
    let mut scopes: Vec<Scope> = Vec::new();
    let mut root: Option<Element> = None;
    let mut nodes = 0usize;

    macro_rules! xml_err {
        ($e:expr) => {
            return blocked("structure", format!("XML 파싱 실패: {name} ({})", $e))
        };
    }

    loop {
        let ev = match reader.read_event() {
            Ok(ev) => ev,
            Err(e) => xml_err!(e),
        };
        match ev {
            Event::Start(ref s) | Event::Empty(ref s) => {
                nodes += 1;
                if nodes > policy.max_xml_nodes {
                    return blocked("structure", format!("XML 노드 수 초과: {name}"));
                }
                if stack.len() >= policy.max_xml_depth {
                    return blocked("structure", format!("XML 중첩 깊이 초과: {name}"));
                }
                if root.is_some() {
                    xml_err!("루트 요소가 둘 이상");
                }
                let qname = s.name().as_ref().to_string();
                let mut raw_attrs = Vec::new();
                let mut decls = Vec::new();
                for a in s.attributes() {
                    let a = match a {
                        Ok(a) => a,
                        Err(e) => xml_err!(e),
                    };
                    let key = a.key.as_ref().to_string();
                    let raw = a.value.to_string();
                    let value = unescape_attr(&raw, name)?;
                    if key == "xmlns" {
                        decls.push((String::new(), value.clone()));
                    } else if let Some(p) = key.strip_prefix("xmlns:") {
                        decls.push((p.to_string(), value.clone()));
                    }
                    raw_attrs.push((key, value));
                }
                scopes.push(Scope { decls });

                let (prefix, local) = split_qname(&qname);
                let Some(ns) = resolve(&scopes, prefix) else {
                    return blocked(
                        "structure",
                        format!("선언되지 않은 네임스페이스 접두어 '{prefix}': {name}"),
                    );
                };
                let mut attrs = Vec::with_capacity(raw_attrs.len());
                for (key, value) in raw_attrs {
                    let (ans, alocal) = if key == "xmlns" || key.starts_with("xmlns:") {
                        (XMLNS_NS.to_string(), split_qname(&key).1.to_string())
                    } else {
                        let (ap, al) = split_qname(&key);
                        let ans = if ap.is_empty() {
                            String::new()
                        } else {
                            match resolve(&scopes, ap) {
                                Some(u) => u,
                                None => {
                                    return blocked(
                                        "structure",
                                        format!("선언되지 않은 속성 접두어 '{ap}': {name}"),
                                    )
                                }
                            }
                        };
                        (ans, al.to_string())
                    };
                    attrs.push(Attr {
                        qname: key,
                        ns: ans,
                        local: alocal,
                        value,
                    });
                }
                let el = Element {
                    qname: qname.clone(),
                    ns,
                    local: local.to_string(),
                    attrs,
                    children: Vec::new(),
                };
                if matches!(ev, Event::Empty(_)) {
                    scopes.pop();
                    attach(&mut stack, &mut root, el);
                } else {
                    stack.push(el);
                }
            }
            Event::End(_) => {
                scopes.pop();
                let Some(el) = stack.pop() else {
                    xml_err!("짝이 맞지 않는 종료 태그")
                };
                attach(&mut stack, &mut root, el);
            }
            Event::Text(t) => {
                let s = t.xml10_content();
                push_text(&mut stack, &s, name)?;
            }
            Event::CData(c) => {
                let s = c.into_inner().to_string();
                push_text(&mut stack, &s, name)?;
            }
            Event::GeneralRef(r) => {
                let ch = if r.is_char_ref() {
                    match r.resolve_char_ref() {
                        Ok(Some(c)) => Some(c),
                        _ => None,
                    }
                } else {
                    predefined_entity(&r)
                };
                match ch {
                    Some(c) => push_text(&mut stack, &c.to_string(), name)?,
                    None => {
                        return blocked(
                            "xxe",
                            format!("허용되지 않은 엔터티 참조(&{};): {name}", &*r),
                        )
                    }
                }
            }
            Event::DocType(_) => {
                return blocked("xxe", format!("DOCTYPE 선언 포함(XXE 의심): {name}"));
            }
            Event::Decl(_) | Event::Comment(_) | Event::PI(_) => {}
            Event::Eof => break,
        }
    }
    if !stack.is_empty() {
        return blocked("structure", format!("닫히지 않은 XML 요소: {name}"));
    }
    match root {
        Some(root) => Ok(Document { root }),
        None => blocked("structure", format!("루트 요소 없음: {name}")),
    }
}

fn attach(stack: &mut [Element], root: &mut Option<Element>, el: Element) {
    match stack.last_mut() {
        Some(parent) => parent.children.push(Node::Element(el)),
        None => *root = Some(el),
    }
}

fn push_text(stack: &mut [Element], s: &str, name: &str) -> Result<()> {
    match stack.last_mut() {
        Some(parent) => {
            if let Some(Node::Text(prev)) = parent.children.last_mut() {
                prev.push_str(s);
            } else {
                parent.children.push(Node::Text(s.to_string()));
            }
            Ok(())
        }
        None if s.trim().is_empty() => Ok(()),
        None => blocked("structure", format!("루트 밖의 텍스트: {name}")),
    }
}

// ----------------------------------------------------------------------------- 직렬화

pub fn serialize(doc: &Document) -> Vec<u8> {
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n");
    write_element(&doc.root, &mut out);
    out.into_bytes()
}

fn write_element(el: &Element, out: &mut String) {
    out.push('<');
    out.push_str(&el.qname);
    for a in &el.attrs {
        out.push(' ');
        out.push_str(&a.qname);
        out.push_str("=\"");
        escape_into(&a.value, out, true);
        out.push('"');
    }
    if el.children.is_empty() {
        out.push_str("/>");
        return;
    }
    out.push('>');
    for n in &el.children {
        match n {
            Node::Element(c) => write_element(c, out),
            Node::Text(t) => escape_into(t, out, false),
        }
    }
    out.push_str("</");
    out.push_str(&el.qname);
    out.push('>');
}

fn escape_into(s: &str, out: &mut String, attr: bool) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' if attr => out.push_str("&quot;"),
            '\t' if attr => out.push_str("&#9;"),
            '\n' if attr => out.push_str("&#10;"),
            '\r' => out.push_str("&#13;"),
            // XML 1.0 에서 허용되지 않는 제어 문자는 버린다
            c if (c as u32) < 0x20 && !matches!(c, '\t' | '\n') => {}
            c => out.push(c),
        }
    }
}

/// 문서 트리를 새로 만들 때 쓰는 간단한 빌더
pub fn element(qname: &str, attrs: &[(&str, &str)], children: Vec<Node>) -> Element {
    let (_, local) = split_qname(qname);
    Element {
        qname: qname.to_string(),
        ns: String::new(),
        local: local.to_string(),
        attrs: attrs
            .iter()
            .map(|(k, v)| Attr {
                qname: k.to_string(),
                ns: String::new(),
                local: split_qname(k).1.to_string(),
                value: v.to_string(),
            })
            .collect(),
        children,
    }
}
