//! RTF 재조합.
//!
//! RTF 를 토큰(그룹·제어어·제어 기호·텍스트) 트리로 해석한 뒤 허용된 요소만 새로 직렬화한다.
//! - OLE 개체(`\object`)는 조립하지 않는다. 개체의 표시용 결과(`\result`)만 남긴다
//!   (수식 편집기 CVE-2017-11882, OLE 링크 CVE-2017-0199 등 RTF 공격의 대부분이 여기에 실린다)
//! - 알 수 없는 `\*` 목적지 그룹(`\*\datastore`, `\*\template`, `\*\themedata`, 글꼴 내장 등)은 버린다.
//!   `\*` 는 "모르면 건너뛰라"는 표시이므로 버려도 정상 문서의 표시에는 영향이 없다
//! - 그림: PNG/JPEG 는 픽셀만 디코딩해 새로 인코딩하고, 메타파일(EMF/WMF)은 레코드 단위로 재조합한다.
//!   비트맵·PICT 등 기타 형식은 버린다
//! - 필드: DDE·INCLUDE·LINK·허용되지 않은 대상의 HYPERLINK 등 위험한 필드는 결과 텍스트만 남긴다
//! - 그림 밖의 이진 데이터(`\bin`), 비정상 제어어(과도한 길이·매개변수)는 버리고,
//!   중첩 깊이가 한도를 넘으면 차단한다
//! - 문서 정보(`\info`: 작성자 등)는 메타데이터 제거 정책에 따라 뺀다

use crate::error::{blocked, Result};
use crate::imaging::{self, ImageKind};
use crate::legacy::blip::PixelBudget;
use crate::metafile;
use crate::ooxml::content::word_field_is_dangerous;
use crate::policy::Policy;
use crate::report::{Findings, Severity};

/// 그룹 최대 중첩 깊이
const MAX_DEPTH: usize = 512;
/// 제어어 이름 최대 길이 (규격상 32)
const MAX_WORD: usize = 32;

#[derive(Debug, Clone)]
enum Node {
    Group(Vec<Node>),
    /// 제어어와 매개변수
    Word(String, Option<i32>),
    /// 제어 기호 (\\, \{, \}, \~, \-, \_, \:, \|, \*, 줄바꿈)
    Symbol(u8),
    /// \'hh
    Hex(u8),
    Text(Vec<u8>),
    /// \binN 이진 데이터
    Bin(Vec<u8>),
}

pub fn is_rtf(data: &[u8]) -> bool {
    data.starts_with(b"{\\rtf")
}

struct Parser<'a> {
    d: &'a [u8],
    p: usize,
    dropped_words: u64,
}

impl Parser<'_> {
    fn parse_group(&mut self, depth: usize) -> Result<Vec<Node>> {
        if depth > MAX_DEPTH {
            return blocked("structure", "RTF 그룹 중첩 깊이 초과");
        }
        let mut out = Vec::new();
        let mut text = Vec::new();
        let flush = |text: &mut Vec<u8>, out: &mut Vec<Node>| {
            if !text.is_empty() {
                out.push(Node::Text(std::mem::take(text)));
            }
        };
        while self.p < self.d.len() {
            let c = self.d[self.p];
            match c {
                b'{' => {
                    flush(&mut text, &mut out);
                    self.p += 1;
                    let g = self.parse_group(depth + 1)?;
                    out.push(Node::Group(g));
                }
                b'}' => {
                    flush(&mut text, &mut out);
                    self.p += 1;
                    return Ok(out);
                }
                b'\\' => {
                    flush(&mut text, &mut out);
                    self.p += 1;
                    self.control(&mut out)?;
                }
                b'\r' | b'\n' => self.p += 1,
                _ => {
                    text.push(c);
                    self.p += 1;
                }
            }
        }
        flush(&mut text, &mut out);
        // 닫히지 않은 그룹: 여기까지를 그룹으로 본다 (Word 와 같은 관대한 처리)
        Ok(out)
    }

    fn control(&mut self, out: &mut Vec<Node>) -> Result<()> {
        let Some(&c) = self.d.get(self.p) else {
            return Ok(());
        };
        if !c.is_ascii_alphabetic() {
            self.p += 1;
            match c {
                b'\'' => {
                    let hex = self.d.get(self.p..self.p + 2);
                    match hex
                        .and_then(|h| std::str::from_utf8(h).ok())
                        .and_then(|h| u8::from_str_radix(h, 16).ok())
                    {
                        Some(v) => {
                            out.push(Node::Hex(v));
                            self.p += 2;
                        }
                        None => self.dropped_words += 1,
                    }
                }
                b'\r' | b'\n' => out.push(Node::Word("par".into(), None)),
                b'\\' | b'{' | b'}' | b'~' | b'-' | b'_' | b':' | b'|' | b'*' => {
                    out.push(Node::Symbol(c))
                }
                _ => self.dropped_words += 1,
            }
            return Ok(());
        }
        let start = self.p;
        while self.p < self.d.len() && self.d[self.p].is_ascii_alphabetic() {
            self.p += 1;
        }
        let name = String::from_utf8_lossy(&self.d[start..self.p]).into_owned();
        let pstart = self.p;
        if self.d.get(self.p) == Some(&b'-') {
            self.p += 1;
        }
        while self.p < self.d.len() && self.d[self.p].is_ascii_digit() {
            self.p += 1;
        }
        let digits = &self.d[pstart..self.p];
        let param = if digits.is_empty() || digits == b"-" {
            None
        } else {
            // 32비트 범위를 넘는 매개변수는 비정상 (파서 정수 오버플로 공격)
            std::str::from_utf8(digits)
                .ok()
                .and_then(|s| s.parse::<i32>().ok())
                .or(Some(i32::MIN))
        };
        if self.d.get(self.p) == Some(&b' ') {
            self.p += 1;
        }
        if name.len() > MAX_WORD || param == Some(i32::MIN) {
            self.dropped_words += 1;
            return Ok(());
        }
        if name == "bin" {
            let n = param.unwrap_or(0).max(0) as usize;
            let end = self.p.saturating_add(n).min(self.d.len());
            out.push(Node::Bin(self.d[self.p..end].to_vec()));
            self.p = end;
            return Ok(());
        }
        out.push(Node::Word(name, param));
        Ok(())
    }
}

/// 그룹의 목적지 이름과 `\*` 표시 여부
fn destination(g: &[Node]) -> (Option<&str>, bool) {
    match g {
        [Node::Symbol(b'*'), Node::Word(w, _), ..] => (Some(w.as_str()), true),
        [Node::Word(w, _), ..] => (Some(w.as_str()), false),
        _ => (None, false),
    }
}

/// 옮기는 `\*` 목적지 (그 밖의 `\*` 그룹은 버린다)
const ALLOWED_STARRED: &[&str] = &[
    "shppict",
    "shpinst",
    "fldinst",
    "bkmkstart",
    "bkmkend",
    "pnseclvl",
    "pntxta",
    "pntxtb",
    "falt",
    "panose",
    "fname",
    "defchp",
    "defpap",
    "nesttableprops",
    "ud",
    "listtext",
    "atnid",
    "atnauthor",
    "annotation",
    "atndate",
    "atnref",
    "tc",
    "xe",
    "cs",
    "ts",
    "tsrowd",
    "lfolevel",
    "pgptbl",
    "mmathPr",
    // 목록(글머리표·번호), 각주 구분선, 수식, 페이지 스타일 등 서식 정보
    "listtable",
    "listoverridetable",
    "listpicture",
    "ftnsep",
    "ftnsepc",
    "aftnsep",
    "aftnsepc",
    "footnote",
    "moMath",
    "moMathPara",
    "pgdsctbl",
    "pgdscno",
    "do",
    "picprop",
    "fchars",
    "lchars",
    "hyphen",
    "pn",
    "revtbl",
    "background",
    "atrfstart",
    "atrfend",
    // 양식 필드 (들어갈 때·나올 때 실행하는 매크로 ffentrymcr/ffexitmcr 는 제외)
    "formfield",
    "ffname",
    "ffl",
    "ffdeftext",
    "ffformat",
    "ffhelptext",
    "ffstattext",
];

struct Sanitizer<'a> {
    policy: &'a Policy,
    objects: u64,
    starred: std::collections::BTreeMap<String, u64>,
    pictures_reencoded: u64,
    pictures_dropped: u64,
    fields: u64,
    bins: u64,
    info: bool,
    budget: PixelBudget,
    metafiles: metafile::Stats,
    /// 그림 처리 중 난 차단 오류 (화소 예산 초과)
    error: Option<crate::error::CdrError>,
}

impl Sanitizer<'_> {
    fn group(&mut self, g: Vec<Node>) -> Option<Vec<Node>> {
        let (dest, starred) = destination(&g);
        let dest = dest.map(str::to_string);
        match dest.as_deref() {
            Some("object") => {
                // 개체는 버리고 표시용 결과만 남긴다
                self.objects += 1;
                let result = g.into_iter().find_map(|n| match n {
                    Node::Group(inner) if matches!(destination(&inner), (Some("result"), _)) => {
                        Some(inner)
                    }
                    _ => None,
                })?;
                let children = self.children(result.into_iter().skip(1).collect());
                return Some(children);
            }
            Some(
                "objdata" | "objclass" | "objname" | "objtime" | "objalias" | "objsect" | "objitem"
                | "objtopic",
            ) => {
                self.objects += 1;
                return None;
            }
            Some("pict") => return self.pict(g),
            Some("nonshppict" | "macpict" | "datafield") => {
                self.pictures_dropped += (dest.as_deref() != Some("datafield")) as u64;
                return None;
            }
            Some("field") => return self.field(g),
            Some("info") if self.policy.strip_metadata => {
                self.info = true;
                return None;
            }
            Some(d) if starred && !ALLOWED_STARRED.contains(&d) => {
                *self.starred.entry(d.to_string()).or_default() += 1;
                return None;
            }
            None if matches!(g.first(), Some(Node::Symbol(b'*'))) => return None,
            _ => {}
        }
        Some(self.children(g))
    }

    fn children(&mut self, nodes: Vec<Node>) -> Vec<Node> {
        let mut out = Vec::with_capacity(nodes.len());
        for n in nodes {
            match n {
                Node::Group(g) => {
                    // 개체 결과처럼 그룹을 풀어 넣는 경우도 한 그룹으로 감싼다
                    if let Some(inner) = self.group(g) {
                        out.push(Node::Group(inner));
                    }
                }
                Node::Bin(_) => self.bins += 1,
                Node::Word(w, p) if is_object_word(&w) => {
                    let _ = p;
                    self.objects += 1;
                }
                other => out.push(other),
            }
        }
        out
    }

    /// 그림: PNG/JPEG 는 재인코딩, EMF/WMF 는 레코드 단위로 재조합해 남긴다
    fn pict(&mut self, g: Vec<Node>) -> Option<Vec<Node>> {
        enum Pic {
            Raster(ImageKind),
            Meta(metafile::Kind),
        }
        let kind = g.iter().find_map(|n| match n {
            Node::Word(w, _) if w == "pngblip" => Some(Pic::Raster(ImageKind::Png)),
            Node::Word(w, _) if w == "jpegblip" => Some(Pic::Raster(ImageKind::Jpeg)),
            Node::Word(w, _) if w == "emfblip" => Some(Pic::Meta(metafile::Kind::Emf)),
            Node::Word(w, _) if w == "wmetafile" => Some(Pic::Meta(metafile::Kind::Wmf)),
            _ => None,
        });
        let Some(kind) = kind else {
            self.pictures_dropped += 1;
            return None;
        };
        // 그림 데이터: 16진수 텍스트 또는 \bin
        let mut hex = Vec::new();
        let mut bin = None;
        for n in &g {
            match n {
                Node::Text(t) => hex.extend(t.iter().copied().filter(|c| c.is_ascii_hexdigit())),
                Node::Bin(b) => bin = Some(b.clone()),
                _ => {}
            }
        }
        let data = match bin {
            Some(b) => b,
            None => hex
                .as_chunks::<2>()
                .0
                .iter()
                .filter_map(|p| u8::from_str_radix(std::str::from_utf8(p).ok()?, 16).ok())
                .collect(),
        };
        let rebuilt = match kind {
            Pic::Raster(k) if ImageKind::sniff(&data) == Some(k) => {
                imaging::reencode_same(&data, k, self.policy).ok()
            }
            Pic::Meta(k) => {
                match metafile::rebuild(&data, self.policy, &mut self.budget, &mut self.metafiles) {
                    Ok((mf, got)) if got == k => Some(mf),
                    Ok(_) => None,
                    Err(e) if e.category() == "resource" => {
                        self.error = Some(e);
                        None
                    }
                    Err(_) => None,
                }
            }
            _ => None,
        };
        let Some(image) = rebuilt else {
            self.pictures_dropped += 1;
            return None;
        };
        self.pictures_reencoded += matches!(kind, Pic::Raster(_)) as u64;
        let mut out: Vec<Node> = g
            .into_iter()
            .filter(|n| match n {
                Node::Word(w, _) => PICT_WORDS.contains(&w.as_str()),
                _ => false,
            })
            .collect();
        let mut text = Vec::with_capacity(image.len() * 2 + image.len() / 64);
        for (i, b) in image.iter().enumerate() {
            if i > 0 && i % 64 == 0 {
                text.push(b'\n');
            }
            text.extend(format!("{b:02x}").bytes());
        }
        out.push(Node::Text(text));
        Some(out)
    }

    /// 필드: 위험한 필드 코드는 결과 텍스트만 남긴다
    fn field(&mut self, g: Vec<Node>) -> Option<Vec<Node>> {
        let mut code = String::new();
        let mut nested = false;
        for n in &g {
            if let Node::Group(inner) = n {
                if matches!(destination(inner), (Some("fldinst"), _)) {
                    collect_text(inner, &mut code, &mut nested);
                }
            }
        }
        let starts_nested = nested && code.trim().is_empty();
        if word_field_is_dangerous(&code, starts_nested, self.policy) {
            self.fields += 1;
            let result = g.into_iter().find_map(|n| match n {
                Node::Group(inner) if matches!(destination(&inner), (Some("fldrslt"), _)) => {
                    Some(inner)
                }
                _ => None,
            })?;
            return Some(self.children(result.into_iter().skip(1).collect()));
        }
        Some(self.children(g))
    }
}

/// 그림 그룹에서 옮기는 제어어 (크기·배율·자르기·형식)
const PICT_WORDS: &[&str] = &[
    "pict",
    "pngblip",
    "jpegblip",
    "emfblip",
    "wmetafile",
    "picw",
    "pich",
    "picwgoal",
    "pichgoal",
    "picscalex",
    "picscaley",
    "piccropl",
    "piccropr",
    "piccropt",
    "piccropb",
    "picbmp",
    "picbpp",
];

fn is_object_word(w: &str) -> bool {
    w.starts_with("obj") || matches!(w, "linkself" | "bliptag")
}

/// 필드 코드 텍스트를 모은다 (중첩 필드는 표시만)
fn collect_text(nodes: &[Node], out: &mut String, nested: &mut bool) {
    for n in nodes {
        match n {
            Node::Text(t) => out.push_str(&String::from_utf8_lossy(t)),
            Node::Hex(h) => out.push(*h as char),
            Node::Symbol(b'\\') => out.push('\\'),
            Node::Word(w, Some(v)) if w == "u" => {
                if let Some(c) = char::from_u32(*v as u16 as u32) {
                    out.push(c);
                }
            }
            Node::Group(g) => {
                if matches!(destination(g), (Some("field"), _)) {
                    *nested = true;
                }
                collect_text(g, out, nested);
            }
            _ => {}
        }
    }
}

fn serialize(nodes: &[Node], out: &mut Vec<u8>) {
    for (i, n) in nodes.iter().enumerate() {
        match n {
            Node::Group(g) => {
                out.push(b'{');
                serialize(g, out);
                out.push(b'}');
            }
            Node::Word(w, p) => {
                out.push(b'\\');
                out.extend(w.as_bytes());
                if let Some(v) = p {
                    out.extend(v.to_string().bytes());
                }
                // 다음이 텍스트면 구분 공백을 둔다
                if matches!(nodes.get(i + 1), Some(Node::Text(_))) {
                    out.push(b' ');
                }
            }
            Node::Symbol(c) => {
                out.push(b'\\');
                out.push(*c);
            }
            Node::Hex(h) => out.extend(format!("\\'{h:02x}").bytes()),
            Node::Text(t) => out.extend(t),
            Node::Bin(_) => {}
        }
    }
}

pub fn reassemble(data: &[u8], policy: &Policy, findings: &mut Findings) -> Result<Vec<u8>> {
    if !is_rtf(data) {
        return blocked("structure", "RTF 형식이 아님");
    }
    let mut parser = Parser {
        d: data,
        p: 1,
        dropped_words: 0,
    };
    let root = parser.parse_group(1)?;
    let trailing = data.len().saturating_sub(parser.p);
    let mut s = Sanitizer {
        policy,
        objects: 0,
        starred: Default::default(),
        pictures_reencoded: 0,
        pictures_dropped: 0,
        fields: 0,
        bins: 0,
        info: false,
        budget: PixelBudget::new(policy),
        metafiles: metafile::Stats::default(),
        error: None,
    };
    let root = s.children(root);
    if let Some(e) = s.error.take() {
        return Err(e);
    }
    s.metafiles.report(findings, "");
    let (objects, pictures_dropped, fields, bins, info, starred, reencoded) = (
        s.objects,
        s.pictures_dropped,
        s.fields,
        s.bins,
        s.info,
        std::mem::take(&mut s.starred),
        s.pictures_reencoded,
    );

    if objects > 0 {
        findings.add(
            "embedded-object",
            Severity::High,
            format!("OLE 개체 {objects}개 - 표시용 결과만 남기고 조립하지 않음"),
            "",
        );
    }
    if fields > 0 {
        findings.add(
            "dde",
            Severity::High,
            format!("위험한 필드 {fields}개 - 결과 텍스트만 남김"),
            "",
        );
    }
    let risky: Vec<&str> = starred
        .keys()
        .map(String::as_str)
        .filter(|k| {
            matches!(
                *k,
                "datastore"
                    | "template"
                    | "objdata"
                    | "fontemb"
                    | "fontfile"
                    | "blipuid"
                    | "passwordhash"
                    | "protusertbl"
            )
        })
        .collect();
    if !risky.is_empty() {
        findings.add(
            "hidden-data",
            Severity::Medium,
            format!("숨겨진 데이터·외부 참조 그룹 제거: {}", risky.join(", ")),
            "",
        );
    }
    let others: u64 = starred.values().sum();
    if others > 0 {
        findings.count("rtf_ignorable_groups_removed", others);
    }
    if pictures_dropped > 0 {
        findings.add(
            "image",
            Severity::Low,
            format!("재조합할 수 없는 그림 {pictures_dropped}개 제거"),
            "",
        );
    }
    if bins > 0 {
        findings.add(
            "hidden-data",
            Severity::Medium,
            format!("그림 밖의 이진 데이터(\\bin) {bins}개 제거"),
            "",
        );
    }
    if parser.dropped_words > 0 {
        findings.add(
            "structure",
            Severity::Low,
            format!("비정상 제어어 {}개 제거", parser.dropped_words),
            "",
        );
    }
    if trailing > 16 {
        findings.add(
            "hidden-data",
            Severity::Low,
            format!("문서 끝 뒤의 데이터 {trailing}바이트 제거"),
            "",
        );
    }
    if info {
        findings.add("metadata", Severity::Info, "문서 정보(작성자 등) 제거", "");
    }
    findings.count("images_reencoded", reencoded);

    let mut out = Vec::with_capacity(data.len());
    out.push(b'{');
    serialize(&root, &mut out);
    out.push(b'}');
    Ok(out)
}
