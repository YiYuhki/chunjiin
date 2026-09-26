//! PDF 재조합.
//!
//! 원본 PDF 를 수정하지 않고 **빈 문서에서 새로 만든다.**
//!
//! 1. 원본의 각 페이지에서 콘텐츠 스트림을 연산자 단위로 해석하고, 허용된 그리기
//!    연산자만 다시 인코딩한다.
//! 2. 페이지가 실제로 사용하는 리소스(글꼴·이미지·그래픽 상태·색공간·패턴·셰이딩)만
//!    허용된 키로 복사한다. 폼 XObject·타일링 패턴·Type3 글리프의 콘텐츠도 같은 방식으로
//!    재구성한다.
//! 3. 주석은 외형(appearance)을 페이지 본문에 평면화하고, 링크는 허용된 URI 와
//!    문서 내 이동만 새로 만든다.
//! 4. 카탈로그는 Pages(+책갈피)만으로 새로 만든다. JavaScript, OpenAction, 추가 액션,
//!    첨부 파일, XFA/AcroForm, 포트폴리오, 메타데이터, 증분 업데이트, 은닉 객체,
//!    파일 끝 덧붙은 데이터는 새 문서에 존재하지 않는다.

mod content;
mod font;
mod raster;
mod scan;

use std::collections::{BTreeMap, HashMap, HashSet};

use lopdf::content::{Content, Operation};
use lopdf::{Dictionary, Document, LoadOptions, Object, ObjectId, Stream, StringFormat};

use crate::error::{blocked, Result};
use crate::policy::Policy;
use crate::report::{Findings, Severity};

const MAX_COPY_DEPTH: usize = 48;
const MAX_OBJECTS: usize = 2_000_000;
const MAX_OUTLINE_ITEMS: usize = 10_000;
/// 콘텐츠 스트림 하나 / 문서 전체의 최대 토큰 수 (연산자 폭탄 방어)
const MAX_STREAM_TOKENS: usize = 4_000_000;
const MAX_DOCUMENT_TOKENS: usize = 40_000_000;

/// 스트림이 어떤 역할로 재조합되는지
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Role {
    Generic,
    /// 그리기 연산자 스트림(폼 XObject, 타일링 패턴, Type3 글리프)
    Content,
    /// 글꼴 기술자의 FontFile2 (TrueType 글꼴 프로그램)
    TrueType,
    /// 글꼴 기술자의 FontFile3 (CFF 또는 OpenType)
    FontFile3,
}

/// 어떤 사전에서도 복사하지 않는 키: 액션·스크립트·첨부·외부 참조·메타데이터·구조 역참조
const DENY_KEYS: &[&[u8]] = &[
    b"JS",
    b"JavaScript",
    b"AA",
    b"A",
    b"OpenAction",
    b"URI",
    b"Launch",
    b"EF",
    b"EmbeddedFile",
    b"EmbeddedFiles",
    b"RichMediaContent",
    b"RichMediaSettings",
    b"Metadata",
    b"PieceInfo",
    b"Parent",
    b"P",
    b"StructParent",
    b"StructParents",
    b"Annots",
    b"OC",
    b"OPI",
    b"Ref",
    b"Alternates",
    b"Names",
    b"XFA",
    b"AcroForm",
    b"Next",
    b"SubmitForm",
    b"ImportData",
    b"Collection",
    b"LastModified",
    b"ID",
];

const FONT_SUBTYPES: &[&[u8]] = &[
    b"Type0",
    b"Type1",
    b"MMType1",
    b"Type3",
    b"TrueType",
    b"CIDFontType0",
    b"CIDFontType2",
];

/// 글꼴 사전에서 옮기는 키 (PDF 32000 9.6~9.7)
const FONT_KEYS: &[&[u8]] = &[
    b"Type",
    b"Subtype",
    b"Name",
    b"BaseFont",
    b"FirstChar",
    b"LastChar",
    b"Widths",
    b"FontDescriptor",
    b"Encoding",
    b"ToUnicode",
    b"DescendantFonts",
    b"CIDSystemInfo",
    b"DW",
    b"W",
    b"DW2",
    b"W2",
    b"CIDToGIDMap",
    b"FontBBox",
    b"FontMatrix",
    b"CharProcs",
    b"Resources",
];

/// 원본 그대로 옮기되 디코딩 검증을 할 수 없는 이미지 필터
const PASSTHROUGH_IMAGE_FILTERS: &[&[u8]] = &[b"DCTDecode", b"CCITTFaxDecode"];
/// 역사적으로 파서 취약점이 많아 재조합 대상에서 제외하는 이미지 필터
const BLOCKED_IMAGE_FILTERS: &[&[u8]] = &[b"JBIG2Decode", b"JPXDecode"];

struct Copier<'a> {
    src: &'a Document,
    dst: Document,
    /// (원본 객체, 역할) → 새 객체. 같은 객체라도 콘텐츠로 쓰일 때는 따로 필터링한다
    map: HashMap<(ObjectId, Role), ObjectId>,
    /// 복사 결과 제외된 원본 객체 (예: JBIG2 이미지)
    rejected: HashSet<(ObjectId, Role)>,
    /// 문서 전체에서 해석한 콘텐츠 토큰 수 (처리량 제한)
    content_tokens: usize,
    policy: &'a Policy,
    findings: &'a mut Findings,
    copied: usize,
    dropped_ops: HashMap<String, u64>,
    font_stats: BTreeMap<&'static str, u64>,
}

impl<'a> Copier<'a> {
    fn deref<'o>(&'o self, obj: &'o Object) -> Option<&'o Object> {
        let mut cur = obj;
        for _ in 0..8 {
            match cur {
                Object::Reference(id) => cur = self.src.get_object(*id).ok()?,
                o => return Some(o),
            }
        }
        None
    }

    /// 객체를 새 문서로 복사한다. 제외 대상이면 None.
    fn copy(&mut self, obj: &Object, role: Role, depth: usize) -> Result<Option<Object>> {
        if depth > MAX_COPY_DEPTH {
            return blocked("structure", "PDF 객체 중첩 깊이 초과");
        }
        Ok(match obj {
            Object::Reference(id) => {
                if let Some(new) = self.map.get(&(*id, role)) {
                    return Ok(Some(Object::Reference(*new)));
                }
                if self.rejected.contains(&(*id, role)) {
                    return Ok(None);
                }
                let Ok(target) = self.src.get_object(*id) else {
                    return Ok(None);
                };
                self.copied += 1;
                if self.copied > MAX_OBJECTS {
                    return blocked("structure", "PDF 객체 수 제한 초과");
                }
                // 순환 참조를 위해 새 ID 를 먼저 예약한다
                let new_id = self.dst.new_object_id();
                self.map.insert((*id, role), new_id);
                let target = target.clone();
                match self.copy(&target, role, depth + 1)? {
                    Some(o) => {
                        self.dst.objects.insert(new_id, o);
                        Some(Object::Reference(new_id))
                    }
                    None => {
                        self.map.remove(&(*id, role));
                        self.rejected.insert((*id, role));
                        None
                    }
                }
            }
            Object::Dictionary(d) => Some(Object::Dictionary(self.copy_dict(d, depth)?)),
            Object::Array(items) => {
                let mut out = Vec::with_capacity(items.len());
                for it in items {
                    if let Some(o) = self.copy(it, role, depth + 1)? {
                        out.push(o);
                    }
                }
                Some(Object::Array(out))
            }
            Object::Stream(s) => self.copy_stream(s, role, depth)?.map(Object::Stream),
            other => Some(other.clone()),
        })
    }

    fn copy_dict(&mut self, d: &Dictionary, depth: usize) -> Result<Dictionary> {
        let subtype = d
            .get(b"Subtype")
            .ok()
            .and_then(|o| self.deref(o))
            .and_then(|o| o.as_name().ok());
        let is_type3 = subtype == Some(b"Type3");
        let is_font = d
            .get(b"Type")
            .ok()
            .and_then(|o| self.deref(o))
            .and_then(|o| o.as_name().ok())
            == Some(b"Font")
            || subtype.is_some_and(|s| FONT_SUBTYPES.contains(&s));
        let mut out = Dictionary::new();
        for (k, v) in d.iter() {
            if DENY_KEYS.contains(&k.as_slice()) {
                continue;
            }
            // 글꼴 사전은 정의된 키만 옮긴다 (알 수 없는 키로 글리프 프로그램을 필터 없이 끼워 넣는 우회 방지)
            if is_font && !FONT_KEYS.contains(&k.as_slice()) {
                continue;
            }
            let role = match k.as_slice() {
                b"CharProcs" if is_type3 => Role::Content,
                b"FontFile2" => Role::TrueType,
                b"FontFile3" => Role::FontFile3,
                _ => Role::Generic,
            };
            let copied = if role == Role::Content {
                // CharProcs: 글리프 이름 → 콘텐츠 스트림
                match self.deref(v).and_then(|o| o.as_dict().ok()).cloned() {
                    Some(procs) => {
                        let mut nd = Dictionary::new();
                        for (gk, gv) in procs.iter() {
                            if let Some(o) = self.copy(gv, Role::Content, depth + 1)? {
                                nd.set(gk.clone(), o);
                            }
                        }
                        Some(Object::Dictionary(nd))
                    }
                    None => None,
                }
            } else {
                self.copy(v, role, depth + 1)?
            };
            if let Some(o) = copied {
                out.set(k.clone(), o);
            }
        }
        Ok(out)
    }

    /// 판정에 쓰는 키(/Subtype, /PatternType, /Filter, /DecodeParms, /Type)의 간접 참조를 풀어 둔다.
    /// 뷰어는 간접 참조를 따라가므로, 풀지 않으면 폼 XObject 를 알아보지 못해 필터를 우회할 수 있다.
    fn normalized(&self, s: &Stream) -> Stream {
        const KEYS: &[&[u8]] = &[
            b"Subtype",
            b"PatternType",
            b"Filter",
            b"DecodeParms",
            b"Type",
            b"Length",
        ];
        let needs = KEYS.iter().any(|k| match s.dict.get(k) {
            Ok(Object::Reference(_)) => true,
            Ok(Object::Array(a)) => a.iter().any(|o| matches!(o, Object::Reference(_))),
            _ => false,
        });
        if !needs {
            return s.clone();
        }
        let mut n = s.clone();
        for k in KEYS {
            let Ok(v) = n.dict.get(k) else { continue };
            let resolved = match v {
                Object::Reference(_) => self.deref(v).cloned(),
                Object::Array(a) => Some(Object::Array(
                    a.iter()
                        .map(|o| self.deref(o).cloned().unwrap_or(Object::Null))
                        .collect(),
                )),
                // 직접 값은 그대로 둔다
                _ => continue,
            };
            match resolved {
                Some(r) => n.dict.set(k.to_vec(), r),
                None => {
                    n.dict.remove(k);
                }
            }
        }
        n
    }

    /// 콘텐츠 스트림을 연산자로 해석한다. 해석 전에 토큰 수를 세어 스트림/문서 단위 예산을 넘으면 차단한다
    /// (작은 압축 스트림이 수천만 개의 연산자로 풀려 메모리를 고갈시키는 공격 방어).
    fn decode_ops(&mut self, plain: &[u8]) -> Result<Option<Vec<Operation>>> {
        let tokens = content::count_tokens(plain);
        if tokens > MAX_STREAM_TOKENS {
            return blocked("resource", format!("콘텐츠 스트림 토큰 수 초과 ({tokens})"));
        }
        self.content_tokens += tokens;
        if self.content_tokens > MAX_DOCUMENT_TOKENS {
            return blocked("resource", "문서 전체 콘텐츠 토큰 수 초과");
        }
        Ok(Content::decode(plain).ok().map(|c| c.operations))
    }

    fn copy_stream(&mut self, s: &Stream, role: Role, depth: usize) -> Result<Option<Stream>> {
        let normalized = self.normalized(s);
        let s = &normalized;
        let subtype = s
            .dict
            .get(b"Subtype")
            .and_then(Object::as_name)
            .ok()
            .map(<[u8]>::to_vec);
        let is_form = subtype.as_deref() == Some(b"Form");
        let is_image = subtype.as_deref() == Some(b"Image");
        let is_tiling = s.dict.get(b"PatternType").and_then(Object::as_i64).ok() == Some(1);
        let filters: Vec<Vec<u8>> = s
            .filters()
            .map(|f| f.into_iter().map(<[u8]>::to_vec).collect())
            .unwrap_or_default();

        if matches!(role, Role::TrueType | Role::FontFile3) {
            if let Some(r) = self.font_program(s, role, depth)? {
                return Ok(r);
            }
        }

        if is_image {
            if let Some(f) = filters
                .iter()
                .find(|f| BLOCKED_IMAGE_FILTERS.contains(&f.as_slice()))
            {
                self.findings.add(
                    "risky-codec",
                    Severity::Medium,
                    format!(
                        "{} 이미지 제외(코덱 취약점 위험)",
                        String::from_utf8_lossy(f)
                    ),
                    "",
                );
                return Ok(None);
            }
        }

        let dict = self.copy_dict(&s.dict, depth)?;
        let mut dict = dict;
        for k in [
            b"Filter".as_slice(),
            b"DecodeParms",
            b"Length",
            b"DL",
            b"F",
            b"FFilter",
            b"FDecodeParms",
        ] {
            dict.remove(k);
        }

        // 1) 그리기 연산자 스트림: 해석 → 필터링 → 재인코딩
        if is_form || is_tiling || role == Role::Content {
            let Ok(plain) = s.get_plain_content_with_limit(self.policy.max_stream_size) else {
                self.findings.add(
                    "structure",
                    Severity::Medium,
                    "해석할 수 없는 콘텐츠 스트림 제외",
                    "",
                );
                return Ok(None);
            };
            let ops = match self.decode_ops(&plain)? {
                Some(ops) => ops,
                None => {
                    self.findings.add(
                        "structure",
                        Severity::Medium,
                        "해석할 수 없는 콘텐츠 스트림 제외",
                        "",
                    );
                    return Ok(None);
                }
            };
            let mut ops = ops;
            if role == Role::Content && !is_form && !is_tiling {
                content::restore_glyph_ops(&mut ops);
            }
            let xobjects = self.resource_names(&dict, b"XObject");
            let ops = content::filter(ops, Some(&xobjects), &mut self.dropped_ops);
            let bytes = content::encode(&ops);
            return Ok(Some(Stream::new(dict, bytes)));
        }

        // 2) 디코딩 가능한 필터(Flate/LZW/ASCII/RunLength)는 풀어서 다시 압축한다
        let passthrough: Vec<&Vec<u8>> = filters
            .iter()
            .filter(|f| PASSTHROUGH_IMAGE_FILTERS.contains(&f.as_slice()))
            .collect();
        if passthrough.is_empty() {
            return match s.get_plain_content_with_limit(self.policy.max_stream_size) {
                Ok(plain) => Ok(Some(Stream::new(dict, plain))),
                Err(_) => {
                    self.findings.add(
                        "structure",
                        Severity::Low,
                        "디코딩할 수 없는 스트림 제외",
                        "",
                    );
                    Ok(None)
                }
            };
        }

        // 3) DCT/CCITT: 마지막 필터로만 허용하고 앞단 필터는 풀어서 원시 코덱 데이터만 남긴다
        if filters
            .last()
            .map(|f| PASSTHROUGH_IMAGE_FILTERS.contains(&f.as_slice()))
            != Some(true)
            || passthrough.len() > 1
        {
            self.findings.add(
                "structure",
                Severity::Low,
                "비정상 필터 체인 스트림 제외",
                "",
            );
            return Ok(None);
        }
        let codec = filters.last().cloned().unwrap_or_default();
        let mut pre = s.clone();
        let pre_filters: Vec<Object> = filters[..filters.len() - 1]
            .iter()
            .map(|f| Object::Name(f.clone()))
            .collect();
        let raw = if pre_filters.is_empty() {
            s.content.clone()
        } else {
            pre.dict.set("Filter", Object::Array(pre_filters));
            pre.dict.remove(b"DecodeParms");
            match pre.get_plain_content_with_limit(self.policy.max_stream_size) {
                Ok(r) => r,
                Err(_) => return Ok(None),
            }
        };
        if codec == b"DCTDecode" && !raw.starts_with(b"\xff\xd8") {
            self.findings.add(
                "image",
                Severity::Medium,
                "JPEG 형식이 아닌 DCT 이미지 제외",
                "",
            );
            return Ok(None);
        }
        dict.set("Filter", Object::Name(codec.clone()));
        if codec == b"CCITTFaxDecode" {
            if let Ok(parms) = s.dict.get(b"DecodeParms") {
                let parms = match parms {
                    Object::Array(a) => a.last().cloned().unwrap_or(Object::Null),
                    o => o.clone(),
                };
                if let Some(p) = self.copy(&parms, Role::Generic, depth + 1)? {
                    dict.set("DecodeParms", p);
                }
            }
        }
        Ok(Some(Stream::new(dict, raw).with_compression(false)))
    }

    /// 글꼴 프로그램 스트림. TrueType 외곽선 글꼴은 새로 조립하고, 조립할 수 없으면 제외한다.
    /// CFF 계열(FontFile3 의 Type1C/CIDFontType0C/CFF OpenType)은 None 을 돌려 일반 스트림으로 옮긴다.
    fn font_program(
        &mut self,
        s: &Stream,
        role: Role,
        depth: usize,
    ) -> Result<Option<Option<Stream>>> {
        let Ok(plain) = s.get_plain_content_with_limit(self.policy.max_stream_size) else {
            self.findings.add(
                "font",
                Severity::Low,
                "해제할 수 없는 글꼴 프로그램 제외",
                "",
            );
            return Ok(Some(None));
        };
        if role == Role::FontFile3 && !font::is_truetype(&plain) {
            // CFF 계열: 구조를 새로 쓰지는 않고, 모든 글리프 프로그램을 독립 해석기로 검증한 뒤 옮긴다
            return match font::validate_cff(&plain) {
                Ok(glyphs) => {
                    *self.font_stats.entry("cff_fonts_validated").or_default() += 1;
                    *self.font_stats.entry("cff_glyphs_validated").or_default() += glyphs as u64;
                    Ok(None)
                }
                Err(e) => {
                    self.findings.add(
                        "font",
                        Severity::Medium,
                        format!("검증을 통과하지 못한 CFF 글꼴 프로그램 제외 ({e})"),
                        "",
                    );
                    Ok(Some(None))
                }
            };
        }
        match font::rebuild_truetype(&plain) {
            Ok(rebuilt) => {
                *self.font_stats.entry("fonts_rebuilt").or_default() += 1;
                *self
                    .font_stats
                    .entry("font_glyph_programs_removed")
                    .or_default() += rebuilt.stripped_glyphs as u64;
                if rebuilt
                    .dropped_tables
                    .iter()
                    .any(|t| matches!(t.as_str(), "fpgm" | "prep" | "cvt"))
                {
                    *self.font_stats.entry("font_hinting_removed").or_default() += 1;
                }
                let mut dict = self.copy_dict(&s.dict, depth)?;
                for k in [
                    b"Filter".as_slice(),
                    b"DecodeParms",
                    b"Length",
                    b"DL",
                    b"F",
                    b"FFilter",
                    b"FDecodeParms",
                    b"Length2",
                    b"Length3",
                ] {
                    dict.remove(k);
                }
                dict.set("Length1", Object::Integer(rebuilt.data.len() as i64));
                Ok(Some(Some(Stream::new(dict, rebuilt.data))))
            }
            Err(e) => {
                self.findings.add(
                    "font",
                    Severity::Low,
                    format!("재조합할 수 없는 TrueType 글꼴 프로그램 제외 ({e})"),
                    "",
                );
                Ok(Some(None))
            }
        }
    }

    /// 복사된 리소스 사전에서 특정 범주의 이름 목록
    fn resource_names(&self, dict: &Dictionary, category: &[u8]) -> HashSet<Vec<u8>> {
        let Ok(res) = dict.get(b"Resources") else {
            return HashSet::new();
        };
        let res = match res {
            Object::Reference(id) => self.dst.get_object(*id).ok(),
            o => Some(o),
        };
        let Some(Ok(res)) = res.map(Object::as_dict) else {
            return HashSet::new();
        };
        let Ok(cat) = res.get(category) else {
            return HashSet::new();
        };
        let cat = match cat {
            Object::Reference(id) => self.dst.get_object(*id).ok(),
            o => Some(o),
        };
        match cat.map(Object::as_dict) {
            Some(Ok(d)) => d.iter().map(|(k, _)| k.clone()).collect(),
            _ => HashSet::new(),
        }
    }
}

pub fn reassemble(data: &[u8], policy: &Policy, findings: &mut Findings) -> Result<Vec<u8>> {
    let rebuilt = rebuild(data, policy, findings)?;
    if policy.pdf_rasterize {
        // 렌더러가 원본의 악성 구조를 보지 않도록 재조합된 문서를 렌더링한다
        return raster::rasterize(&rebuilt, policy, findings);
    }
    Ok(rebuilt)
}

fn rebuild(data: &[u8], policy: &Policy, findings: &mut Findings) -> Result<Vec<u8>> {
    let mut opts = LoadOptions::with_max_decompressed_size(policy.max_stream_size);
    opts.strict = false;
    let src = match Document::load_mem_with_options(data, opts) {
        Ok(d) => d,
        Err(e) => {
            let msg = e.to_string();
            if msg.to_ascii_lowercase().contains("password")
                || msg.to_ascii_lowercase().contains("decrypt")
            {
                return blocked("encrypted", "암호로 보호된 PDF - 내용 검사 불가");
            }
            return blocked("structure", format!("PDF 해석 실패: {msg}"));
        }
    };
    if src.is_encrypted() {
        return blocked("encrypted", "암호로 보호된 PDF - 내용 검사 불가");
    }
    if src.was_encrypted() {
        findings.add(
            "encryption",
            Severity::Info,
            "권한 암호가 설정된 문서를 암호 없이 재조합",
            "",
        );
    }

    // 원본에서 새 문서에 포함되지 않는 위험 요소를 보고한다
    scan::report_threats(data, &src, policy, findings);

    let pages = src.get_pages();
    if pages.is_empty() {
        return blocked("structure", "페이지가 없는 PDF");
    }
    if pages.len() > policy.max_pdf_pages {
        return blocked(
            "structure",
            format!("페이지 수 제한 초과 ({})", pages.len()),
        );
    }

    let mut copier = Copier {
        src: &src,
        dst: Document::with_version("1.7"),
        map: HashMap::new(),
        rejected: HashSet::new(),
        policy,
        findings,
        copied: 0,
        dropped_ops: HashMap::new(),
        font_stats: BTreeMap::new(),
        content_tokens: 0,
    };
    let pages_id = copier.dst.new_object_id();

    // 1차: 페이지 ID 예약 (문서 내 이동 링크/책갈피 대상 매핑용)
    let mut page_map: HashMap<ObjectId, ObjectId> = HashMap::new();
    let mut order: Vec<(ObjectId, ObjectId)> = Vec::new();
    for src_id in pages.values() {
        let new_id = copier.dst.new_object_id();
        page_map.insert(*src_id, new_id);
        order.push((*src_id, new_id));
    }

    // 2차: 페이지 재조합
    let mut links_total = 0u64;
    let mut flattened_total = 0u64;
    for (idx, (src_id, new_id)) in order.iter().enumerate() {
        let (page, links, flattened) =
            build_page(&mut copier, *src_id, pages_id, &page_map, idx + 1)?;
        links_total += links;
        flattened_total += flattened;
        copier.dst.objects.insert(*new_id, Object::Dictionary(page));
    }

    let kids: Vec<Object> = order.iter().map(|(_, n)| Object::Reference(*n)).collect();
    let mut pages_dict = Dictionary::new();
    pages_dict.set("Type", Object::Name(b"Pages".to_vec()));
    pages_dict.set("Count", Object::Integer(kids.len() as i64));
    pages_dict.set("Kids", Object::Array(kids));
    copier
        .dst
        .objects
        .insert(pages_id, Object::Dictionary(pages_dict));

    // 카탈로그: Pages 와 책갈피만
    let mut catalog = Dictionary::new();
    catalog.set("Type", Object::Name(b"Catalog".to_vec()));
    catalog.set("Pages", Object::Reference(pages_id));
    if let Some(outlines) = build_outlines(&mut copier, &page_map) {
        catalog.set("Outlines", Object::Reference(outlines));
    }
    let catalog_id = copier.dst.add_object(Object::Dictionary(catalog));

    let mut info = Dictionary::new();
    info.set(
        "Producer",
        Object::String(b"CDR reassembly".to_vec(), StringFormat::Literal),
    );
    if !policy.strip_metadata {
        if let Ok(src_info) = src.trailer.get(b"Info").and_then(|o| match o {
            Object::Reference(id) => src.get_dictionary(*id),
            o => o.as_dict(),
        }) {
            for key in [
                b"Title".as_slice(),
                b"Author",
                b"Subject",
                b"Keywords",
                b"CreationDate",
            ] {
                if let Ok(Object::String(s, f)) = src_info.get(key) {
                    info.set(key.to_vec(), Object::String(s.clone(), *f));
                }
            }
        }
    }
    let info_id = copier.dst.add_object(Object::Dictionary(info));

    let dropped_ops: u64 = copier.dropped_ops.values().sum();
    let mut dropped_list: Vec<_> = copier.dropped_ops.iter().collect();
    dropped_list.sort();
    let copied_objects = copier.copied as u64;
    let Copier {
        mut dst,
        findings,
        font_stats,
        ..
    } = copier;
    for (k, v) in font_stats {
        findings.count(k, v);
    }
    if dropped_ops > 0 {
        let names: Vec<String> = dropped_list
            .iter()
            .take(10)
            .map(|(k, v)| format!("{k}×{v}"))
            .collect();
        findings.add(
            "content-stream",
            Severity::Low,
            format!("허용 목록 외 콘텐츠 연산자 제외: {}", names.join(", ")),
            "",
        );
    }
    findings.count("pages", order.len() as u64);
    findings.count("objects_copied", copied_objects);
    findings.count("links_rebuilt", links_total);
    findings.count("annotations_flattened", flattened_total);

    dst.trailer.set("Root", Object::Reference(catalog_id));
    dst.trailer.set("Info", Object::Reference(info_id));
    dst.max_id = dst.objects.keys().map(|(id, _)| *id).max().unwrap_or(0);
    dst.compress();

    let mut out = Vec::new();
    if let Err(e) = dst.save_to(&mut out) {
        return blocked("reconstruct", format!("PDF 작성 실패: {e}"));
    }
    Ok(out)
}

/// 페이지 트리에서 상속되는 속성을 찾는다.
fn inherited<'a>(src: &'a Document, page_id: ObjectId, key: &[u8]) -> Option<&'a Object> {
    let mut cur = src.get_dictionary(page_id).ok()?;
    for _ in 0..64 {
        if let Ok(v) = cur.get(key) {
            return Some(v);
        }
        let parent = cur.get(b"Parent").and_then(Object::as_reference).ok()?;
        cur = src.get_dictionary(parent).ok()?;
    }
    None
}

fn number(o: &Object) -> Option<f32> {
    match o {
        Object::Integer(i) => Some(*i as f32),
        Object::Real(r) if r.is_finite() => Some(*r),
        _ => None,
    }
}

fn rect(src: &Document, o: Option<&Object>) -> Option<[f32; 4]> {
    let o = match o? {
        Object::Reference(id) => src.get_object(*id).ok()?,
        o => o,
    };
    let arr = o.as_array().ok()?;
    if arr.len() != 4 {
        return None;
    }
    let v: Vec<f32> = arr
        .iter()
        .filter_map(|x| number(src.dereference(x).ok()?.1))
        .collect();
    if v.len() != 4 {
        return None;
    }
    let (x0, x1) = (v[0].min(v[2]), v[0].max(v[2]));
    let (y0, y1) = (v[1].min(v[3]), v[1].max(v[3]));
    if x1 - x0 < 1.0 || y1 - y0 < 1.0 || x1 - x0 > 200_000.0 || y1 - y0 > 200_000.0 {
        return None;
    }
    Some([x0, y0, x1, y1])
}

fn rect_obj(r: [f32; 4]) -> Object {
    Object::Array(r.iter().map(|v| Object::Real(*v)).collect())
}

const RESOURCE_CATEGORIES: &[&[u8]] = &[
    b"Font",
    b"XObject",
    b"ExtGState",
    b"ColorSpace",
    b"Pattern",
    b"Shading",
];

fn build_page(
    c: &mut Copier,
    src_id: ObjectId,
    pages_id: ObjectId,
    page_map: &HashMap<ObjectId, ObjectId>,
    page_no: usize,
) -> Result<(Dictionary, u64, u64)> {
    let src = c.src;
    let media = rect(src, inherited(src, src_id, b"MediaBox")).unwrap_or([0.0, 0.0, 612.0, 792.0]);
    let crop = rect(src, inherited(src, src_id, b"CropBox"));
    let rotate = inherited(src, src_id, b"Rotate")
        .and_then(|o| o.as_i64().ok())
        .filter(|r| r % 90 == 0)
        .map(|r| r.rem_euclid(360));

    // 리소스: 허용 범주만 새로 구성
    let mut resources = Dictionary::new();
    if let Some(res) = inherited(src, src_id, b"Resources")
        .and_then(|o| c.deref(o))
        .and_then(|o| o.as_dict().ok())
        .cloned()
    {
        for cat in RESOURCE_CATEGORIES {
            let Some(entries) = res
                .get(cat)
                .ok()
                .and_then(|o| c.deref(o))
                .and_then(|o| o.as_dict().ok())
                .cloned()
            else {
                continue;
            };
            let mut nd = Dictionary::new();
            for (name, val) in entries.iter() {
                if let Some(o) = c.copy(val, Role::Generic, 0)? {
                    nd.set(name.clone(), o);
                }
            }
            if !nd.is_empty() {
                resources.set(cat.to_vec(), Object::Dictionary(nd));
            }
        }
    }

    // 콘텐츠
    let raw = match src.get_page_content_with_limit(src_id, c.policy.max_stream_size) {
        Ok(r) => r,
        Err(e) => {
            return blocked(
                "structure",
                format!("{page_no} 페이지 콘텐츠 해제 실패: {e}"),
            )
        }
    };
    let ops = match c.decode_ops(&raw)? {
        Some(ops) => ops,
        None => {
            return blocked(
                "structure",
                format!("{page_no} 페이지 콘텐츠 스트림 해석 실패"),
            )
        }
    };
    let xobject_names: HashSet<Vec<u8>> = match resources.get(b"XObject") {
        Ok(Object::Dictionary(d)) => d.iter().map(|(k, _)| k.clone()).collect(),
        _ => HashSet::new(),
    };
    let mut ops = content::filter(ops, Some(&xobject_names), &mut c.dropped_ops);
    // 원본 콘텐츠의 그래픽 상태가 주석 평면화에 영향을 주지 않도록 감싼다
    ops.insert(0, Operation::new("q", vec![]));
    ops.push(Operation::new("Q", vec![]));

    // 주석: 링크 재생성, 나머지는 외형 평면화
    let mut links: Vec<Object> = Vec::new();
    let mut flattened = 0u64;
    let annots: Vec<Object> = src
        .get_dictionary(src_id)
        .ok()
        .and_then(|d| d.get(b"Annots").ok())
        .and_then(|o| c.deref(o))
        .and_then(|o| o.as_array().ok())
        .cloned()
        .unwrap_or_default();
    let mut ap_index = 0usize;
    for a in annots.iter().take(10_000) {
        let Some(annot) = c.deref(a).and_then(|o| o.as_dict().ok()).cloned() else {
            continue;
        };
        let subtype = annot
            .get(b"Subtype")
            .and_then(Object::as_name)
            .unwrap_or(b"");
        let flags = annot.get(b"F").and_then(Object::as_i64).unwrap_or(0);
        let Some(r) = rect(src, annot.get(b"Rect").ok()) else {
            continue;
        };
        if subtype == b"Link" {
            if let Some(link) = build_link(c, &annot, r, page_map) {
                links.push(Object::Reference(
                    c.dst.add_object(Object::Dictionary(link)),
                ));
            }
            continue;
        }
        if subtype == b"Popup" || flags & 0x2 != 0 || !c.policy.flatten_pdf_annotations {
            continue;
        }
        if let Some((name, matrix)) =
            flatten_annotation(c, &annot, r, &mut resources, &mut ap_index)?
        {
            ops.push(Operation::new("q", vec![]));
            ops.push(Operation::new(
                "cm",
                matrix.iter().map(|v| Object::Real(*v)).collect(),
            ));
            ops.push(Operation::new("Do", vec![Object::Name(name)]));
            ops.push(Operation::new("Q", vec![]));
            flattened += 1;
        }
    }

    let content_id = c.dst.add_object(Object::Stream(Stream::new(
        Dictionary::new(),
        content::encode(&ops),
    )));

    let mut page = Dictionary::new();
    page.set("Type", Object::Name(b"Page".to_vec()));
    page.set("Parent", Object::Reference(pages_id));
    page.set("MediaBox", rect_obj(media));
    if let Some(cb) = crop {
        page.set("CropBox", rect_obj(cb));
    }
    if let Some(rot) = rotate {
        page.set("Rotate", Object::Integer(rot));
    }
    page.set("Resources", Object::Dictionary(resources));
    page.set("Contents", Object::Reference(content_id));
    let link_count = links.len() as u64;
    if !links.is_empty() {
        page.set("Annots", Object::Array(links));
    }
    Ok((page, link_count, flattened))
}

/// 링크 주석을 새로 만든다: 허용 스킴의 URI 또는 문서 내 페이지 이동만.
fn build_link(
    c: &mut Copier,
    annot: &Dictionary,
    r: [f32; 4],
    page_map: &HashMap<ObjectId, ObjectId>,
) -> Option<Dictionary> {
    let mut link = Dictionary::new();
    link.set("Type", Object::Name(b"Annot".to_vec()));
    link.set("Subtype", Object::Name(b"Link".to_vec()));
    link.set("Rect", rect_obj(r));
    link.set(
        "Border",
        Object::Array(vec![
            Object::Integer(0),
            Object::Integer(0),
            Object::Integer(0),
        ]),
    );

    let action = annot
        .get(b"A")
        .ok()
        .and_then(|o| c.deref(o))
        .and_then(|o| o.as_dict().ok());
    if let Some(action) = action {
        match action.get(b"S").and_then(Object::as_name).unwrap_or(b"") {
            b"URI" => {
                let uri = action
                    .get(b"URI")
                    .ok()
                    .and_then(|o| c.deref(o))
                    .and_then(|o| o.as_str().ok())?;
                let uri_s = String::from_utf8_lossy(uri).to_string();
                if !c.policy.uri_allowed(&uri_s) || c.policy.remove_hyperlinks {
                    return None; // scan 단계에서 이미 보고됨
                }
                let mut a = Dictionary::new();
                a.set("S", Object::Name(b"URI".to_vec()));
                a.set("URI", Object::String(uri.to_vec(), StringFormat::Literal));
                link.set("A", Object::Dictionary(a));
                return Some(link);
            }
            b"GoTo" => {
                let dest = action.get(b"D").ok().and_then(|o| c.deref(o))?;
                link.set("Dest", map_dest(c, dest, page_map)?);
                return Some(link);
            }
            _ => return None,
        }
    }
    let dest = annot.get(b"Dest").ok().and_then(|o| c.deref(o))?;
    link.set("Dest", map_dest(c, dest, page_map)?);
    Some(link)
}

/// 명시적 목적지 배열의 페이지 참조를 새 문서의 페이지로 바꾼다.
fn map_dest(c: &Copier, dest: &Object, page_map: &HashMap<ObjectId, ObjectId>) -> Option<Object> {
    let arr = dest.as_array().ok()?;
    let page = arr.first()?.as_reference().ok()?;
    let new_page = page_map.get(&page)?;
    let mut out = vec![Object::Reference(*new_page)];
    let kind = arr.get(1).and_then(|o| o.as_name().ok()).unwrap_or(b"Fit");
    let allowed: &[&[u8]] = &[
        b"XYZ", b"Fit", b"FitH", b"FitV", b"FitR", b"FitB", b"FitBH", b"FitBV",
    ];
    if !allowed.contains(&kind) {
        return Some(Object::Array(vec![
            Object::Reference(*new_page),
            Object::Name(b"Fit".to_vec()),
        ]));
    }
    out.push(Object::Name(kind.to_vec()));
    for o in arr.iter().skip(2).take(4) {
        match c.deref(o) {
            Some(Object::Integer(i)) => out.push(Object::Integer(*i)),
            Some(Object::Real(r)) => out.push(Object::Real(*r)),
            _ => out.push(Object::Null),
        }
    }
    Some(Object::Array(out))
}

/// 주석의 정상 외형(/AP /N)을 폼 XObject 로 재조합하고 페이지에 그릴 변환 행렬을 계산한다.
fn flatten_annotation(
    c: &mut Copier,
    annot: &Dictionary,
    r: [f32; 4],
    resources: &mut Dictionary,
    index: &mut usize,
) -> Result<Option<(Vec<u8>, [f32; 6])>> {
    let Some(ap) = annot
        .get(b"AP")
        .ok()
        .and_then(|o| c.deref(o))
        .and_then(|o| o.as_dict().ok())
        .cloned()
    else {
        return Ok(None);
    };
    let Ok(normal) = ap.get(b"N") else {
        return Ok(None);
    };
    // 상태별 외형(체크박스 등)이면 /AS 로 선택
    let normal = match c.deref(normal) {
        Some(Object::Dictionary(states)) => {
            let Ok(state) = annot.get(b"AS").and_then(Object::as_name) else {
                return Ok(None);
            };
            match states.get(state) {
                Ok(o) => o.clone(),
                Err(_) => return Ok(None),
            }
        }
        Some(Object::Stream(_)) => normal.clone(),
        _ => return Ok(None),
    };
    let Some(Object::Stream(stream)) = c.deref(&normal).cloned() else {
        return Ok(None);
    };
    let bbox =
        rect(c.src, stream.dict.get(b"BBox").ok()).unwrap_or([0.0, 0.0, r[2] - r[0], r[3] - r[1]]);
    let m: [f32; 6] = match stream
        .dict
        .get(b"Matrix")
        .ok()
        .and_then(|o| c.deref(o))
        .and_then(|o| o.as_array().ok())
    {
        Some(a) if a.len() == 6 => {
            let v: Vec<f32> = a.iter().filter_map(number).collect();
            if v.len() == 6 {
                [v[0], v[1], v[2], v[3], v[4], v[5]]
            } else {
                [1.0, 0.0, 0.0, 1.0, 0.0, 0.0]
            }
        }
        _ => [1.0, 0.0, 0.0, 1.0, 0.0, 0.0],
    };

    // 폼 XObject 로 재조합 (appearance 스트림의 Subtype 이 누락된 경우 보정)
    let mut form = stream.clone();
    form.dict.set("Type", Object::Name(b"XObject".to_vec()));
    form.dict.set("Subtype", Object::Name(b"Form".to_vec()));
    let Some(Object::Stream(mut copied)) =
        c.copy_stream(&form, Role::Content, 1)?.map(Object::Stream)
    else {
        return Ok(None);
    };
    copied.dict.set("BBox", rect_obj(bbox));
    let form_id = c.dst.add_object(Object::Stream(copied));

    // PDF 32000 12.5.5: 변환된 BBox 를 Rect 에 맞추는 행렬 A
    let corners = [
        (bbox[0], bbox[1]),
        (bbox[2], bbox[1]),
        (bbox[0], bbox[3]),
        (bbox[2], bbox[3]),
    ];
    let tx: Vec<(f32, f32)> = corners
        .iter()
        .map(|(x, y)| (m[0] * x + m[2] * y + m[4], m[1] * x + m[3] * y + m[5]))
        .collect();
    let min_x = tx.iter().map(|p| p.0).fold(f32::INFINITY, f32::min);
    let max_x = tx.iter().map(|p| p.0).fold(f32::NEG_INFINITY, f32::max);
    let min_y = tx.iter().map(|p| p.1).fold(f32::INFINITY, f32::min);
    let max_y = tx.iter().map(|p| p.1).fold(f32::NEG_INFINITY, f32::max);
    if max_x - min_x <= 0.0 || max_y - min_y <= 0.0 {
        return Ok(None);
    }
    let sx = (r[2] - r[0]) / (max_x - min_x);
    let sy = (r[3] - r[1]) / (max_y - min_y);
    let matrix = [sx, 0.0, 0.0, sy, r[0] - min_x * sx, r[1] - min_y * sy];

    *index += 1;
    let name = format!("CdrAnnot{index}").into_bytes();
    let xobjects = match resources.get_mut(b"XObject") {
        Ok(Object::Dictionary(d)) => d,
        _ => {
            resources.set("XObject", Object::Dictionary(Dictionary::new()));
            resources
                .get_mut(b"XObject")
                .and_then(Object::as_dict_mut)
                .expect("방금 생성")
        }
    };
    xobjects.set(name.clone(), Object::Reference(form_id));
    Ok(Some((name, matrix)))
}

/// 책갈피를 제목과 문서 내 이동 목적지만으로 새로 만든다.
fn build_outlines(c: &mut Copier, page_map: &HashMap<ObjectId, ObjectId>) -> Option<ObjectId> {
    let src = c.src;
    let root = src
        .catalog()
        .ok()?
        .get(b"Outlines")
        .ok()?
        .as_reference()
        .ok()?;
    let first = src
        .get_dictionary(root)
        .ok()?
        .get(b"First")
        .ok()?
        .as_reference()
        .ok()?;
    let mut visited = HashSet::new();
    let outlines_id = c.dst.new_object_id();
    let (first_new, last_new, count) =
        build_outline_level(c, first, outlines_id, page_map, &mut visited, 0)?;
    let mut d = Dictionary::new();
    d.set("Type", Object::Name(b"Outlines".to_vec()));
    d.set("First", Object::Reference(first_new));
    d.set("Last", Object::Reference(last_new));
    d.set("Count", Object::Integer(count));
    c.dst.objects.insert(outlines_id, Object::Dictionary(d));
    Some(outlines_id)
}

fn build_outline_level(
    c: &mut Copier,
    first: ObjectId,
    parent: ObjectId,
    page_map: &HashMap<ObjectId, ObjectId>,
    visited: &mut HashSet<ObjectId>,
    depth: usize,
) -> Option<(ObjectId, ObjectId, i64)> {
    if depth > 32 {
        return None;
    }
    let src = c.src;
    let mut items: Vec<(ObjectId, Dictionary)> = Vec::new();
    let mut cur = Some(first);
    let mut total = 0i64;
    while let Some(id) = cur {
        if !visited.insert(id) || visited.len() > MAX_OUTLINE_ITEMS {
            break;
        }
        let Ok(item) = src.get_dictionary(id) else {
            break;
        };
        let new_id = c.dst.new_object_id();
        let mut d = Dictionary::new();
        let title = item
            .get(b"Title")
            .ok()
            .and_then(|o| c.deref(o))
            .and_then(|o| o.as_str().ok())
            .unwrap_or(b"")
            .to_vec();
        d.set("Title", Object::String(title, StringFormat::Literal));
        d.set("Parent", Object::Reference(parent));
        let dest = item
            .get(b"Dest")
            .ok()
            .and_then(|o| c.deref(o))
            .cloned()
            .or_else(|| {
                let a = item
                    .get(b"A")
                    .ok()
                    .and_then(|o| c.deref(o))?
                    .as_dict()
                    .ok()?;
                if a.get(b"S").and_then(Object::as_name).ok()? == b"GoTo" {
                    a.get(b"D").ok().and_then(|o| c.deref(o)).cloned()
                } else {
                    None
                }
            });
        if let Some(dest) = dest.and_then(|d| map_dest(c, &d, page_map)) {
            d.set("Dest", dest);
        }
        if let Ok(child) = item.get(b"First").and_then(Object::as_reference) {
            if let Some((f, l, n)) =
                build_outline_level(c, child, new_id, page_map, visited, depth + 1)
            {
                d.set("First", Object::Reference(f));
                d.set("Last", Object::Reference(l));
                d.set("Count", Object::Integer(-n)); // 하위 항목은 접힌 상태로
            }
        }
        items.push((new_id, d));
        total += 1;
        cur = item.get(b"Next").and_then(Object::as_reference).ok();
    }
    if items.is_empty() {
        return None;
    }
    let ids: Vec<ObjectId> = items.iter().map(|(i, _)| *i).collect();
    for (i, (id, mut d)) in items.into_iter().enumerate() {
        if i > 0 {
            d.set("Prev", Object::Reference(ids[i - 1]));
        }
        if i + 1 < ids.len() {
            d.set("Next", Object::Reference(ids[i + 1]));
        }
        c.dst.objects.insert(id, Object::Dictionary(d));
    }
    Some((ids[0], *ids.last().unwrap(), total))
}
