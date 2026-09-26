//! 정책 설정 파일(TOML).
//!
//! 지정하지 않은 항목은 기본값을 쓴다. 알 수 없는 키는 오타로 인한 정책 누락을 막기 위해
//! 오류로 처리한다. 기본 설정 파일은 `cdr policy` 로 출력할 수 있다.

use std::path::Path;

use serde::Deserialize;

use crate::policy::Policy;

const MB: u64 = 1024 * 1024;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyFile {
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub links: Links,
    #[serde(default)]
    pub content: Content,
    #[serde(default)]
    pub pdf: Pdf,
    #[serde(default)]
    pub archive: Archive,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Archive {
    pub enabled: Option<bool>,
    pub strict: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub max_file_size_mb: Option<u64>,
    pub max_zip_entries: Option<usize>,
    pub max_zip_total_mb: Option<u64>,
    pub max_zip_ratio: Option<u64>,
    pub max_xml_depth: Option<usize>,
    pub max_xml_nodes: Option<usize>,
    pub max_image_megapixels: Option<u64>,
    pub max_pdf_pages: Option<usize>,
    pub max_stream_size_mb: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Links {
    pub allowed_uri_schemes: Option<Vec<String>>,
    pub remove_hyperlinks: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Content {
    pub strip_metadata: Option<bool>,
    pub flatten_pdf_annotations: Option<bool>,
    pub neutralize_embedded_ole: Option<bool>,
    pub allow_images: Option<bool>,
    pub allow_text: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pdf {
    pub rasterize: Option<bool>,
    pub raster_dpi: Option<f32>,
    pub raster_jpeg_quality: Option<u8>,
}

impl PolicyFile {
    pub fn parse(text: &str) -> Result<PolicyFile, String> {
        toml::from_str(text).map_err(|e| format!("정책 파일 해석 실패: {e}"))
    }

    pub fn load(path: &Path) -> Result<PolicyFile, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("정책 파일 읽기 실패: {} ({e})", path.display()))?;
        Self::parse(&text)
    }

    /// 기본 정책 위에 설정 파일 값을 덮어쓴 정책
    pub fn into_policy(self) -> Result<Policy, String> {
        let mut p = Policy::default();
        let l = self.limits;
        let to_usize = |mb: u64| usize::try_from(mb.saturating_mul(MB)).unwrap_or(usize::MAX);
        if let Some(v) = l.max_file_size_mb {
            p.max_file_size = to_usize(v);
        }
        if let Some(v) = l.max_zip_entries {
            p.max_zip_entries = v;
        }
        if let Some(v) = l.max_zip_total_mb {
            p.max_zip_total = v.saturating_mul(MB);
        }
        if let Some(v) = l.max_zip_ratio {
            p.max_zip_ratio = v;
        }
        if let Some(v) = l.max_xml_depth {
            p.max_xml_depth = v;
        }
        if let Some(v) = l.max_xml_nodes {
            p.max_xml_nodes = v;
        }
        if let Some(v) = l.max_image_megapixels {
            p.max_image_pixels = v.saturating_mul(1_000_000);
        }
        if let Some(v) = l.max_pdf_pages {
            p.max_pdf_pages = v;
        }
        if let Some(v) = l.max_stream_size_mb {
            p.max_stream_size = to_usize(v);
        }

        if let Some(schemes) = self.links.allowed_uri_schemes {
            let mut out = Vec::new();
            for s in schemes {
                let s = s.trim().trim_end_matches(':').to_ascii_lowercase();
                if s.is_empty()
                    || !s
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
                {
                    return Err(format!("잘못된 URI 스킴: {s:?}"));
                }
                if matches!(s.as_str(), "file" | "javascript" | "vbscript" | "data") {
                    return Err(format!("위험한 URI 스킴은 허용할 수 없습니다: {s}"));
                }
                out.push(s);
            }
            p.allowed_uri_schemes = out;
        }
        if let Some(v) = self.links.remove_hyperlinks {
            p.remove_hyperlinks = v;
        }
        if let Some(v) = self.content.strip_metadata {
            p.strip_metadata = v;
        }
        if let Some(v) = self.content.flatten_pdf_annotations {
            p.flatten_pdf_annotations = v;
        }
        if let Some(v) = self.content.neutralize_embedded_ole {
            p.neutralize_embedded_ole = v;
        }
        if let Some(v) = self.content.allow_images {
            p.allow_images = v;
        }
        if let Some(v) = self.content.allow_text {
            p.allow_text = v;
        }
        if let Some(v) = self.archive.enabled {
            p.allow_archives = v;
        }
        if let Some(v) = self.archive.strict {
            p.strict_archives = v;
        }
        if let Some(v) = self.pdf.rasterize {
            p.pdf_rasterize = v;
        }
        if let Some(v) = self.pdf.raster_dpi {
            if !(36.0..=600.0).contains(&v) {
                return Err(format!("raster_dpi 는 36~600 이어야 합니다: {v}"));
            }
            p.raster_dpi = v;
        }
        if let Some(v) = self.pdf.raster_jpeg_quality {
            if !(10..=100).contains(&v) {
                return Err(format!("raster_jpeg_quality 는 10~100 이어야 합니다: {v}"));
            }
            p.raster_jpeg_quality = v;
        }
        Ok(p)
    }
}

/// 기본값과 설명이 들어간 정책 파일 예시
pub fn default_toml() -> String {
    let p = Policy::default();
    let schemes: Vec<String> = p
        .allowed_uri_schemes
        .iter()
        .map(|s| format!("\"{s}\""))
        .collect();
    format!(
        r#"# CDR 정책 파일 - 지정하지 않은 항목은 아래 기본값을 사용합니다.

[limits]
max_file_size_mb = {}          # 입력 파일 최대 크기
max_zip_entries = {}          # 압축 컨테이너(OOXML/HWPX) 최대 엔트리 수
max_zip_total_mb = {}          # 압축 해제 총량
max_zip_ratio = {}              # 엔트리별 최대 압축률 (Zip bomb 방어)
max_xml_depth = {}              # XML 최대 중첩 깊이
max_xml_nodes = {}          # 문서 전체 XML 최대 노드(요소+속성) 수
max_image_megapixels = {}       # 이미지 최대 화소 수(백만)
max_pdf_pages = {}             # PDF 최대 페이지 수
max_stream_size_mb = {}         # PDF 스트림/HWP 레코드 해제 최대 크기

[links]
allowed_uri_schemes = [{}]   # 남길 하이퍼링크 스킴 (file/javascript 등은 지정 불가)
remove_hyperlinks = {}         # 허용 스킴 링크까지 모두 제거

[content]
strip_metadata = {}             # 작성자 등 메타데이터 제거
flatten_pdf_annotations = {}    # PDF 주석·폼 외형을 본문에 평면화하여 보존
neutralize_embedded_ole = {}   # 레거시 PPT/XLS 임베디드 OLE 를 차단 대신 빈 개체로 대체
allow_images = {}               # 단독 이미지(PNG/JPEG/GIF/BMP)를 픽셀 재인코딩으로 재조합
allow_text = {}                 # 텍스트·CSV(txt/log/csv/tsv) 재조합(CSV 수식 주입 무력화)

[pdf]
rasterize = {}                 # 최고 보안 모드: 페이지를 이미지로 재구성
raster_dpi = {}                 # 이미지화 해상도
raster_jpeg_quality = {}         # 이미지화 JPEG 품질

[archive]
enabled = {}                   # 일반 ZIP 압축 파일을 항목별로 재조합 (false 면 차단)
strict = {}                    # 항목이 하나라도 차단되면 압축 파일 전체를 차단
"#,
        p.max_file_size as u64 / MB,
        p.max_zip_entries,
        p.max_zip_total / MB,
        p.max_zip_ratio,
        p.max_xml_depth,
        p.max_xml_nodes,
        p.max_image_pixels / 1_000_000,
        p.max_pdf_pages,
        p.max_stream_size as u64 / MB,
        schemes.join(", "),
        p.remove_hyperlinks,
        p.strip_metadata,
        p.flatten_pdf_annotations,
        p.neutralize_embedded_ole,
        p.allow_images,
        p.allow_text,
        p.pdf_rasterize,
        p.raster_dpi,
        p.raster_jpeg_quality,
        p.allow_archives,
        p.strict_archives,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_template_round_trips() {
        let p = PolicyFile::parse(&default_toml())
            .unwrap()
            .into_policy()
            .unwrap();
        let d = Policy::default();
        assert_eq!(p.max_file_size, d.max_file_size);
        assert_eq!(p.allowed_uri_schemes, d.allowed_uri_schemes);
        assert_eq!(p.raster_dpi, d.raster_dpi);
        assert_eq!(p.max_image_pixels, d.max_image_pixels);
    }

    #[test]
    fn overrides_and_validation() {
        let p = PolicyFile::parse(
            "[links]\nallowed_uri_schemes = [\"HTTPS\"]\n[pdf]\nrasterize = true\n",
        )
        .unwrap()
        .into_policy()
        .unwrap();
        assert_eq!(p.allowed_uri_schemes, vec!["https"]);
        assert!(p.pdf_rasterize);
        assert!(!p.uri_allowed("http://x"));
        assert!(
            PolicyFile::parse("[links]\nallowed_urischemes = []").is_err(),
            "오타 키는 거부"
        );
        assert!(
            PolicyFile::parse("[links]\nallowed_uri_schemes = [\"file\"]")
                .unwrap()
                .into_policy()
                .is_err()
        );
        assert!(PolicyFile::parse("[pdf]\nraster_dpi = 5000")
            .unwrap()
            .into_policy()
            .is_err());
    }
}
