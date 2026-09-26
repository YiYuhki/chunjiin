//! 재조합 정책.

#[derive(Debug, Clone)]
pub struct Policy {
    /// 입력 파일 최대 크기
    pub max_file_size: usize,

    /// 압축 컨테이너(OOXML) 제한 - Zip bomb 방어
    pub max_zip_entries: usize,
    pub max_zip_total: u64,
    pub max_zip_ratio: u64,

    /// XML 파싱 제한
    pub max_xml_depth: usize,
    pub max_xml_nodes: usize,

    /// 이미지 최대 픽셀 수 - 디컴프레션 폭탄 방어
    pub max_image_pixels: u64,

    /// PDF 제한
    pub max_pdf_pages: usize,
    pub max_stream_size: usize,

    /// 하이퍼링크: 허용 스킴 / 전부 제거 여부
    pub allowed_uri_schemes: Vec<String>,
    pub remove_hyperlinks: bool,

    /// 작성자 등 메타데이터 제거
    pub strip_metadata: bool,

    /// PDF 주석(폼 필드 포함)의 외형을 페이지 본문에 평면화하여 보존
    pub flatten_pdf_annotations: bool,

    /// 최고 보안 모드: PDF 를 재조합한 뒤 각 페이지를 이미지로 렌더링하여
    /// 이미지만으로 된 PDF 를 다시 만든다 (텍스트 선택·링크는 사라진다)
    pub pdf_rasterize: bool,
    /// 래스터화 해상도(DPI)
    pub raster_dpi: f32,
    /// 래스터화 JPEG 품질(1~100)
    pub raster_jpeg_quality: u8,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            max_file_size: 100 * 1024 * 1024,
            max_zip_entries: 10_000,
            max_zip_total: 1024 * 1024 * 1024,
            max_zip_ratio: 200,
            max_xml_depth: 256,
            max_xml_nodes: 5_000_000,
            max_image_pixels: 150_000_000,
            max_pdf_pages: 5_000,
            max_stream_size: 256 * 1024 * 1024,
            allowed_uri_schemes: vec!["http".into(), "https".into(), "mailto".into()],
            remove_hyperlinks: false,
            strip_metadata: true,
            flatten_pdf_annotations: true,
            pdf_rasterize: false,
            raster_dpi: 150.0,
            raster_jpeg_quality: 85,
        }
    }
}

impl Policy {
    /// 링크 대상이 허용 스킴인지 확인한다. 스킴이 없는 경로(상대 경로, UNC 등)는 허용하지 않는다.
    pub fn uri_allowed(&self, uri: &str) -> bool {
        let uri = uri.trim();
        match uri.find(':') {
            Some(idx) if idx > 0 => {
                let scheme = &uri[..idx];
                if !scheme
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
                {
                    return false;
                }
                let scheme = scheme.to_ascii_lowercase();
                self.allowed_uri_schemes.contains(&scheme)
            }
            _ => false,
        }
    }
}
