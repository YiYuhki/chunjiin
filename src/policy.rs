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
    /// 문서(패키지) 전체의 최대 XML 노드(요소+속성) 수
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

    /// 레거시 PPT/XLS 의 임베디드 OLE 개체(와 PPT VBA 저장소)를 차단하지 않고
    /// 빈 개체로 대체한다. 미리보기 그림은 유지된다. (Office 에서의 동작은 문서에 따라 다를 수 있음)
    pub neutralize_embedded_ole: bool,

    /// 단독 이미지 파일(PNG/JPEG/GIF/BMP)을 픽셀 재인코딩으로 재조합한다 (false 면 차단)
    pub allow_images: bool,
    /// 일반 ZIP 압축 파일을 항목별로 재조합한다 (false 면 차단)
    pub allow_archives: bool,
    /// 압축 파일 안의 항목이 하나라도 차단되면 압축 파일 전체를 차단한다
    /// (false 면 차단된 항목만 빼고 새 압축 파일을 만든다)
    pub strict_archives: bool,

    /// 재검증 단계 전용: 이미 재인코딩된 이미지를 다시 인코딩하지 않고 헤더(크기)만 검사한다.
    /// 일반 사용에서는 false 여야 한다.
    #[doc(hidden)]
    pub media_passthrough: bool,
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
            neutralize_embedded_ole: false,
            allow_images: true,
            allow_archives: true,
            strict_archives: false,
            media_passthrough: false,
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
