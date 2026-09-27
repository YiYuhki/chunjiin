//! 최고 보안 모드: 페이지를 픽셀로 렌더링하여 이미지만으로 된 PDF 를 새로 만든다.
//!
//! 글꼴 프로그램, 벡터 그래픽, 이미지 코덱 데이터 등 원본에서 온 어떤 바이트도
//! 결과물에 남지 않는다. 렌더링은 순수 Rust(unsafe 금지) 렌더러 hayro 로 수행하며,
//! 입력은 이미 구조 재조합을 거친 문서이다.

use std::io::Cursor;

use hayro::hayro_interpret::InterpreterSettings;
use hayro::hayro_syntax::Pdf;
use hayro::vello_cpu::color::palette::css::WHITE;
use hayro::{render, RenderCache, RenderSettings};
use image::codecs::jpeg::JpegEncoder;
use image::{ExtendedColorType, ImageEncoder};
use lopdf::{dictionary, Document, Object, Stream};

use crate::error::{blocked, Result};
use crate::policy::Policy;
use crate::report::{Findings, Severity};

/// 페이지 한 장의 최대 픽셀 수 (메모리 보호)
const MAX_PAGE_PIXELS: f32 = 40_000_000.0;

pub fn rasterize(rebuilt: &[u8], policy: &Policy, findings: &mut Findings) -> Result<Vec<u8>> {
    let pdf = match Pdf::new(rebuilt.to_vec()) {
        Ok(p) => p,
        Err(e) => return blocked("rasterize", format!("래스터화용 PDF 해석 실패: {e:?}")),
    };
    let settings = InterpreterSettings::default();
    let cache = RenderCache::new();

    let mut doc = Document::with_version("1.7");
    let pages_id = doc.new_object_id();
    let mut kids = Vec::new();
    let mut reduced = 0u64;

    for page in pdf.pages().iter() {
        let (w_pt, h_pt) = page.render_dimensions();
        if !(w_pt.is_finite() && h_pt.is_finite()) || w_pt < 1.0 || h_pt < 1.0 {
            return blocked("rasterize", "비정상 페이지 크기");
        }
        // 요청 DPI 로 렌더링하되 페이지당 픽셀 수와 u16 한계를 넘지 않게 줄인다
        let mut scale = policy.raster_dpi.clamp(36.0, 600.0) / 72.0;
        let max_by_pixels = (MAX_PAGE_PIXELS / (w_pt * h_pt)).sqrt();
        let max_by_dim = 65_000.0 / w_pt.max(h_pt);
        let limit = max_by_pixels.min(max_by_dim);
        if scale > limit {
            scale = limit;
            reduced += 1;
        }
        let render_settings = RenderSettings {
            x_scale: scale,
            y_scale: scale,
            bg_color: WHITE,
            ..Default::default()
        };
        let pixmap = render(page, &cache, &settings, &render_settings);
        let (pw, ph) = (pixmap.width() as u32, pixmap.height() as u32);
        if pw == 0 || ph == 0 {
            return blocked("rasterize", "페이지 렌더링 결과가 비어 있음");
        }

        // 흰 배경 위에 렌더링했으므로 불투명 - RGB 로 변환
        let rgba = pixmap.take_unpremultiplied();
        let mut rgb = Vec::with_capacity(rgba.len() * 3);
        for p in &rgba {
            rgb.extend_from_slice(&[p.r, p.g, p.b]);
        }
        let mut jpeg = Cursor::new(Vec::new());
        let enc =
            JpegEncoder::new_with_quality(&mut jpeg, policy.raster_jpeg_quality.clamp(10, 100));
        if let Err(e) = enc.write_image(&rgb, pw, ph, ExtendedColorType::Rgb8) {
            return blocked("rasterize", format!("페이지 이미지 인코딩 실패: {e}"));
        }

        let image_id = doc.add_object(
            Stream::new(
                dictionary! {
                    "Type" => "XObject", "Subtype" => "Image",
                    "Width" => pw as i64, "Height" => ph as i64,
                    "ColorSpace" => "DeviceRGB", "BitsPerComponent" => 8, "Filter" => "DCTDecode",
                },
                jpeg.into_inner(),
            )
            .with_compression(false),
        );
        let content = format!("q {w_pt} 0 0 {h_pt} 0 0 cm /Pg Do Q");
        let content_id = doc.add_object(Stream::new(dictionary! {}, content.into_bytes()));
        let page_id = doc.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "MediaBox" => vec![0.into(), 0.into(), Object::Real(w_pt), Object::Real(h_pt)],
            "Resources" => dictionary! { "XObject" => dictionary! { "Pg" => image_id } },
            "Contents" => content_id,
        });
        kids.push(Object::Reference(page_id));
    }

    let count = kids.len() as i64;
    doc.objects.insert(
        pages_id,
        Object::Dictionary(dictionary! { "Type" => "Pages", "Kids" => kids, "Count" => count }),
    );
    let catalog = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
    let info = doc.add_object(
        dictionary! { "Producer" => Object::string_literal("CDR reassembly (rasterized)") },
    );
    doc.trailer.set("Root", catalog);
    doc.trailer.set("Info", info);
    doc.compress();

    findings.add(
        "rasterized",
        Severity::Info,
        format!(
            "최고 보안 모드: {count}쪽을 {}DPI 이미지로 재구성(텍스트 선택·링크 없음)",
            policy.raster_dpi
        ),
        "",
    );
    if reduced > 0 {
        findings.add(
            "rasterized",
            Severity::Info,
            format!("대형 페이지 {reduced}쪽은 해상도를 낮춰 렌더링"),
            "",
        );
    }
    findings.count("pages_rasterized", count as u64);

    let mut out = Vec::new();
    if let Err(e) = doc.save_to(&mut out) {
        return blocked("reconstruct", format!("PDF 작성 실패: {e}"));
    }
    Ok(out)
}
