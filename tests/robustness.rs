//! 결정적(시드 고정) 변조 테스트: 모든 형식의 샘플을 무작위로 변조해 넣었을 때
//! - 엔진 내부 패닉(= "internal" 차단)이 없어야 하고
//! - 결과물이 나오면 그 결과물은 다시 넣어도 차단되지 않아야 한다(재조합 결과의 안정성).
//!
//! 압축 컨테이너(ZIP)와 복합 파일(CFB)은 체크섬·구조 때문에 바이트를 무작위로 바꾸면
//! 대부분 초입에서 거부되므로, 컨테이너를 풀어 **내부 파트를 변조한 뒤 다시 포장**하여
//! 실제 파서(XML, 레코드, 콘텐츠 스트림)까지 변조 입력이 도달하게 한다.
//!
//! 반복 횟수는 CDR_FUZZ_ITERS 환경 변수로 늘릴 수 있다(기본 60).

mod common;

use cdr::{Engine, Policy, Status};
use common::legacy;

/// 재현 가능한 xorshift 난수
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

const INTERESTING: &[&[u8]] = &[
    b"<",
    b">",
    b"&",
    b"\"",
    b"'",
    b"/",
    b"=",
    b":",
    b"\x00",
    b"\xff",
    b"<!DOCTYPE x [<!ENTITY a \"b\">]>",
    b"&#0;",
    b"&amp;",
    b"]]>",
    b"<?xml?>",
    b"r:id=\"rId999\"",
    b"\x13 DDEAUTO calc \x14",
    b"/JS",
    b"/AA",
    b"(\\)",
    b"<<",
    b">>",
    b"stream",
    b"endstream",
    b"obj",
    b"999999999",
    b"-1",
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
    b"PK\x03\x04",
];

fn mutate_bytes(rng: &mut Rng, data: &[u8]) -> Vec<u8> {
    let mut d = data.to_vec();
    for _ in 0..1 + rng.below(4) {
        if d.is_empty() {
            d.push(0);
        }
        match rng.below(6) {
            0 => {
                // 비트/바이트 뒤집기
                for _ in 0..1 + rng.below(16) {
                    let i = rng.below(d.len());
                    d[i] = rng.next() as u8;
                }
            }
            1 => d.truncate(rng.below(d.len())),
            2 => {
                // 구간 복제 (중첩·반복 구조 유도)
                let a = rng.below(d.len());
                let b = (a + 1 + rng.below(256)).min(d.len());
                let chunk = d[a..b].to_vec();
                for _ in 0..1 + rng.below(8) {
                    d.splice(a..a, chunk.iter().copied());
                }
            }
            3 => {
                let tok = INTERESTING[rng.below(INTERESTING.len())];
                let i = rng.below(d.len());
                d.splice(i..i, tok.iter().copied());
            }
            4 => {
                // 구간 삭제
                let a = rng.below(d.len());
                let b = (a + rng.below(64)).min(d.len());
                d.drain(a..b);
            }
            _ => {
                // 길이 필드처럼 보이는 4바이트를 극단값으로
                if d.len() >= 4 {
                    let i = rng.below(d.len() - 3);
                    let v: u32 = [0, 1, 0x7fff_ffff, 0xffff_ffff, 0x0fff_ffff][rng.below(5)];
                    d[i..i + 4].copy_from_slice(&v.to_le_bytes());
                }
            }
        }
    }
    d
}

/// ZIP 컨테이너: 파트 하나를 골라 변조하고 다시 포장
fn mutate_zip(rng: &mut Rng, data: &[u8]) -> Vec<u8> {
    let mut parts = common::unzip(data);
    if parts.is_empty() {
        return mutate_bytes(rng, data);
    }
    let i = rng.below(parts.len());
    parts[i].1 = mutate_bytes(rng, &parts[i].1);
    let refs: Vec<(&str, &[u8])> = parts
        .iter()
        .map(|(n, d)| (n.as_str(), d.as_slice()))
        .collect();
    common::make_zip(&refs)
}

/// 복합 파일: 스트림 하나를 골라 (압축돼 있으면 풀어서) 변조하고 다시 조립
fn mutate_cfb(rng: &mut Rng, data: &[u8]) -> Vec<u8> {
    let mut streams = legacy::read_cfb(data);
    if streams.is_empty() {
        return mutate_bytes(rng, data);
    }
    let i = rng.below(streams.len());
    let raw = &streams[i].1;
    let mut plain = Vec::new();
    let inflated = std::io::Read::read_to_end(
        &mut flate2::read::DeflateDecoder::new(raw.as_slice()),
        &mut plain,
    )
    .is_ok()
        && !plain.is_empty();
    streams[i].1 = if inflated && rng.below(2) == 0 {
        let m = mutate_bytes(rng, &plain);
        let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut e, &m).unwrap();
        e.finish().unwrap()
    } else {
        mutate_bytes(rng, raw)
    };
    let refs: Vec<(&str, &[u8])> = streams
        .iter()
        .map(|(n, d)| (n.as_str(), d.as_slice()))
        .collect();
    legacy::cfb(&refs)
}

fn iterations() -> usize {
    std::env::var("CDR_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60)
}

fn run(name: &str, seed: u64, sample: Vec<u8>, mutate: fn(&mut Rng, &[u8]) -> Vec<u8>) {
    run_with(Engine::default(), name, seed, sample, mutate)
}

fn run_with(
    engine: Engine,
    name: &str,
    seed: u64,
    sample: Vec<u8>,
    mutate: fn(&mut Rng, &[u8]) -> Vec<u8>,
) {
    let mut rng = Rng(seed);
    let mut outputs = 0;
    for i in 0..iterations() {
        let input = mutate(&mut rng, &sample);
        let r = engine.process(&input, name);
        assert!(
            !r.findings.iter().any(|f| f.category == "internal"),
            "{name} #{i}: 엔진 내부 오류(패닉) - {}",
            r.reason
        );
        if let (Some(out), Some(out_name)) = (&r.output, &r.output_filename) {
            outputs += 1;
            let again = engine.process(out, out_name);
            assert_ne!(
                again.status,
                Status::Blocked,
                "{name} #{i}: 재조합 결과가 다시 차단됨 - {}",
                again.reason
            );
        }
    }
    eprintln!("{name}: {} 회 변조, 재조합 성공 {outputs}", iterations());
}

#[test]
fn fuzz_ooxml() {
    run("a.docm", 1, common::malicious_docm(), mutate_zip);
    run("a.xlsm", 2, common::malicious_xlsm(), mutate_zip);
    run("a.ppsm", 3, common::malicious_ppsm(), mutate_zip);
}

#[test]
fn fuzz_hwpx() {
    run("a.hwpx", 4, common::malicious_hwpx(), mutate_zip);
}

#[test]
fn fuzz_pdf() {
    run("a.pdf", 5, common::malicious_pdf(), mutate_bytes);
    run("b.pdf", 6, common::clean_pdf(), mutate_bytes);
}

#[test]
fn fuzz_legacy() {
    run("a.hwp", 7, legacy::malicious_hwp(1 | 8), mutate_cfb);
    run("b.hwp", 8, legacy::malicious_hwp(0), mutate_cfb);
    run("a.doc", 9, legacy::malicious_doc(1 << 9), mutate_cfb);
    // 기본 정책은 임베디드 OLE 가 있으면 차단하므로, 대체 모드로 BIFF 해석까지 도달시킨다
    let neutralizing = Engine::new(Policy {
        neutralize_embedded_ole: true,
        ..Policy::default()
    });
    run_with(
        neutralizing,
        "a.xls",
        10,
        legacy::xls(0, &[legacy::obproj()]),
        mutate_cfb,
    );
    run("a.ppt", 11, legacy::ppt(false), mutate_cfb);
    run("p.ppt", 16, legacy::ppt_with_pictures(), mutate_cfb);
}

#[test]
fn fuzz_raw_bytes_all_formats() {
    // 컨테이너 자체(ZIP 헤더, CFB 헤더/FAT)를 직접 변조
    run("r.docx", 12, common::malicious_docm(), mutate_bytes);
    run("r.hwpx", 13, common::malicious_hwpx(), mutate_bytes);
    run("r.doc", 14, legacy::malicious_doc(1 << 9), mutate_bytes);
    run("r.ppt", 15, legacy::ppt(false), mutate_bytes);
    run("rp.ppt", 17, legacy::ppt_with_pictures(), mutate_bytes);
}
