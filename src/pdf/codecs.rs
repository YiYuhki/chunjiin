//! JBIG2·JPEG 2000(JPX) 이미지를 화소로 푼다.
//!
//! 두 코덱은 뷰어의 디코더 취약점(JBIG2 는 FORCEDENTRY 등)이 자주 악용되어 코덱 데이터를
//! 그대로 옮기지 않는다. 메모리 안전한 디코더(hayro)로 끝까지 풀어 원시 표본만 옮긴다.
//! 풀기 전에 머리글의 크기를 화소 한도와 비교한다.

/// JBIG2 → 1비트 표본 (행마다 바이트 정렬, PDF 규칙대로 검정 = 0)과 폭·높이
pub(super) fn jbig2(
    data: &[u8],
    globals: Option<&[u8]>,
    max_pixels: u64,
) -> Option<(Vec<u8>, usize, usize)> {
    let image = hayro_jbig2::Image::new_embedded(data, globals).ok()?;
    let (w, h) = (image.width() as usize, image.height() as usize);
    if (w as u64).checked_mul(h as u64)? > max_pixels {
        return None;
    }
    let stride = w.div_ceil(8);
    struct Bits {
        out: Vec<u8>,
        stride: usize,
        row: usize,
        x: usize,
        w: usize,
        h: usize,
    }
    impl Bits {
        fn put(&mut self, black: bool) {
            if self.row < self.h && self.x < self.w {
                if black {
                    let i = self.row * self.stride + self.x / 8;
                    self.out[i] &= !(0x80 >> (self.x % 8));
                }
                self.x += 1;
            }
        }
    }
    impl hayro_jbig2::Decoder for Bits {
        fn push_pixel(&mut self, black: bool) {
            self.put(black);
        }
        fn push_pixel_chunk(&mut self, black: bool, chunk_count: u32) {
            // 바이트 경계에서만 불린다: 흰색(초기값)은 건너뛰고 검정은 바이트 단위로 채운다
            let n = (chunk_count as usize * 8).min(self.w.saturating_sub(self.x));
            if self.row < self.h && self.x.is_multiple_of(8) {
                if black {
                    let at = self.row * self.stride + self.x / 8;
                    let full = n / 8;
                    self.out[at..at + full].fill(0);
                    for k in full * 8..n {
                        self.out[at + k / 8] &= !(0x80 >> (k % 8));
                    }
                }
                self.x += n;
            } else {
                for _ in 0..n {
                    self.put(black);
                }
            }
        }
        fn next_line(&mut self) {
            self.row += 1;
            self.x = 0;
        }
    }
    let mut b = Bits {
        out: vec![0xFF; stride.checked_mul(h)?],
        stride,
        row: 0,
        x: 0,
        w,
        h,
    };
    image.decode(&mut b).ok()?;
    (b.row >= h).then_some((b.out, w, h))
}

/// 풀어 낸 JPEG 2000 이미지
pub(super) struct Jpx {
    /// 성분별 8비트 표본 (알파 제외, 성분 교차)
    pub samples: Vec<u8>,
    pub alpha: Option<Vec<u8>>,
    pub components: usize,
    /// 손실 압축(9-7 웨이블릿) 코드스트림인지
    pub lossy: bool,
    /// JP2 의 ICC 프로필 (머리글·크기·색 공간 성분 수를 검증한 것만)
    pub icc: Option<Vec<u8>>,
    /// 코드스트림의 원래 비트 수 (디코더는 모든 표본을 8비트로 늘린다)
    pub bit_depth: u8,
    pub width: usize,
    pub height: usize,
}

/// JPX → 8비트 표본. `palette` 가 false 면 색상표 번호를 그대로 둔다 (PDF 의 Indexed 색 공간)
pub(super) fn jpx(data: &[u8], palette: bool, max_pixels: u64) -> Option<Jpx> {
    let settings = hayro_jpeg2000::DecodeSettings {
        resolve_palette_indices: palette,
        ..Default::default()
    };
    let image = hayro_jpeg2000::Image::new(data, &settings).ok()?;
    let (w, h) = (image.width() as usize, image.height() as usize);
    let n = usize::from(image.color_space().num_channels());
    if w == 0 || h == 0 || (w as u64).checked_mul(h as u64)? > max_pixels || !(1..=4).contains(&n) {
        return None;
    }
    let all = n + usize::from(image.has_alpha());
    let bit_depth = image.original_bit_depth();
    let lossy = cod_irreversible(data);
    let icc = match image.color_space() {
        hayro_jpeg2000::ColorSpace::Icc { profile, .. } => icc_profile(profile, n),
        _ => None,
    };
    let decoded = image.decode().ok()?;
    if decoded.len() != w.checked_mul(h)?.checked_mul(all)? {
        return None;
    }
    if all == n {
        return Some(Jpx {
            samples: decoded,
            alpha: None,
            components: n,
            lossy,
            icc,
            bit_depth,
            width: w,
            height: h,
        });
    }
    let mut samples = Vec::with_capacity(w * h * n);
    let mut alpha = Vec::with_capacity(w * h);
    for px in decoded.chunks_exact(all) {
        samples.extend(&px[..n]);
        alpha.push(px[n]);
    }
    Some(Jpx {
        samples,
        alpha: Some(alpha),
        components: n,
        lossy,
        icc,
        bit_depth,
        width: w,
        height: h,
    })
}

/// 코드스트림의 COD 표지가 9-7 비가역 웨이블릿(손실 압축)을 쓰는지
fn cod_irreversible(data: &[u8]) -> bool {
    // JP2 면 jp2c 상자 안의 코드스트림, 아니면 그대로
    let cs = data
        .windows(4)
        .position(|w| w == b"\xFF\x4F\xFF\x51")
        .map_or(data, |i| &data[i..]);
    let Some(at) = cs.windows(2).position(|w| w == b"\xFF\x52") else {
        return false;
    };
    // FF52, Lcod(2), Scod(1), SGcod(4), 분해 수·코드블록 폭·높이·방식(4), 변환(1)
    cs.get(at + 13) == Some(&0)
}

/// ICC 프로필 검증: 머리글의 크기, `acsp` 서명, 데이터 색 공간의 성분 수가 맞아야 한다
fn icc_profile(p: &[u8], n: usize) -> Option<Vec<u8>> {
    const MAX: usize = 4 << 20;
    let size = u32::from_be_bytes(p.get(0..4)?.try_into().ok()?) as usize;
    let space = p.get(16..20)?;
    let comps = match space {
        b"GRAY" => 1,
        b"RGB " | b"Lab " => 3,
        b"CMYK" => 4,
        _ => return None,
    };
    (size == p.len() && (132..=MAX).contains(&size) && p.get(36..40)? == b"acsp" && comps == n)
        .then(|| p.to_vec())
}

/// 1비트 표본(행마다 바이트 정렬, 검정 = 0)을 CCITT G4 로 압축한다
pub(super) fn g4(bits: &[u8], w: usize, h: usize) -> Option<Vec<u8>> {
    let stride = w.div_ceil(8);
    let mut enc = fax::encoder::Encoder::new(fax::VecWriter::new());
    for row in bits.chunks(stride).take(h) {
        let px = (0..w).map(|x| {
            if row[x / 8] & (0x80 >> (x % 8)) == 0 {
                fax::Color::Black
            } else {
                fax::Color::White
            }
        });
        enc.encode_line(px, u32::try_from(w).ok()?).ok()?;
    }
    Some(enc.finish().ok()?.finish())
}

#[cfg(test)]
mod tests {
    #[test]
    fn g4_roundtrip() {
        let (w, h) = (53usize, 17usize);
        let stride = w.div_ceil(8);
        let mut bits = vec![0xFFu8; stride * h];
        let mut x: u32 = 1;
        for y in 0..h {
            for c in 0..w {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
                if (c / 4 + y) % 3 == 0 || x >> 29 == 0 {
                    bits[y * stride + c / 8] &= !(0x80 >> (c % 8));
                }
            }
        }
        let g4 = super::g4(&bits, w, h).unwrap();
        let p = super::super::ccitt::Params {
            k: -1,
            black_is_1: false,
            byte_align: false,
        };
        let (out, lines) = super::super::ccitt::decode(&g4, &p, w, h).unwrap();
        assert_eq!(lines, h);
        assert_eq!(out, bits);
    }
}
