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
    let decoded = image.decode().ok()?;
    if decoded.len() != w.checked_mul(h)?.checked_mul(all)? {
        return None;
    }
    if all == n {
        return Some(Jpx {
            samples: decoded,
            alpha: None,
            components: n,
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
        bit_depth,
        width: w,
        height: h,
    })
}
