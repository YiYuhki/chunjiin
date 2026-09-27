//! 단독 이미지 재조합.

use cdr::{Engine, Status};
use image::codecs::gif::{GifDecoder, GifEncoder, Repeat};
use image::{AnimationDecoder, Delay, Frame, Rgba, RgbaImage};
use std::io::Cursor;

/// 색이 바뀌는 3프레임 애니메이션 GIF (뒤에 페이로드를 덧붙임)
fn animated_gif(frames: usize) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut enc = GifEncoder::new(&mut out);
        enc.set_repeat(Repeat::Infinite).unwrap();
        for i in 0..frames {
            let c = [(i * 80) as u8, 200, 255 - (i * 80) as u8, 255];
            let img = RgbaImage::from_pixel(12, 8, Rgba(c));
            enc.encode_frame(Frame::from_parts(
                img,
                0,
                0,
                Delay::from_numer_denom_ms(150, 1),
            ))
            .unwrap();
        }
    }
    out.extend(b"<?php system($_GET[c]); ?>");
    out
}

fn frames(gif: &[u8]) -> Vec<Frame> {
    GifDecoder::new(Cursor::new(gif))
        .unwrap()
        .into_frames()
        .collect_frames()
        .unwrap()
}

#[test]
fn animated_gif_keeps_frames() {
    let src = animated_gif(3);
    let r = Engine::default().process(&src, "a.gif");
    assert_ne!(r.status, Status::Blocked, "{}", r.reason);
    let out = r.output.unwrap();
    assert!(!out.windows(5).any(|w| w == b"<?php"));
    let f = frames(&out);
    assert_eq!(f.len(), 3, "프레임 유지");
    for (i, fr) in f.iter().enumerate() {
        assert_eq!(fr.delay().numer_denom_ms(), (150, 1));
        let p = fr.buffer().get_pixel(5, 5);
        assert!((i32::from(p[0]) - (i * 80) as i32).abs() <= 8, "{i}: {p:?}");
        assert!(
            (i32::from(p[2]) - (255 - i * 80) as i32).abs() <= 8,
            "{i}: {p:?}"
        );
    }
    let again = Engine::default().process(&out, "a.gif");
    assert_eq!(again.status, Status::Clean, "{:#?}", again.findings);

    // 프레임 수 상한: 뒷부분은 옮기지 않는다
    let r = Engine::default().process(&animated_gif(1200), "b.gif");
    assert_ne!(r.status, Status::Blocked, "{}", r.reason);
    assert_eq!(frames(r.output.as_ref().unwrap()).len(), 1000);

    // 정지 GIF 는 한 프레임
    let r = Engine::default().process(&animated_gif(1), "c.gif");
    assert_eq!(frames(r.output.as_ref().unwrap()).len(), 1);
}
