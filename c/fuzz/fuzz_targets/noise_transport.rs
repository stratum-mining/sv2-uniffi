// What a server reads from the network, before and after the handshake:
//
// - mode 0: any act 1 from an initiator;
// - mode 1: after a real handshake, any bytes as the encrypted stream;
// - mode 2: after a real handshake, frames the input chooses (any header,
//   any payload), encrypted by the miner, maybe with one bit flipped on the
//   wire, read back in pieces the input chooses and decoded as a server
//   would.
//
// Nothing may panic, the reader must make progress or stop, and what the
// miner sent intact must come back intact.
#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use sv2_sri::*;

fn authority() -> &'static ([u8; 32], [u8; 32]) {
    static KEYS: OnceLock<([u8; 32], [u8; 32])> = OnceLock::new();
    KEYS.get_or_init(|| {
        let (mut sk, mut pk) = ([0u8; 32], [0u8; 32]);
        assert_eq!(
            unsafe { sv2_sri_authority_keypair_generate(sk.as_mut_ptr(), pk.as_mut_ptr()) },
            SV2_SRI_OK
        );
        (sk, pk)
    })
}

/// Feed `input` to the server `step` bytes at a time; every plaintext
/// frame that comes out goes to `seen`.  Returns false once the session
/// failed.
unsafe fn read_all(n: *mut Sv2SriNoise, mut input: &[u8], step: usize, seen: &mut Vec<Vec<u8>>) -> bool {
    let mut out = vec![0u8; 8192];
    while !input.is_empty() {
        let piece = input.len().min(step);
        let (mut out_len, mut consumed) = (0u32, 0u32);
        let r = unsafe {
            sv2_sri_noise_read_frame(
                n,
                input.as_ptr(),
                piece as u32,
                out.as_mut_ptr(),
                out.len() as u32,
                &mut out_len,
                &mut consumed,
            )
        };
        assert_ne!(r, SV2_SRI_ERR_INTERNAL);
        if r < 0 {
            return false;
        }
        assert!(consumed as usize <= piece);
        if r == SV2_SRI_OK {
            assert!(out_len as usize >= SV2_SRI_FRAME_HEADER_SIZE && out_len as usize <= out.len());
            let frame = out[..out_len as usize].to_vec();
            // decode it as a server would
            let ext = u16::from_le_bytes([frame[0], frame[1]]);
            let mut body = frame[SV2_SRI_FRAME_HEADER_SIZE..].to_vec();
            let mut m = core::mem::MaybeUninit::<Sv2SriMessage>::zeroed();
            let d =
                unsafe { sv2_sri_message_decode(ext, frame[2], body.as_mut_ptr(), body.len() as u32, m.as_mut_ptr()) };
            assert_ne!(d, SV2_SRI_ERR_INTERNAL);
            seen.push(frame);
        } else if consumed == 0 {
            return true;
        }
        input = &input[consumed as usize..];
    }
    true
}

unsafe fn handshake(server: *mut Sv2SriNoise, pk: &[u8; 32], now: u32) -> *mut Sv2SriNoise {
    unsafe {
        let miner = sv2_sri_noise_initiator_new(pk.as_ptr());
        let mut act1 = [0u8; SV2_SRI_ACT1_SIZE];
        let mut act2 = [0u8; SV2_SRI_ACT2_SIZE];
        assert_eq!(sv2_sri_noise_initiator_step0(miner, act1.as_mut_ptr()), SV2_SRI_OK);
        assert_eq!(
            sv2_sri_noise_responder_step1(server, act1.as_ptr(), now, act2.as_mut_ptr()),
            SV2_SRI_OK
        );
        assert_eq!(sv2_sri_noise_initiator_step2(miner, act2.as_ptr(), now), SV2_SRI_OK);
        miner
    }
}

fuzz_target!(|data: &[u8]| {
    let (sk, pk) = authority();
    let [mode, step, flip_hi, flip_lo, rest @ ..] = data else {
        return;
    };
    let now = 1_700_000_000;
    let step = 1 + *step as usize * 3;
    unsafe {
        let server = sv2_sri_noise_responder_new(pk.as_ptr(), sk.as_ptr(), 3600);
        assert!(!server.is_null());
        match mode % 3 {
            0 => {
                if rest.len() >= SV2_SRI_ACT1_SIZE {
                    let mut act2 = [0u8; SV2_SRI_ACT2_SIZE];
                    let r = sv2_sri_noise_responder_step1(server, rest.as_ptr(), now, act2.as_mut_ptr());
                    assert_ne!(r, SV2_SRI_ERR_INTERNAL);
                }
            }
            1 => {
                let miner = handshake(server, pk, now);
                read_all(server, rest, step, &mut Vec::new());
                sv2_sri_noise_free(miner);
            }
            _ => {
                let miner = handshake(server, pk, now);
                // frames: 3 bytes of header choice (extension, type), one
                // length byte, then that many payload bytes
                let (mut sent, mut wire, mut input) = (Vec::new(), Vec::new(), rest);
                while input.len() >= 4 {
                    let len = (input[3] as usize * 23).min(input.len() - 4);
                    let mut frame = vec![input[0], input[1], input[2]];
                    frame.extend_from_slice(&(len as u32).to_le_bytes()[..3]);
                    frame.extend_from_slice(&input[4..4 + len]);
                    input = &input[4 + len..];
                    let cap = sv2_sri_noise_encrypted_frame_size(frame.len() as u32) as usize;
                    let mut out = vec![0u8; cap];
                    let n = sv2_sri_noise_encrypt_frame(
                        miner,
                        frame.as_ptr(),
                        frame.len() as u32,
                        out.as_mut_ptr(),
                        cap as u32,
                    );
                    assert_ne!(n, SV2_SRI_ERR_INTERNAL);
                    if n < 0 {
                        break;
                    }
                    assert_eq!(n as usize, cap);
                    wire.extend_from_slice(&out);
                    sent.push(frame);
                }
                let flip = ((*flip_hi as usize) << 8) | *flip_lo as usize;
                let flipped = flip < wire.len() * 8 && *mode >= 128;
                if flipped {
                    wire[flip / 8] ^= 1 << (flip % 8);
                }
                let mut seen = Vec::new();
                let ok = read_all(server, &wire, step, &mut seen);
                if !flipped {
                    assert!(ok, "an intact stream failed");
                    assert_eq!(seen, sent, "an intact stream came back different");
                } else {
                    // a flipped bit fails the tag of its piece; what came
                    // before it is what was sent
                    assert!(seen.len() <= sent.len());
                    assert_eq!(seen[..], sent[..seen.len()]);
                }
                sv2_sri_noise_free(miner);
            }
        }
        sv2_sri_noise_free(server);
    }
});
