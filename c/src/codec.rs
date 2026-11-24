// The encrypted transport through codec_sv2.
//
// A `Sv2SriNoise` is one connection: a codec_sv2 handshake state that
// becomes the two halves of a transport state once the handshake completes,
// plus the crate's encoder and decoder.  The decoder owns the receive side
// reassembly (it reads the encrypted header, then the payload a chunk at a
// time) and the encoder the chunking on the way out; this file only moves
// bytes between the caller's buffers and the crate's.
//
// As in noise_sv2, a responder makes a fresh static key when it is created
// and signs a certificate valid from `now` for `cert_validity_secs` at every
// handshake.  There is nothing to renew.  stratum-mining/stratum#2437 is
// the upstream request for a responder built from a static key and a
// pre-issued certificate; this API changes with it.

use core::time::Duration;

use codec_sv2::{
    Decrypted, EncodableFrame, Handshake, InitiatorSent, NoiseDecoder, NoiseEncoder, TransportDecryptState,
    TransportEncryptState, SV2_FRAME_PLAINTEXT_CHUNK_SIZE,
};
use framing_sv2::header::Header;
use noise_sv2::{Initiator, Responder};
use secp256k1::XOnlyPublicKey;

use crate::ffi::{guard, input, obj_mut, output, ret};
use crate::{
    SV2_SRI_ACT1_SIZE, SV2_SRI_ACT2_SIZE, SV2_SRI_AEAD_MAC_SIZE, SV2_SRI_ENCRYPTED_HEADER_SIZE, SV2_SRI_ERR_CERT,
    SV2_SRI_ERR_CRYPTO, SV2_SRI_ERR_INTERNAL, SV2_SRI_ERR_INVALID, SV2_SRI_ERR_OVERFLOW, SV2_SRI_ERR_STATE,
    SV2_SRI_FRAME_HEADER_SIZE, SV2_SRI_NEED_MORE, SV2_SRI_OK,
};

enum Role {
    Initiator(Handshake<Initiator>),
    InitiatorSent(Handshake<InitiatorSent>),
    Responder(Handshake<Responder>),
    Transport {
        encrypt: TransportEncryptState,
        // taken by the decoder for the duration of a decode round
        decrypt: Option<TransportDecryptState>,
    },
    // a failed handshake or AEAD step leaves the session unusable
    Dead,
}

/// One Noise session.  Opaque to C.
pub struct Sv2SriNoise {
    role: Role,
    encoder: NoiseEncoder,
    decoder: NoiseDecoder,
    initiator_pinned: bool,
    authenticated: bool,
    // encrypted bytes of the frame being received that the decoder has taken
    fed: usize,
}

impl Sv2SriNoise {
    fn new(role: Role) -> Box<Self> {
        Box::new(Self {
            role,
            encoder: NoiseEncoder::new(),
            decoder: NoiseDecoder::new(),
            initiator_pinned: false,
            authenticated: false,
            fed: 0,
        })
    }

    fn kill(&mut self, code: i32) -> i32 {
        self.role = Role::Dead;
        code
    }
}

/// A plaintext frame the caller already encoded, handed to the encoder as is.
struct Raw<'a>(&'a [u8]);

impl EncodableFrame for Raw<'_> {
    fn encoded_length(&self) -> usize {
        self.0.len()
    }

    fn encode_into(self, dst: &mut [u8]) -> Result<(), framing_sv2::Error> {
        dst.copy_from_slice(self.0);
        Ok(())
    }
}

/// Create a responder from the authority key pair (x-only public key and
/// secret key, 32 bytes each).  Returns NULL when they do not match.
/// Free with `sv2_sri_noise_free()`.
///
/// # Safety
/// `authority_pk` and `authority_sk` must each point at 32 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn sv2_sri_noise_responder_new(
    authority_pk: *const u8,
    authority_sk: *const u8,
    cert_validity_secs: u32,
) -> *mut Sv2SriNoise {
    guard(core::ptr::null_mut(), || {
        // SAFETY: forwarded to the caller
        let (pk, sk) = match unsafe { (input(authority_pk, 32), input(authority_sk, 32)) } {
            (Ok(pk), Ok(sk)) => (pk, sk),
            _ => return core::ptr::null_mut(),
        };
        let (Ok(pk), Ok(sk)) = (<&[u8; 32]>::try_from(pk), <&[u8; 32]>::try_from(sk)) else {
            return core::ptr::null_mut();
        };
        if cert_validity_secs == 0 {
            return core::ptr::null_mut();
        }
        match Responder::from_authority_kp(pk, sk, Duration::from_secs(cert_validity_secs as u64)) {
            Ok(r) => Box::into_raw(Sv2SriNoise::new(Role::Responder(Handshake::responder(r)))),
            Err(_) => core::ptr::null_mut(),
        }
    })
}

/// Create an initiator.  With `authority_pk` (32 bytes, x-only) the
/// responder's certificate must be signed by that key; with NULL any
/// responder is accepted.  Free with `sv2_sri_noise_free()`.
///
/// # Safety
/// `authority_pk` must be NULL or point at 32 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn sv2_sri_noise_initiator_new(authority_pk: *const u8) -> *mut Sv2SriNoise {
    guard(core::ptr::null_mut(), || {
        let (initiator, pinned) = if authority_pk.is_null() {
            match Initiator::without_pk() {
                Ok(i) => (i, false),
                Err(_) => return core::ptr::null_mut(),
            }
        } else {
            // SAFETY: forwarded to the caller
            let Ok(pk) = (unsafe { input(authority_pk, 32) }) else {
                return core::ptr::null_mut();
            };
            match XOnlyPublicKey::from_slice(pk) {
                Ok(pk) => (Initiator::new(Some(pk)), true),
                Err(_) => return core::ptr::null_mut(),
            }
        };
        let mut n = Sv2SriNoise::new(Role::Initiator(Handshake::initiator(initiator)));
        n.initiator_pinned = pinned;
        Box::into_raw(n)
    })
}

/// Release a session and the keys it holds.  NULL is ignored.
///
/// # Safety
/// `n` must be NULL or a pointer from one of the `_new` functions, not
/// freed before.
#[no_mangle]
pub unsafe extern "C" fn sv2_sri_noise_free(n: *mut Sv2SriNoise) {
    guard((), || {
        if !n.is_null() {
            // SAFETY: the pointer came from Box::into_raw
            drop(unsafe { Box::from_raw(n) });
        }
    })
}

/// Initiator: write act 1 (64 bytes) to send.
///
/// # Safety
/// `n` must be a live session and `out` must point at 64 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn sv2_sri_noise_initiator_step0(n: *mut Sv2SriNoise, out: *mut u8) -> i32 {
    guard(SV2_SRI_ERR_INTERNAL, || {
        ret((|| {
            // SAFETY: forwarded to the caller
            let (n, out) = unsafe { (obj_mut(n)?, output(out, SV2_SRI_ACT1_SIZE)?) };
            match core::mem::replace(&mut n.role, Role::Dead) {
                Role::Initiator(h) => match h.step_0() {
                    Ok((act1, next)) => {
                        out.copy_from_slice(act1.payload());
                        n.role = Role::InitiatorSent(next);
                        Ok(SV2_SRI_OK)
                    }
                    Err(_) => Err(SV2_SRI_ERR_CRYPTO),
                },
                other => {
                    n.role = other;
                    Err(SV2_SRI_ERR_STATE)
                }
            }
        })())
    })
}

/// Responder: consume act 1 (64 bytes) and write act 2 (234 bytes) to
/// send.  The certificate inside is valid from `now` (unix seconds).  On
/// success the session is in transport mode.
///
/// # Safety
/// `n` must be a live session, `act1` must point at 64 readable bytes and
/// `act2_out` at 234 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn sv2_sri_noise_responder_step1(
    n: *mut Sv2SriNoise,
    act1: *const u8,
    now: u32,
    act2_out: *mut u8,
) -> i32 {
    guard(SV2_SRI_ERR_INTERNAL, || {
        ret((|| {
            // SAFETY: forwarded to the caller
            let (n, act1, out) = unsafe {
                (
                    obj_mut(n)?,
                    input(act1, SV2_SRI_ACT1_SIZE)?,
                    output(act2_out, SV2_SRI_ACT2_SIZE)?,
                )
            };
            let mut theirs = [0u8; SV2_SRI_ACT1_SIZE];
            theirs.copy_from_slice(act1);
            match core::mem::replace(&mut n.role, Role::Dead) {
                Role::Responder(h) => match h.step_1_with_now_rng(theirs, now, &mut rand::thread_rng()) {
                    Ok((act2, transport)) => {
                        out.copy_from_slice(act2.payload());
                        let (encrypt, decrypt) = transport.split();
                        n.role = Role::Transport {
                            encrypt,
                            decrypt: Some(decrypt),
                        };
                        Ok(SV2_SRI_OK)
                    }
                    Err(_) => Err(SV2_SRI_ERR_CRYPTO),
                },
                other => {
                    n.role = other;
                    Err(SV2_SRI_ERR_STATE)
                }
            }
        })())
    })
}

/// Initiator: consume act 2 (234 bytes).  `now` (unix seconds) is checked
/// against the certificate's validity.  `SV2_SRI_ERR_CERT` means the
/// responder could not be authenticated with the pinned authority key.
///
/// # Safety
/// `n` must be a live session and `act2` must point at 234 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn sv2_sri_noise_initiator_step2(n: *mut Sv2SriNoise, act2: *const u8, now: u32) -> i32 {
    guard(SV2_SRI_ERR_INTERNAL, || {
        ret((|| {
            // SAFETY: forwarded to the caller
            let (n, act2) = unsafe { (obj_mut(n)?, input(act2, SV2_SRI_ACT2_SIZE)?) };
            let mut msg = [0u8; SV2_SRI_ACT2_SIZE];
            msg.copy_from_slice(act2);
            match core::mem::replace(&mut n.role, Role::Dead) {
                Role::InitiatorSent(h) => match h.step_2_with_now(msg, now) {
                    Ok(transport) => {
                        let (encrypt, decrypt) = transport.split();
                        n.role = Role::Transport {
                            encrypt,
                            decrypt: Some(decrypt),
                        };
                        n.authenticated = n.initiator_pinned;
                        Ok(SV2_SRI_OK)
                    }
                    Err(codec_sv2::Error::NoiseSv2Error(noise_sv2::Error::InvalidCertificate(_))) => {
                        Err(SV2_SRI_ERR_CERT)
                    }
                    Err(codec_sv2::Error::NoiseSv2Error(noise_sv2::Error::Aead(_)))
                    | Err(codec_sv2::Error::AeadError(_)) => Err(SV2_SRI_ERR_CRYPTO),
                    Err(_) => Err(SV2_SRI_ERR_INVALID),
                },
                other => {
                    n.role = other;
                    Err(SV2_SRI_ERR_STATE)
                }
            }
        })())
    })
}

/// Whether the handshake has completed and frames can be exchanged.
///
/// # Safety
/// `n` must be NULL or a live session.
#[no_mangle]
pub unsafe extern "C" fn sv2_sri_noise_is_transport(n: *const Sv2SriNoise) -> bool {
    guard(false, || {
        // SAFETY: forwarded to the caller
        matches!(
            unsafe { n.as_ref() },
            Some(Sv2SriNoise {
                role: Role::Transport { .. },
                ..
            })
        )
    })
}

/// Initiator: whether the responder's certificate was verified against a
/// pinned authority key (false when the initiator was created without one).
///
/// # Safety
/// `n` must be NULL or a live session.
#[no_mangle]
pub unsafe extern "C" fn sv2_sri_noise_is_authenticated(n: *const Sv2SriNoise) -> bool {
    guard(false, || {
        // SAFETY: forwarded to the caller
        unsafe { n.as_ref() }.is_some_and(|n| n.authenticated)
    })
}

/// Ciphertext bytes that follow an encrypted header announcing
/// `payload_len` plaintext bytes.
#[no_mangle]
pub extern "C" fn sv2_sri_noise_encrypted_payload_size(payload_len: u32) -> u32 {
    guard(0, || {
        let chunks = (payload_len as usize).div_ceil(SV2_FRAME_PLAINTEXT_CHUNK_SIZE);
        (payload_len as usize + chunks * SV2_SRI_AEAD_MAC_SIZE) as u32
    })
}

/// Wire size of a plaintext frame of `frame_len` bytes (header included),
/// or 0 when `frame_len` is shorter than a header.
#[no_mangle]
pub extern "C" fn sv2_sri_noise_encrypted_frame_size(frame_len: u32) -> u32 {
    guard(0, || {
        if (frame_len as usize) < SV2_SRI_FRAME_HEADER_SIZE {
            return 0;
        }
        SV2_SRI_ENCRYPTED_HEADER_SIZE as u32
            + sv2_sri_noise_encrypted_payload_size(frame_len - SV2_SRI_FRAME_HEADER_SIZE as u32)
    })
}

/// Encrypt one complete plaintext frame (header and payload, as
/// `sv2_sri_message_encode()` writes it) into `out`: the header becomes 22
/// bytes, the payload is encrypted in chunks of at most 65519 bytes, each
/// with its own tag.  Returns the bytes written.  A buffer too small for the
/// result fails before any nonce is used; any failure after that ends the
/// session.
///
/// # Safety
/// `n` must be a live session, `frame` must point at `frame_len` readable
/// bytes and `out` at `out_cap` writable bytes, not overlapping `frame`.
#[no_mangle]
pub unsafe extern "C" fn sv2_sri_noise_encrypt_frame(
    n: *mut Sv2SriNoise,
    frame: *const u8,
    frame_len: u32,
    out: *mut u8,
    out_cap: u32,
) -> i32 {
    guard(SV2_SRI_ERR_INTERNAL, || {
        ret((|| {
            // SAFETY: forwarded to the caller
            let (n, frame, out) = unsafe {
                (
                    obj_mut(n)?,
                    input(frame, frame_len as usize)?,
                    output(out, out_cap as usize)?,
                )
            };
            let Role::Transport { encrypt, .. } = &mut n.role else {
                return Err(SV2_SRI_ERR_STATE);
            };
            let header = Header::from_bytes(frame).map_err(|_| SV2_SRI_ERR_INVALID)?;
            if header.payload_length() != frame.len() - SV2_SRI_FRAME_HEADER_SIZE {
                return Err(SV2_SRI_ERR_INVALID);
            }
            let total = sv2_sri_noise_encrypted_frame_size(frame_len) as usize;
            if total > out.len() {
                return Err(SV2_SRI_ERR_OVERFLOW);
            }
            match n.encoder.encode_transport(Raw(frame), encrypt) {
                Ok(wire) => {
                    let wire: &[u8] = wire.as_ref();
                    if wire.len() != total {
                        return Err(n.kill(SV2_SRI_ERR_CRYPTO));
                    }
                    out[..total].copy_from_slice(wire);
                    Ok(total as i32)
                }
                Err(_) => Err(n.kill(SV2_SRI_ERR_CRYPTO)),
            }
        })())
    })
}

/// Incremental decryption from a byte stream.  Feed whatever has arrived:
///
/// - `SV2_SRI_OK`: one plaintext frame (header and payload) is in `out`,
///   `*out_len` bytes long, and `*consumed` input bytes were used;
/// - `SV2_SRI_NEED_MORE`: `*consumed` bytes were used (the decoder keeps
///   them) and the caller should drop them and wait;
/// - negative: fatal, the session is dead.
///
/// `out_cap` bounds the frame: a header announcing more than fits fails
/// with `SV2_SRI_ERR_OVERFLOW` as soon as the header is decrypted, before
/// the payload is read, when the bound is under one chunk (65519 bytes of
/// payload); a larger bound is enforced a chunk at a time.
///
/// # Safety
/// `n` must be a live session, `input_buf` must point at `in_len` readable
/// bytes, `out` at `out_cap` writable bytes not overlapping it, and
/// `out_len` and `consumed` must be writable.
#[no_mangle]
pub unsafe extern "C" fn sv2_sri_noise_read_frame(
    n: *mut Sv2SriNoise,
    input_buf: *const u8,
    in_len: u32,
    out: *mut u8,
    out_cap: u32,
    out_len: *mut u32,
    consumed: *mut u32,
) -> i32 {
    guard(SV2_SRI_ERR_INTERNAL, || {
        ret((|| {
            // SAFETY: forwarded to the caller
            let (n, mut inp, out, out_len, consumed) = unsafe {
                (
                    obj_mut(n)?,
                    input(input_buf, in_len as usize)?,
                    output(out, out_cap as usize)?,
                    obj_mut(out_len)?,
                    obj_mut(consumed)?,
                )
            };
            *out_len = 0;
            *consumed = 0;
            let Role::Transport { decrypt, .. } = &mut n.role else {
                return Err(SV2_SRI_ERR_STATE);
            };
            // What the caller lets one frame grow to, on the wire.
            let max_payload = out.len().saturating_sub(SV2_SRI_FRAME_HEADER_SIZE);
            let max_encrypted = sv2_sri_noise_encrypted_payload_size(max_payload as u32) as usize;

            loop {
                // The decoder asks for what it is missing, one chunk at most.
                let want = n.decoder.read_len();
                if want > 0 {
                    if inp.is_empty() {
                        return Ok(SV2_SRI_NEED_MORE);
                    }
                    let take = want.min(inp.len());
                    n.decoder.read_buf()[..take].copy_from_slice(&inp[..take]);
                    if n.decoder.advance(take).is_err() {
                        return Err(n.kill(SV2_SRI_ERR_INVALID));
                    }
                    inp = &inp[take..];
                    *consumed += take as u32;
                    n.fed += take;
                }
                let Some(state) = decrypt.take() else {
                    return Err(n.kill(SV2_SRI_ERR_STATE));
                };
                match n.decoder.next_transport_frame(state) {
                    Ok(Decrypted::Frame(frame, state)) => {
                        *decrypt = Some(state);
                        n.fed = 0;
                        let bytes = frame.as_bytes();
                        if bytes.len() > out.len() {
                            return Err(n.kill(SV2_SRI_ERR_OVERFLOW));
                        }
                        out[..bytes.len()].copy_from_slice(bytes);
                        *out_len = bytes.len() as u32;
                        return Ok(SV2_SRI_OK);
                    }
                    Ok(Decrypted::Incomplete(state)) => {
                        *decrypt = Some(state);
                        // Right after the header, the decoder asks for the whole
                        // encrypted payload when that fits one chunk; past that
                        // point the bytes taken so far tell.
                        let next = n.decoder.read_len();
                        let past_header = n.fed.saturating_sub(SV2_SRI_ENCRYPTED_HEADER_SIZE);
                        if (n.fed == SV2_SRI_ENCRYPTED_HEADER_SIZE && next > max_encrypted)
                            || past_header > max_encrypted
                        {
                            return Err(n.kill(SV2_SRI_ERR_OVERFLOW));
                        }
                    }
                    // the crate consumed the state: the nonce sequence is unusable
                    Err(codec_sv2::Error::AeadError(_)) => return Err(n.kill(SV2_SRI_ERR_CRYPTO)),
                    Err(_) => return Err(n.kill(SV2_SRI_ERR_INVALID)),
                }
            }
        })())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{sv2_sri_authority_keypair_generate, SV2_SRI_ERR_OVERFLOW};

    fn pair() -> (*mut Sv2SriNoise, *mut Sv2SriNoise) {
        let (mut sk, mut pk) = ([0u8; 32], [0u8; 32]);
        unsafe {
            assert_eq!(
                sv2_sri_authority_keypair_generate(sk.as_mut_ptr(), pk.as_mut_ptr()),
                SV2_SRI_OK
            );
            let r = sv2_sri_noise_responder_new(pk.as_ptr(), sk.as_ptr(), 3600);
            let i = sv2_sri_noise_initiator_new(pk.as_ptr());
            let (mut act1, mut act2) = ([0u8; SV2_SRI_ACT1_SIZE], [0u8; SV2_SRI_ACT2_SIZE]);
            assert_eq!(sv2_sri_noise_initiator_step0(i, act1.as_mut_ptr()), SV2_SRI_OK);
            assert_eq!(
                sv2_sri_noise_responder_step1(r, act1.as_ptr(), 1_760_000_000, act2.as_mut_ptr()),
                SV2_SRI_OK
            );
            assert_eq!(
                sv2_sri_noise_initiator_step2(i, act2.as_ptr(), 1_760_000_000),
                SV2_SRI_OK
            );
            assert!(sv2_sri_noise_is_transport(r) && sv2_sri_noise_is_transport(i));
            assert!(sv2_sri_noise_is_authenticated(i));
            (i, r)
        }
    }

    fn frame(payload_len: usize) -> Vec<u8> {
        let mut f = vec![0u8; SV2_SRI_FRAME_HEADER_SIZE + payload_len];
        f[2] = 0x1b;
        f[3..6].copy_from_slice(&(payload_len as u32).to_le_bytes()[..3]);
        for (i, b) in f[6..].iter_mut().enumerate() {
            *b = (i * 7) as u8;
        }
        f
    }

    // Frames of every size class go through, fed whole and a byte at a time.
    #[test]
    fn frames_round_trip_across_chunk_boundaries() {
        let (i, r) = pair();
        for &len in &[
            0usize,
            1,
            100,
            SV2_FRAME_PLAINTEXT_CHUNK_SIZE,
            SV2_FRAME_PLAINTEXT_CHUNK_SIZE + 1,
            140_000,
        ] {
            let plain = frame(len);
            let mut wire = vec![0u8; sv2_sri_noise_encrypted_frame_size(plain.len() as u32) as usize];
            for trickle in [false, true] {
                let n = unsafe {
                    sv2_sri_noise_encrypt_frame(
                        i,
                        plain.as_ptr(),
                        plain.len() as u32,
                        wire.as_mut_ptr(),
                        wire.len() as u32,
                    )
                };
                assert_eq!(n as usize, wire.len());
                let mut out = vec![0u8; plain.len() + 1];
                let (mut got, mut pos) = (0u32, 0usize);
                let mut code = SV2_SRI_NEED_MORE;
                while pos < wire.len() {
                    let step = if trickle { 1 } else { wire.len() - pos };
                    let mut used = 0u32;
                    code = unsafe {
                        sv2_sri_noise_read_frame(
                            r,
                            wire[pos..].as_ptr(),
                            step as u32,
                            out.as_mut_ptr(),
                            out.len() as u32,
                            &mut got,
                            &mut used,
                        )
                    };
                    assert!(code >= 0, "payload of {len}, trickle {trickle}: {code}");
                    pos += used as usize;
                    if code == SV2_SRI_OK {
                        break;
                    }
                }
                assert_eq!(
                    (code, pos),
                    (SV2_SRI_OK, wire.len()),
                    "payload of {len}, trickle {trickle}"
                );
                assert_eq!(&out[..got as usize], &plain[..]);
            }
        }
        unsafe {
            sv2_sri_noise_free(i);
            sv2_sri_noise_free(r);
        }
    }

    // A header announcing more than the caller's buffer is refused before
    // any of the payload is read, and the session is over.
    #[test]
    fn oversize_frame_is_refused_at_the_header() {
        let (i, r) = pair();
        let plain = frame(5000);
        let mut wire = vec![0u8; sv2_sri_noise_encrypted_frame_size(plain.len() as u32) as usize];
        unsafe {
            assert!(
                sv2_sri_noise_encrypt_frame(
                    i,
                    plain.as_ptr(),
                    plain.len() as u32,
                    wire.as_mut_ptr(),
                    wire.len() as u32
                ) > 0
            );
        }
        let mut out = [0u8; 4096];
        let (mut got, mut used) = (0u32, 0u32);
        let code = unsafe {
            sv2_sri_noise_read_frame(
                r,
                wire.as_ptr(),
                wire.len() as u32,
                out.as_mut_ptr(),
                4096,
                &mut got,
                &mut used,
            )
        };
        assert_eq!(code, SV2_SRI_ERR_OVERFLOW);
        assert_eq!(used as usize, SV2_SRI_ENCRYPTED_HEADER_SIZE);
        assert!(!unsafe { sv2_sri_noise_is_transport(r) });
        unsafe {
            sv2_sri_noise_free(i);
            sv2_sri_noise_free(r);
        }
    }

    // Encrypting into a buffer that cannot hold the result must not use a
    // nonce: the next frame still decrypts.
    #[test]
    fn a_refused_encrypt_does_not_desynchronise() {
        let (i, r) = pair();
        let plain = frame(300);
        let mut small = [0u8; 100];
        let code =
            unsafe { sv2_sri_noise_encrypt_frame(i, plain.as_ptr(), plain.len() as u32, small.as_mut_ptr(), 100) };
        assert_eq!(code, SV2_SRI_ERR_OVERFLOW);
        let mut wire = vec![0u8; sv2_sri_noise_encrypted_frame_size(plain.len() as u32) as usize];
        unsafe {
            assert!(
                sv2_sri_noise_encrypt_frame(
                    i,
                    plain.as_ptr(),
                    plain.len() as u32,
                    wire.as_mut_ptr(),
                    wire.len() as u32
                ) > 0
            );
        }
        let mut out = [0u8; 4096];
        let (mut got, mut used) = (0u32, 0u32);
        let code = unsafe {
            sv2_sri_noise_read_frame(
                r,
                wire.as_ptr(),
                wire.len() as u32,
                out.as_mut_ptr(),
                4096,
                &mut got,
                &mut used,
            )
        };
        assert_eq!((code, got as usize), (SV2_SRI_OK, plain.len()));
        unsafe {
            sv2_sri_noise_free(i);
            sv2_sri_noise_free(r);
        }
    }
}
