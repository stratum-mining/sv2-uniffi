// The two primitives an SV2 server needs outside the protocol itself:
// random bytes (extranonce prefixes) and SHA-256 (merkle roots in tests).

use rand::RngCore;
use secp256k1::hashes::{sha256, Hash};

use crate::ffi::{guard, input, output};

/// Fill `buf` with `len` bytes from a CSPRNG seeded by the OS
/// (`rand::thread_rng`, the generator noise_sv2 uses for its keys).
///
/// # Safety
/// `buf` must point at `len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn sv2_sri_random(buf: *mut u8, len: usize) {
    guard((), || {
        // SAFETY: forwarded to the caller
        if let Ok(buf) = unsafe { output(buf, len) } {
            rand::thread_rng().fill_bytes(buf);
        }
    })
}

/// SHA-256 of `len` bytes into `out` (32 bytes).
///
/// # Safety
/// `data` must point at `len` readable bytes and `out` at 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn sv2_sri_sha256(data: *const u8, len: usize, out: *mut u8) {
    guard((), || {
        // SAFETY: forwarded to the caller
        if let (Ok(data), Ok(out)) = unsafe { (input(data, len), output(out, 32)) } {
            out.copy_from_slice(sha256::Hash::hash(data).as_byte_array());
        }
    })
}
