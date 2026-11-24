// Authority keys: generation, derivation and the base58 text form SRI
// tools print (key_utils::Secp256k1PublicKey).

use core::ffi::{c_char, CStr};
use core::str::FromStr;

use key_utils::Secp256k1PublicKey;
use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};

use crate::ffi::{guard, input, output, ret};
use crate::{SV2_SRI_ERR_INTERNAL, SV2_SRI_ERR_INVALID, SV2_SRI_ERR_OVERFLOW, SV2_SRI_OK};

fn xonly_of(sk: &SecretKey) -> [u8; 32] {
    let secp = Secp256k1::signing_only();
    Keypair::from_secret_key(&secp, sk).x_only_public_key().0.serialize()
}

/// Generate a new authority key: a 32 byte secret key and its 32 byte
/// x-only public key, which is what miners pin.
///
/// # Safety
/// `sk_out` and `pk_out` must each point at 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn sv2_sri_authority_keypair_generate(sk_out: *mut u8, pk_out: *mut u8) -> i32 {
    guard(SV2_SRI_ERR_INTERNAL, || {
        ret((|| {
            // SAFETY: forwarded to the caller
            let (sk_out, pk_out) = unsafe { (output(sk_out, 32)?, output(pk_out, 32)?) };
            let sk = SecretKey::new(&mut rand::thread_rng());
            sk_out.copy_from_slice(&sk.secret_bytes());
            pk_out.copy_from_slice(&xonly_of(&sk));
            Ok(SV2_SRI_OK)
        })())
    })
}

/// Check an authority secret key and derive its x-only public key.
///
/// # Safety
/// `sk` must point at 32 readable bytes and `pk_out` at 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn sv2_sri_authority_pubkey(sk: *const u8, pk_out: *mut u8) -> i32 {
    guard(SV2_SRI_ERR_INTERNAL, || {
        ret((|| {
            // SAFETY: forwarded to the caller
            let (sk, pk_out) = unsafe { (input(sk, 32)?, output(pk_out, 32)?) };
            let sk = SecretKey::from_slice(sk).map_err(|_| SV2_SRI_ERR_INVALID)?;
            pk_out.copy_from_slice(&xonly_of(&sk));
            Ok(SV2_SRI_OK)
        })())
    })
}

/// Write the base58check text form of an x-only authority public key into
/// `out`, NUL terminated.  Returns the string length without the NUL.
///
/// # Safety
/// `pk` must point at 32 readable bytes and `out` at `cap` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn sv2_sri_authority_pubkey_to_base58(pk: *const u8, out: *mut c_char, cap: usize) -> i32 {
    guard(SV2_SRI_ERR_INTERNAL, || {
        ret((|| {
            // SAFETY: forwarded to the caller
            // c_char is i8 on some targets and u8 on others (aarch64 Linux)
            let (pk, out) = unsafe { (input(pk, 32)?, output(out.cast::<u8>(), cap)?) };
            let pk = XOnlyPublicKey::from_slice(pk).map_err(|_| SV2_SRI_ERR_INVALID)?;
            let text = Secp256k1PublicKey(pk).to_string();
            if text.len() + 1 > out.len() {
                return Err(SV2_SRI_ERR_OVERFLOW);
            }
            out[..text.len()].copy_from_slice(text.as_bytes());
            out[text.len()] = 0;
            Ok(text.len() as i32)
        })())
    })
}

/// Parse the base58check text form back into the 32 byte x-only key.
///
/// # Safety
/// `text` must be a NUL terminated string and `pk_out` must point at 32
/// writable bytes.
#[no_mangle]
pub unsafe extern "C" fn sv2_sri_authority_pubkey_from_base58(text: *const c_char, pk_out: *mut u8) -> i32 {
    guard(SV2_SRI_ERR_INTERNAL, || {
        ret((|| {
            if text.is_null() {
                return Err(SV2_SRI_ERR_INVALID);
            }
            // SAFETY: forwarded to the caller
            let (text, pk_out) = unsafe { (CStr::from_ptr(text), output(pk_out, 32)?) };
            let text = text.to_str().map_err(|_| SV2_SRI_ERR_INVALID)?;
            let pk = Secp256k1PublicKey::from_str(text).map_err(|_| SV2_SRI_ERR_INVALID)?;
            pk_out.copy_from_slice(&pk.0.serialize());
            Ok(SV2_SRI_OK)
        })())
    })
}
