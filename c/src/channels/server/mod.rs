//! The server channels, and what the extended and the standard one share:
//! the conversions from the C records to the crate's types and the
//! folding of a share verdict into a status.

use binary_sv2::{B064KOwned, Seq0255Owned, U256Owned};
use bitcoin::hashes::Hash as _;
use bitcoin::Target;
use channels_sv2::chain_tip::ChainTip;
use channels_sv2::server::jobs::PrebuiltJob;
use channels_sv2::server::share_accounting::{ShareValidationError, ShareValidationResult};
use mining_sv2::ERROR_CODE_SUBMIT_SHARES_INVALID_NON_ROLLABLE_VERSION_BIT;

use crate::channels::{
    Sv2SriPrebuiltJob, SV2_SRI_ERR_SHARE_BUDGET, SV2_SRI_ERR_SHARE_DUPLICATE, SV2_SRI_ERR_SHARE_EXTRANONCE_SIZE,
    SV2_SRI_ERR_SHARE_INVALID, SV2_SRI_ERR_SHARE_JOB_ID, SV2_SRI_ERR_SHARE_NO_CHAIN_TIP, SV2_SRI_ERR_SHARE_STALE,
    SV2_SRI_ERR_SHARE_TARGET, SV2_SRI_ERR_SHARE_VERSION, SV2_SRI_ERR_SHARE_VERSION_BIT, SV2_SRI_SHARE_BLOCK,
    SV2_SRI_SHARE_VALID,
};
use crate::ffi::{input, obj, output};
use crate::SV2_SRI_ERR_INVALID;

pub mod extended;
pub mod standard;

pub use extended::*;
pub use standard::*;

/// # Safety
/// `p` must point at 32 readable bytes.
pub(crate) unsafe fn arr32(p: *const u8) -> Result<[u8; 32], i32> {
    // SAFETY: forwarded to the caller
    let b = unsafe { input(p, 32)? };
    b.try_into().map_err(|_| SV2_SRI_ERR_INVALID)
}

/// A target as on the wire: 32 bytes, little endian
///
/// # Safety
/// `p` must point at 32 readable bytes.
pub(crate) unsafe fn target(p: *const u8) -> Result<Target, i32> {
    // SAFETY: forwarded to the caller
    Ok(Target::from_le_bytes(unsafe { arr32(p)? }))
}

/// The chain tip of a SetNewPrevHash
///
/// # Safety
/// `prev_hash` must point at 32 readable bytes.
pub(crate) unsafe fn chain_tip(prev_hash: *const u8, nbits: u32, ntime_start: u32) -> Result<ChainTip, i32> {
    // SAFETY: forwarded to the caller
    let h = unsafe { arr32(prev_hash)? };
    Ok(ChainTip::new(U256Owned::from(h), nbits, ntime_start))
}

/// The crate's job for a record.  The bytes are copied: the job outlives
/// the call.
///
/// # Safety
/// `j` must point at a record whose byte fields describe readable memory.
pub(crate) unsafe fn prebuilt(j: *const Sv2SriPrebuiltJob) -> Result<PrebuiltJob, i32> {
    // SAFETY: forwarded to the caller
    let j = unsafe { obj(j)? };
    // SAFETY: forwarded to the caller
    let (prefix, suffix, path) = unsafe {
        (
            j.coinbase_tx_prefix.as_slice()?,
            j.coinbase_tx_suffix.as_slice()?,
            j.merkle_path.as_slice()?,
        )
    };
    if path.len() % 32 != 0 {
        return Err(SV2_SRI_ERR_INVALID);
    }
    let mut hashes = Vec::with_capacity(path.len() / 32);
    for h in path.chunks_exact(32) {
        let a: [u8; 32] = h.try_into().map_err(|_| SV2_SRI_ERR_INVALID)?;
        hashes.push(U256Owned::from(a));
    }
    Ok(PrebuiltJob {
        ntime_start: j.has_ntime_start.then_some(j.ntime_start),
        version: j.version,
        coinbase_tx_prefix: B064KOwned::new(prefix.to_vec()).map_err(|_| SV2_SRI_ERR_INVALID)?,
        coinbase_tx_suffix: B064KOwned::new(suffix.to_vec()).map_err(|_| SV2_SRI_ERR_INVALID)?,
        merkle_path: Seq0255Owned::new(hashes).map_err(|_| SV2_SRI_ERR_INVALID)?,
    })
}

/// Fold the crate's verdict into a status.  A share that passes has its
/// hash written to `hash` (32 bytes, the double SHA-256 as bytes).  With a
/// block, `*coinbase_len` gets the length of the coinbase the crate returns
/// and the bytes go to `coinbase` when they fit in `coinbase_cap`; for
/// anything else `*coinbase_len` is 0.  Either pointer may be NULL.
///
/// # Safety
/// `hash` must point at 32 writable bytes, `coinbase` must be NULL or point
/// at `coinbase_cap` writable bytes, and `coinbase_len` must be NULL or
/// writable.
pub(crate) unsafe fn share_status(
    r: Result<ShareValidationResult, ShareValidationError>,
    hash: *mut u8,
    coinbase: *mut u8,
    coinbase_cap: u32,
    coinbase_len: *mut u32,
) -> i32 {
    // SAFETY: forwarded to the caller
    let coinbase_len = unsafe { coinbase_len.as_mut() };
    match r {
        Ok(v) => {
            let (status, h, block_coinbase) = match v {
                ShareValidationResult::Valid(h) => (SV2_SRI_SHARE_VALID, h, Vec::new()),
                ShareValidationResult::BlockFound(h, _, c) => (SV2_SRI_SHARE_BLOCK, h, c),
            };
            // SAFETY: forwarded to the caller
            match unsafe { output(hash, 32) } {
                Ok(out) => out.copy_from_slice(&h.to_byte_array()),
                Err(e) => return e,
            }
            if let Some(len) = coinbase_len {
                *len = block_coinbase.len() as u32;
            }
            if !coinbase.is_null() && !block_coinbase.is_empty() && block_coinbase.len() <= coinbase_cap as usize {
                // SAFETY: forwarded to the caller
                match unsafe { output(coinbase, block_coinbase.len()) } {
                    Ok(out) => out.copy_from_slice(&block_coinbase),
                    Err(e) => return e,
                }
            }
            status
        }
        Err(e) => {
            if let Some(len) = coinbase_len {
                *len = 0;
            }
            share_error(e)
        }
    }
}

fn share_error(e: ShareValidationError) -> i32 {
    match e {
        ShareValidationError::Invalid(code) => {
            if code == ERROR_CODE_SUBMIT_SHARES_INVALID_NON_ROLLABLE_VERSION_BIT {
                SV2_SRI_ERR_SHARE_VERSION_BIT
            } else {
                SV2_SRI_ERR_SHARE_INVALID
            }
        }
        ShareValidationError::Stale(_) => SV2_SRI_ERR_SHARE_STALE,
        ShareValidationError::InvalidJobId(_) => SV2_SRI_ERR_SHARE_JOB_ID,
        ShareValidationError::DoesNotMeetTarget(_) => SV2_SRI_ERR_SHARE_TARGET,
        ShareValidationError::VersionRollingNotAllowed(_) => SV2_SRI_ERR_SHARE_VERSION,
        ShareValidationError::DuplicateShare(_) => SV2_SRI_ERR_SHARE_DUPLICATE,
        ShareValidationError::BadExtranonceSize(_) => SV2_SRI_ERR_SHARE_EXTRANONCE_SIZE,
        ShareValidationError::NoChainTip => SV2_SRI_ERR_SHARE_NO_CHAIN_TIP,
        ShareValidationError::SeenSharesBudgetExhausted => SV2_SRI_ERR_SHARE_BUDGET,
    }
}

/// The user identity of an open request, which the crate keeps as text
///
/// # Safety
/// `b` must describe readable memory.
pub(crate) unsafe fn user_identity(b: &crate::ffi::Sv2SriBytes) -> Result<String, i32> {
    // SAFETY: forwarded to the caller
    let s = unsafe { b.as_slice()? };
    core::str::from_utf8(s)
        .map(str::to_owned)
        .map_err(|_| SV2_SRI_ERR_INVALID)
}
