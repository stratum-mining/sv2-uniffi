//! The extranonce allocator: `channels_sv2::extranonce_manager`.
//!
//! An allocator hands every channel opened through it a prefix no other
//! channel of the allocator has at the same time, and takes it back when
//! the channel is freed.  Its layout is
//! `local_prefix || index || rollable`, where `local_prefix` is the
//! caller's (a server or thread tag), `index` is the allocator's and sized
//! by `max_channels`, and `rollable` is the miner's.  A standard channel
//! gets the whole extranonce as its prefix, with the rollable part zero.

use channels_sv2::extranonce_manager::{ExtranonceAllocator, ExtranonceAllocatorError};

use crate::channels::{SV2_SRI_ERR_CH_CAPACITY, SV2_SRI_ERR_CH_EXTRANONCE_SIZE, SV2_SRI_ERR_CH_OTHER};
use crate::ffi::{guard, input, obj};
use crate::{SV2_SRI_ERR_INTERNAL, SV2_SRI_ERR_INVALID};

/// One extranonce allocator.  Opaque to C.
pub struct Sv2SriExtranonceAllocator {
    pub(crate) inner: ExtranonceAllocator,
}

pub(crate) fn alloc_err(e: ExtranonceAllocatorError) -> i32 {
    match e {
        ExtranonceAllocatorError::CapacityExhausted => SV2_SRI_ERR_CH_CAPACITY,
        ExtranonceAllocatorError::InvalidRollableSize => SV2_SRI_ERR_CH_EXTRANONCE_SIZE,
        _ => SV2_SRI_ERR_CH_OTHER,
    }
}

/// Create an allocator for extranonces of `total_extranonce_len` bytes
/// (at most 32) that start with the `local_prefix_len` bytes at
/// `local_prefix` and have room for `max_channels` channels at once.
/// Returns NULL when the prefix and the index do not fit, or
/// `max_channels` is 0.  Free with `sv2_sri_extranonce_allocator_free()`
/// after every channel opened through it.
///
/// # Safety
/// `local_prefix` must point at `local_prefix_len` readable bytes, or be
/// NULL when that is 0.
#[no_mangle]
pub unsafe extern "C" fn sv2_sri_extranonce_allocator_new(
    local_prefix: *const u8,
    local_prefix_len: u32,
    total_extranonce_len: u8,
    max_channels: u32,
) -> *mut Sv2SriExtranonceAllocator {
    guard(core::ptr::null_mut(), || {
        // SAFETY: forwarded to the caller
        let Ok(prefix) = (unsafe { input(local_prefix, local_prefix_len as usize) }) else {
            return core::ptr::null_mut();
        };
        match ExtranonceAllocator::new(prefix.to_vec(), total_extranonce_len, max_channels) {
            Ok(inner) => Box::into_raw(Box::new(Sv2SriExtranonceAllocator { inner })),
            Err(_) => core::ptr::null_mut(),
        }
    })
}

/// # Safety
/// `a` must be NULL or a pointer from `sv2_sri_extranonce_allocator_new()`,
/// not freed before, with no channel opened through it still alive.
#[no_mangle]
pub unsafe extern "C" fn sv2_sri_extranonce_allocator_free(a: *mut Sv2SriExtranonceAllocator) {
    guard((), || {
        if !a.is_null() {
            // SAFETY: the pointer came from Box::into_raw
            drop(unsafe { Box::from_raw(a) });
        }
    })
}

/// The rollable bytes an extended channel of this allocator gets, or
/// `SV2_SRI_ERR_INVALID`.
///
/// # Safety
/// `a` must be a live allocator.
#[no_mangle]
pub unsafe extern "C" fn sv2_sri_extranonce_allocator_rollable_size(a: *const Sv2SriExtranonceAllocator) -> i32 {
    guard(SV2_SRI_ERR_INTERNAL, || {
        // SAFETY: forwarded to the caller
        match unsafe { obj(a) } {
            Ok(a) => a.inner.rollable_extranonce_size() as i32,
            Err(_) => SV2_SRI_ERR_INVALID,
        }
    })
}
