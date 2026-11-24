//! A standard server channel:
//! `channels_sv2::server::standard::StandardChannel`.  The whole extranonce
//! is the channel's prefix, so the crate computes each job's merkle root
//! and the channel sends NewMiningJob.

use channels_sv2::server::error::StandardChannelError;
use channels_sv2::server::jobs::error::JobFactoryError;
use channels_sv2::server::standard::StandardChannel;
use mining_sv2::SubmitSharesStandardOwned;

use crate::channels::server::{chain_tip, prebuilt, share_status, target, user_identity};
use crate::channels::{
    alloc_err, Sv2SriChannelOpen, Sv2SriExtranonceAllocator, Sv2SriPrebuiltJob, SV2_SRI_ERR_CH_CHAIN_TIP,
    SV2_SRI_ERR_CH_COINBASE, SV2_SRI_ERR_CH_JOB_ID, SV2_SRI_ERR_CH_MAX_TARGET, SV2_SRI_ERR_CH_NOMINAL_HASHRATE,
    SV2_SRI_ERR_CH_NTIME_START, SV2_SRI_ERR_CH_OTHER, SV2_SRI_ERR_CH_TARGET,
};
use crate::ffi::{guard, obj, obj_mut, output, ret};
use crate::messages::Sv2SriSubmitSharesStandard;
use crate::{SV2_SRI_ERR_INTERNAL, SV2_SRI_ERR_OVERFLOW, SV2_SRI_OK};

/// One standard channel.  Opaque to C.
pub struct Sv2SriStandardChannel {
    inner: StandardChannel,
}

fn err(e: StandardChannelError) -> i32 {
    match e {
        StandardChannelError::OpenChannelInvalidMaxTarget(_)
        | StandardChannelError::UpdateChannelInvalidMaxTarget(_) => SV2_SRI_ERR_CH_MAX_TARGET,
        StandardChannelError::OpenChannelInvalidNominalHashrate(_)
        | StandardChannelError::UpdateChannelInvalidNominalHashrate(_) => SV2_SRI_ERR_CH_NOMINAL_HASHRATE,
        StandardChannelError::InvalidTarget => SV2_SRI_ERR_CH_TARGET,
        StandardChannelError::JobIdNotFound | StandardChannelError::TemplateIdNotFound => SV2_SRI_ERR_CH_JOB_ID,
        StandardChannelError::ChainTipNotSet => SV2_SRI_ERR_CH_CHAIN_TIP,
        StandardChannelError::JobNtimeStartBelowChainTip => SV2_SRI_ERR_CH_NTIME_START,
        StandardChannelError::JobFactoryError(JobFactoryError::InvalidPrebuiltCoinbase) => SV2_SRI_ERR_CH_COINBASE,
        _ => SV2_SRI_ERR_CH_OTHER,
    }
}

/// # Safety
/// As `sv2_sri_standard_channel_new()`.
unsafe fn new(
    allocator: *mut Sv2SriExtranonceAllocator,
    o: *const Sv2SriChannelOpen,
) -> Result<Sv2SriStandardChannel, i32> {
    // SAFETY: forwarded to the caller
    let (a, o) = unsafe { (obj_mut(allocator)?, obj(o)?) };
    // SAFETY: forwarded to the caller
    let (user, max_target) = unsafe { (user_identity(&o.user_identity)?, target(o.max_target)?) };
    let prefix = a.inner.allocate_standard().map_err(alloc_err)?;
    // the prefix goes back to the allocator with the error
    let inner = StandardChannel::new_for_pool(
        o.channel_id,
        user,
        prefix,
        max_target,
        o.nominal_hash_rate,
        o.share_batch_size as usize,
        o.expected_shares_per_minute,
        String::new(),
        (o.max_past_jobs != 0).then_some(o.max_past_jobs as usize),
    )
    .map_err(err)?;
    Ok(Sv2SriStandardChannel { inner })
}

/// Open a standard channel with a prefix from `allocator`: the whole
/// extranonce, with the rollable part zero.  Returns NULL with `*status`
/// set when the request is refused.  Free with
/// `sv2_sri_standard_channel_free()`.
///
/// # Safety
/// `allocator` must be a live allocator, `o` must point at a record whose
/// byte fields describe readable memory and whose `max_target` points at 32
/// bytes, and `status` must be NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn sv2_sri_standard_channel_new(
    allocator: *mut Sv2SriExtranonceAllocator,
    o: *const Sv2SriChannelOpen,
    status: *mut i32,
) -> *mut Sv2SriStandardChannel {
    guard(core::ptr::null_mut(), || {
        // SAFETY: forwarded to the caller
        let r = unsafe { new(allocator, o) };
        let (p, s) = match r {
            Ok(ch) => (Box::into_raw(Box::new(ch)), SV2_SRI_OK),
            Err(e) => (core::ptr::null_mut(), e),
        };
        // SAFETY: forwarded to the caller
        if let Ok(status) = unsafe { obj_mut(status) } {
            *status = s;
        }
        p
    })
}

/// # Safety
/// `ch` must be NULL or a pointer from `sv2_sri_standard_channel_new()`,
/// not freed before.
#[no_mangle]
pub unsafe extern "C" fn sv2_sri_standard_channel_free(ch: *mut Sv2SriStandardChannel) {
    guard((), || {
        if !ch.is_null() {
            // SAFETY: the pointer came from Box::into_raw
            drop(unsafe { Box::from_raw(ch) });
        }
    })
}

/// The channel's extranonce prefix, written to `out` (capacity `cap`).
/// Returns its length, or `SV2_SRI_ERR_OVERFLOW`.
///
/// # Safety
/// `ch` must be a live channel and `out` must point at `cap` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn sv2_sri_standard_channel_extranonce_prefix(
    ch: *const Sv2SriStandardChannel,
    out: *mut u8,
    cap: u32,
) -> i32 {
    guard(SV2_SRI_ERR_INTERNAL, || {
        ret((|| {
            // SAFETY: forwarded to the caller
            let (ch, out) = unsafe { (obj(ch)?, output(out, cap as usize)?) };
            let prefix = ch.inner.get_extranonce_prefix();
            if prefix.len() > out.len() {
                return Err(SV2_SRI_ERR_OVERFLOW);
            }
            out[..prefix.len()].copy_from_slice(prefix);
            Ok(prefix.len() as i32)
        })())
    })
}

/// As `sv2_sri_extended_channel_set_target()`.
///
/// # Safety
/// `ch` must be a live channel and `target` must point at 32 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn sv2_sri_standard_channel_set_target(
    ch: *mut Sv2SriStandardChannel,
    target_: *const u8,
) -> i32 {
    guard(SV2_SRI_ERR_INTERNAL, || {
        ret((|| {
            // SAFETY: forwarded to the caller
            let (ch, t) = unsafe { (obj_mut(ch)?, target(target_)?) };
            ch.inner.set_target(t).map_err(err)?;
            Ok(SV2_SRI_OK)
        })())
    })
}

/// As `sv2_sri_extended_channel_update()`.
///
/// # Safety
/// `ch` must be a live channel and `max_target` must point at 32 readable
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn sv2_sri_standard_channel_update(
    ch: *mut Sv2SriStandardChannel,
    nominal_hash_rate: f32,
    max_target: *const u8,
) -> i32 {
    guard(SV2_SRI_ERR_INTERNAL, || {
        ret((|| {
            // SAFETY: forwarded to the caller
            let (ch, t) = unsafe { (obj_mut(ch)?, target(max_target)?) };
            ch.inner.update_channel(nominal_hash_rate, Some(t)).map_err(err)?;
            Ok(SV2_SRI_OK)
        })())
    })
}

/// As `sv2_sri_extended_channel_prebuilt_job()`, with the merkle root of
/// the job's NewMiningJob, computed by the crate from the bytes and the
/// channel's extranonce, written to `merkle_root` (32 bytes).
///
/// # Safety
/// `ch` must be a live channel, `job` must point at a record whose byte
/// fields describe readable memory, `job_id` must be writable and
/// `merkle_root` must point at 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn sv2_sri_standard_channel_prebuilt_job(
    ch: *mut Sv2SriStandardChannel,
    job: *const Sv2SriPrebuiltJob,
    job_id: *mut u32,
    merkle_root: *mut u8,
) -> i32 {
    guard(SV2_SRI_ERR_INTERNAL, || {
        ret((|| {
            // SAFETY: forwarded to the caller
            let (ch, job, job_id, root) =
                unsafe { (obj_mut(ch)?, prebuilt(job)?, obj_mut(job_id)?, output(merkle_root, 32)?) };
            let future = job.ntime_start.is_none();
            let id = ch.inner.on_prebuilt_job(job).map_err(err)?;
            let j = if future {
                ch.inner.get_future_job(id)
            } else {
                ch.inner.get_active_job()
            };
            root.copy_from_slice(&j.ok_or(SV2_SRI_ERR_CH_OTHER)?.get_merkle_root().to_array());
            *job_id = id;
            Ok(SV2_SRI_OK)
        })())
    })
}

/// As `sv2_sri_extended_channel_job_target()`.
///
/// # Safety
/// `ch` must be a live channel and `out` must point at 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn sv2_sri_standard_channel_job_target(
    ch: *const Sv2SriStandardChannel,
    job_id: u32,
    out: *mut u8,
) -> i32 {
    guard(SV2_SRI_ERR_INTERNAL, || {
        ret((|| {
            // SAFETY: forwarded to the caller
            let (ch, out) = unsafe { (obj(ch)?, output(out, 32)?) };
            let t = ch.inner.get_job_target(job_id).ok_or(SV2_SRI_ERR_CH_JOB_ID)?;
            out.copy_from_slice(&t.to_le_bytes());
            Ok(SV2_SRI_OK)
        })())
    })
}

/// As `sv2_sri_extended_channel_activate_job()`.
///
/// # Safety
/// `ch` must be a live channel and `prev_hash` must point at 32 readable
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn sv2_sri_standard_channel_activate_job(
    ch: *mut Sv2SriStandardChannel,
    job_id: u32,
    prev_hash: *const u8,
    nbits: u32,
    ntime_start: u32,
) -> i32 {
    guard(SV2_SRI_ERR_INTERNAL, || {
        ret((|| {
            // SAFETY: forwarded to the caller
            let (ch, tip) = unsafe { (obj_mut(ch)?, chain_tip(prev_hash, nbits, ntime_start)?) };
            ch.inner.activate_future_job(job_id, tip).map_err(err)?;
            Ok(SV2_SRI_OK)
        })())
    })
}

/// Validate a SubmitSharesStandard, as
/// `sv2_sri_extended_channel_validate_share()`.
///
/// # Safety
/// `ch` must be a live channel, `share` must be readable, `hash` must
/// point at 32 writable bytes, `coinbase` must be NULL or point at
/// `coinbase_cap` writable bytes, and `coinbase_len` must be NULL or
/// writable.
#[no_mangle]
pub unsafe extern "C" fn sv2_sri_standard_channel_validate_share(
    ch: *mut Sv2SriStandardChannel,
    share: *const Sv2SriSubmitSharesStandard,
    hash: *mut u8,
    coinbase: *mut u8,
    coinbase_cap: u32,
    coinbase_len: *mut u32,
) -> i32 {
    guard(SV2_SRI_ERR_INTERNAL, || {
        ret((|| {
            // SAFETY: forwarded to the caller
            let (ch, s) = unsafe { (obj_mut(ch)?, obj(share)?) };
            let share = SubmitSharesStandardOwned {
                channel_id: ch.inner.get_channel_id(),
                sequence_number: s.sequence_number,
                job_id: s.job_id,
                nonce: s.nonce,
                ntime: s.ntime,
                version: s.version,
            };
            // SAFETY: forwarded to the caller
            Ok(unsafe {
                share_status(
                    ch.inner.validate_share(share),
                    hash,
                    coinbase,
                    coinbase_cap,
                    coinbase_len,
                )
            })
        })())
    })
}
