//! An extended server channel:
//! `channels_sv2::server::extended::ExtendedChannel`.

use binary_sv2::B032Owned;
use channels_sv2::server::error::ExtendedChannelError;
use channels_sv2::server::extended::ExtendedChannel;
use channels_sv2::server::jobs::error::JobFactoryError;
use mining_sv2::SubmitSharesExtendedOwned;

use crate::channels::server::{chain_tip, prebuilt, share_status, target, user_identity};
use crate::channels::{
    alloc_err, Sv2SriChannelOpen, Sv2SriExtranonceAllocator, Sv2SriPrebuiltJob, SV2_SRI_ERR_CH_CHAIN_TIP,
    SV2_SRI_ERR_CH_COINBASE, SV2_SRI_ERR_CH_EXTRANONCE_SIZE, SV2_SRI_ERR_CH_JOB_ID, SV2_SRI_ERR_CH_MAX_TARGET,
    SV2_SRI_ERR_CH_NOMINAL_HASHRATE, SV2_SRI_ERR_CH_NTIME_START, SV2_SRI_ERR_CH_OTHER, SV2_SRI_ERR_CH_TARGET,
};
use crate::ffi::{guard, obj, obj_mut, output, ret};
use crate::messages::Sv2SriSubmitSharesExtended;
use crate::{SV2_SRI_ERR_INTERNAL, SV2_SRI_ERR_INVALID, SV2_SRI_ERR_OVERFLOW, SV2_SRI_OK};

/// One extended channel.  Opaque to C.
pub struct Sv2SriExtendedChannel {
    inner: ExtendedChannel,
}

fn err(e: ExtendedChannelError) -> i32 {
    match e {
        ExtendedChannelError::OpenChannelInvalidMaxTarget(_)
        | ExtendedChannelError::UpdateChannelInvalidMaxTarget(_) => SV2_SRI_ERR_CH_MAX_TARGET,
        ExtendedChannelError::OpenChannelInvalidNominalHashrate(_)
        | ExtendedChannelError::UpdateChannelInvalidNominalHashrate(_) => SV2_SRI_ERR_CH_NOMINAL_HASHRATE,
        ExtendedChannelError::RequestedMinExtranonceSizeTooLarge(_) => SV2_SRI_ERR_CH_EXTRANONCE_SIZE,
        ExtendedChannelError::InvalidTarget => SV2_SRI_ERR_CH_TARGET,
        ExtendedChannelError::JobIdNotFound | ExtendedChannelError::TemplateIdNotFound => SV2_SRI_ERR_CH_JOB_ID,
        ExtendedChannelError::ChainTipNotSet => SV2_SRI_ERR_CH_CHAIN_TIP,
        ExtendedChannelError::JobNtimeStartBelowChainTip => SV2_SRI_ERR_CH_NTIME_START,
        ExtendedChannelError::JobFactoryError(JobFactoryError::InvalidPrebuiltCoinbase) => SV2_SRI_ERR_CH_COINBASE,
        _ => SV2_SRI_ERR_CH_OTHER,
    }
}

/// # Safety
/// As `sv2_sri_extended_channel_new()`.
unsafe fn new(
    allocator: *mut Sv2SriExtranonceAllocator,
    o: *const Sv2SriChannelOpen,
) -> Result<Sv2SriExtendedChannel, i32> {
    // SAFETY: forwarded to the caller
    let (a, o) = unsafe { (obj_mut(allocator)?, obj(o)?) };
    // SAFETY: forwarded to the caller
    let (user, max_target) = unsafe { (user_identity(&o.user_identity)?, target(o.max_target)?) };
    let prefix = a
        .inner
        .allocate_extended(o.min_extranonce_size as usize)
        .map_err(alloc_err)?;
    let rollable = a.inner.rollable_extranonce_size() as u16;
    // the prefix goes back to the allocator with the error
    let inner = ExtendedChannel::new_for_pool(
        o.channel_id,
        user,
        prefix,
        max_target,
        o.nominal_hash_rate,
        !o.no_version_rolling,
        rollable,
        o.share_batch_size as usize,
        o.expected_shares_per_minute,
        String::new(),
        (o.max_past_jobs != 0).then_some(o.max_past_jobs as usize),
    )
    .map_err(err)?;
    Ok(Sv2SriExtendedChannel { inner })
}

/// Open an extended channel with a prefix from `allocator`; the miner rolls
/// the allocator's rollable bytes (`sv2_sri_extranonce_allocator_rollable_size()`).
/// Version rolling is allowed unless `no_version_rolling` is set.  Returns
/// NULL with `*status` set when the request is refused.  Free with
/// `sv2_sri_extended_channel_free()`.
///
/// # Safety
/// `allocator` must be a live allocator, `o` must point at a record whose
/// byte fields describe readable memory and whose `max_target` points at 32
/// bytes, and `status` must be NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn sv2_sri_extended_channel_new(
    allocator: *mut Sv2SriExtranonceAllocator,
    o: *const Sv2SriChannelOpen,
    status: *mut i32,
) -> *mut Sv2SriExtendedChannel {
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
/// `ch` must be NULL or a pointer from `sv2_sri_extended_channel_new()`,
/// not freed before.
#[no_mangle]
pub unsafe extern "C" fn sv2_sri_extended_channel_free(ch: *mut Sv2SriExtendedChannel) {
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
pub unsafe extern "C" fn sv2_sri_extended_channel_extranonce_prefix(
    ch: *const Sv2SriExtendedChannel,
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

/// The target of the jobs that follow: what SetTarget tells the miner.
/// Jobs already created keep theirs.  A zero target, or one above the
/// channel's `max_target` (at open, or from the last UpdateChannel), is
/// refused with `SV2_SRI_ERR_CH_TARGET`.
///
/// # Safety
/// `ch` must be a live channel and `target` must point at 32 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn sv2_sri_extended_channel_set_target(
    ch: *mut Sv2SriExtendedChannel,
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

/// UpdateChannel: the new nominal hashrate and `maximum_target`.  The
/// crate derives a target from them, at or below `maximum_target`, which
/// `sv2_sri_extended_channel_set_target()` overrides; from now on a target
/// above `maximum_target` is refused.
///
/// # Safety
/// `ch` must be a live channel and `max_target` must point at 32 readable
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn sv2_sri_extended_channel_update(
    ch: *mut Sv2SriExtendedChannel,
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

/// A job for the channel, as the bytes the server sends it.  A future job
/// (`has_ntime_start` false) waits for `sv2_sri_extended_channel_activate_job()`;
/// otherwise the job is active under the channel's chain tip and the
/// previous one retires to the past jobs, still accepting shares.  An
/// active job needs the chain tip (`SV2_SRI_ERR_CH_CHAIN_TIP`) and an
/// `ntime_start` no lower than the tip's (`SV2_SRI_ERR_CH_NTIME_START`).
/// `*job_id` is the id the miner is told.
///
/// # Safety
/// `ch` must be a live channel, `job` must point at a record whose byte
/// fields describe readable memory, and `job_id` must be writable.
#[no_mangle]
pub unsafe extern "C" fn sv2_sri_extended_channel_prebuilt_job(
    ch: *mut Sv2SriExtendedChannel,
    job: *const Sv2SriPrebuiltJob,
    job_id: *mut u32,
) -> i32 {
    guard(SV2_SRI_ERR_INTERNAL, || {
        ret((|| {
            // SAFETY: forwarded to the caller
            let (ch, job, job_id) = unsafe { (obj_mut(ch)?, prebuilt(job)?, obj_mut(job_id)?) };
            *job_id = ch.inner.on_prebuilt_job(job).map_err(err)?;
            Ok(SV2_SRI_OK)
        })())
    })
}

/// The target shares on job `job_id` are checked against, and the one an
/// accepted share is credited at: the channel's target when the job was
/// created or activated, written to `out` (32 bytes, as on the wire).
/// Returns `SV2_SRI_ERR_CH_JOB_ID` for a job the channel takes no shares
/// on: unknown, future, evicted from the past jobs, or stale.
///
/// # Safety
/// `ch` must be a live channel and `out` must point at 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn sv2_sri_extended_channel_job_target(
    ch: *const Sv2SriExtendedChannel,
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

/// SetNewPrevHash: the future job `job_id` is the active job under the tip
/// `prev_hash` (32 bytes as on the wire), `nbits`, `ntime_start`.  Every
/// other job goes stale.
///
/// # Safety
/// `ch` must be a live channel and `prev_hash` must point at 32 readable
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn sv2_sri_extended_channel_activate_job(
    ch: *mut Sv2SriExtendedChannel,
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

/// Validate a SubmitSharesExtended.  Returns `SV2_SRI_SHARE_VALID` or
/// `SV2_SRI_SHARE_BLOCK` with the share hash in `hash` (32 bytes), or a
/// `SV2_SRI_ERR_SHARE_*` code.  With a block, `*coinbase_len` gets the
/// length of the block's coinbase, the job's prefix, the extranonce and the
/// job's suffix as handed over (no witness data), and the bytes go to
/// `coinbase` when they fit in `coinbase_cap`; otherwise `*coinbase_len` is
/// 0.  Pass NULL, 0, NULL to skip the coinbase.
///
/// # Safety
/// `ch` must be a live channel, `share` must point at a record whose
/// `extranonce` describes readable memory, `hash` must point at 32
/// writable bytes, `coinbase` must be NULL or point at `coinbase_cap`
/// writable bytes, and `coinbase_len` must be NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn sv2_sri_extended_channel_validate_share(
    ch: *mut Sv2SriExtendedChannel,
    share: *const Sv2SriSubmitSharesExtended,
    hash: *mut u8,
    coinbase: *mut u8,
    coinbase_cap: u32,
    coinbase_len: *mut u32,
) -> i32 {
    guard(SV2_SRI_ERR_INTERNAL, || {
        ret((|| {
            // SAFETY: forwarded to the caller
            let (ch, s) = unsafe { (obj_mut(ch)?, obj(share)?) };
            // SAFETY: forwarded to the caller
            let extranonce = unsafe { s.extranonce.as_slice()? };
            let share = SubmitSharesExtendedOwned {
                channel_id: ch.inner.get_channel_id(),
                sequence_number: s.sequence_number,
                job_id: s.job_id,
                nonce: s.nonce,
                ntime: s.ntime,
                version: s.version,
                extranonce: B032Owned::new(extranonce.to_vec()).map_err(|_| SV2_SRI_ERR_INVALID)?,
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
