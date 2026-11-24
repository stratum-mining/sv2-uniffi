//! Server-side mining channels through `channels_sv2`, laid out the way
//! the UniFFI crate's `channels` module is: an extranonce allocator and, as
//! opaque objects, an extended and a standard server channel.
//!
//! The application keeps everything that is its own (DATUM Gateway, for
//! one, keeps the coinbase per difficulty tier, vardiff and the pool
//! submission) and
//! hands a channel each job as the bytes of the `NewExtendedMiningJob` it
//! sends, a `Sv2SriPrebuiltJob` (`channels_sv2::server::jobs::PrebuiltJob`).
//! The crate allocates the extranonce prefix, issues the job ids, keeps the
//! future, active, past and stale jobs with the target each was sent at
//! (`sv2_sri_*_channel_job_target()`, the target a share is credited at),
//! and validates the shares: unknown or stale job id, extranonce size,
//! version bits, ntime against the tip, the job's target, duplicates, and
//! whether the hash meets the network target.
//!
//! Status codes: `SV2_SRI_OK`, `SV2_SRI_SHARE_VALID` or `SV2_SRI_SHARE_BLOCK`
//! from share validation, or a negative `SV2_SRI_ERR_CH_*` /
//! `SV2_SRI_ERR_SHARE_*` code.  `sv2_sri_channel_error_code()` gives the
//! spec's error-code string for one, as the crate defines it, for the error
//! reply.  The channel objects are not thread safe: a channel and the
//! allocator it came from belong to one thread.

use crate::ffi::{guard, Sv2SriBytes};

pub mod extranonce;
pub mod server;

pub use extranonce::*;
pub use server::*;

/// A share that passes
pub const SV2_SRI_SHARE_VALID: i32 = 1;
/// A share that passes and meets the network target
pub const SV2_SRI_SHARE_BLOCK: i32 = 2;

/// `max_target` is zero: "max-target-out-of-range"
pub const SV2_SRI_ERR_CH_MAX_TARGET: i32 = -20;
/// The nominal hashrate gives no target: "invalid-nominal-hashrate"
pub const SV2_SRI_ERR_CH_NOMINAL_HASHRATE: i32 = -21;
/// More rollable bytes asked for than the allocator leaves:
/// "min-extranonce-size-too-large"
pub const SV2_SRI_ERR_CH_EXTRANONCE_SIZE: i32 = -22;
/// The allocator has no prefix left: "channel-capacity-exhausted"
pub const SV2_SRI_ERR_CH_CAPACITY: i32 = -23;
/// No job with that id: no future one to activate, or none the channel
/// takes shares on for its target
pub const SV2_SRI_ERR_CH_JOB_ID: i32 = -24;
/// A non-future job before the channel has a chain tip
pub const SV2_SRI_ERR_CH_CHAIN_TIP: i32 = -25;
/// The job's bytes do not form a coinbase around the extranonce slot
pub const SV2_SRI_ERR_CH_COINBASE: i32 = -26;
/// A zero target, or one above the channel's `max_target`
pub const SV2_SRI_ERR_CH_TARGET: i32 = -27;
/// Another channel error, one of the crate's own invariants
pub const SV2_SRI_ERR_CH_OTHER: i32 = -28;
/// An active job whose `ntime_start` is below the chain tip's
pub const SV2_SRI_ERR_CH_NTIME_START: i32 = -29;

/// The share is invalid for another reason: "invalid-share"
pub const SV2_SRI_ERR_SHARE_INVALID: i32 = -30;
/// The share is on a job of a previous chain tip: "stale-share"
pub const SV2_SRI_ERR_SHARE_STALE: i32 = -31;
/// The channel never had that job, or no longer does: "invalid-job-id"
pub const SV2_SRI_ERR_SHARE_JOB_ID: i32 = -32;
/// The hash is above the job's target: "difficulty-too-low"
pub const SV2_SRI_ERR_SHARE_TARGET: i32 = -33;
/// The version differs where the job allows no rolling:
/// "version-rolling-not-allowed"
pub const SV2_SRI_ERR_SHARE_VERSION: i32 = -34;
/// A rolled bit outside the general-purpose ones:
/// "invalid-non-rollable-version-bit"
pub const SV2_SRI_ERR_SHARE_VERSION_BIT: i32 = -35;
/// The hash was accepted before under this chain tip: "duplicate-share"
pub const SV2_SRI_ERR_SHARE_DUPLICATE: i32 = -36;
/// The extranonce is not the channel's rollable size: "bad-extranonce-size"
pub const SV2_SRI_ERR_SHARE_EXTRANONCE_SIZE: i32 = -37;
/// The channel has no chain tip yet, so no job can be active
pub const SV2_SRI_ERR_SHARE_NO_CHAIN_TIP: i32 = -38;
/// The accepted-share set is full for this chain tip: forgetting a hash
/// would let a share be credited twice, so the channel has to be closed
pub const SV2_SRI_ERR_SHARE_BUDGET: i32 = -39;

/// What OpenStandardMiningChannel or OpenExtendedMiningChannel asked for,
/// and the server's policy for the channel.  The crate's pool tag is left
/// out on purpose: the crate adds it
/// only to the coinbases it builds from templates, and the jobs here are
/// prebuilt ones it uses as given, so a tag would only take scriptSig room
/// from the extranonce at open.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2SriChannelOpen {
    /// The server's id for the channel
    pub channel_id: u32,
    /// `user_identity` as sent; UTF-8
    pub user_identity: Sv2SriBytes,
    /// `nominal_hash_rate` as sent; zero gives `max_target`
    pub nominal_hash_rate: f32,
    /// `max_target` as sent: 32 bytes as on the wire
    pub max_target: *const u8,
    /// Extended channels: the rollable bytes asked for
    /// (`min_extranonce_size`); at most what the allocator leaves
    pub min_extranonce_size: u16,
    /// How many accepted shares one SubmitShares.Success acknowledges
    pub share_batch_size: u32,
    /// The share rate the server's vardiff aims at, which sizes the set of
    /// accepted hashes kept for the duplicate check
    pub expected_shares_per_minute: f32,
    /// How many past jobs the channel keeps under a tip for shares still
    /// coming on them, each with its coinbase bytes; 0 for the crate's
    /// default (16)
    pub max_past_jobs: u32,
    /// Extended channels: refuse shares that roll the header version
    /// (`version-rolling-not-allowed`); false allows rolling the
    /// general-purpose bits.  Standard channels always allow it: the crate
    /// has no such setting for them.
    pub no_version_rolling: bool,
}

/// A job as the bytes of the NewExtendedMiningJob the server sends, used as
/// given: no tag is added, nothing is parsed out of them.  The extranonce
/// slot between prefix and suffix is the channel's full extranonce size,
/// and the bytes around it must form a coinbase transaction.
/// `has_ntime_start` false is a future job, which waits for its
/// SetNewPrevHash; true is a job active at once under the channel's chain
/// tip, whose shares are bounded by `ntime_start` (the message's own field:
/// no lower than the tip's).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2SriPrebuiltJob {
    pub has_ntime_start: bool,
    pub ntime_start: u32,
    /// Block header version
    pub version: u32,
    /// Coinbase bytes before the extranonce
    pub coinbase_tx_prefix: Sv2SriBytes,
    /// Coinbase bytes after the extranonce
    pub coinbase_tx_suffix: Sv2SriBytes,
    /// The merkle path, deepest first: a multiple of 32 bytes
    pub merkle_path: Sv2SriBytes,
}

/// The spec's error code for a status, as the crate defines it: what goes
/// in OpenMiningChannel.Error, UpdateChannel.Error or SubmitShares.Error.
/// Empty for a status that has none.
#[no_mangle]
pub extern "C" fn sv2_sri_channel_error_code(status: i32) -> Sv2SriBytes {
    guard(Sv2SriBytes::EMPTY, || {
        use mining_sv2::*;
        let s: &'static str = match status {
            SV2_SRI_ERR_CH_MAX_TARGET => ERROR_CODE_OPEN_MINING_CHANNEL_MAX_TARGET_OUT_OF_RANGE,
            SV2_SRI_ERR_CH_NOMINAL_HASHRATE => ERROR_CODE_OPEN_MINING_CHANNEL_INVALID_NOMINAL_HASHRATE,
            SV2_SRI_ERR_CH_EXTRANONCE_SIZE => ERROR_CODE_OPEN_MINING_CHANNEL_MIN_EXTRANONCE_SIZE_TOO_LARGE,
            SV2_SRI_ERR_CH_CAPACITY => ERROR_CODE_OPEN_MINING_CHANNEL_CHANNEL_CAPACITY_EXHAUSTED,
            SV2_SRI_ERR_SHARE_INVALID => ERROR_CODE_SUBMIT_SHARES_INVALID_SHARE,
            SV2_SRI_ERR_SHARE_STALE => ERROR_CODE_SUBMIT_SHARES_STALE_SHARE,
            SV2_SRI_ERR_SHARE_JOB_ID => ERROR_CODE_SUBMIT_SHARES_INVALID_JOB_ID,
            SV2_SRI_ERR_SHARE_TARGET => ERROR_CODE_SUBMIT_SHARES_DIFFICULTY_TOO_LOW,
            SV2_SRI_ERR_SHARE_VERSION => ERROR_CODE_VERSION_ROLLING_NOT_ALLOWED,
            SV2_SRI_ERR_SHARE_VERSION_BIT => ERROR_CODE_SUBMIT_SHARES_INVALID_NON_ROLLABLE_VERSION_BIT,
            SV2_SRI_ERR_SHARE_DUPLICATE => ERROR_CODE_SUBMIT_SHARES_DUPLICATE_SHARE,
            SV2_SRI_ERR_SHARE_EXTRANONCE_SIZE => ERROR_CODE_SUBMIT_SHARES_BAD_EXTRANONCE_SIZE,
            _ => return Sv2SriBytes::EMPTY,
        };
        Sv2SriBytes::from_slice(s.as_bytes())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::{Sv2SriSubmitSharesExtended, Sv2SriSubmitSharesStandard};
    use crate::SV2_SRI_OK;
    use core::ptr::null_mut;

    // A coinbase around a 12 byte extranonce slot in its scriptSig, split
    // as a server splits it: the bytes before the slot and after.
    fn coinbase() -> (Vec<u8>, Vec<u8>) {
        let mut prefix = vec![1, 0, 0, 0, 1];
        prefix.extend_from_slice(&[0; 32]);
        prefix.extend_from_slice(&[0xff; 4]);
        prefix.push(16); // scriptSig: 4 bytes of height push, then the slot
        prefix.extend_from_slice(&[3, 0x10, 0x20, 0x30]);
        let mut suffix = vec![0xff; 4]; // sequence
        suffix.push(1); // one output
        suffix.extend_from_slice(&[0; 8]);
        suffix.extend_from_slice(&[1, 0x51]);
        suffix.extend_from_slice(&[0; 4]);
        (prefix, suffix)
    }

    fn open(channel_id: u32, max_target: &[u8; 32]) -> Sv2SriChannelOpen {
        Sv2SriChannelOpen {
            channel_id,
            user_identity: Sv2SriBytes::from_slice(b"worker"),
            nominal_hash_rate: 1.0e6,
            max_target: max_target.as_ptr(),
            min_extranonce_size: 8,
            share_batch_size: 1,
            expected_shares_per_minute: 8.0,
            max_past_jobs: 4,
            no_version_rolling: false,
        }
    }

    // A future job
    fn job(prefix: &[u8], suffix: &[u8]) -> Sv2SriPrebuiltJob {
        Sv2SriPrebuiltJob {
            has_ntime_start: false,
            ntime_start: 0,
            version: 0x20000000,
            coinbase_tx_prefix: Sv2SriBytes::from_slice(prefix),
            coinbase_tx_suffix: Sv2SriBytes::from_slice(suffix),
            merkle_path: Sv2SriBytes::EMPTY,
        }
    }

    // A job active at once, from `ntime_start`
    fn active(prefix: &[u8], suffix: &[u8], ntime_start: u32) -> Sv2SriPrebuiltJob {
        Sv2SriPrebuiltJob {
            has_ntime_start: true,
            ntime_start,
            ..job(prefix, suffix)
        }
    }

    // A target with its most significant byte (the last one, little
    // endian) set to `top` and every other byte 0xff
    fn target_top(top: u8) -> [u8; 32] {
        let mut t = [0xffu8; 32];
        t[31] = top;
        t
    }

    unsafe fn ext_job_target(ch: *const Sv2SriExtendedChannel, job_id: u32) -> Result<[u8; 32], i32> {
        let mut t = [0u8; 32];
        match unsafe { sv2_sri_extended_channel_job_target(ch, job_id, t.as_mut_ptr()) } {
            SV2_SRI_OK => Ok(t),
            e => Err(e),
        }
    }

    // Validate a share without asking for a block's coinbase
    unsafe fn validate_ext(
        ch: *mut Sv2SriExtendedChannel,
        share: &Sv2SriSubmitSharesExtended,
        hash: &mut [u8; 32],
    ) -> i32 {
        unsafe { sv2_sri_extended_channel_validate_share(ch, share, hash.as_mut_ptr(), null_mut(), 0, null_mut()) }
    }

    unsafe fn validate_std(
        ch: *mut Sv2SriStandardChannel,
        share: &Sv2SriSubmitSharesStandard,
        hash: &mut [u8; 32],
    ) -> i32 {
        unsafe { sv2_sri_standard_channel_validate_share(ch, share, hash.as_mut_ptr(), null_mut(), 0, null_mut()) }
    }

    #[test]
    fn extended_channel_serves_a_prebuilt_job_and_checks_shares() {
        let easy = [0xffu8; 32];
        let (prefix, suffix) = coinbase();
        unsafe {
            let a = sv2_sri_extranonce_allocator_new([0xaa, 0xbb].as_ptr(), 2, 12, 65535);
            assert!(!a.is_null());
            assert_eq!(sv2_sri_extranonce_allocator_rollable_size(a), 8);

            let mut status = 99;
            let ch = sv2_sri_extended_channel_new(a, &open(7, &easy), &mut status);
            assert!(!ch.is_null());
            assert_eq!(status, SV2_SRI_OK);
            let mut p = [0u8; 12];
            assert_eq!(sv2_sri_extended_channel_extranonce_prefix(ch, p.as_mut_ptr(), 12), 4);
            assert_eq!(&p[..2], &[0xaa, 0xbb]);
            assert_eq!(sv2_sri_extended_channel_set_target(ch, easy.as_ptr()), SV2_SRI_OK);

            // the first job is a future one, activated by SetNewPrevHash
            let mut job_id = 0;
            assert_eq!(
                sv2_sri_extended_channel_prebuilt_job(ch, &job(&prefix, &suffix), &mut job_id),
                SV2_SRI_OK
            );
            assert_eq!(
                sv2_sri_extended_channel_activate_job(ch, job_id + 1, [0u8; 32].as_ptr(), 0x1d00ffff, 1_700_000_000),
                SV2_SRI_ERR_CH_JOB_ID
            );
            assert_eq!(
                sv2_sri_extended_channel_activate_job(ch, job_id, [0u8; 32].as_ptr(), 0x1d00ffff, 1_700_000_000),
                SV2_SRI_OK
            );

            let extranonce = [1u8, 2, 3, 4, 5, 6, 7, 8];
            let mut share = Sv2SriSubmitSharesExtended {
                channel_id: 7,
                sequence_number: 1,
                job_id,
                nonce: 42,
                ntime: 1_700_000_001,
                version: 0x20000000,
                extranonce: Sv2SriBytes::from_slice(&extranonce),
            };
            let mut hash = [0u8; 32];
            // the all-ones target takes any hash
            assert_eq!(validate_ext(ch, &share, &mut hash), SV2_SRI_SHARE_VALID);
            assert_ne!(hash, [0u8; 32]);
            assert_eq!(validate_ext(ch, &share, &mut hash), SV2_SRI_ERR_SHARE_DUPLICATE);
            share.job_id += 1;
            assert_eq!(validate_ext(ch, &share, &mut hash), SV2_SRI_ERR_SHARE_JOB_ID);
            share.job_id = job_id;
            share.extranonce = Sv2SriBytes::from_slice(&extranonce[..4]);
            assert_eq!(validate_ext(ch, &share, &mut hash), SV2_SRI_ERR_SHARE_EXTRANONCE_SIZE);
            assert_eq!(
                sv2_sri_channel_error_code(SV2_SRI_ERR_SHARE_EXTRANONCE_SIZE)
                    .as_slice()
                    .unwrap(),
                b"bad-extranonce-size"
            );

            // a second job under the same tip is active at once
            let mut second = 0;
            assert_eq!(
                sv2_sri_extended_channel_prebuilt_job(ch, &active(&prefix, &suffix, 1_700_000_000), &mut second),
                SV2_SRI_OK
            );
            assert_ne!(second, job_id);
            // bytes that are not a coinbase are refused
            assert_eq!(
                sv2_sri_extended_channel_prebuilt_job(ch, &active(&prefix[..3], &suffix, 1_700_000_000), &mut second),
                SV2_SRI_ERR_CH_COINBASE
            );

            sv2_sri_extended_channel_free(ch);
            sv2_sri_extranonce_allocator_free(a);
        }
    }

    #[test]
    fn standard_channel_computes_the_merkle_root() {
        let easy = [0xffu8; 32];
        let (prefix, suffix) = coinbase();
        unsafe {
            let a = sv2_sri_extranonce_allocator_new([0xaa, 0xbb].as_ptr(), 2, 12, 65535);
            let mut status = 99;
            let ch = sv2_sri_standard_channel_new(a, &open(9, &easy), &mut status);
            assert!(!ch.is_null(), "{status}");
            let mut p = [0u8; 12];
            assert_eq!(sv2_sri_standard_channel_extranonce_prefix(ch, p.as_mut_ptr(), 12), 12);
            assert_eq!(&p[..2], &[0xaa, 0xbb]);
            assert_eq!(sv2_sri_standard_channel_set_target(ch, easy.as_ptr()), SV2_SRI_OK);

            let (mut job_id, mut root) = (0, [0u8; 32]);
            assert_eq!(
                sv2_sri_standard_channel_prebuilt_job(ch, &job(&prefix, &suffix), &mut job_id, root.as_mut_ptr()),
                SV2_SRI_OK
            );
            assert_ne!(root, [0u8; 32]);
            assert_eq!(
                sv2_sri_standard_channel_activate_job(ch, job_id, [0u8; 32].as_ptr(), 0x1d00ffff, 1_700_000_000),
                SV2_SRI_OK
            );
            let share = Sv2SriSubmitSharesStandard {
                channel_id: 9,
                sequence_number: 1,
                job_id,
                nonce: 1,
                ntime: 1_700_000_000,
                version: 0x20000000,
            };
            let mut hash = [0u8; 32];
            assert_eq!(validate_std(ch, &share, &mut hash), SV2_SRI_SHARE_VALID);
            let mut t = [0u8; 32];
            assert_eq!(
                sv2_sri_standard_channel_job_target(ch, job_id, t.as_mut_ptr()),
                SV2_SRI_OK
            );
            assert_eq!(t, easy);
            assert_eq!(
                sv2_sri_standard_channel_job_target(ch, job_id + 1, t.as_mut_ptr()),
                SV2_SRI_ERR_CH_JOB_ID
            );

            // a job active at once has its merkle root too
            let (mut second, mut second_root) = (0, [0u8; 32]);
            assert_eq!(
                sv2_sri_standard_channel_prebuilt_job(
                    ch,
                    &active(&prefix, &suffix, 1_700_000_000),
                    &mut second,
                    second_root.as_mut_ptr()
                ),
                SV2_SRI_OK
            );
            assert_ne!(second, job_id);
            assert_ne!(second_root, [0u8; 32]);

            // a zero max_target is refused at open
            let mut status = 0;
            assert!(sv2_sri_standard_channel_new(a, &open(10, &[0u8; 32]), &mut status).is_null());
            assert_eq!(status, SV2_SRI_ERR_CH_MAX_TARGET);
            assert_eq!(
                sv2_sri_channel_error_code(status).as_slice().unwrap(),
                b"max-target-out-of-range"
            );

            sv2_sri_standard_channel_free(ch);
            sv2_sri_extranonce_allocator_free(a);
        }
    }

    #[test]
    fn a_block_hands_back_its_coinbase() {
        let easy = [0xffu8; 32];
        let (prefix, suffix) = coinbase();
        unsafe {
            let a = sv2_sri_extranonce_allocator_new([0xaa, 0xbb].as_ptr(), 2, 12, 65535);
            let mut status = 99;
            let ch = sv2_sri_extended_channel_new(a, &open(7, &easy), &mut status);
            assert!(!ch.is_null(), "{status}");
            let mut channel_prefix = [0u8; 12];
            let n = sv2_sri_extended_channel_extranonce_prefix(ch, channel_prefix.as_mut_ptr(), 12) as usize;
            assert_eq!(sv2_sri_extended_channel_set_target(ch, easy.as_ptr()), SV2_SRI_OK);
            let mut job_id = 0;
            assert_eq!(
                sv2_sri_extended_channel_prebuilt_job(ch, &job(&prefix, &suffix), &mut job_id),
                SV2_SRI_OK
            );
            // regtest's network target takes about half of all hashes
            assert_eq!(
                sv2_sri_extended_channel_activate_job(ch, job_id, [0u8; 32].as_ptr(), 0x207fffff, 1_700_000_000),
                SV2_SRI_OK
            );

            let extranonce = [1u8, 2, 3, 4, 5, 6, 7, 8];
            let mut expected = prefix.clone();
            expected.extend_from_slice(&channel_prefix[..n]);
            expected.extend_from_slice(&extranonce);
            expected.extend_from_slice(&suffix);

            let mut hash = [0u8; 32];
            let (mut valid, mut blocks) = (0, 0);
            for nonce in 0..64 {
                let share = Sv2SriSubmitSharesExtended {
                    channel_id: 7,
                    sequence_number: nonce,
                    job_id,
                    nonce,
                    ntime: 1_700_000_001,
                    version: 0x20000000,
                    extranonce: Sv2SriBytes::from_slice(&extranonce),
                };
                let mut out = [0xeeu8; 256];
                let mut len = 99u32;
                // the first block gets a buffer that fits, the next one a short one
                let cap = if blocks == 0 { out.len() as u32 } else { 8 };
                let s = sv2_sri_extended_channel_validate_share(
                    ch,
                    &share,
                    hash.as_mut_ptr(),
                    out.as_mut_ptr(),
                    cap,
                    &mut len,
                );
                match s {
                    SV2_SRI_SHARE_VALID => {
                        assert_eq!(len, 0);
                        assert!(out.iter().all(|&b| b == 0xee));
                        valid += 1;
                    }
                    SV2_SRI_SHARE_BLOCK => {
                        assert_eq!(len as usize, expected.len());
                        if blocks == 0 {
                            assert_eq!(&out[..expected.len()], &expected[..]);
                        } else {
                            // a coinbase that does not fit is not written
                            assert!(out.iter().all(|&b| b == 0xee));
                        }
                        blocks += 1;
                    }
                    s => panic!("unexpected status {s}"),
                }
                // NULL skips the coinbase
                let again = Sv2SriSubmitSharesExtended {
                    nonce: nonce + 1000,
                    sequence_number: nonce + 1000,
                    ..share
                };
                let s = validate_ext(ch, &again, &mut hash);
                assert!(s == SV2_SRI_SHARE_VALID || s == SV2_SRI_SHARE_BLOCK);
            }
            assert!(valid > 0 && blocks > 1, "{valid} valid, {blocks} blocks");

            sv2_sri_extended_channel_free(ch);
            sv2_sri_extranonce_allocator_free(a);
        }
    }

    #[test]
    fn an_extended_channel_can_refuse_version_rolling() {
        let easy = [0xffu8; 32];
        let (prefix, suffix) = coinbase();
        unsafe {
            let a = sv2_sri_extranonce_allocator_new([0xaa, 0xbb].as_ptr(), 2, 12, 65535);
            let mut status = 99;
            let o = Sv2SriChannelOpen {
                no_version_rolling: true,
                ..open(7, &easy)
            };
            let ch = sv2_sri_extended_channel_new(a, &o, &mut status);
            assert!(!ch.is_null(), "{status}");
            assert_eq!(sv2_sri_extended_channel_set_target(ch, easy.as_ptr()), SV2_SRI_OK);
            let mut job_id = 0;
            assert_eq!(
                sv2_sri_extended_channel_prebuilt_job(ch, &job(&prefix, &suffix), &mut job_id),
                SV2_SRI_OK
            );
            assert_eq!(
                sv2_sri_extended_channel_activate_job(ch, job_id, [0u8; 32].as_ptr(), 0x1d00ffff, 1_700_000_000),
                SV2_SRI_OK
            );

            let extranonce = [1u8, 2, 3, 4, 5, 6, 7, 8];
            let mut share = Sv2SriSubmitSharesExtended {
                channel_id: 7,
                sequence_number: 1,
                job_id,
                nonce: 42,
                ntime: 1_700_000_001,
                version: 0x20000000 | 0x2000, // a BIP 320 bit rolled
                extranonce: Sv2SriBytes::from_slice(&extranonce),
            };
            let mut hash = [0u8; 32];
            assert_eq!(validate_ext(ch, &share, &mut hash), SV2_SRI_ERR_SHARE_VERSION);
            assert_eq!(
                sv2_sri_channel_error_code(SV2_SRI_ERR_SHARE_VERSION)
                    .as_slice()
                    .unwrap(),
                b"version-rolling-not-allowed"
            );
            share.version = 0x20000000;
            assert_eq!(validate_ext(ch, &share, &mut hash), SV2_SRI_SHARE_VALID);

            sv2_sri_extended_channel_free(ch);
            sv2_sri_extranonce_allocator_free(a);
        }
    }

    #[test]
    fn each_job_keeps_the_target_it_was_sent_at() {
        let easy = [0xffu8; 32];
        let (prefix, suffix) = coinbase();
        let (t1, t2) = (target_top(0x7f), target_top(0x3f));
        unsafe {
            let a = sv2_sri_extranonce_allocator_new([0xaa, 0xbb].as_ptr(), 2, 12, 65535);
            let mut status = 99;
            let ch = sv2_sri_extended_channel_new(a, &open(7, &easy), &mut status);
            assert!(!ch.is_null(), "{status}");
            assert_eq!(sv2_sri_extended_channel_set_target(ch, t1.as_ptr()), SV2_SRI_OK);

            // a future job takes no shares, so it has no target until its
            // SetNewPrevHash
            let mut first = 0;
            assert_eq!(
                sv2_sri_extended_channel_prebuilt_job(ch, &job(&prefix, &suffix), &mut first),
                SV2_SRI_OK
            );
            assert_eq!(ext_job_target(ch, first), Err(SV2_SRI_ERR_CH_JOB_ID));
            assert_eq!(
                sv2_sri_extended_channel_activate_job(ch, first, [0u8; 32].as_ptr(), 0x1d00ffff, 1_700_000_000),
                SV2_SRI_OK
            );
            assert_eq!(ext_job_target(ch, first), Ok(t1));

            // a SetTarget is for the jobs that follow: the active job retires
            // to the past jobs with its own
            assert_eq!(sv2_sri_extended_channel_set_target(ch, t2.as_ptr()), SV2_SRI_OK);
            let mut second = 0;
            assert_eq!(
                sv2_sri_extended_channel_prebuilt_job(ch, &active(&prefix, &suffix, 1_700_000_010), &mut second),
                SV2_SRI_OK
            );
            assert_eq!(ext_job_target(ch, first), Ok(t1));
            assert_eq!(ext_job_target(ch, second), Ok(t2));
            assert_eq!(ext_job_target(ch, second + 1), Err(SV2_SRI_ERR_CH_JOB_ID));

            // a new tip leaves only the job activated under it
            let mut third = 0;
            assert_eq!(
                sv2_sri_extended_channel_prebuilt_job(ch, &job(&prefix, &suffix), &mut third),
                SV2_SRI_OK
            );
            assert_eq!(
                sv2_sri_extended_channel_activate_job(ch, third, [1u8; 32].as_ptr(), 0x1d00ffff, 1_700_000_600),
                SV2_SRI_OK
            );
            assert_eq!(ext_job_target(ch, first), Err(SV2_SRI_ERR_CH_JOB_ID));
            assert_eq!(ext_job_target(ch, second), Err(SV2_SRI_ERR_CH_JOB_ID));
            assert_eq!(ext_job_target(ch, third), Ok(t2));

            sv2_sri_extended_channel_free(ch);
            sv2_sri_extranonce_allocator_free(a);
        }
    }

    #[test]
    fn a_target_stays_at_or_below_max_target() {
        let (max, current, lower) = (target_top(0x7f), target_top(0x3f), target_top(0x0f));
        unsafe {
            let a = sv2_sri_extranonce_allocator_new([0xaa, 0xbb].as_ptr(), 2, 12, 65535);
            let mut status = 99;
            let ch = sv2_sri_extended_channel_new(a, &open(7, &max), &mut status);
            assert!(!ch.is_null(), "{status}");
            // a SetTarget never goes above max_target (spec 5.3.21)
            assert_eq!(
                sv2_sri_extended_channel_set_target(ch, [0xffu8; 32].as_ptr()),
                SV2_SRI_ERR_CH_TARGET
            );
            assert_eq!(sv2_sri_extended_channel_set_target(ch, current.as_ptr()), SV2_SRI_OK);

            // An UpdateChannel lowering max_target under the current target is
            // accepted (5.3.7); the old target cannot come back, the server's
            // SetTarget for the new max_target has to be at or below it
            let hashrate = 1.0e6;
            assert_eq!(
                sv2_sri_extended_channel_update(ch, hashrate, lower.as_ptr()),
                SV2_SRI_OK
            );
            assert_eq!(
                sv2_sri_extended_channel_set_target(ch, current.as_ptr()),
                SV2_SRI_ERR_CH_TARGET
            );
            assert_eq!(sv2_sri_extended_channel_set_target(ch, lower.as_ptr()), SV2_SRI_OK);
            sv2_sri_extended_channel_free(ch);

            // the same on a standard channel
            let ch = sv2_sri_standard_channel_new(a, &open(9, &max), &mut status);
            assert!(!ch.is_null(), "{status}");
            assert_eq!(sv2_sri_standard_channel_set_target(ch, current.as_ptr()), SV2_SRI_OK);
            assert_eq!(
                sv2_sri_standard_channel_update(ch, hashrate, lower.as_ptr()),
                SV2_SRI_OK
            );
            assert_eq!(
                sv2_sri_standard_channel_set_target(ch, current.as_ptr()),
                SV2_SRI_ERR_CH_TARGET
            );
            assert_eq!(sv2_sri_standard_channel_set_target(ch, lower.as_ptr()), SV2_SRI_OK);
            sv2_sri_standard_channel_free(ch);
            sv2_sri_extranonce_allocator_free(a);
        }
    }

    // What a decoded OpenMiningChannel or UpdateChannel can carry in
    // nominal_hash_rate: the crate refuses a rate that is negative or not
    // finite with a status, and a refused open gives its prefix back to the
    // allocator.
    #[test]
    fn a_hash_rate_that_is_not_one_is_refused() {
        let easy = [0xffu8; 32];
        let rates = [
            (f32::NAN, SV2_SRI_ERR_CH_NOMINAL_HASHRATE),
            (f32::INFINITY, SV2_SRI_ERR_CH_NOMINAL_HASHRATE),
            (f32::NEG_INFINITY, SV2_SRI_ERR_CH_NOMINAL_HASHRATE),
            (-1.0, SV2_SRI_ERR_CH_NOMINAL_HASHRATE),
            (-0.0, SV2_SRI_ERR_CH_NOMINAL_HASHRATE),
            (0.0, SV2_SRI_OK),
            (f32::MAX, SV2_SRI_OK),
        ];
        unsafe {
            // room for two channels: a prefix kept by a refused open would
            // run the allocator out below
            let a = sv2_sri_extranonce_allocator_new([0xaa, 0xbb].as_ptr(), 2, 12, 2);
            for (rate, expected) in rates {
                let o = Sv2SriChannelOpen {
                    nominal_hash_rate: rate,
                    ..open(7, &easy)
                };
                let mut status = 99;
                let ch = sv2_sri_extended_channel_new(a, &o, &mut status);
                assert_eq!(status, expected, "extended, {rate}");
                assert_eq!(ch.is_null(), expected != SV2_SRI_OK, "extended, {rate}");
                sv2_sri_extended_channel_free(ch);
                let mut status = 99;
                let ch = sv2_sri_standard_channel_new(a, &o, &mut status);
                assert_eq!(status, expected, "standard, {rate}");
                assert_eq!(ch.is_null(), expected != SV2_SRI_OK, "standard, {rate}");
                sv2_sri_standard_channel_free(ch);
            }
            let mut status = 99;
            let ext = sv2_sri_extended_channel_new(a, &open(7, &easy), &mut status);
            assert!(!ext.is_null(), "{status}");
            let std = sv2_sri_standard_channel_new(a, &open(9, &easy), &mut status);
            assert!(!std.is_null(), "{status}");
            for (rate, expected) in rates {
                assert_eq!(
                    sv2_sri_extended_channel_update(ext, rate, easy.as_ptr()),
                    expected,
                    "extended, {rate}"
                );
                assert_eq!(
                    sv2_sri_standard_channel_update(std, rate, easy.as_ptr()),
                    expected,
                    "standard, {rate}"
                );
            }
            sv2_sri_extended_channel_free(ext);
            sv2_sri_standard_channel_free(std);
            sv2_sri_extranonce_allocator_free(a);
        }
    }

    #[test]
    fn an_active_job_needs_the_tip_and_starts_no_earlier() {
        let easy = [0xffu8; 32];
        let (prefix, suffix) = coinbase();
        unsafe {
            let a = sv2_sri_extranonce_allocator_new([0xaa, 0xbb].as_ptr(), 2, 12, 65535);
            let mut status = 99;
            let ch = sv2_sri_extended_channel_new(a, &open(7, &easy), &mut status);
            assert!(!ch.is_null(), "{status}");
            let mut job_id = 0;
            assert_eq!(
                sv2_sri_extended_channel_prebuilt_job(ch, &active(&prefix, &suffix, 1_700_000_000), &mut job_id),
                SV2_SRI_ERR_CH_CHAIN_TIP
            );
            assert_eq!(
                sv2_sri_extended_channel_prebuilt_job(ch, &job(&prefix, &suffix), &mut job_id),
                SV2_SRI_OK
            );
            assert_eq!(
                sv2_sri_extended_channel_activate_job(ch, job_id, [0u8; 32].as_ptr(), 0x1d00ffff, 1_700_000_000),
                SV2_SRI_OK
            );
            let mut second = 0;
            assert_eq!(
                sv2_sri_extended_channel_prebuilt_job(ch, &active(&prefix, &suffix, 1_699_999_999), &mut second),
                SV2_SRI_ERR_CH_NTIME_START
            );
            assert_eq!(
                sv2_sri_extended_channel_prebuilt_job(ch, &active(&prefix, &suffix, 1_700_000_000), &mut second),
                SV2_SRI_OK
            );
            assert_eq!(second, job_id + 1);
            sv2_sri_extended_channel_free(ch);
            sv2_sri_extranonce_allocator_free(a);
        }
    }
}
