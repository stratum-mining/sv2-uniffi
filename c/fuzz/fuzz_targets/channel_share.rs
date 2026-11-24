// A server's extended and standard channels driven by the input: targets,
// UpdateChannel, jobs (future or active, with any coinbase split and merkle
// path), SetNewPrevHash, and shares with any job id, nonce, ntime, version
// and extranonce.  Whatever the crate decides, it must not panic, and a
// share it accepts must be on a job it holds a target for.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sv2_sri::*;

struct Input<'a>(&'a [u8]);

impl Input<'_> {
    fn byte(&mut self) -> Option<u8> {
        let (&b, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(b)
    }

    fn u32(&mut self) -> Option<u32> {
        let b: [u8; 4] = self.0.get(..4)?.try_into().ok()?;
        self.0 = &self.0[4..];
        Some(u32::from_le_bytes(b))
    }

    fn bytes(&mut self, n: usize) -> &[u8] {
        let n = n.min(self.0.len());
        let (b, rest) = self.0.split_at(n);
        self.0 = rest;
        b
    }

    fn target(&mut self) -> [u8; 32] {
        // most significant byte from the input, the rest all ones, so the
        // targets stay in a range where shares can pass
        let mut t = [0xffu8; 32];
        t[31] = self.byte().unwrap_or(0xff);
        t[30] = self.byte().unwrap_or(0xff);
        t
    }
}

// A coinbase around a 12 byte extranonce slot (the crate's own test one)
fn coinbase() -> (Vec<u8>, Vec<u8>) {
    let mut prefix = vec![1, 0, 0, 0, 1];
    prefix.extend_from_slice(&[0; 32]);
    prefix.extend_from_slice(&[0xff; 4]);
    prefix.push(16);
    prefix.extend_from_slice(&[3, 0x10, 0x20, 0x30]);
    let mut suffix = vec![0xff; 4];
    suffix.push(1);
    suffix.extend_from_slice(&[0; 8]);
    suffix.extend_from_slice(&[1, 0x51]);
    suffix.extend_from_slice(&[0; 4]);
    (prefix, suffix)
}

fuzz_target!(|data: &[u8]| {
    let mut inp = Input(data);
    let Some(flags) = inp.byte() else {
        return;
    };
    let extended = flags & 1 == 1;
    let max_target = inp.target();
    let (good_prefix, good_suffix) = coinbase();
    unsafe {
        let a = sv2_sri_extranonce_allocator_new([0xaa, 0xbb].as_ptr(), 2, 12, 64);
        assert!(!a.is_null());
        let open = Sv2SriChannelOpen {
            channel_id: 1,
            user_identity: Sv2SriBytes {
                data: b"w".as_ptr(),
                len: 1,
            },
            nominal_hash_rate: 1.0e6,
            max_target: max_target.as_ptr(),
            min_extranonce_size: 8,
            share_batch_size: 1 + (flags as u32 >> 4),
            expected_shares_per_minute: 6.0,
            max_past_jobs: (flags as u32 >> 1) & 7,
            no_version_rolling: flags & 0x08 != 0,
        };
        let mut status = 0;
        let (ext, std) = if extended {
            (
                sv2_sri_extended_channel_new(a, &open, &mut status),
                core::ptr::null_mut(),
            )
        } else {
            (
                core::ptr::null_mut(),
                sv2_sri_standard_channel_new(a, &open, &mut status),
            )
        };
        assert_ne!(status, SV2_SRI_ERR_INTERNAL);
        if ext.is_null() && std.is_null() {
            sv2_sri_extranonce_allocator_free(a);
            return;
        }
        let mut job_ids = Vec::new();
        let mut hash = [0u8; 32];
        while let Some(op) = inp.byte() {
            let r = match op % 6 {
                0 => {
                    let t = inp.target();
                    if extended {
                        sv2_sri_extended_channel_set_target(ext, t.as_ptr())
                    } else {
                        sv2_sri_standard_channel_set_target(std, t.as_ptr())
                    }
                }
                1 => {
                    let t = inp.target();
                    let rate = inp.u32().map(f32::from_bits).unwrap_or(1.0);
                    if extended {
                        sv2_sri_extended_channel_update(ext, rate, t.as_ptr())
                    } else {
                        sv2_sri_standard_channel_update(std, rate, t.as_ptr())
                    }
                }
                2 => {
                    // a job: the good coinbase most of the time, or input bytes
                    let kind = inp.byte().unwrap_or(0);
                    let (prefix, suffix) = if kind & 0x0f == 0 {
                        let p = inp.bytes(kind as usize >> 4 << 2).to_vec();
                        let s = inp.bytes(16).to_vec();
                        (p, s)
                    } else {
                        (good_prefix.clone(), good_suffix.clone())
                    };
                    let path = inp.bytes((kind as usize >> 5) * 32).to_vec();
                    let job = Sv2SriPrebuiltJob {
                        has_ntime_start: kind & 0x10 != 0,
                        ntime_start: inp.u32().unwrap_or(1_700_000_000),
                        version: inp.u32().unwrap_or(0x2000_0000),
                        coinbase_tx_prefix: Sv2SriBytes {
                            data: prefix.as_ptr(),
                            len: prefix.len() as u32,
                        },
                        coinbase_tx_suffix: Sv2SriBytes {
                            data: suffix.as_ptr(),
                            len: suffix.len() as u32,
                        },
                        merkle_path: Sv2SriBytes {
                            data: path.as_ptr(),
                            len: path.len() as u32,
                        },
                    };
                    let mut id = 0;
                    let mut root = [0u8; 32];
                    let r = if extended {
                        sv2_sri_extended_channel_prebuilt_job(ext, &job, &mut id)
                    } else {
                        sv2_sri_standard_channel_prebuilt_job(std, &job, &mut id, root.as_mut_ptr())
                    };
                    if r == SV2_SRI_OK {
                        job_ids.push(id);
                    }
                    r
                }
                3 => {
                    let id = pick(&mut inp, &job_ids);
                    let prev = inp.bytes(32).to_vec();
                    let mut prev_hash = [0u8; 32];
                    prev_hash[..prev.len()].copy_from_slice(&prev);
                    let nbits = inp.u32().unwrap_or(0x1d00ffff);
                    let ntime = inp.u32().unwrap_or(1_700_000_000);
                    if extended {
                        sv2_sri_extended_channel_activate_job(ext, id, prev_hash.as_ptr(), nbits, ntime)
                    } else {
                        sv2_sri_standard_channel_activate_job(std, id, prev_hash.as_ptr(), nbits, ntime)
                    }
                }
                4 => {
                    let id = pick(&mut inp, &job_ids);
                    let nonce = inp.u32().unwrap_or(0);
                    let ntime = inp.u32().unwrap_or(1_700_000_001);
                    let version = inp.u32().unwrap_or(0x2000_0000);
                    let n = inp.byte().unwrap_or(8) as usize % 34;
                    let en = inp.bytes(n).to_vec();
                    let (mut cb, mut cb_len) = ([0u8; 512], 0u32);
                    let r = if extended {
                        let share = Sv2SriSubmitSharesExtended {
                            channel_id: 1,
                            sequence_number: 1,
                            job_id: id,
                            nonce,
                            ntime,
                            version,
                            extranonce: Sv2SriBytes {
                                data: en.as_ptr(),
                                len: en.len() as u32,
                            },
                        };
                        sv2_sri_extended_channel_validate_share(
                            ext,
                            &share,
                            hash.as_mut_ptr(),
                            cb.as_mut_ptr(),
                            512,
                            &mut cb_len,
                        )
                    } else {
                        let share = Sv2SriSubmitSharesStandard {
                            channel_id: 1,
                            sequence_number: 1,
                            job_id: id,
                            nonce,
                            ntime,
                            version,
                        };
                        sv2_sri_standard_channel_validate_share(
                            std,
                            &share,
                            hash.as_mut_ptr(),
                            cb.as_mut_ptr(),
                            512,
                            &mut cb_len,
                        )
                    };
                    if r == SV2_SRI_SHARE_VALID || r == SV2_SRI_SHARE_BLOCK {
                        let mut t = [0u8; 32];
                        let jt = if extended {
                            sv2_sri_extended_channel_job_target(ext, id, t.as_mut_ptr())
                        } else {
                            sv2_sri_standard_channel_job_target(std, id, t.as_mut_ptr())
                        };
                        assert_eq!(jt, SV2_SRI_OK, "an accepted share on a job with no target");
                    }
                    r
                }
                _ => {
                    let mut t = [0u8; 32];
                    let id = pick(&mut inp, &job_ids);
                    if extended {
                        sv2_sri_extended_channel_job_target(ext, id, t.as_mut_ptr())
                    } else {
                        sv2_sri_standard_channel_job_target(std, id, t.as_mut_ptr())
                    }
                }
            };
            assert_ne!(r, SV2_SRI_ERR_INTERNAL, "op {}", op % 6);
        }
        sv2_sri_extended_channel_free(ext);
        sv2_sri_standard_channel_free(std);
        sv2_sri_extranonce_allocator_free(a);
    }
});

// A job id the channel gave out, or now and then any id
fn pick(inp: &mut Input, ids: &[u32]) -> u32 {
    let b = inp.byte().unwrap_or(0);
    if ids.is_empty() || b == 0xff {
        return inp.u32().unwrap_or(1);
    }
    ids[b as usize % ids.len()]
}
