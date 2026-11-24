// sv2_sri_message_decode() on any header fields and payload, and, for
// what decodes, the encoder on the record it gave back: re-encoding must
// work, but for the two cases named below, and decode again.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sv2_sri::*;

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }
    let extension_type = u16::from_le_bytes([data[0], data[1]]);
    let msg_type = data[2];
    let mut payload = data[3..].to_vec();
    let mut m = core::mem::MaybeUninit::<Sv2SriMessage>::zeroed();
    let r = unsafe {
        sv2_sri_message_decode(
            extension_type,
            msg_type,
            payload.as_mut_ptr(),
            payload.len() as u32,
            m.as_mut_ptr(),
        )
    };
    assert_ne!(r, SV2_SRI_ERR_INTERNAL);
    if r != SV2_SRI_OK {
        return;
    }
    let mut frame = vec![0u8; SV2_SRI_FRAME_HEADER_SIZE + payload.len() + 64];
    let n = unsafe { sv2_sri_message_encode(m.as_ptr(), frame.as_mut_ptr(), frame.len() as u32) };
    assert_ne!(n, SV2_SRI_ERR_INTERNAL);
    // A decoded record re-encodes, with two exceptions: a SetupConnection
    // carrying a protocol the crates have no value for (decoded on purpose,
    // so a role can answer it with SetupConnection.Error), and a
    // nominal_hash_rate that is negative or not finite, which binary_sv2
    // decodes but does not serialize.
    if n < 0 {
        assert_eq!(n, SV2_SRI_ERR_INVALID);
        // SAFETY: the member read is the one msg_type names
        let rate = unsafe {
            let m = m.assume_init_ref();
            match msg_type {
                SV2_SRI_MSG_OPEN_STANDARD_MINING_CHANNEL => Some(m.u.open_standard_mining_channel.nominal_hash_rate),
                SV2_SRI_MSG_OPEN_EXTENDED_MINING_CHANNEL => Some(m.u.open_extended_mining_channel.nominal_hash_rate),
                SV2_SRI_MSG_UPDATE_CHANNEL => Some(m.u.update_channel.nominal_hash_rate),
                _ => None,
            }
        };
        match rate {
            Some(rate) => assert!(!rate.is_finite() || rate.is_sign_negative(), "{rate} does not encode"),
            None => assert_eq!(msg_type, SV2_SRI_MSG_SETUP_CONNECTION),
        }
        return;
    }
    frame.truncate(n as usize);
    let (ext, ty) = (u16::from_le_bytes([frame[0], frame[1]]), frame[2]);
    let mut again = core::mem::MaybeUninit::<Sv2SriMessage>::zeroed();
    let body = &mut frame[SV2_SRI_FRAME_HEADER_SIZE..];
    let r = unsafe { sv2_sri_message_decode(ext, ty, body.as_mut_ptr(), body.len() as u32, again.as_mut_ptr()) };
    assert_eq!(r, SV2_SRI_OK, "a frame the encoder wrote does not decode");
});
