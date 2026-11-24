// Frame headers through framing_sv2.

use framing_sv2::header::Header;

use crate::ffi::{guard, input, obj, obj_mut, output, ret};
use crate::{
    SV2_SRI_ERR_INTERNAL, SV2_SRI_ERR_INVALID, SV2_SRI_ERR_OVERFLOW, SV2_SRI_ERR_TRUNCATED, SV2_SRI_FRAME_HEADER_SIZE,
    SV2_SRI_OK,
};

/// Bit 15 of extension_type: the payload starts with a channel_id
pub const SV2_SRI_CHANNEL_MSG_BIT: u16 = 0x8000;

/// A decoded frame header.  `extension_type` keeps the channel_msg bit.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2SriFrameHeader {
    pub extension_type: u16,
    pub msg_type: u8,
    pub msg_length: u32,
}

/// Parse the first 6 bytes of `buf`.
///
/// # Safety
/// `buf` must point at `len` readable bytes and `out` at a writable header.
#[no_mangle]
pub unsafe extern "C" fn sv2_sri_frame_header_decode(buf: *const u8, len: u32, out: *mut Sv2SriFrameHeader) -> i32 {
    guard(SV2_SRI_ERR_INTERNAL, || {
        ret((|| {
            // SAFETY: forwarded to the caller
            let (buf, out) = unsafe { (input(buf, len as usize)?, obj_mut(out)?) };
            let h = Header::from_bytes(buf).map_err(|_| SV2_SRI_ERR_TRUNCATED)?;
            *out = Sv2SriFrameHeader {
                extension_type: h.ext_type(),
                msg_type: h.msg_type(),
                msg_length: h.payload_length() as u32,
            };
            Ok(SV2_SRI_OK)
        })())
    })
}

/// Write a header into `buf`.  Returns 6, or an error when `msg_length`
/// does not fit 24 bits or `cap` is too small.
///
/// # Safety
/// `h` must point at a header and `buf` at `cap` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn sv2_sri_frame_header_encode(h: *const Sv2SriFrameHeader, buf: *mut u8, cap: u32) -> i32 {
    guard(SV2_SRI_ERR_INTERNAL, || {
        ret((|| {
            // SAFETY: forwarded to the caller
            let (h, buf) = unsafe { (obj(h)?, output(buf, cap as usize)?) };
            if buf.len() < SV2_SRI_FRAME_HEADER_SIZE {
                return Err(SV2_SRI_ERR_OVERFLOW);
            }
            if h.msg_length > 0x00FF_FFFF {
                return Err(SV2_SRI_ERR_INVALID);
            }
            // framing_sv2 builds headers from a message or from bytes; go
            // through the bytes so the crate still does the writing.
            let l = h.msg_length.to_le_bytes();
            let e = h.extension_type.to_le_bytes();
            let raw = [e[0], e[1], h.msg_type, l[0], l[1], l[2]];
            let header = Header::from_bytes(&raw).map_err(|_| SV2_SRI_ERR_INVALID)?;
            header.write_into(buf).map_err(|_| SV2_SRI_ERR_OVERFLOW)?;
            Ok(SV2_SRI_FRAME_HEADER_SIZE as i32)
        })())
    })
}

/// Whether a base protocol message type travels with the channel_msg bit
/// set, according to the subprotocol crates.  Unknown types return false.
#[no_mangle]
pub extern "C" fn sv2_sri_msg_has_channel_bit(msg_type: u8) -> bool {
    guard(false, || {
        use common_messages_sv2 as c;
        use mining_sv2 as m;
        match msg_type {
            c::MESSAGE_TYPE_SETUP_CONNECTION => c::CHANNEL_BIT_SETUP_CONNECTION,
            c::MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS => c::CHANNEL_BIT_SETUP_CONNECTION_SUCCESS,
            c::MESSAGE_TYPE_SETUP_CONNECTION_ERROR => c::CHANNEL_BIT_SETUP_CONNECTION_ERROR,
            c::MESSAGE_TYPE_CHANNEL_ENDPOINT_CHANGED => c::CHANNEL_BIT_CHANNEL_ENDPOINT_CHANGED,
            c::MESSAGE_TYPE_RECONNECT => c::CHANNEL_BIT_RECONNECT,
            m::MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL => m::CHANNEL_BIT_OPEN_STANDARD_MINING_CHANNEL,
            m::MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS => m::CHANNEL_BIT_OPEN_STANDARD_MINING_CHANNEL_SUCCESS,
            m::MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR => m::CHANNEL_BIT_OPEN_MINING_CHANNEL_ERROR,
            m::MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL => m::CHANNEL_BIT_OPEN_EXTENDED_MINING_CHANNEL,
            m::MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS => m::CHANNEL_BIT_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS,
            m::MESSAGE_TYPE_NEW_MINING_JOB => m::CHANNEL_BIT_NEW_MINING_JOB,
            m::MESSAGE_TYPE_UPDATE_CHANNEL => m::CHANNEL_BIT_UPDATE_CHANNEL,
            m::MESSAGE_TYPE_UPDATE_CHANNEL_ERROR => m::CHANNEL_BIT_UPDATE_CHANNEL_ERROR,
            m::MESSAGE_TYPE_CLOSE_CHANNEL => m::CHANNEL_BIT_CLOSE_CHANNEL,
            m::MESSAGE_TYPE_SET_EXTRANONCE_PREFIX => m::CHANNEL_BIT_SET_EXTRANONCE_PREFIX,
            m::MESSAGE_TYPE_SUBMIT_SHARES_STANDARD => m::CHANNEL_BIT_SUBMIT_SHARES_STANDARD,
            m::MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED => m::CHANNEL_BIT_SUBMIT_SHARES_EXTENDED,
            m::MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS => m::CHANNEL_BIT_SUBMIT_SHARES_SUCCESS,
            m::MESSAGE_TYPE_SUBMIT_SHARES_ERROR => m::CHANNEL_BIT_SUBMIT_SHARES_ERROR,
            m::MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB => m::CHANNEL_BIT_NEW_EXTENDED_MINING_JOB,
            m::MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH => m::CHANNEL_BIT_MINING_SET_NEW_PREV_HASH,
            m::MESSAGE_TYPE_SET_TARGET => m::CHANNEL_BIT_SET_TARGET,
            m::MESSAGE_TYPE_SET_CUSTOM_MINING_JOB => m::CHANNEL_BIT_SET_CUSTOM_MINING_JOB,
            m::MESSAGE_TYPE_SET_CUSTOM_MINING_JOB_SUCCESS => m::CHANNEL_BIT_SET_CUSTOM_MINING_JOB_SUCCESS,
            m::MESSAGE_TYPE_SET_CUSTOM_MINING_JOB_ERROR => m::CHANNEL_BIT_SET_CUSTOM_MINING_JOB_ERROR,
            m::MESSAGE_TYPE_SET_GROUP_CHANNEL => m::CHANNEL_BIT_SET_GROUP_CHANNEL,
            _ => false,
        }
    })
}
