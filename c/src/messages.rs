// The common and mining messages as C records, dispatched by parsers_sv2.
//
// `sv2_sri_message_decode()` turns the payload of a frame into a
// `Sv2SriMessage`: parsers_sv2 decides from the frame header which message
// it is, whether it belongs to an extension, and what the bytes after the
// message are (TLV fields, or garbage).  `sv2_sri_message_encode()` is the
// other direction, with the message type and the channel_msg bit coming
// from the same crate.  What is here is the records and the field-by-field
// conversions between them and the crates' structs, which is what a binding
// is for.

use binary_sv2::{GetSize, Seq0255, Seq064K, Str0255, Sv2Option, B032, B064K, U256};
use codec_sv2::EncodableFrame;
use common_messages_sv2::{
    ChannelEndpointChanged, Protocol, Reconnect, SetupConnection, SetupConnectionError, SetupConnectionSuccess,
};
use framing_sv2::{framing::MessageFrame, header::Header};
use mining_sv2::{
    CloseChannel, NewExtendedMiningJob, NewMiningJob, OpenExtendedMiningChannel, OpenExtendedMiningChannelSuccess,
    OpenMiningChannelError, OpenStandardMiningChannel, OpenStandardMiningChannelSuccess, SetExtranoncePrefix,
    SetGroupChannel, SetNewPrevHash, SetTarget, SubmitSharesError, SubmitSharesExtended, SubmitSharesStandard,
    SubmitSharesSuccess, UpdateChannel, UpdateChannelError,
};
use parsers_sv2::{AnyMessage, CommonMessages, IsSv2Message, Mining, ParserError, TlvList};

use crate::ffi::{binary_err, guard, input, obj, obj_mut, output, ret, Sv2SriBytes};
use crate::{
    SV2_SRI_ERR_INTERNAL, SV2_SRI_ERR_INVALID, SV2_SRI_ERR_OVERFLOW, SV2_SRI_ERR_TRAILING, SV2_SRI_ERR_UNSUPPORTED,
    SV2_SRI_FRAME_HEADER_SIZE, SV2_SRI_OK,
};

/////////////////////////////////
// Message types
/////////////////////////////////

// The values the subprotocol crates assign; `Sv2SriMessage::msg_type` holds
// one of these.  cbindgen only sees literals, so they are checked against
// the crates below.

/// SetupConnection
pub const SV2_SRI_MSG_SETUP_CONNECTION: u8 = 0x00;
/// SetupConnection.Success
pub const SV2_SRI_MSG_SETUP_CONNECTION_SUCCESS: u8 = 0x01;
/// SetupConnection.Error
pub const SV2_SRI_MSG_SETUP_CONNECTION_ERROR: u8 = 0x02;
/// ChannelEndpointChanged
pub const SV2_SRI_MSG_CHANNEL_ENDPOINT_CHANGED: u8 = 0x03;
/// Reconnect
pub const SV2_SRI_MSG_RECONNECT: u8 = 0x04;
/// OpenStandardMiningChannel
pub const SV2_SRI_MSG_OPEN_STANDARD_MINING_CHANNEL: u8 = 0x10;
/// OpenStandardMiningChannel.Success
pub const SV2_SRI_MSG_OPEN_STANDARD_MINING_CHANNEL_SUCCESS: u8 = 0x11;
/// OpenMiningChannel.Error
pub const SV2_SRI_MSG_OPEN_MINING_CHANNEL_ERROR: u8 = 0x12;
/// OpenExtendedMiningChannel
pub const SV2_SRI_MSG_OPEN_EXTENDED_MINING_CHANNEL: u8 = 0x13;
/// OpenExtendedMiningChannel.Success
pub const SV2_SRI_MSG_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS: u8 = 0x14;
/// NewMiningJob
pub const SV2_SRI_MSG_NEW_MINING_JOB: u8 = 0x15;
/// UpdateChannel
pub const SV2_SRI_MSG_UPDATE_CHANNEL: u8 = 0x16;
/// UpdateChannel.Error
pub const SV2_SRI_MSG_UPDATE_CHANNEL_ERROR: u8 = 0x17;
/// CloseChannel
pub const SV2_SRI_MSG_CLOSE_CHANNEL: u8 = 0x18;
/// SetExtranoncePrefix
pub const SV2_SRI_MSG_SET_EXTRANONCE_PREFIX: u8 = 0x19;
/// SubmitSharesStandard
pub const SV2_SRI_MSG_SUBMIT_SHARES_STANDARD: u8 = 0x1a;
/// SubmitSharesExtended
pub const SV2_SRI_MSG_SUBMIT_SHARES_EXTENDED: u8 = 0x1b;
/// SubmitShares.Success
pub const SV2_SRI_MSG_SUBMIT_SHARES_SUCCESS: u8 = 0x1c;
/// SubmitShares.Error
pub const SV2_SRI_MSG_SUBMIT_SHARES_ERROR: u8 = 0x1d;
/// NewExtendedMiningJob
pub const SV2_SRI_MSG_NEW_EXTENDED_MINING_JOB: u8 = 0x1f;
/// SetNewPrevHash (mining protocol)
pub const SV2_SRI_MSG_SET_NEW_PREV_HASH: u8 = 0x20;
/// SetTarget
pub const SV2_SRI_MSG_SET_TARGET: u8 = 0x21;
/// SetGroupChannel
pub const SV2_SRI_MSG_SET_GROUP_CHANNEL: u8 = 0x25;

const _: () = {
    use common_messages_sv2 as c;
    use mining_sv2 as m;
    assert!(SV2_SRI_MSG_SETUP_CONNECTION == c::MESSAGE_TYPE_SETUP_CONNECTION);
    assert!(SV2_SRI_MSG_SETUP_CONNECTION_SUCCESS == c::MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS);
    assert!(SV2_SRI_MSG_SETUP_CONNECTION_ERROR == c::MESSAGE_TYPE_SETUP_CONNECTION_ERROR);
    assert!(SV2_SRI_MSG_CHANNEL_ENDPOINT_CHANGED == c::MESSAGE_TYPE_CHANNEL_ENDPOINT_CHANGED);
    assert!(SV2_SRI_MSG_RECONNECT == c::MESSAGE_TYPE_RECONNECT);
    assert!(SV2_SRI_MSG_OPEN_STANDARD_MINING_CHANNEL == m::MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL);
    assert!(SV2_SRI_MSG_OPEN_STANDARD_MINING_CHANNEL_SUCCESS == m::MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS);
    assert!(SV2_SRI_MSG_OPEN_MINING_CHANNEL_ERROR == m::MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR);
    assert!(SV2_SRI_MSG_OPEN_EXTENDED_MINING_CHANNEL == m::MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL);
    assert!(SV2_SRI_MSG_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS == m::MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS);
    assert!(SV2_SRI_MSG_NEW_MINING_JOB == m::MESSAGE_TYPE_NEW_MINING_JOB);
    assert!(SV2_SRI_MSG_UPDATE_CHANNEL == m::MESSAGE_TYPE_UPDATE_CHANNEL);
    assert!(SV2_SRI_MSG_UPDATE_CHANNEL_ERROR == m::MESSAGE_TYPE_UPDATE_CHANNEL_ERROR);
    assert!(SV2_SRI_MSG_CLOSE_CHANNEL == m::MESSAGE_TYPE_CLOSE_CHANNEL);
    assert!(SV2_SRI_MSG_SET_EXTRANONCE_PREFIX == m::MESSAGE_TYPE_SET_EXTRANONCE_PREFIX);
    assert!(SV2_SRI_MSG_SUBMIT_SHARES_STANDARD == m::MESSAGE_TYPE_SUBMIT_SHARES_STANDARD);
    assert!(SV2_SRI_MSG_SUBMIT_SHARES_EXTENDED == m::MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED);
    assert!(SV2_SRI_MSG_SUBMIT_SHARES_SUCCESS == m::MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS);
    assert!(SV2_SRI_MSG_SUBMIT_SHARES_ERROR == m::MESSAGE_TYPE_SUBMIT_SHARES_ERROR);
    assert!(SV2_SRI_MSG_NEW_EXTENDED_MINING_JOB == m::MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB);
    assert!(SV2_SRI_MSG_SET_NEW_PREV_HASH == m::MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH);
    assert!(SV2_SRI_MSG_SET_TARGET == m::MESSAGE_TYPE_SET_TARGET);
    assert!(SV2_SRI_MSG_SET_GROUP_CHANNEL == m::MESSAGE_TYPE_SET_GROUP_CHANNEL);
};

/////////////////////////////////
// Records
/////////////////////////////////

/// SetupConnection (0x00)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2SriSetupConnection {
    pub protocol: u8,
    pub min_version: u16,
    pub max_version: u16,
    pub flags: u32,
    pub endpoint_host: Sv2SriBytes,
    pub endpoint_port: u16,
    pub vendor: Sv2SriBytes,
    pub hardware_version: Sv2SriBytes,
    pub firmware: Sv2SriBytes,
    pub device_id: Sv2SriBytes,
}

/// SetupConnection.Success (0x01)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2SriSetupConnectionSuccess {
    pub used_version: u16,
    pub flags: u32,
}

/// SetupConnection.Error (0x02)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2SriSetupConnectionError {
    pub flags: u32,
    pub error_code: Sv2SriBytes,
}

/// ChannelEndpointChanged (0x03)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2SriChannelEndpointChanged {
    pub channel_id: u32,
}

/// Reconnect (0x04)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2SriReconnect {
    pub new_host: Sv2SriBytes,
    pub new_port: u16,
}

/// OpenStandardMiningChannel (0x10)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2SriOpenStandardMiningChannel {
    pub request_id: u32,
    pub user_identity: Sv2SriBytes,
    pub nominal_hash_rate: f32,
    pub max_target: [u8; 32],
}

/// OpenStandardMiningChannel.Success (0x11)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2SriOpenStandardMiningChannelSuccess {
    pub request_id: u32,
    pub channel_id: u32,
    pub target: [u8; 32],
    pub extranonce_prefix: Sv2SriBytes,
    pub group_channel_id: u32,
}

/// OpenMiningChannel.Error (0x12)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2SriOpenMiningChannelError {
    pub request_id: u32,
    pub error_code: Sv2SriBytes,
}

/// OpenExtendedMiningChannel (0x13)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2SriOpenExtendedMiningChannel {
    pub request_id: u32,
    pub user_identity: Sv2SriBytes,
    pub nominal_hash_rate: f32,
    pub max_target: [u8; 32],
    pub min_extranonce_size: u16,
}

/// OpenExtendedMiningChannel.Success (0x14)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2SriOpenExtendedMiningChannelSuccess {
    pub request_id: u32,
    pub channel_id: u32,
    pub target: [u8; 32],
    pub extranonce_size: u16,
    pub extranonce_prefix: Sv2SriBytes,
    pub group_channel_id: u32,
}

/// UpdateChannel (0x16)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2SriUpdateChannel {
    pub channel_id: u32,
    pub nominal_hash_rate: f32,
    pub maximum_target: [u8; 32],
}

/// UpdateChannel.Error (0x17)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2SriUpdateChannelError {
    pub channel_id: u32,
    pub error_code: Sv2SriBytes,
}

/// CloseChannel (0x18)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2SriCloseChannel {
    pub channel_id: u32,
    pub reason_code: Sv2SriBytes,
}

/// SetExtranoncePrefix (0x19)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2SriSetExtranoncePrefix {
    pub channel_id: u32,
    pub extranonce_prefix: Sv2SriBytes,
}

/// SetTarget (0x21)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2SriSetTarget {
    pub channel_id: u32,
    pub maximum_target: [u8; 32],
}

/// SetGroupChannel (0x25).  `channel_ids` is `channel_ids_count` little
/// endian u32 values.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2SriSetGroupChannel {
    pub group_channel_id: u32,
    pub channel_ids_count: u16,
    pub channel_ids: Sv2SriBytes,
}

/// NewMiningJob (0x15).  `has_min_ntime` false is a future job.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2SriNewMiningJob {
    pub channel_id: u32,
    pub job_id: u32,
    pub has_min_ntime: bool,
    pub min_ntime: u32,
    pub version: u32,
    pub merkle_root: [u8; 32],
}

/// NewExtendedMiningJob (0x1f).  `merkle_path` is `merkle_path_count`
/// 32 byte hashes back to back.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2SriNewExtendedMiningJob {
    pub channel_id: u32,
    pub job_id: u32,
    pub has_min_ntime: bool,
    pub min_ntime: u32,
    pub version: u32,
    pub version_rolling_allowed: bool,
    pub merkle_path_count: u8,
    pub merkle_path: Sv2SriBytes,
    pub coinbase_tx_prefix: Sv2SriBytes,
    pub coinbase_tx_suffix: Sv2SriBytes,
}

/// SetNewPrevHash (0x20)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2SriSetNewPrevHash {
    pub channel_id: u32,
    pub job_id: u32,
    pub prev_hash: [u8; 32],
    pub min_ntime: u32,
    pub nbits: u32,
}

/// SubmitSharesStandard (0x1a)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2SriSubmitSharesStandard {
    pub channel_id: u32,
    pub sequence_number: u32,
    pub job_id: u32,
    pub nonce: u32,
    pub ntime: u32,
    pub version: u32,
}

/// SubmitSharesExtended (0x1b)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2SriSubmitSharesExtended {
    pub channel_id: u32,
    pub sequence_number: u32,
    pub job_id: u32,
    pub nonce: u32,
    pub ntime: u32,
    pub version: u32,
    pub extranonce: Sv2SriBytes,
}

/// SubmitShares.Success (0x1c)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2SriSubmitSharesSuccess {
    pub channel_id: u32,
    pub last_sequence_number: u32,
    pub new_submits_accepted_count: u32,
    pub new_shares_sum: u64,
}

/// SubmitShares.Error (0x1d)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2SriSubmitSharesError {
    pub channel_id: u32,
    pub sequence_number: u32,
    pub error_code: Sv2SriBytes,
}

/// The record of one message; `Sv2SriMessage::msg_type` says which member
/// is live.
#[repr(C)]
#[derive(Clone, Copy)]
pub union Sv2SriMessageUnion {
    pub setup_connection: Sv2SriSetupConnection,
    pub setup_connection_success: Sv2SriSetupConnectionSuccess,
    pub setup_connection_error: Sv2SriSetupConnectionError,
    pub channel_endpoint_changed: Sv2SriChannelEndpointChanged,
    pub reconnect: Sv2SriReconnect,
    pub open_standard_mining_channel: Sv2SriOpenStandardMiningChannel,
    pub open_standard_mining_channel_success: Sv2SriOpenStandardMiningChannelSuccess,
    pub open_mining_channel_error: Sv2SriOpenMiningChannelError,
    pub open_extended_mining_channel: Sv2SriOpenExtendedMiningChannel,
    pub open_extended_mining_channel_success: Sv2SriOpenExtendedMiningChannelSuccess,
    pub update_channel: Sv2SriUpdateChannel,
    pub update_channel_error: Sv2SriUpdateChannelError,
    pub close_channel: Sv2SriCloseChannel,
    pub set_extranonce_prefix: Sv2SriSetExtranoncePrefix,
    pub set_target: Sv2SriSetTarget,
    pub set_group_channel: Sv2SriSetGroupChannel,
    pub new_mining_job: Sv2SriNewMiningJob,
    pub new_extended_mining_job: Sv2SriNewExtendedMiningJob,
    pub set_new_prev_hash: Sv2SriSetNewPrevHash,
    pub submit_shares_standard: Sv2SriSubmitSharesStandard,
    pub submit_shares_extended: Sv2SriSubmitSharesExtended,
    pub submit_shares_success: Sv2SriSubmitSharesSuccess,
    pub submit_shares_error: Sv2SriSubmitSharesError,
}

/// One decoded message, or one to encode: the message type (one of the
/// `SV2_SRI_MSG_*` values) and its record.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2SriMessage {
    pub msg_type: u8,
    pub u: Sv2SriMessageUnion,
}

/////////////////////////////////
// Conversions
/////////////////////////////////

/// # Safety
/// `b` must describe readable memory that outlives `'a`.
unsafe fn str0255<'a>(b: &Sv2SriBytes) -> Result<Str0255<'a>, i32> {
    // SAFETY: forwarded to the caller
    let s: &'a [u8] = unsafe { b.as_slice()? };
    Str0255::try_from(s).map_err(|_| SV2_SRI_ERR_INVALID)
}

/// # Safety
/// `b` must describe readable memory that outlives `'a`.
unsafe fn b032<'a>(b: &Sv2SriBytes) -> Result<B032<'a>, i32> {
    // SAFETY: forwarded to the caller
    let s: &'a [u8] = unsafe { b.as_slice()? };
    B032::try_from(s).map_err(|_| SV2_SRI_ERR_INVALID)
}

/// # Safety
/// `b` must describe readable memory that outlives `'a`.
unsafe fn b064k<'a>(b: &Sv2SriBytes) -> Result<B064K<'a>, i32> {
    // SAFETY: forwarded to the caller
    let s: &'a [u8] = unsafe { b.as_slice()? };
    B064K::try_from(s).map_err(|_| SV2_SRI_ERR_INVALID)
}

fn u256(a: &[u8; 32]) -> Result<U256<'_>, i32> {
    U256::try_from(&a[..]).map_err(|_| SV2_SRI_ERR_INVALID)
}

fn view(b: &[u8]) -> Sv2SriBytes {
    Sv2SriBytes::from_slice(b)
}

fn arr32(src: &U256<'_>) -> [u8; 32] {
    let mut a = [0u8; 32];
    a.copy_from_slice(src.as_bytes());
    a
}

fn opt_ntime(has: bool, v: u32) -> Sv2Option<'static, u32> {
    Sv2Option::new(if has { Some(v) } else { None })
}

/// The crates' message for a record.  The byte fields of `m` are borrowed
/// for as long as the message lives.
///
/// # Safety
/// Every byte field of the live record must describe readable memory that
/// outlives the returned message.
unsafe fn to_any(m: &Sv2SriMessage) -> Result<AnyMessage<'_>, i32> {
    use Mining as M;
    // SAFETY: the member read matches the tag, and the byte fields are the
    // caller's
    unsafe {
        Ok(match m.msg_type {
            SV2_SRI_MSG_SETUP_CONNECTION => {
                let c = &m.u.setup_connection;
                CommonMessages::SetupConnection(SetupConnection {
                    protocol: Protocol::try_from(c.protocol).map_err(|_| SV2_SRI_ERR_INVALID)?,
                    min_version: c.min_version,
                    max_version: c.max_version,
                    flags: c.flags,
                    endpoint_host: str0255(&c.endpoint_host)?,
                    endpoint_port: c.endpoint_port,
                    vendor: str0255(&c.vendor)?,
                    hardware_version: str0255(&c.hardware_version)?,
                    firmware: str0255(&c.firmware)?,
                    device_id: str0255(&c.device_id)?,
                })
                .into()
            }
            SV2_SRI_MSG_SETUP_CONNECTION_SUCCESS => {
                let c = &m.u.setup_connection_success;
                CommonMessages::SetupConnectionSuccess(SetupConnectionSuccess {
                    used_version: c.used_version,
                    flags: c.flags,
                })
                .into()
            }
            SV2_SRI_MSG_SETUP_CONNECTION_ERROR => {
                let c = &m.u.setup_connection_error;
                CommonMessages::SetupConnectionError(SetupConnectionError {
                    flags: c.flags,
                    error_code: str0255(&c.error_code)?,
                })
                .into()
            }
            SV2_SRI_MSG_CHANNEL_ENDPOINT_CHANGED => {
                let c = &m.u.channel_endpoint_changed;
                CommonMessages::ChannelEndpointChanged(ChannelEndpointChanged {
                    channel_id: c.channel_id,
                })
                .into()
            }
            SV2_SRI_MSG_RECONNECT => {
                let c = &m.u.reconnect;
                CommonMessages::Reconnect(Reconnect {
                    new_host: str0255(&c.new_host)?,
                    new_port: c.new_port,
                })
                .into()
            }
            SV2_SRI_MSG_OPEN_STANDARD_MINING_CHANNEL => {
                let c = &m.u.open_standard_mining_channel;
                AnyMessage::Mining(M::OpenStandardMiningChannel(OpenStandardMiningChannel {
                    request_id: c.request_id,
                    user_identity: str0255(&c.user_identity)?,
                    nominal_hash_rate: c.nominal_hash_rate,
                    max_target: u256(&c.max_target)?,
                }))
            }
            SV2_SRI_MSG_OPEN_STANDARD_MINING_CHANNEL_SUCCESS => {
                let c = &m.u.open_standard_mining_channel_success;
                AnyMessage::Mining(M::OpenStandardMiningChannelSuccess(OpenStandardMiningChannelSuccess {
                    request_id: c.request_id,
                    channel_id: c.channel_id,
                    target: u256(&c.target)?,
                    extranonce_prefix: b032(&c.extranonce_prefix)?,
                    group_channel_id: c.group_channel_id,
                }))
            }
            SV2_SRI_MSG_OPEN_MINING_CHANNEL_ERROR => {
                let c = &m.u.open_mining_channel_error;
                AnyMessage::Mining(M::OpenMiningChannelError(OpenMiningChannelError {
                    request_id: c.request_id,
                    error_code: str0255(&c.error_code)?,
                }))
            }
            SV2_SRI_MSG_OPEN_EXTENDED_MINING_CHANNEL => {
                let c = &m.u.open_extended_mining_channel;
                AnyMessage::Mining(M::OpenExtendedMiningChannel(OpenExtendedMiningChannel {
                    request_id: c.request_id,
                    user_identity: str0255(&c.user_identity)?,
                    nominal_hash_rate: c.nominal_hash_rate,
                    max_target: u256(&c.max_target)?,
                    min_extranonce_size: c.min_extranonce_size,
                }))
            }
            SV2_SRI_MSG_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS => {
                let c = &m.u.open_extended_mining_channel_success;
                AnyMessage::Mining(M::OpenExtendedMiningChannelSuccess(OpenExtendedMiningChannelSuccess {
                    request_id: c.request_id,
                    channel_id: c.channel_id,
                    target: u256(&c.target)?,
                    extranonce_size: c.extranonce_size,
                    extranonce_prefix: b032(&c.extranonce_prefix)?,
                    group_channel_id: c.group_channel_id,
                }))
            }
            SV2_SRI_MSG_UPDATE_CHANNEL => {
                let c = &m.u.update_channel;
                AnyMessage::Mining(M::UpdateChannel(UpdateChannel {
                    channel_id: c.channel_id,
                    nominal_hash_rate: c.nominal_hash_rate,
                    max_target: u256(&c.maximum_target)?,
                }))
            }
            SV2_SRI_MSG_UPDATE_CHANNEL_ERROR => {
                let c = &m.u.update_channel_error;
                AnyMessage::Mining(M::UpdateChannelError(UpdateChannelError {
                    channel_id: c.channel_id,
                    error_code: str0255(&c.error_code)?,
                }))
            }
            SV2_SRI_MSG_CLOSE_CHANNEL => {
                let c = &m.u.close_channel;
                AnyMessage::Mining(M::CloseChannel(CloseChannel {
                    channel_id: c.channel_id,
                    reason_code: str0255(&c.reason_code)?,
                }))
            }
            SV2_SRI_MSG_SET_EXTRANONCE_PREFIX => {
                let c = &m.u.set_extranonce_prefix;
                AnyMessage::Mining(M::SetExtranoncePrefix(SetExtranoncePrefix {
                    channel_id: c.channel_id,
                    extranonce_prefix: b032(&c.extranonce_prefix)?,
                }))
            }
            SV2_SRI_MSG_SET_TARGET => {
                let c = &m.u.set_target;
                AnyMessage::Mining(M::SetTarget(SetTarget {
                    channel_id: c.channel_id,
                    target: u256(&c.maximum_target)?,
                }))
            }
            SV2_SRI_MSG_SET_GROUP_CHANNEL => {
                let c = &m.u.set_group_channel;
                let raw = c.channel_ids.as_slice()?;
                if raw.len() != c.channel_ids_count as usize * 4 {
                    return Err(SV2_SRI_ERR_INVALID);
                }
                let ids = raw
                    .chunks_exact(4)
                    .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
                    .collect();
                AnyMessage::Mining(M::SetGroupChannel(SetGroupChannel {
                    group_channel_id: c.group_channel_id,
                    channel_ids: Seq064K::new(ids).map_err(|_| SV2_SRI_ERR_INVALID)?,
                }))
            }
            SV2_SRI_MSG_NEW_MINING_JOB => {
                let c = &m.u.new_mining_job;
                AnyMessage::Mining(M::NewMiningJob(NewMiningJob {
                    channel_id: c.channel_id,
                    job_id: c.job_id,
                    ntime_start: opt_ntime(c.has_min_ntime, c.min_ntime),
                    version: c.version,
                    merkle_root: u256(&c.merkle_root)?,
                }))
            }
            SV2_SRI_MSG_NEW_EXTENDED_MINING_JOB => {
                let c = &m.u.new_extended_mining_job;
                let path = c.merkle_path.as_slice()?;
                if path.len() != c.merkle_path_count as usize * 32 {
                    return Err(SV2_SRI_ERR_INVALID);
                }
                let mut hashes = Vec::with_capacity(c.merkle_path_count as usize);
                for h in path.chunks_exact(32) {
                    hashes.push(U256::try_from(h).map_err(|_| SV2_SRI_ERR_INVALID)?);
                }
                AnyMessage::Mining(M::NewExtendedMiningJob(NewExtendedMiningJob {
                    channel_id: c.channel_id,
                    job_id: c.job_id,
                    ntime_start: opt_ntime(c.has_min_ntime, c.min_ntime),
                    version: c.version,
                    version_rolling_allowed: c.version_rolling_allowed,
                    merkle_path: Seq0255::new(hashes).map_err(|_| SV2_SRI_ERR_INVALID)?,
                    coinbase_tx_prefix: b064k(&c.coinbase_tx_prefix)?,
                    coinbase_tx_suffix: b064k(&c.coinbase_tx_suffix)?,
                }))
            }
            SV2_SRI_MSG_SET_NEW_PREV_HASH => {
                let c = &m.u.set_new_prev_hash;
                AnyMessage::Mining(M::SetNewPrevHash(SetNewPrevHash {
                    channel_id: c.channel_id,
                    job_id: c.job_id,
                    prev_hash: u256(&c.prev_hash)?,
                    ntime_start: c.min_ntime,
                    nbits: c.nbits,
                }))
            }
            SV2_SRI_MSG_SUBMIT_SHARES_STANDARD => {
                let c = &m.u.submit_shares_standard;
                AnyMessage::Mining(M::SubmitSharesStandard(SubmitSharesStandard {
                    channel_id: c.channel_id,
                    sequence_number: c.sequence_number,
                    job_id: c.job_id,
                    nonce: c.nonce,
                    ntime: c.ntime,
                    version: c.version,
                }))
            }
            SV2_SRI_MSG_SUBMIT_SHARES_EXTENDED => {
                let c = &m.u.submit_shares_extended;
                AnyMessage::Mining(M::SubmitSharesExtended(SubmitSharesExtended {
                    channel_id: c.channel_id,
                    sequence_number: c.sequence_number,
                    job_id: c.job_id,
                    nonce: c.nonce,
                    ntime: c.ntime,
                    version: c.version,
                    extranonce: b032(&c.extranonce)?,
                }))
            }
            SV2_SRI_MSG_SUBMIT_SHARES_SUCCESS => {
                let c = &m.u.submit_shares_success;
                AnyMessage::Mining(M::SubmitSharesSuccess(SubmitSharesSuccess {
                    channel_id: c.channel_id,
                    last_sequence_number: c.last_sequence_number,
                    new_submits_accepted_count: c.new_submits_accepted_count,
                    new_shares_sum: c.new_shares_sum,
                }))
            }
            SV2_SRI_MSG_SUBMIT_SHARES_ERROR => {
                let c = &m.u.submit_shares_error;
                AnyMessage::Mining(M::SubmitSharesError(SubmitSharesError {
                    channel_id: c.channel_id,
                    sequence_number: c.sequence_number,
                    error_code: str0255(&c.error_code)?,
                }))
            }
            _ => return Err(SV2_SRI_ERR_INVALID),
        })
    }
}

/// The record for a decoded message.  Byte fields point into the payload
/// the message was decoded from.
fn to_record(msg: &AnyMessage<'_>) -> Result<Sv2SriMessage, i32> {
    use Mining as M;
    let msg_type = msg.message_type();
    let u = match msg {
        AnyMessage::Common(CommonMessages::SetupConnection(m)) => Sv2SriMessageUnion {
            setup_connection: Sv2SriSetupConnection {
                protocol: m.protocol as u8,
                min_version: m.min_version,
                max_version: m.max_version,
                flags: m.flags,
                endpoint_host: view(m.endpoint_host.as_bytes()),
                endpoint_port: m.endpoint_port,
                vendor: view(m.vendor.as_bytes()),
                hardware_version: view(m.hardware_version.as_bytes()),
                firmware: view(m.firmware.as_bytes()),
                device_id: view(m.device_id.as_bytes()),
            },
        },
        AnyMessage::Common(CommonMessages::SetupConnectionSuccess(m)) => Sv2SriMessageUnion {
            setup_connection_success: Sv2SriSetupConnectionSuccess {
                used_version: m.used_version,
                flags: m.flags,
            },
        },
        AnyMessage::Common(CommonMessages::SetupConnectionError(m)) => Sv2SriMessageUnion {
            setup_connection_error: Sv2SriSetupConnectionError {
                flags: m.flags,
                error_code: view(m.error_code.as_bytes()),
            },
        },
        AnyMessage::Common(CommonMessages::ChannelEndpointChanged(m)) => Sv2SriMessageUnion {
            channel_endpoint_changed: Sv2SriChannelEndpointChanged {
                channel_id: m.channel_id,
            },
        },
        AnyMessage::Common(CommonMessages::Reconnect(m)) => Sv2SriMessageUnion {
            reconnect: Sv2SriReconnect {
                new_host: view(m.new_host.as_bytes()),
                new_port: m.new_port,
            },
        },
        AnyMessage::Mining(M::OpenStandardMiningChannel(m)) => Sv2SriMessageUnion {
            open_standard_mining_channel: Sv2SriOpenStandardMiningChannel {
                request_id: m.request_id,
                user_identity: view(m.user_identity.as_bytes()),
                nominal_hash_rate: m.nominal_hash_rate,
                max_target: arr32(&m.max_target),
            },
        },
        AnyMessage::Mining(M::OpenStandardMiningChannelSuccess(m)) => Sv2SriMessageUnion {
            open_standard_mining_channel_success: Sv2SriOpenStandardMiningChannelSuccess {
                request_id: m.request_id,
                channel_id: m.channel_id,
                target: arr32(&m.target),
                extranonce_prefix: view(m.extranonce_prefix.as_bytes()),
                group_channel_id: m.group_channel_id,
            },
        },
        AnyMessage::Mining(M::OpenMiningChannelError(m)) => Sv2SriMessageUnion {
            open_mining_channel_error: Sv2SriOpenMiningChannelError {
                request_id: m.request_id,
                error_code: view(m.error_code.as_bytes()),
            },
        },
        AnyMessage::Mining(M::OpenExtendedMiningChannel(m)) => Sv2SriMessageUnion {
            open_extended_mining_channel: Sv2SriOpenExtendedMiningChannel {
                request_id: m.request_id,
                user_identity: view(m.user_identity.as_bytes()),
                nominal_hash_rate: m.nominal_hash_rate,
                max_target: arr32(&m.max_target),
                min_extranonce_size: m.min_extranonce_size,
            },
        },
        AnyMessage::Mining(M::OpenExtendedMiningChannelSuccess(m)) => Sv2SriMessageUnion {
            open_extended_mining_channel_success: Sv2SriOpenExtendedMiningChannelSuccess {
                request_id: m.request_id,
                channel_id: m.channel_id,
                target: arr32(&m.target),
                extranonce_size: m.extranonce_size,
                extranonce_prefix: view(m.extranonce_prefix.as_bytes()),
                group_channel_id: m.group_channel_id,
            },
        },
        AnyMessage::Mining(M::UpdateChannel(m)) => Sv2SriMessageUnion {
            update_channel: Sv2SriUpdateChannel {
                channel_id: m.channel_id,
                nominal_hash_rate: m.nominal_hash_rate,
                maximum_target: arr32(&m.max_target),
            },
        },
        AnyMessage::Mining(M::UpdateChannelError(m)) => Sv2SriMessageUnion {
            update_channel_error: Sv2SriUpdateChannelError {
                channel_id: m.channel_id,
                error_code: view(m.error_code.as_bytes()),
            },
        },
        AnyMessage::Mining(M::CloseChannel(m)) => Sv2SriMessageUnion {
            close_channel: Sv2SriCloseChannel {
                channel_id: m.channel_id,
                reason_code: view(m.reason_code.as_bytes()),
            },
        },
        AnyMessage::Mining(M::SetExtranoncePrefix(m)) => Sv2SriMessageUnion {
            set_extranonce_prefix: Sv2SriSetExtranoncePrefix {
                channel_id: m.channel_id,
                extranonce_prefix: view(m.extranonce_prefix.as_bytes()),
            },
        },
        AnyMessage::Mining(M::SetTarget(m)) => Sv2SriMessageUnion {
            set_target: Sv2SriSetTarget {
                channel_id: m.channel_id,
                maximum_target: arr32(&m.target),
            },
        },
        AnyMessage::Mining(M::SetGroupChannel(m)) => {
            // mining_sv2 decodes the ids into its own vector, which does not
            // outlive the call; the record points at them in the payload,
            // after the u32 group id and the u16 count.
            let count = m.channel_ids.len();
            Sv2SriMessageUnion {
                set_group_channel: Sv2SriSetGroupChannel {
                    group_channel_id: m.group_channel_id,
                    channel_ids_count: count as u16,
                    channel_ids: Sv2SriBytes {
                        data: core::ptr::null(),
                        len: (count * 4) as u32,
                    },
                },
            }
        }
        AnyMessage::Mining(M::NewMiningJob(m)) => {
            let ntime = m.ntime_start.clone().into_inner();
            Sv2SriMessageUnion {
                new_mining_job: Sv2SriNewMiningJob {
                    channel_id: m.channel_id,
                    job_id: m.job_id,
                    has_min_ntime: ntime.is_some(),
                    min_ntime: ntime.unwrap_or(0),
                    version: m.version,
                    merkle_root: arr32(&m.merkle_root),
                },
            }
        }
        AnyMessage::Mining(M::NewExtendedMiningJob(m)) => {
            // The hashes sit back to back in the payload after their u8
            // count; binary_sv2 hands them out one by one, so check they are
            // contiguous before describing them as one range.
            let path = m.merkle_path.as_slice();
            let merkle_path = match path.first() {
                None => Sv2SriBytes::EMPTY,
                Some(first) => {
                    let base = first.as_bytes().as_ptr();
                    for (i, h) in path.iter().enumerate() {
                        if h.as_bytes().as_ptr() != base.wrapping_add(i * 32) {
                            return Err(SV2_SRI_ERR_INVALID);
                        }
                    }
                    Sv2SriBytes {
                        data: base,
                        len: (path.len() * 32) as u32,
                    }
                }
            };
            let ntime = m.ntime_start.clone().into_inner();
            Sv2SriMessageUnion {
                new_extended_mining_job: Sv2SriNewExtendedMiningJob {
                    channel_id: m.channel_id,
                    job_id: m.job_id,
                    has_min_ntime: ntime.is_some(),
                    min_ntime: ntime.unwrap_or(0),
                    version: m.version,
                    version_rolling_allowed: m.version_rolling_allowed,
                    merkle_path_count: path.len() as u8,
                    merkle_path,
                    coinbase_tx_prefix: view(m.coinbase_tx_prefix.as_bytes()),
                    coinbase_tx_suffix: view(m.coinbase_tx_suffix.as_bytes()),
                },
            }
        }
        AnyMessage::Mining(M::SetNewPrevHash(m)) => Sv2SriMessageUnion {
            set_new_prev_hash: Sv2SriSetNewPrevHash {
                channel_id: m.channel_id,
                job_id: m.job_id,
                prev_hash: arr32(&m.prev_hash),
                min_ntime: m.ntime_start,
                nbits: m.nbits,
            },
        },
        AnyMessage::Mining(M::SubmitSharesStandard(m)) => Sv2SriMessageUnion {
            submit_shares_standard: Sv2SriSubmitSharesStandard {
                channel_id: m.channel_id,
                sequence_number: m.sequence_number,
                job_id: m.job_id,
                nonce: m.nonce,
                ntime: m.ntime,
                version: m.version,
            },
        },
        AnyMessage::Mining(M::SubmitSharesExtended(m)) => Sv2SriMessageUnion {
            submit_shares_extended: Sv2SriSubmitSharesExtended {
                channel_id: m.channel_id,
                sequence_number: m.sequence_number,
                job_id: m.job_id,
                nonce: m.nonce,
                ntime: m.ntime,
                version: m.version,
                extranonce: view(m.extranonce.as_bytes()),
            },
        },
        AnyMessage::Mining(M::SubmitSharesSuccess(m)) => Sv2SriMessageUnion {
            submit_shares_success: Sv2SriSubmitSharesSuccess {
                channel_id: m.channel_id,
                last_sequence_number: m.last_sequence_number,
                new_submits_accepted_count: m.new_submits_accepted_count,
                new_shares_sum: m.new_shares_sum,
            },
        },
        // well-formed, but outside what this API has records for
        AnyMessage::Mining(
            M::SetCustomMiningJob(_) | M::SetCustomMiningJobSuccess(_) | M::SetCustomMiningJobError(_),
        )
        | AnyMessage::JobDeclaration(_)
        | AnyMessage::TemplateDistribution(_)
        | AnyMessage::Extensions(_) => return Err(SV2_SRI_ERR_UNSUPPORTED),
        AnyMessage::Mining(M::SubmitSharesError(m)) => Sv2SriMessageUnion {
            submit_shares_error: Sv2SriSubmitSharesError {
                channel_id: m.channel_id,
                sequence_number: m.sequence_number,
                error_code: view(m.error_code.as_bytes()),
            },
        },
    };
    Ok(Sv2SriMessage { msg_type, u })
}

fn parser_err(e: ParserError) -> i32 {
    match e {
        // a message type or extension the crates do not know
        ParserError::UnexpectedMessage(_) => SV2_SRI_ERR_UNSUPPORTED,
        ParserError::BinaryError(e) => binary_err(e),
        _ => SV2_SRI_ERR_INVALID,
    }
}

// The message, its record and how many payload bytes it took.
//
// # Safety
// `payload` must point at `len` bytes that are valid, and not otherwise
// borrowed, for the call.
unsafe fn parse(header: Header, payload: *mut u8, len: u32) -> Result<(Sv2SriMessage, usize), i32> {
    // SAFETY: forwarded to the caller
    let buf = unsafe { output(payload, len as usize)? };
    let msg = AnyMessage::try_from((header, buf)).map_err(parser_err)?;
    if header.channel_msg() != msg.channel_bit() {
        return Err(SV2_SRI_ERR_INVALID);
    }
    let size = msg.get_size();
    let mut record = to_record(&msg)?;
    if msg.message_type() == SV2_SRI_MSG_SET_GROUP_CHANNEL {
        // SAFETY: the decode checked the payload holds the ids at this offset
        record.u.set_group_channel.channel_ids.data = unsafe { payload.add(4 + 2) };
    }
    Ok((record, size))
}

// Bytes after the message are TLV fields (which a role that negotiated no
// extension ignores, as parsers_sv2 does) or garbage.
fn tail_is_tlv(tail: &[u8]) -> bool {
    let mut seen = 0;
    for item in TlvList::from_bytes(tail).iter() {
        match item {
            Ok(tlv) => seen += tlv.encoded_size(),
            Err(_) => return false,
        }
    }
    seen == tail.len()
}

/// Decode the payload of a frame whose header carries `extension_type`
/// (channel_msg bit included) and `msg_type`.  On `SV2_SRI_OK` the record
/// in `out` is the message, with its byte fields pointing into `payload`,
/// which must outlive it.
///
/// `SV2_SRI_ERR_UNSUPPORTED` is a well-formed frame of a message or an
/// extension this API has no record for (an unknown type, an extension's
/// messages, job declaration, template distribution); the caller decides
/// whether to ignore it.  `SV2_SRI_ERR_TRAILING` is bytes after the message
/// that are not TLV fields; TLV fields are accepted and ignored.
/// `SV2_SRI_ERR_INVALID` includes a channel_msg bit that does not match the
/// message.
///
/// binary_sv2 decodes from a mutable slice, hence the non-const pointer;
/// the bytes are left as they were (a SetupConnection's protocol byte is
/// masked for the retry below and restored before the call returns).
///
/// # Safety
/// `payload` must point at `len` readable and writable bytes and `out` at
/// a writable record.
#[no_mangle]
pub unsafe extern "C" fn sv2_sri_message_decode(
    extension_type: u16,
    msg_type: u8,
    payload: *mut u8,
    len: u32,
    out: *mut Sv2SriMessage,
) -> i32 {
    guard(SV2_SRI_ERR_INTERNAL, || {
        ret((|| {
            // SAFETY: forwarded to the caller
            let out = unsafe { obj_mut(out)? };
            let e = extension_type.to_le_bytes();
            let l = len.to_le_bytes();
            let header =
                Header::from_bytes(&[e[0], e[1], msg_type, l[0], l[1], l[2]]).map_err(|_| SV2_SRI_ERR_INVALID)?;
            if len > 0x00FF_FFFF {
                return Err(SV2_SRI_ERR_INVALID);
            }
            // SAFETY: forwarded to the caller
            let (record, size) = match unsafe { parse(header, payload, len) } {
                Ok(v) => v,
                // common_messages_sv2 refuses a `protocol` it does not know
                // rather than decoding the byte, so the role could not answer
                // SetupConnection.Error (unsupported-protocol) as §3.6.1
                // requires.  Decode the rest with the byte masked and hand
                // the real value back.
                Err(code)
                    if code != SV2_SRI_ERR_UNSUPPORTED
                    && header.ext_type_without_channel_msg() == 0
                    && msg_type == SV2_SRI_MSG_SETUP_CONNECTION
                    && len > 0
                    // SAFETY: `len` > 0 readable bytes at `payload`
                    && Protocol::try_from(unsafe { *payload }).is_err() =>
                {
                    // SAFETY: as above, and the slice from `parse` is gone
                    let raw = unsafe { *payload };
                    unsafe { *payload = 0 };
                    // SAFETY: forwarded to the caller
                    let parsed = unsafe { parse(header, payload, len) };
                    // SAFETY: the mutable slice of the retry is gone too
                    unsafe { *payload = raw };
                    let (mut record, size) = parsed?;
                    record.u.setup_connection.protocol = raw;
                    (record, size)
                }
                Err(code) => return Err(code),
            };
            if size < len as usize {
                // SAFETY: inside the payload, past what the message took
                let tail = unsafe { input(payload.add(size), len as usize - size)? };
                if !tail_is_tlv(tail) {
                    return Err(SV2_SRI_ERR_TRAILING);
                }
            }
            *out = record;
            Ok(SV2_SRI_OK)
        })())
    })
}

/// Write one complete plaintext frame for the record in `m` into `out`:
/// the 6 byte header, with the message type and the channel_msg bit the
/// subprotocol crate assigns, then the payload.  Returns the frame length,
/// `SV2_SRI_ERR_OVERFLOW` when `cap` is too small, or `SV2_SRI_ERR_INVALID`
/// for a field out of range or a `msg_type` this API has no record for.
/// Out of range includes a `nominal_hash_rate` that is negative or not
/// finite, which binary_sv2 does not serialize (the decoder still hands
/// one over as it came).  Byte fields of `m` are read only during the call.
///
/// # Safety
/// `m` must point at a record whose byte fields are readable, and `out` at
/// `cap` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn sv2_sri_message_encode(m: *const Sv2SriMessage, out: *mut u8, cap: u32) -> i32 {
    guard(SV2_SRI_ERR_INTERNAL, || {
        ret((|| {
            // SAFETY: forwarded to the caller
            let (m, out) = unsafe { (obj(m)?, output(out, cap as usize)?) };
            // SAFETY: the byte views are the caller's
            let msg = unsafe { to_any(m)? };
            let (msg_type, extension, channel) = (msg.message_type(), msg.extension_type(), msg.channel_bit());
            // AnyMessage itself has no serializer; its two halves do.
            match msg {
                AnyMessage::Common(c) => write(MessageFrame::from_message(c, msg_type, extension, channel), out),
                AnyMessage::Mining(c) => write(MessageFrame::from_message(c, msg_type, extension, channel), out),
                _ => Err(SV2_SRI_ERR_INVALID),
            }
        })())
    })
}

fn write<T: binary_sv2::Serialize + GetSize>(
    frame: Result<MessageFrame<T>, framing_sv2::Error>,
    out: &mut [u8],
) -> Result<i32, i32> {
    let frame = frame.map_err(|_| SV2_SRI_ERR_INVALID)?;
    let len = frame.encoded_length();
    if len > out.len() {
        return Err(SV2_SRI_ERR_OVERFLOW);
    }
    frame.encode_into(&mut out[..len]).map_err(|_| SV2_SRI_ERR_INVALID)?;
    Ok(len as i32)
}

const _: () = assert!(SV2_SRI_FRAME_HEADER_SIZE == Header::SIZE);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SV2_SRI_FRAME_HEADER_SIZE as H;

    fn bytes(s: &[u8]) -> Sv2SriBytes {
        Sv2SriBytes::from_slice(s)
    }

    fn encode(m: &Sv2SriMessage) -> Vec<u8> {
        let mut out = vec![0u8; 200_000];
        let n = unsafe { sv2_sri_message_encode(m, out.as_mut_ptr(), out.len() as u32) };
        assert!(n > 0, "encode of type {:#x} gave {n}", m.msg_type);
        out.truncate(n as usize);
        out
    }

    fn decode(frame: &mut [u8]) -> Result<Sv2SriMessage, i32> {
        let ext = u16::from_le_bytes([frame[0], frame[1]]);
        let msg_type = frame[2];
        let mut m = Sv2SriMessage {
            msg_type: 0xff,
            u: Sv2SriMessageUnion {
                setup_connection_success: Sv2SriSetupConnectionSuccess {
                    used_version: 0,
                    flags: 0,
                },
            },
        };
        let payload = &mut frame[H..];
        let r = unsafe { sv2_sri_message_decode(ext, msg_type, payload.as_mut_ptr(), payload.len() as u32, &mut m) };
        if r == SV2_SRI_OK {
            Ok(m)
        } else {
            Err(r)
        }
    }

    fn setup_connection(protocol: u8) -> Sv2SriMessage {
        Sv2SriMessage {
            msg_type: SV2_SRI_MSG_SETUP_CONNECTION,
            u: Sv2SriMessageUnion {
                setup_connection: Sv2SriSetupConnection {
                    protocol,
                    min_version: 2,
                    max_version: 2,
                    flags: 1,
                    endpoint_host: bytes(b"pool.example.org"),
                    endpoint_port: 3336,
                    vendor: bytes(b"Bitaxe"),
                    hardware_version: bytes(b"BM1370"),
                    firmware: bytes(b"v2.9.0"),
                    device_id: bytes(b""),
                },
            },
        }
    }

    // Every record goes out as a frame and comes back as the same record.
    #[test]
    fn records_round_trip() {
        let target = [0x11u8; 32];
        let prefix = [7u8; 12];
        let path = [9u8; 3 * 32];
        let ids = [1u8, 0, 0, 0, 2, 0, 0, 0];
        let cases = [
            setup_connection(0),
            Sv2SriMessage {
                msg_type: SV2_SRI_MSG_SETUP_CONNECTION_ERROR,
                u: Sv2SriMessageUnion {
                    setup_connection_error: Sv2SriSetupConnectionError {
                        flags: 6,
                        error_code: bytes(b"unsupported-feature-flags"),
                    },
                },
            },
            Sv2SriMessage {
                msg_type: SV2_SRI_MSG_OPEN_EXTENDED_MINING_CHANNEL,
                u: Sv2SriMessageUnion {
                    open_extended_mining_channel: Sv2SriOpenExtendedMiningChannel {
                        request_id: 10,
                        user_identity: bytes(b"tb1qexample.bitaxe"),
                        nominal_hash_rate: 5.5e11,
                        max_target: target,
                        min_extranonce_size: 8,
                    },
                },
            },
            Sv2SriMessage {
                msg_type: SV2_SRI_MSG_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS,
                u: Sv2SriMessageUnion {
                    open_extended_mining_channel_success: Sv2SriOpenExtendedMiningChannelSuccess {
                        request_id: 10,
                        channel_id: 5,
                        target,
                        extranonce_size: 8,
                        extranonce_prefix: bytes(&prefix[..4]),
                        group_channel_id: 1,
                    },
                },
            },
            Sv2SriMessage {
                msg_type: SV2_SRI_MSG_SET_GROUP_CHANNEL,
                u: Sv2SriMessageUnion {
                    set_group_channel: Sv2SriSetGroupChannel {
                        group_channel_id: 1,
                        channel_ids_count: 2,
                        channel_ids: bytes(&ids),
                    },
                },
            },
            Sv2SriMessage {
                msg_type: SV2_SRI_MSG_NEW_EXTENDED_MINING_JOB,
                u: Sv2SriMessageUnion {
                    new_extended_mining_job: Sv2SriNewExtendedMiningJob {
                        channel_id: 5,
                        job_id: 7,
                        has_min_ntime: true,
                        min_ntime: 1_760_000_000,
                        version: 0x2000_0000,
                        version_rolling_allowed: true,
                        merkle_path_count: 3,
                        merkle_path: bytes(&path),
                        coinbase_tx_prefix: bytes(&[1u8; 2048]),
                        coinbase_tx_suffix: bytes(&[2u8; 300]),
                    },
                },
            },
            Sv2SriMessage {
                msg_type: SV2_SRI_MSG_SUBMIT_SHARES_EXTENDED,
                u: Sv2SriMessageUnion {
                    submit_shares_extended: Sv2SriSubmitSharesExtended {
                        channel_id: 5,
                        sequence_number: 2,
                        job_id: 8,
                        nonce: 0x1234_5678,
                        ntime: 1_760_000_003,
                        version: 0x20a0_0000,
                        extranonce: bytes(&[3u8; 8]),
                    },
                },
            },
            Sv2SriMessage {
                msg_type: SV2_SRI_MSG_SUBMIT_SHARES_SUCCESS,
                u: Sv2SriMessageUnion {
                    submit_shares_success: Sv2SriSubmitSharesSuccess {
                        channel_id: 5,
                        last_sequence_number: 2,
                        new_submits_accepted_count: 2,
                        new_shares_sum: 0x1_0000_0002,
                    },
                },
            },
        ];
        for m in &cases {
            let mut frame = encode(m);
            let back = decode(&mut frame).unwrap_or_else(|e| panic!("type {:#x}: {e}", m.msg_type));
            assert_eq!(back.msg_type, m.msg_type);
            let again = encode(&back);
            assert_eq!(again, frame, "type {:#x}", m.msg_type);
            // one byte too many is garbage, one too few is truncated
            frame.push(0);
            assert_eq!(
                decode(&mut frame).err(),
                Some(SV2_SRI_ERR_TRAILING),
                "type {:#x}",
                m.msg_type
            );
            frame.truncate(frame.len() - 2);
            assert!(decode(&mut frame).is_err(), "type {:#x}", m.msg_type);
            // and no damage to a valid frame makes the crates panic
            frame.pop();
            frame.pop();
            let mut rng = XorShift(0x5eed ^ m.msg_type as u64);
            for _ in 0..2000 {
                let mut bad = frame.clone();
                mutate(&mut rng, &mut bad);
                if bad.len() >= H {
                    assert_ne!(
                        decode(&mut bad).err(),
                        Some(SV2_SRI_ERR_INTERNAL),
                        "type {:#x}",
                        m.msg_type
                    );
                }
            }
        }
    }

    /// A small deterministic generator, so a failure replays.
    struct XorShift(u64);

    impl XorShift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    /// Flip, overwrite, insert or cut bytes of a frame, keeping its header
    /// length field consistent half of the time.
    fn mutate(rng: &mut XorShift, f: &mut Vec<u8>) {
        for _ in 0..1 + rng.below(4) {
            let i = rng.below(f.len().max(1));
            match rng.below(5) {
                0 if !f.is_empty() => f[i] ^= 1 << rng.below(8),
                1 if !f.is_empty() => f[i] = rng.next() as u8,
                2 => f.insert(i.min(f.len()), rng.next() as u8),
                3 if !f.is_empty() => f.truncate(i),
                _ => {
                    let extra = rng.below(40);
                    for _ in 0..extra {
                        f.push(rng.next() as u8);
                    }
                }
            }
        }
        if f.len() >= H && rng.below(2) == 0 {
            let n = (f.len() - H) as u32;
            f[3..6].copy_from_slice(&n.to_le_bytes()[..3]);
        }
    }

    // Random payloads under every message type, with and without the
    // channel_msg bit and under extensions: whatever the verdict, it is not
    // a panic.
    #[test]
    fn random_payloads_never_panic() {
        let mut rng = XorShift(0x000c_3a17);
        let mut payload = vec![0u8; 512];
        for ext in [0u16, 0x8000, 0x0001, 0x0002, 0x8002] {
            for msg_type in 0..=255u8 {
                for _ in 0..40 {
                    let len = rng.below(payload.len());
                    for b in payload[..len].iter_mut() {
                        *b = rng.next() as u8;
                    }
                    let mut m = core::mem::MaybeUninit::<Sv2SriMessage>::zeroed();
                    let r = unsafe {
                        sv2_sri_message_decode(ext, msg_type, payload.as_mut_ptr(), len as u32, m.as_mut_ptr())
                    };
                    assert_ne!(r, SV2_SRI_ERR_INTERNAL, "ext {ext:#x} type {msg_type:#x} len {len}");
                    if r == SV2_SRI_OK {
                        let mut out = vec![0u8; 1 << 17];
                        let n = unsafe { sv2_sri_message_encode(m.as_ptr(), out.as_mut_ptr(), out.len() as u32) };
                        assert_ne!(n, SV2_SRI_ERR_INTERNAL, "re-encode of type {msg_type:#x}");
                    }
                }
            }
        }
    }

    // binary_sv2 refuses to serialize a hash rate that is negative or not
    // finite, so the encoder has no frame for one.  The decoder hands over
    // whatever a peer sent: the channel is what refuses it.
    #[test]
    fn a_hash_rate_that_is_not_one_does_not_encode() {
        let open = |rate: f32| Sv2SriMessage {
            msg_type: SV2_SRI_MSG_OPEN_STANDARD_MINING_CHANNEL,
            u: Sv2SriMessageUnion {
                open_standard_mining_channel: Sv2SriOpenStandardMiningChannel {
                    request_id: 1,
                    user_identity: bytes(b"worker"),
                    nominal_hash_rate: rate,
                    max_target: [0xff; 32],
                },
            },
        };
        let extended = |rate: f32| Sv2SriMessage {
            msg_type: SV2_SRI_MSG_OPEN_EXTENDED_MINING_CHANNEL,
            u: Sv2SriMessageUnion {
                open_extended_mining_channel: Sv2SriOpenExtendedMiningChannel {
                    request_id: 1,
                    user_identity: bytes(b"worker"),
                    nominal_hash_rate: rate,
                    max_target: [0xff; 32],
                    min_extranonce_size: 8,
                },
            },
        };
        let update = |rate: f32| Sv2SriMessage {
            msg_type: SV2_SRI_MSG_UPDATE_CHANNEL,
            u: Sv2SriMessageUnion {
                update_channel: Sv2SriUpdateChannel {
                    channel_id: 1,
                    nominal_hash_rate: rate,
                    maximum_target: [0xff; 32],
                },
            },
        };
        let mut out = [0u8; 128];
        for rate in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, -1.0, -0.0] {
            for m in [open(rate), extended(rate), update(rate)] {
                let n = unsafe { sv2_sri_message_encode(&m, out.as_mut_ptr(), out.len() as u32) };
                assert_eq!(n, SV2_SRI_ERR_INVALID, "type {:#x}, {rate}", m.msg_type);
            }
        }
        for rate in [0.0, f32::MIN_POSITIVE, 1.0e12, f32::MAX] {
            for m in [open(rate), extended(rate), update(rate)] {
                let n = unsafe { sv2_sri_message_encode(&m, out.as_mut_ptr(), out.len() as u32) };
                assert!(n > 0, "type {:#x}, {rate}: {n}", m.msg_type);
            }
        }
        // on the wire the field follows request_id and the identity
        let mut frame = encode(&open(1.0e12));
        let at = H + 4 + 1 + b"worker".len();
        assert_eq!(frame[at..at + 4], 1.0e12f32.to_le_bytes());
        frame[at..at + 4].copy_from_slice(&f32::NAN.to_le_bytes());
        let m = decode(&mut frame).expect("decodes");
        assert!(unsafe { m.u.open_standard_mining_channel.nominal_hash_rate }.is_nan());
    }

    // An unknown protocol must reach the role, so it can answer
    // SetupConnection.Error (spec §3.6.1).
    #[test]
    fn setup_connection_with_an_unknown_protocol_decodes() {
        let mut frame = encode(&setup_connection(0));
        frame[H] = 3;
        let m = decode(&mut frame).expect("decodes");
        assert_eq!(m.msg_type, SV2_SRI_MSG_SETUP_CONNECTION);
        let c = unsafe { m.u.setup_connection };
        assert_eq!((c.protocol, c.min_version, c.endpoint_port), (3, 2, 3336));
        assert_eq!(unsafe { c.vendor.as_slice() }.unwrap(), b"Bitaxe");
        assert_eq!(frame[H], 3, "the payload is left as it was");
        // the encoder has no byte to put on the wire for it
        let mut out = [0u8; 64];
        assert_eq!(
            unsafe { sv2_sri_message_encode(&setup_connection(3), out.as_mut_ptr(), 64) },
            SV2_SRI_ERR_INVALID
        );
    }

    // TLV fields after a message are what parsers_sv2 accepts; anything
    // else after it is not.
    #[test]
    fn tlv_fields_are_tolerated_and_garbage_is_not() {
        let base = encode(&setup_connection(0));
        // worker identity, extension 0x0002, field 1, "rig1"
        let mut with_tlv = base.clone();
        with_tlv.extend_from_slice(&[0x02, 0x00, 0x01, 0x04, 0x00, b'r', b'i', b'g', b'1']);
        let n = (with_tlv.len() - H) as u32;
        with_tlv[3..6].copy_from_slice(&n.to_le_bytes()[..3]);
        assert!(decode(&mut with_tlv).is_ok());
        let mut short_tlv = base.clone();
        short_tlv.extend_from_slice(&[0x02, 0x00, 0x01, 0x09, 0x00, b'r']);
        let n = (short_tlv.len() - H) as u32;
        short_tlv[3..6].copy_from_slice(&n.to_le_bytes()[..3]);
        assert_eq!(decode(&mut short_tlv).err(), Some(SV2_SRI_ERR_TRAILING));
    }

    // Dispatch is the crate's: unknown types and extensions are reported as
    // such, a channel_msg bit that does not fit the message is invalid.
    #[test]
    fn dispatch_follows_parsers_sv2() {
        let mut unknown = encode(&setup_connection(0));
        unknown[2] = 0x7f;
        assert_eq!(decode(&mut unknown).err(), Some(SV2_SRI_ERR_UNSUPPORTED));
        let mut extension = encode(&setup_connection(0));
        extension[0] = 0x05;
        assert_eq!(decode(&mut extension).err(), Some(SV2_SRI_ERR_UNSUPPORTED));
        // RequestExtensions: extension 1, type 0; request_id 1 then one
        // requested extension, 0x0002
        let mut request = vec![0x01, 0x00, 0x00, 0x06, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00];
        assert_eq!(decode(&mut request).err(), Some(SV2_SRI_ERR_UNSUPPORTED));
        let mut wrong_bit = encode(&setup_connection(0));
        wrong_bit[1] |= 0x80;
        assert_eq!(decode(&mut wrong_bit).err(), Some(SV2_SRI_ERR_INVALID));
    }
}
