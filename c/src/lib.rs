//! sv2_sri: a C API over the Stratum V2 Reference Implementation crates.
//!
//! For C programs that speak Stratum V2 with SRI's own code underneath:
//! the first one is DATUM Gateway, whose SV2 server is plain C.  The API is
//! cut to what a pool-side SV2 server needs today and laid out the way
//! the UniFFI crate at the root of this repository is:
//!
//! - `codec`: one Noise session per connection.  The handshake as responder
//!   (and as initiator, for tests and benchmarks) and the encrypted
//!   transport run through `codec_sv2`, which owns the chunking and the
//!   receive side reassembly; the authority key and certificate come from
//!   `noise_sv2`.
//! - `messages`: the common and mining messages as plain C records.  One
//!   decoder turns a frame into a record and one encoder turns a record
//!   into a frame; which message a frame holds, whether it is addressed to
//!   a channel and what to do with TLV fields are decided by `parsers_sv2`,
//!   SRI's own dispatcher, not here.
//! - `frame`: frame headers through `framing_sv2`.
//! - `keys`: the authority key and its base58 text form.
//! - `channels`: server-side mining channels through `channels_sv2`: an
//!   extranonce allocator, and extended and standard channels that take
//!   their jobs as the bytes the server sends and validate the shares.
//!
//! Memory rules, which hold for every function here:
//!
//! - Buffers are owned by the caller.  Encoders write into a caller buffer
//!   of a given capacity, decoders read a caller buffer.
//! - Decoded variable length fields (`Sv2SriBytes`) point into the payload
//!   the caller passed in and are valid as long as that buffer is.
//! - The Rust allocations a caller holds are the objects of the `_new()`
//!   functions, each released with its `_free()`: a `Sv2SriNoise` per
//!   connection, and in `channels` an allocator and a channel object per
//!   channel, which keeps the jobs it was given.  The crates allocate
//!   internally while they work; nothing else outlives a call.
//!
//! Every function returns `SV2_SRI_OK` (0), a positive byte count where the
//! documentation says so, or one of the negative `SV2_SRI_ERR_*` codes.  The
//! values are part of the API: a caller can store and compare them.
//!
//! No panic leaves the library: every exported function runs its body
//! under `catch_unwind` and reports a panic as `SV2_SRI_ERR_INTERNAL`
//! (NULL for a constructor), so one bad input on one connection cannot
//! take a server's other connections down with it.

#![deny(unsafe_op_in_unsafe_fn)]

mod channels;
mod codec;
mod ffi;
mod frame;
mod keys;
mod messages;
mod util;

pub use channels::*;
pub use codec::*;
pub use ffi::Sv2SriBytes;
pub use frame::*;
pub use keys::*;
pub use messages::*;
pub use util::*;

/// Success
pub const SV2_SRI_OK: i32 = 0;
/// `sv2_sri_noise_read_frame()`: more input is needed
pub const SV2_SRI_NEED_MORE: i32 = 1;
/// Input ended before the message did
pub const SV2_SRI_ERR_TRUNCATED: i32 = -1;
/// Output buffer too small, or a frame larger than the caller allows
pub const SV2_SRI_ERR_OVERFLOW: i32 = -2;
/// Malformed or out of spec value, or a NULL argument
pub const SV2_SRI_ERR_INVALID: i32 = -3;
/// AEAD, ECDH or signature failure
pub const SV2_SRI_ERR_CRYPTO: i32 = -4;
/// The call does not fit the handshake state
pub const SV2_SRI_ERR_STATE: i32 = -5;
/// The responder's certificate did not verify against the pinned authority key
pub const SV2_SRI_ERR_CERT: i32 = -7;
/// Bytes left over after the last field of a message that are not TLV fields
pub const SV2_SRI_ERR_TRAILING: i32 = -8;
/// A well-formed frame of a message or extension this API has no record for
pub const SV2_SRI_ERR_UNSUPPORTED: i32 = -9;
/// A bug: the call panicked inside the library or the crates under it.  The
/// object it was made on may be half updated and must be freed, not used
/// again; anything else the caller holds is unaffected.  Functions that
/// return a pointer return NULL instead, and those that return nothing
/// return.
pub const SV2_SRI_ERR_INTERNAL: i32 = -10;

/// Plain SV2 frame header: extension_type (u16), msg_type (u8), msg_length (u24)
pub const SV2_SRI_FRAME_HEADER_SIZE: usize = 6;
/// AEAD tag appended to every encrypted piece
pub const SV2_SRI_AEAD_MAC_SIZE: usize = 16;
/// Encrypted frame header on the wire
pub const SV2_SRI_ENCRYPTED_HEADER_SIZE: usize = 22;
/// Largest encrypted chunk of payload
pub const SV2_SRI_MAX_ENCRYPTED_CHUNK: usize = 65535;
/// Handshake act 1 (initiator to responder): ElligatorSwift ephemeral key
pub const SV2_SRI_ACT1_SIZE: usize = 64;
/// Handshake act 2 (responder to initiator): e, encrypted s, encrypted certificate
pub const SV2_SRI_ACT2_SIZE: usize = 234;
/// Size of the base58 text form of an authority public key, NUL included
pub const SV2_SRI_AUTHORITY_BASE58_MAX: usize = 64;

// cbindgen only sees literals, so tie each one to the crate it comes from.
const _: () = {
    assert!(SV2_SRI_FRAME_HEADER_SIZE == framing_sv2::SV2_FRAME_HEADER_SIZE);
    assert!(SV2_SRI_AEAD_MAC_SIZE == noise_sv2::AEAD_MAC_LEN);
    assert!(SV2_SRI_ENCRYPTED_HEADER_SIZE == codec_sv2::ENCRYPTED_SV2_FRAME_HEADER_SIZE);
    assert!(SV2_SRI_MAX_ENCRYPTED_CHUNK == framing_sv2::SV2_FRAME_CHUNK_SIZE);
    assert!(SV2_SRI_ACT1_SIZE == noise_sv2::ELLSWIFT_ENCODING_SIZE);
    assert!(SV2_SRI_ACT2_SIZE == noise_sv2::INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE);
};
