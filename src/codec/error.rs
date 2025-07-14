use crate::messages::error::Sv2MessageError;
use std::fmt::Display;

#[derive(Debug, uniffi::Error)]
pub enum Sv2CodecError {
    LockError,
    BadKey,
    FailedToCreateInitiator,
    FailedToCreateResponder,
    FailedHandshakeStep0,
    FailedHandshakeStep1,
    FailedHandshakeStep2,
    BadInitiatorFrame,
    BadResponderFrame,
    FailedToConvertMessageToFrame,
    FailedToDecodeFrame,
    FailedToGetFrameHeader,
    Sv2MessagesError(Sv2MessageError),
    MissingBytes,
    InvalidDataSize { expected: u32, actual: u32 },
}

impl Display for Sv2CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
