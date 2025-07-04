use codec_sv2::{NoiseEncoder as InnerNoiseEncoder, StandardEitherFrame, StandardSv2Frame};
use roles_logic_sv2::parsers::AnyMessage as InnerAnyMessage;

use std::{
    convert::TryInto,
    sync::{Arc, Mutex},
};

use crate::{
    codec::{error::Sv2CodecError, state::Sv2CodecState},
    messages::{sv2_message_to_inner, Sv2Message},
};

#[derive(uniffi::Object)]
pub struct Sv2Encoder {
    inner: Mutex<InnerNoiseEncoder<InnerAnyMessage<'static>>>,
}

#[uniffi::export]
impl Sv2Encoder {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(InnerNoiseEncoder::new()),
        }
    }

    /// encodes a Sv2 message into a frame.
    ///
    /// codec_state must be generated from the handshake process.
    ///
    /// Returns a byte array of the encrypted frame to be sent over the wire.
    pub fn encode(
        &self,
        message: Sv2Message,
        codec_state: Arc<Sv2CodecState>,
    ) -> Result<Vec<u8>, Sv2CodecError> {
        let mut inner_encoder = self.inner.lock().map_err(|_| Sv2CodecError::LockError)?;

        let inner_message =
            sv2_message_to_inner(message).map_err(Sv2CodecError::Sv2MessagesError)?;

        let message_frame: StandardEitherFrame<InnerAnyMessage<'static>> = inner_message
            .try_into()
            .map_err(|_| Sv2CodecError::FailedToConvertMessageToFrame)
            .map(|sv2_frame: StandardSv2Frame<InnerAnyMessage<'static>>| sv2_frame.into())?;

        let mut inner_state = codec_state
            .inner
            .lock()
            .map_err(|_| Sv2CodecError::LockError)?
            .clone();

        let frame = inner_encoder
            .encode(message_frame, &mut inner_state)
            .map_err(|_| Sv2CodecError::FailedToConvertMessageToFrame)?;

        Ok(frame.as_ref().to_vec())
    }
}
