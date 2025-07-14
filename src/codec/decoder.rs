use codec_sv2::{StandardNoiseDecoder as InnerNoiseDecoder, StandardSv2Frame};
use parsers_sv2::AnyMessage as InnerAnyMessage;

use std::{
    convert::TryInto,
    sync::{Arc, Mutex},
};

use crate::{
    codec::{error::Sv2CodecError, state::Sv2CodecState},
    messages::{inner_to_sv2_message, Sv2Message},
};

#[derive(uniffi::Object)]
pub struct Sv2Decoder {
    inner: Mutex<InnerNoiseDecoder<InnerAnyMessage<'static>>>,
    buffer_size: Mutex<u32>,
}

#[uniffi::export]
impl Sv2Decoder {
    #[uniffi::constructor]
    pub fn new() -> Self {
        let mut inner_decoder = InnerNoiseDecoder::new();
        let initial_writable_size = inner_decoder.writable().len() as u32;

        Self {
            inner: Mutex::new(inner_decoder),
            buffer_size: Mutex::new(initial_writable_size),
        }
    }

    /// Returns the size of the buffer that needs to be filled with data from TCP stream
    pub fn buffer_size(&self) -> Result<u32, Sv2CodecError> {
        let buffer_size = self
            .buffer_size
            .lock()
            .map_err(|_| Sv2CodecError::LockError)?;
        Ok(*buffer_size)
    }

    /// Attempts to decode the next frame after data has been written to the decoder
    ///
    /// This should be called after reading exactly `buffer_size()` bytes from the TCP stream
    /// and passing that data to this method.
    ///
    /// Returns:
    /// - `Ok(message)` if a complete frame was decoded
    /// - `Err(MissingBytes)` if more bytes are needed (call `buffer_size()` to see how many)
    /// - `Err(other)` for other decoding errors
    pub fn try_decode(
        &self,
        data: Vec<u8>,
        state: Arc<Sv2CodecState>,
    ) -> Result<Sv2Message, Sv2CodecError> {
        let mut inner_decoder = self.inner.lock().map_err(|_| Sv2CodecError::LockError)?;
        let mut buffer_size = self
            .buffer_size
            .lock()
            .map_err(|_| Sv2CodecError::LockError)?;

        let mut inner_state = {
            let state_guard = state.inner.lock().map_err(|_| Sv2CodecError::LockError)?;
            state_guard.clone()
        };

        // Write the data to the decoder buffer
        if !data.is_empty() {
            let decoder_buf = inner_decoder.writable();
            if decoder_buf.len() != data.len() {
                return Err(Sv2CodecError::InvalidDataSize {
                    expected: decoder_buf.len() as u32,
                    actual: data.len() as u32,
                });
            }
            decoder_buf.copy_from_slice(&data);
        }

        // Try to decode the frame
        match inner_decoder.next_frame(&mut inner_state) {
            Ok(decoded_frame) => {
                // Successfully decoded - convert to StandardSv2Frame
                let mut sv2_frame: StandardSv2Frame<InnerAnyMessage<'static>> = decoded_frame
                    .try_into()
                    .map_err(|_| Sv2CodecError::FailedToDecodeFrame)?;

                let sv2_frame_header = sv2_frame
                    .get_header()
                    .ok_or(Sv2CodecError::FailedToGetFrameHeader)?;
                let sv2_message_type = sv2_frame_header.msg_type();
                let mut sv2_message_payload = sv2_frame.payload().to_vec();

                let sv2_message: InnerAnyMessage =
                    (sv2_message_type, sv2_message_payload.as_mut_slice())
                        .try_into()
                        .map_err(|_| Sv2CodecError::FailedToDecodeFrame)?;
                let sv2_message: InnerAnyMessage<'static> = sv2_message.into_static();

                // Update the original state with changes
                {
                    let mut state_guard =
                        state.inner.lock().map_err(|_| Sv2CodecError::LockError)?;
                    *state_guard = inner_state;
                }

                // After successful decode, reset to initial state for next frame
                *buffer_size = 0;

                Ok(inner_to_sv2_message(&sv2_message))
            }
            Err(codec_sv2::Error::MissingBytes(bytes_needed)) => {
                // Update the original state with changes
                {
                    let mut state_guard =
                        state.inner.lock().map_err(|_| Sv2CodecError::LockError)?;
                    *state_guard = inner_state;
                }

                // Update the buffer size for next read
                *buffer_size = bytes_needed as u32;

                Err(Sv2CodecError::MissingBytes)
            }
            Err(e) => {
                eprintln!("Failed to decode frame: {:?}", e);
                Err(Sv2CodecError::FailedToDecodeFrame)
            }
        }
    }
}
