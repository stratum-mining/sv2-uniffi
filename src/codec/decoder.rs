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
}

#[uniffi::export]
impl Sv2Decoder {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(InnerNoiseDecoder::new()),
        }
    }

    /// decodes a byte array into a `Sv2Message`
    ///
    /// we assume the byte array contains an encrypted Sv2 frame, otherwise it will return an error
    ///
    /// codec_state must be generated from the handshake process.
    pub fn decode(
        &self,
        frame: Vec<u8>,
        state: Arc<Sv2CodecState>,
    ) -> Result<Sv2Message, Sv2CodecError> {
        let mut inner_decoder = self.inner.lock().map_err(|_| Sv2CodecError::LockError)?;

        let mut inner_state = {
            let state_guard = state.inner.lock().map_err(|_| Sv2CodecError::LockError)?;
            state_guard.clone()
        };

        // Write the entire frame to the decoder buffer
        let mut frame_offset = 0;

        loop {
            // Get the writable buffer from the decoder
            let decoder_buf = inner_decoder.writable();
            let decoder_buf_size = decoder_buf.len();

            // Check if we have more data to write
            if frame_offset < frame.len() {
                // Calculate how much data to write (minimum of remaining frame data or buffer size)
                let bytes_to_write = std::cmp::min(decoder_buf_size, frame.len() - frame_offset);

                // Write the data to the decoder buffer
                decoder_buf[..bytes_to_write]
                    .copy_from_slice(&frame[frame_offset..frame_offset + bytes_to_write]);
                frame_offset += bytes_to_write;
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
                    let mut sv2_message_payload = sv2_frame.payload().to_vec(); // Clone the payload to avoid borrowing issues

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

                    return Ok(inner_to_sv2_message(&sv2_message));
                }
                Err(codec_sv2::Error::MissingBytes(_)) => {
                    // Need more data - continue the loop if we have more data to write
                    if frame_offset >= frame.len() {
                        return Err(Sv2CodecError::FailedToDecodeFrame);
                    }
                    // Continue the loop to write more data
                }
                Err(_) => {
                    return Err(Sv2CodecError::FailedToDecodeFrame);
                }
            }
        }
    }
}
