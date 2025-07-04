use codec_sv2::{
    noise_sv2::{ELLSWIFT_ENCODING_SIZE, INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE},
    HandshakeRole, Initiator, Responder, State as InnerCodecState,
};

use std::{convert::TryInto, sync::Mutex};

use crate::codec::error::Sv2CodecError;

#[derive(uniffi::Object)]
pub struct Sv2CodecState {
    pub inner: Mutex<InnerCodecState>,
}

#[uniffi::export]
impl Sv2CodecState {
    #[uniffi::constructor]
    pub fn new_initiator(authority_pub_key: Vec<u8>) -> Result<Self, Sv2CodecError> {
        let authority_pub_key: [u8; 32] = authority_pub_key
            .try_into()
            .map_err(|_| Sv2CodecError::BadKey)?;
        let initiator = Initiator::from_raw_k(authority_pub_key)
            .map_err(|_| Sv2CodecError::FailedToCreateInitiator)?;
        Ok(Self {
            inner: Mutex::new(InnerCodecState::initialized(HandshakeRole::Initiator(
                initiator,
            ))),
        })
    }

    #[uniffi::constructor]
    pub fn new_responder(
        authority_pub_key: Vec<u8>,
        authority_priv_key: Vec<u8>,
        cert_validity_secs: u64,
    ) -> Result<Self, Sv2CodecError> {
        let authority_pub_key: [u8; 32] = authority_pub_key
            .try_into()
            .map_err(|_| Sv2CodecError::BadKey)?;
        let authority_priv_key: [u8; 32] = authority_priv_key
            .try_into()
            .map_err(|_| Sv2CodecError::BadKey)?;
        let cert_validity_secs = std::time::Duration::from_secs(cert_validity_secs);
        let responder = Responder::from_authority_kp(
            &authority_pub_key,
            &authority_priv_key,
            cert_validity_secs,
        )
        .map_err(|_| Sv2CodecError::FailedToCreateResponder)?;
        Ok(Self {
            inner: Mutex::new(InnerCodecState::initialized(HandshakeRole::Responder(
                responder,
            ))),
        })
    }

    pub fn step_0(&self) -> Result<Vec<u8>, Sv2CodecError> {
        let mut state = self.inner.lock().map_err(|_| Sv2CodecError::LockError)?;
        let handshake_frame = state
            .step_0()
            .map_err(|_| Sv2CodecError::FailedHandshakeStep0)?;
        Ok(handshake_frame.get_payload_when_handshaking())
    }

    pub fn step_1(&self, initiator_frame: Vec<u8>) -> Result<Vec<u8>, Sv2CodecError> {
        let initiator_frame: [u8; ELLSWIFT_ENCODING_SIZE] = initiator_frame
            .try_into()
            .map_err(|_| Sv2CodecError::BadInitiatorFrame)?;
        let mut state = self.inner.lock().map_err(|_| Sv2CodecError::LockError)?;
        let (handshake_frame, new_state) = state
            .step_1(initiator_frame)
            .map_err(|_| Sv2CodecError::FailedHandshakeStep1)?;

        // Update the state to transport mode
        *state = new_state;

        Ok(handshake_frame.get_payload_when_handshaking())
    }

    pub fn step_2(&self, responder_frame: Vec<u8>) -> Result<(), Sv2CodecError> {
        let responder_frame: [u8; INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE] = responder_frame
            .try_into()
            .map_err(|_| Sv2CodecError::BadResponderFrame)?;
        let mut state = self.inner.lock().map_err(|_| Sv2CodecError::LockError)?;
        let new_state = state
            .step_2(responder_frame)
            .map_err(|_| Sv2CodecError::FailedHandshakeStep2)?;

        // Update the state to transport mode
        *state = new_state;

        Ok(())
    }

    pub fn handshake_complete(&self) -> Result<bool, Sv2CodecError> {
        let state = self.inner.lock().map_err(|_| Sv2CodecError::LockError)?;
        match *state {
            InnerCodecState::Transport(_) => Ok(true),
            _ => Ok(false),
        }
    }
}
