use crate::channels::server::share_validation::ShareValidationError;
use crate::messages::error::Sv2MessageError;
use std::fmt::Display;

#[derive(Debug, uniffi::Error)]
pub enum Sv2ServerExtendedChannelError {
    LockError,
    BadMaxTarget,
    InvalidNominalHashrate,
    RequestedMaxTargetOutOfRange,
    RequestedMinExtranonceSizeTooLarge,
    FailedToConvertMessage(Sv2MessageError),
    FailedToCreateExtendedChannel,
    FailedToUpdateChannel,
    FailedToProcessNewTemplate,
    FailedToProcessNewPrevHash,
    FailedToProcessSetCustomMiningJob,
    MessageIsNotNewTemplate,
    MessageIsNotSetNewPrevHash,
    MessageIsNotSetCustomMiningJob,
    MessageIsNotSubmitSharesExtended,
    MessageIsNotNewExtendedMiningJob,
    ShareValidationError(ShareValidationError),
    FailedToGetActiveJob,
}

impl Display for Sv2ServerExtendedChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, uniffi::Error)]
pub enum Sv2ServerStandardChannelError {
    FailedToCreateStandardChannel,
    BadMaxTarget,
    LockError,
    FailedToUpdateChannel,
    MessageIsNotNewTemplate,
    MessageIsNotSetNewPrevHash,
    MessageIsNotSubmitSharesStandard,
    MessageIsNotNewMiningJob,
    FailedToProcessNewPrevHash,
    FailedToConvertMessage(Sv2MessageError),
    FailedToProcessNewTemplate,
    ShareValidationError(ShareValidationError),
    FailedToGetActiveJob,
    FailedToProcessGroupChannelJob,
}

impl Display for Sv2ServerStandardChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, uniffi::Error)]
pub enum Sv2ServerGroupChannelError {
    LockError,
    FailedToGetActiveJob,
    MessageIsNotNewExtendedMiningJob,
    MessageIsNotNewTemplate,
    MessageIsNotSetNewPrevHash,
    FailedToProcessNewTemplate,
    FailedToConvertMessage(Sv2MessageError),
    FailedToProcessNewPrevHash,
}

impl Display for Sv2ServerGroupChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
