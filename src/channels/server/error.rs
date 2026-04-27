use crate::channels::server::share_accounting::ShareValidationError;
use crate::messages::error::Sv2MessageError;
use std::fmt::Display;

#[derive(Debug, uniffi::Error)]
pub enum Sv2ServerExtendedChannelError {
    LockError,
    BadMaxTarget,
    InvalidNominalHashrate,
    RequestedMinExtranonceSizeTooLarge,
    FailedToConvertMessage { error: Sv2MessageError },
    FailedToCreateExtendedChannel,
    FailedToConsumeExtranoncePrefix,
    FailedToUpdateChannel,
    FailedToProcessNewTemplate,
    FailedToProcessNewPrevHash,
    FailedToProcessSetCustomMiningJob,
    FailedToProcessGroupChannelJob,
    ExtranoncePrefixTooLarge,
    MessageIsNotNewTemplate,
    MessageIsNotSetNewPrevHash,
    MessageIsNotSetCustomMiningJob,
    MessageIsNotSubmitSharesExtended,
    MessageIsNotNewExtendedMiningJob,
    MessageIsNotGroupChannelJob,
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
    FailedToConsumeExtranoncePrefix,
    BadMaxTarget,
    LockError,
    FailedToUpdateChannel,
    ExtranoncePrefixTooLarge,
    MessageIsNotNewTemplate,
    MessageIsNotSetNewPrevHash,
    MessageIsNotSubmitSharesStandard,
    MessageIsNotNewMiningJob,
    FailedToProcessNewPrevHash,
    FailedToConvertMessage { error: Sv2MessageError },
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
    FailedToCreateGroupChannel,
    FailedToGetActiveJob,
    MessageIsNotNewExtendedMiningJob,
    MessageIsNotNewTemplate,
    MessageIsNotSetNewPrevHash,
    FailedToProcessNewTemplate,
    FailedToConvertMessage { error: Sv2MessageError },
    FailedToProcessNewPrevHash,
}

impl Display for Sv2ServerGroupChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
