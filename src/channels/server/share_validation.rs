use std::fmt::Display;

#[derive(uniffi::Enum)]
pub enum ShareValidationResult {
    Valid(Vec<u8>),
    BlockFound(Vec<u8>, Option<u64>, Vec<u8>),
}

#[derive(uniffi::Enum, Debug)]
pub enum ShareValidationError {
    Invalid,
    Stale,
    InvalidJobId,
    DoesNotMeetTarget,
    VersionRollingNotAllowed,
    DuplicateShare,
    InvalidCoinbase,
    NoChainTip,
    BadExtranonceSize,
}

impl Display for ShareValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
