use std::fmt::Display;

#[derive(uniffi::Enum)]
pub enum ShareValidationResult {
    Valid,
    ValidWithAcknowledgement(u32, u32, u64),
    BlockFound(Option<u64>, Vec<u8>),
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
}

impl Display for ShareValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
