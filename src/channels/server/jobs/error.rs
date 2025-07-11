use std::fmt::Display;

#[derive(Debug, uniffi::Error)]
pub enum Sv2ExtendedJobError {
    LockError,
    MessageIsNotNewExtendedMiningJob,
    MessageIsNotNewTemplate,
    MessageIsNotSetCustomMiningJob,
}

impl Display for Sv2ExtendedJobError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, uniffi::Error)]
pub enum Sv2StandardJobError {
    LockError,
    MessageIsNotNewMiningJob,
    MessageIsNotNewTemplate,
}

impl Display for Sv2StandardJobError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
