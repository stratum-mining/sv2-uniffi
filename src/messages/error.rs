use std::fmt::Display;

#[derive(Debug, uniffi::Error)]
pub enum Sv2MessageError {
    FailedToConvertProtocol,
    FailedToSerializeString,
}

impl Display for Sv2MessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
