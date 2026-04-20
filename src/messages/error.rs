use std::fmt::Display;

#[allow(clippy::enum_variant_names)]
#[derive(Debug, uniffi::Error)]
pub enum Sv2MessageError {
    FailedToConvertProtocol,
    FailedToSerializeString,
    FailedToSerializeByteArray,
}

impl Display for Sv2MessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
