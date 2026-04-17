#[derive(uniffi::Record)]
pub struct RequestExtensions {
    pub request_id: u16,
    pub requested_extensions: Vec<u16>,
}

#[derive(uniffi::Record)]
pub struct RequestExtensionsSuccess {
    pub request_id: u16,
    pub supported_extensions: Vec<u16>,
}

#[derive(uniffi::Record)]
pub struct RequestExtensionsError {
    pub request_id: u16,
    pub unsupported_extensions: Vec<u16>,
    pub required_extensions: Vec<u16>,
}
