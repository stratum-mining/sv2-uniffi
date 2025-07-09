#[derive(uniffi::Record)]
pub struct SetupConnection {
    pub protocol: u8,
    pub min_version: u16,
    pub max_version: u16,
    pub flags: u32,
    pub endpoint_host: String,
    pub endpoint_port: u16,
    pub vendor: String,
    pub hardware_version: String,
    pub firmware: String,
    pub device_id: String,
}

#[derive(uniffi::Record)]
pub struct SetupConnectionSuccess {
    pub used_version: u16,
    pub flags: u32,
}

#[derive(uniffi::Record)]
pub struct SetupConnectionError {
    pub flags: u32,
    pub error_code: String,
}

#[derive(uniffi::Record)]
pub struct ChannelEndpointChanged {
    pub channel_id: u32,
}

#[derive(uniffi::Record)]
pub struct Reconnect {
    pub new_host: String,
    pub new_port: u16,
}
