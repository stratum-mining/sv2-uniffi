#[derive(uniffi::Record)]
pub struct CoinbaseOutputConstraints {
    pub coinbase_output_max_additional_size: u32,
    pub coinbase_output_max_additional_sigops: u16,
}

#[derive(uniffi::Record)]
pub struct NewTemplate {
    pub template_id: u64,
    pub future_template: bool,
    pub version: u32,
    pub coinbase_tx_version: u32,
    pub coinbase_prefix: Vec<u8>,
    pub coinbase_tx_input_sequence: u32,
    pub coinbase_tx_value_remaining: u64,
    pub coinbase_tx_outputs_count: u32,
    pub coinbase_tx_outputs: Vec<u8>,
    pub coinbase_tx_locktime: u32,
    pub merkle_path: Vec<Vec<u8>>,
}

#[derive(uniffi::Record)]
pub struct SetNewPrevHashTemplateDistribution {
    pub template_id: u64,
    pub prev_hash: Vec<u8>,
    pub header_timestamp: u32,
    pub nbits: u32,
    pub target: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct RequestTransactionData {
    pub template_id: u64,
}

#[derive(uniffi::Record)]
pub struct RequestTransactionDataSuccess {
    pub template_id: u64,
    pub excess_data: Vec<u8>,
    pub transaction_list: Vec<Vec<u8>>,
}

#[derive(uniffi::Record)]
pub struct RequestTransactionDataError {
    pub template_id: u64,
    pub error_code: String,
}

#[derive(uniffi::Record)]
pub struct SubmitSolution {
    pub template_id: u64,
    pub version: u32,
    pub header_timestamp: u32,
    pub header_nonce: u32,
    pub coinbase_tx: Vec<u8>,
}
