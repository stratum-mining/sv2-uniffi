#[derive(uniffi::Record)]
pub struct AllocateMiningJobToken {
    pub user_identifier: String,
    pub request_id: u32,
}

#[derive(uniffi::Record)]
pub struct AllocateMiningJobTokenSuccess {
    pub request_id: u32,
    pub mining_job_token: Vec<u8>,
    pub coinbase_tx_outputs: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct DeclareMiningJob {
    pub request_id: u32,
    pub mining_job_token: Vec<u8>,
    pub version: u32,
    pub coinbase_tx_prefix: Vec<u8>,
    pub coinbase_tx_suffix: Vec<u8>,
    pub tx_ids_list: Vec<Vec<u8>>,
    pub excess_data: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct DeclareMiningJobSuccess {
    pub request_id: u32,
    pub new_mining_job_token: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct DeclareMiningJobError {
    pub request_id: u32,
    pub error_code: String,
    pub error_details: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct ProvideMissingTransactions {
    pub request_id: u32,
    pub unknown_tx_position_list: Vec<u16>,
}

#[derive(uniffi::Record)]
pub struct ProvideMissingTransactionsSuccess {
    pub request_id: u32,
    pub transaction_list: Vec<Vec<u8>>,
}

#[derive(uniffi::Record)]
pub struct PushSolution {
    pub extranonce: Vec<u8>,
    pub prev_hash: Vec<u8>,
    pub nonce: u32,
    pub ntime: u32,
    pub nbits: u32,
    pub version: u32,
}
