use channels_sv2::server::share_accounting::ShareAccounting as InnerShareAccounting;
use std::fmt::Display;

#[derive(uniffi::Enum)]
pub enum ShareValidationResult {
    Valid {
        share_hash: Vec<u8>,
    },
    BlockFound {
        share_hash: Vec<u8>,
        template_id: Option<u64>,
        coinbase: Vec<u8>,
    },
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

#[derive(uniffi::Object, Clone, Debug)]
pub struct ShareAccounting {
    inner: InnerShareAccounting,
}

impl ShareAccounting {
    pub fn from_inner(inner: InnerShareAccounting) -> Self {
        Self { inner }
    }
}

#[uniffi::export]
impl ShareAccounting {
    pub fn get_last_share_sequence_number(&self) -> u32 {
        self.inner.get_last_share_sequence_number()
    }

    pub fn get_shares_accepted(&self) -> u32 {
        self.inner.get_shares_accepted()
    }

    pub fn get_share_work_sum(&self) -> f64 {
        self.inner.get_share_work_sum()
    }

    pub fn get_last_batch_accepted(&self) -> u32 {
        self.inner.get_last_batch_accepted()
    }

    pub fn get_last_batch_work_sum(&self) -> f64 {
        self.inner.get_last_batch_work_sum()
    }

    pub fn get_share_batch_size(&self) -> u64 {
        self.inner.get_share_batch_size() as u64
    }

    pub fn should_acknowledge(&self) -> bool {
        self.inner.should_acknowledge()
    }

    pub fn get_best_diff(&self) -> f64 {
        self.inner.get_best_diff()
    }

    pub fn get_blocks_found(&self) -> u32 {
        self.inner.get_blocks_found()
    }
}
