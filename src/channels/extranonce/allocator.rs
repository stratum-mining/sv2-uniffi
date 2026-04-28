use channels_sv2::extranonce_manager::{
    bytes_needed, ExtranonceAllocator, ExtranonceAllocatorError as InnerExtranonceAllocatorError,
};
use std::convert::TryInto;
use std::fmt;
use std::fmt::Display;
use std::sync::{Arc, Mutex};

use crate::channels::extranonce::prefix::Sv2ExtranoncePrefix;

#[derive(uniffi::Object)]
pub struct Sv2ExtranonceAllocator {
    inner: Mutex<ExtranonceAllocator>,
}

#[uniffi::export]
impl Sv2ExtranonceAllocator {
    #[uniffi::constructor]
    pub fn new(
        local_prefix_bytes: Vec<u8>,
        total_extranonce_len: u32,
        max_channels: u32,
    ) -> Result<Self, Sv2ExtranonceAllocatorError> {
        let total_extranonce_len = total_extranonce_len
            .try_into()
            .map_err(|_| Sv2ExtranonceAllocatorError::ExceedsMaxLength)?;
        let inner =
            ExtranonceAllocator::new(local_prefix_bytes, total_extranonce_len, max_channels)?;
        Ok(Self {
            inner: Mutex::new(inner),
        })
    }

    pub fn allocate_standard(
        &self,
    ) -> Result<Arc<Sv2ExtranoncePrefix>, Sv2ExtranonceAllocatorError> {
        let prefix = self
            .inner
            .lock()
            .map_err(|_| Sv2ExtranonceAllocatorError::LockError)?
            .allocate_standard()?;
        Ok(Sv2ExtranoncePrefix::from_inner(prefix))
    }

    pub fn allocate_extended(
        &self,
        min_rollable_size: u32,
    ) -> Result<Arc<Sv2ExtranoncePrefix>, Sv2ExtranonceAllocatorError> {
        let min_rollable_size = min_rollable_size
            .try_into()
            .map_err(|_| Sv2ExtranonceAllocatorError::InvalidRollableSize)?;
        let prefix = self
            .inner
            .lock()
            .map_err(|_| Sv2ExtranonceAllocatorError::LockError)?
            .allocate_extended(min_rollable_size)?;
        Ok(Sv2ExtranoncePrefix::from_inner(prefix))
    }

    pub fn rollable_extranonce_size(&self) -> Result<u32, Sv2ExtranonceAllocatorError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| Sv2ExtranonceAllocatorError::LockError)?;
        Ok(inner.rollable_extranonce_size() as u32)
    }

    pub fn total_extranonce_len(&self) -> Result<u32, Sv2ExtranonceAllocatorError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| Sv2ExtranonceAllocatorError::LockError)?;
        Ok(inner.total_extranonce_len() as u32)
    }

    pub fn local_prefix_len(&self) -> Result<u32, Sv2ExtranonceAllocatorError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| Sv2ExtranonceAllocatorError::LockError)?;
        Ok(inner.local_prefix_len() as u32)
    }

    pub fn local_index_len(&self) -> Result<u32, Sv2ExtranonceAllocatorError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| Sv2ExtranonceAllocatorError::LockError)?;
        Ok(inner.local_index_len() as u32)
    }

    pub fn full_prefix_len(&self) -> Result<u32, Sv2ExtranonceAllocatorError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| Sv2ExtranonceAllocatorError::LockError)?;
        Ok(inner.full_prefix_len() as u32)
    }

    pub fn allocated_count(&self) -> Result<u32, Sv2ExtranonceAllocatorError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| Sv2ExtranonceAllocatorError::LockError)?;
        Ok(inner.allocated_count())
    }

    pub fn max_channels(&self) -> Result<u32, Sv2ExtranonceAllocatorError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| Sv2ExtranonceAllocatorError::LockError)?;
        Ok(inner.max_channels())
    }
}

#[uniffi::export]
pub fn sv2_extranonce_bytes_needed(n: u32) -> u32 {
    bytes_needed(n) as u32
}

#[derive(Debug, uniffi::Error)]
pub enum Sv2ExtranonceAllocatorError {
    LockError,
    PrefixAlreadyConsumed,
    ExceedsMaxLength,
    ZeroMaxChannels,
    PrefixExceedsTotalLength,
    CapacityExhausted,
    InvalidRollableSize,
}

impl From<InnerExtranonceAllocatorError> for Sv2ExtranonceAllocatorError {
    fn from(value: InnerExtranonceAllocatorError) -> Self {
        match value {
            InnerExtranonceAllocatorError::ExceedsMaxLength => Self::ExceedsMaxLength,
            InnerExtranonceAllocatorError::ZeroMaxChannels => Self::ZeroMaxChannels,
            InnerExtranonceAllocatorError::PrefixExceedsTotalLength => {
                Self::PrefixExceedsTotalLength
            }
            InnerExtranonceAllocatorError::CapacityExhausted => Self::CapacityExhausted,
            InnerExtranonceAllocatorError::InvalidRollableSize => Self::InvalidRollableSize,
        }
    }
}

impl Display for Sv2ExtranonceAllocatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
