use mining_sv2::{ExtendedExtranonce, FULL_EXTRANONCE_LEN};
use std::fmt;
use std::fmt::Display;
use std::ops::Range;
use std::sync::Mutex;

#[derive(uniffi::Object)]
pub struct Sv2ExtranoncePrefixFactoryExtended {
    pub inner: Mutex<ExtendedExtranonce>,
}

#[uniffi::export]
impl Sv2ExtranoncePrefixFactoryExtended {
    /// Create a new Factory for generating unique extranonce_prefix for Sv2 Extended Channels.
    ///
    /// A full Sv2 Extranonce (extranonce_prefix + extranonce) has 32 bytes.
    ///
    /// # Arguments
    ///
    /// * `allocation_size` - How many bytes (out of 32) we want to use for allocation of unique extranonce_prefix
    /// * `static_prefix` - A static prefix to guarantee unique search space allocation across different factories (optional)
    ///
    #[uniffi::constructor]
    pub fn new(
        allocation_size: u32,
        static_prefix: Option<Vec<u8>>,
    ) -> Result<Self, ExtranoncePrefixFactoryError> {
        let range_0 = Range { start: 0, end: 0 };
        let range_1 = Range {
            start: 0,
            end: allocation_size as usize,
        };
        let range_2 = Range {
            start: allocation_size as usize,
            end: FULL_EXTRANONCE_LEN,
        };
        let inner = ExtendedExtranonce::new(range_0, range_1, range_2, static_prefix)
            .map_err(|_| ExtranoncePrefixFactoryError::FailedToCreateExtendedExtranonce)?;

        Ok(Self {
            inner: Mutex::new(inner),
        })
    }

    /// Generate a new unique extranonce_prefix.
    ///
    /// # Arguments
    ///
    /// * `min_required_len` - How many bytes (out of 32) we want to roll during mining, at minimum.
    ///
    pub fn next_extranonce_prefix(
        &self,
        min_required_len: u32,
    ) -> Result<Vec<u8>, ExtranoncePrefixFactoryError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ExtranoncePrefixFactoryError::LockError)?;
        let next_extranonce_prefix = inner
            .next_prefix_extended(min_required_len as usize)
            .map_err(|_| ExtranoncePrefixFactoryError::FailedToCreateExtranoncePrefix)?;
        Ok(next_extranonce_prefix.to_vec())
    }
}

#[derive(uniffi::Object)]
pub struct Sv2ExtranoncePrefixFactoryStandard {
    pub inner: Mutex<ExtendedExtranonce>,
}

#[uniffi::export]
impl Sv2ExtranoncePrefixFactoryStandard {
    /// Create a new Factory for generating unique extranonce_prefix for Sv2 Standard Channels.
    ///
    /// A full Sv2 Extranonce (extranonce_prefix + extranonce) has 32 bytes.
    ///
    /// # Arguments
    ///
    /// * `static_prefix` - A static prefix to guarantee unique search space allocation across different factories (optional)
    ///
    #[uniffi::constructor]
    pub fn new(static_prefix: Option<Vec<u8>>) -> Result<Self, ExtranoncePrefixFactoryError> {
        let range_0 = Range { start: 0, end: 0 };
        let range_1 = Range {
            start: 0,
            end: 1, // this is a workaround while ExtendedExtranonce is used for both standard and extended channels
        };
        let range_2 = Range {
            start: 1, // this is a workaround while ExtendedExtranonce is used for both standard and extended channels
            end: FULL_EXTRANONCE_LEN, // this is a workaround while ExtendedExtranonce is used for both standard and extended channels
        };
        let inner = ExtendedExtranonce::new(range_0, range_1, range_2, static_prefix)
            .map_err(|_| ExtranoncePrefixFactoryError::FailedToCreateExtendedExtranonce)?;
        Ok(Self {
            inner: Mutex::new(inner),
        })
    }

    /// Generate a new unique extranonce_prefix.
    pub fn next_extranonce_prefix(&self) -> Result<Vec<u8>, ExtranoncePrefixFactoryError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| ExtranoncePrefixFactoryError::LockError)?;
        let next_extranonce_prefix = inner
            .next_prefix_standard()
            .map_err(|_| ExtranoncePrefixFactoryError::FailedToCreateExtranoncePrefix)?;
        Ok(next_extranonce_prefix.to_vec())
    }
}

#[derive(Debug, uniffi::Error)]
pub enum ExtranoncePrefixFactoryError {
    LockError,
    PrefixTooLong,
    FailedToCreateExtendedExtranonce,
    FailedToCreateExtranoncePrefix,
}

impl Display for ExtranoncePrefixFactoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
