use channels_sv2::extranonce_manager::AllocatedExtranoncePrefix;
use std::sync::{Arc, Mutex};

use crate::channels::extranonce::allocator::Sv2ExtranonceAllocatorError;

#[derive(uniffi::Object)]
pub struct Sv2ExtranoncePrefix {
    /// UniFFI exposes this object as a shared handle, so we cannot move the
    /// inner prefix across the FFI boundary directly. `Option` lets Rust
    /// consume the move-only `AllocatedExtranoncePrefix` exactly once via
    /// `take_inner()`, and report reuse as `PrefixAlreadyConsumed`.
    inner: Mutex<Option<AllocatedExtranoncePrefix>>,
}

impl Sv2ExtranoncePrefix {
    pub(crate) fn from_inner(prefix: AllocatedExtranoncePrefix) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Some(prefix)),
        })
    }

    pub(crate) fn take_inner(
        &self,
    ) -> Result<AllocatedExtranoncePrefix, Sv2ExtranonceAllocatorError> {
        self.inner
            .lock()
            .map_err(|_| Sv2ExtranonceAllocatorError::LockError)?
            .take()
            .ok_or(Sv2ExtranonceAllocatorError::PrefixAlreadyConsumed)
    }
}

#[uniffi::export]
impl Sv2ExtranoncePrefix {
    pub fn as_bytes(&self) -> Result<Vec<u8>, Sv2ExtranonceAllocatorError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| Sv2ExtranonceAllocatorError::LockError)?;
        let prefix = inner
            .as_ref()
            .ok_or(Sv2ExtranonceAllocatorError::PrefixAlreadyConsumed)?;
        Ok(prefix.as_bytes().to_vec())
    }

    pub fn len(&self) -> Result<u32, Sv2ExtranonceAllocatorError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| Sv2ExtranonceAllocatorError::LockError)?;
        let prefix = inner
            .as_ref()
            .ok_or(Sv2ExtranonceAllocatorError::PrefixAlreadyConsumed)?;
        Ok(prefix.len() as u32)
    }

    pub fn is_empty(&self) -> Result<bool, Sv2ExtranonceAllocatorError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| Sv2ExtranonceAllocatorError::LockError)?;
        let prefix = inner
            .as_ref()
            .ok_or(Sv2ExtranonceAllocatorError::PrefixAlreadyConsumed)?;
        Ok(prefix.is_empty())
    }
}
