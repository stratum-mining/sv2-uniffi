// Helpers shared by the extern functions: pointer checks, borrowed byte
// views and error mapping.

use core::slice;

use crate::{SV2_SRI_ERR_INVALID, SV2_SRI_ERR_TRUNCATED};

/// A borrowed byte range.  Encoders read from it; decoders point it into
/// the payload they were given.  `data` may be NULL when `len` is 0.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2SriBytes {
    pub data: *const u8,
    pub len: u32,
}

impl Sv2SriBytes {
    pub(crate) fn from_slice(s: &[u8]) -> Self {
        Self {
            data: s.as_ptr(),
            len: s.len() as u32,
        }
    }

    pub(crate) const EMPTY: Self = Self {
        data: core::ptr::null(),
        len: 0,
    };

    /// # Safety
    /// `data` must point at `len` readable bytes that outlive `'a`.
    pub(crate) unsafe fn as_slice<'a>(&self) -> Result<&'a [u8], i32> {
        if self.len == 0 {
            return Ok(&[]);
        }
        if self.data.is_null() {
            return Err(SV2_SRI_ERR_INVALID);
        }
        // SAFETY: non-null, and the caller vouches for the length
        Ok(unsafe { slice::from_raw_parts(self.data, self.len as usize) })
    }
}

/// Run the body of an exported function and report a panic as `on_panic`
/// instead of letting it reach C.  Unwinding out of an `extern "C"`
/// function is undefined before Rust 1.81 and aborts the process from
/// 1.81 on; either way a server would lose every connection to one bad
/// input on one of them.  The release profile unwinds for this reason.
/// The panic message still goes to stderr through the default hook.
pub(crate) fn guard<T>(on_panic: T, body: impl FnOnce() -> T) -> T {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)).unwrap_or(on_panic)
}

/// Run a body that reports failure as an error code and fold the result
/// into the single i32 the C side sees.
pub(crate) fn ret(r: Result<i32, i32>) -> i32 {
    match r {
        Ok(v) => v,
        Err(e) => e,
    }
}

/// # Safety
/// `p` must be NULL or point at a valid `T` for `'a`.
pub(crate) unsafe fn obj<'a, T>(p: *const T) -> Result<&'a T, i32> {
    // SAFETY: forwarded to the caller
    unsafe { p.as_ref() }.ok_or(SV2_SRI_ERR_INVALID)
}

/// # Safety
/// `p` must be NULL or point at a writable `T` for `'a`.
pub(crate) unsafe fn obj_mut<'a, T>(p: *mut T) -> Result<&'a mut T, i32> {
    // SAFETY: forwarded to the caller
    unsafe { p.as_mut() }.ok_or(SV2_SRI_ERR_INVALID)
}

/// # Safety
/// `p` must be NULL or point at `len` readable bytes for `'a`.
pub(crate) unsafe fn input<'a>(p: *const u8, len: usize) -> Result<&'a [u8], i32> {
    if len == 0 {
        return Ok(&[]);
    }
    if p.is_null() {
        return Err(SV2_SRI_ERR_INVALID);
    }
    // SAFETY: forwarded to the caller
    Ok(unsafe { slice::from_raw_parts(p, len) })
}

/// # Safety
/// `p` must be NULL or point at `len` writable bytes for `'a`, not aliased
/// by anything else during the call.
pub(crate) unsafe fn output<'a>(p: *mut u8, len: usize) -> Result<&'a mut [u8], i32> {
    if len == 0 {
        return Ok(&mut []);
    }
    if p.is_null() {
        return Err(SV2_SRI_ERR_INVALID);
    }
    // SAFETY: forwarded to the caller
    Ok(unsafe { slice::from_raw_parts_mut(p, len) })
}

/// binary_sv2 reports a short buffer in several ways; everything else is a
/// malformed value.
pub(crate) fn binary_err(e: binary_sv2::Error) -> i32 {
    match e {
        binary_sv2::Error::OutOfBound
        | binary_sv2::Error::ReadError(_, _)
        | binary_sv2::Error::DecodableConversionError => SV2_SRI_ERR_TRUNCATED,
        _ => SV2_SRI_ERR_INVALID,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SV2_SRI_ERR_INTERNAL;

    #[test]
    fn a_panic_becomes_the_fallback_value() {
        assert_eq!(guard(SV2_SRI_ERR_INTERNAL, || 7), 7);
        assert_eq!(
            guard(SV2_SRI_ERR_INTERNAL, || -> i32 { panic!("from a crate") }),
            SV2_SRI_ERR_INTERNAL
        );
        let p: *mut u8 = guard(core::ptr::null_mut(), || panic!("in a constructor"));
        assert!(p.is_null());
    }
}
