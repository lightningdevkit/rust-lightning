use std::sync::Arc;
use crate::error::FFIResult;

/// These tests should be used for asserting that the wrapper code can see the expected
/// error messages when it fails (or succeeds).
ffi! {
    fn ffi_test_error() -> FFIResult {
        use std::io;

        FFIResult::internal_error().context(io::Error::new(io::ErrorKind::Other, "A test error."))
    }

    fn ffi_test_ok() -> FFIResult {
        FFIResult::ok()
    }
}

