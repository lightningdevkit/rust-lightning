/// Error handling based on refs: https://michael-f-bryan.github.io/rust-ffi-guide/errors/return_types.html

use std::error::Error;
use std::cell::RefCell;
use std::ops::Try;
use std::fmt::Write;
use std::panic::{catch_unwind, UnwindSafe};
use std::any::Any;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::utils::option_extensions::OptionMutExt;

static LAST_ERR_ID: AtomicU32 = AtomicU32::new(0);

fn next_err_id() -> u32 {
    LAST_ERR_ID.fetch_add(1, Ordering::SeqCst)
}

thread_local! {
    static LAST_RESULT: RefCell<Option<LastResult>> = RefCell::new(None);
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FFIResult {
    kind: Kind,
    id: u32,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Ok,
    EmptyPointerProvided,
    InvalidDataLength,
    /// Indicates we have passed byte array from wrapper which is not rust-lightning compatible.
    DeserializationFailure,
    /// Return this when buffer for allocating error message is too small.
    /// When this is the last error, the caller should try to increase the buffer size and call the function again.
    BufferTooSmall,
    InternalError,
}

impl<E> From<E> for FFIResult
    where E:
    Error
{
    fn from(e: E) -> Self {
        FFIResult::internal_error().context(e)
    }
}

/// Allow casting standard `Result` to FFIResult
/// In this way, we assure 
impl Try for FFIResult {
    type Ok = Self;
    type Error = Self;

    fn into_result(self) -> Result<<Self as Try>::Ok, <Self as Try>::Error> {
        match self.kind {
            Kind::Ok => Ok(self),
            _ => Err(self)
        }
    }

    fn from_error(result: Self::Error) -> Self {
        if result.as_err().is_none() {
            panic!(format!("attempted to return success code `{:?}` as an error", result));
        }
        result
    }

    fn from_ok(result: <Self as Try>::Ok) -> Self {
        if result.as_err().is_some() {
            panic!(format!("attempted to return error code `{:?}` as success", result));
        }
        result
    }
}

fn format_error(err: &dyn Error) -> String {
    let mut error_string = String::new();
    let mut source = err.source();
    writeln!(error_string, "Error: {}", err);
    while let Some(parent_err) = source {
        let _ = writeln!(error_string, "Caused by: {}.", parent_err);
        source = parent_err.source();
    }

    if let Some(backtrace) = err.backtrace() {
        let _ = writeln!(error_string, "backtrace: {}", backtrace);
    }
    error_string
}

fn extract_panic(err: &Box<dyn Any + Send + 'static>) -> Option<String> {
    if let Some(e) = err.downcast_ref::<String>() {
        Some(e.to_string())
    } else if let Some(e) = err.downcast_ref::<&'static str>() {
        Some((*e).to_owned())
    } else {
        None
    }
}

impl FFIResult {
    /// FFIResult is not a tagged union, so when an error has occured in rust-lightning side, 
    /// there is no way to return a type safe information to the caller side.
    /// Instead, we set an error message to `LAST_RESULT` so that caller can see the error message.
    pub(super) fn context(self, e: impl Error) -> Self {
        assert!(
            self.as_err().is_some(),
            "context can only be attached to errors"
        );
        let err = Some(format_error(&e));
        LAST_RESULT.with(|last_result| {
            *last_result.borrow_mut() = Some(LastResult { value: self, err, });
        });
        self
    }

    pub(super) fn ok() -> Self {
        FFIResult { kind: Kind::Ok, id: 0 }
    }

    pub fn is_ok(&self) -> bool {
        self.kind == Kind::Ok
    }

    pub(super) fn empty_pointer_provided() -> Self {
        FFIResult { kind: Kind::EmptyPointerProvided, id: next_err_id() }
    }

    pub fn is_empty_pointer_provided(&self) -> bool {
        self.kind == Kind::EmptyPointerProvided
    }

    pub(super) fn deserialization_failure() -> Self {
        FFIResult { kind: Kind::DeserializationFailure, id: next_err_id() }
    }

    pub fn is_deserialization_failure(&self) -> bool {
        self.kind == Kind::DeserializationFailure
    }

    pub(super) fn buffer_too_small() -> Self {
        FFIResult { kind: Kind::BufferTooSmall, id: next_err_id() }
    }

    pub fn is_buffer_too_small(&self) -> bool {
        self.kind == Kind::BufferTooSmall
    }

    pub(super) fn invalid_data_length() -> Self {
        FFIResult { kind: Kind::InvalidDataLength, id: next_err_id() }
    }

    pub fn is_invalid_data_length(&self) -> bool {
        self.kind == Kind::InvalidDataLength
    }

    pub(super) fn internal_error() -> Self {
        FFIResult { kind: Kind::InternalError, id: next_err_id() }
    }

    pub fn is_internal_error(&self) -> bool {
        self.kind == Kind::InternalError
    }

    /// Attempt to get a human-readable error message for a result.
    /// If the result is successful then this method returns `None`.
    pub fn as_err(&self) -> Option<&'static str> {
        match self.kind {
            Kind::Ok => None,
            Kind::EmptyPointerProvided => Some("a required pointer argument was null"),
            Kind::InvalidDataLength => Some("provided data buffer has invalid length"),
            Kind::DeserializationFailure => Some("Failed to deserialize byte array passed to ffi"),
            Kind::InternalError => Some("An internal error occured"),
            Kind::BufferTooSmall => Some("buffer was too small"),
        }
    }


    /// Call a function that returns a `FFIResult`, setting the thread local last result.
    /// This method will also catch panics, so the function to call must be unwind safe.
    pub(super) fn catch(f: impl FnOnce() -> Self + UnwindSafe) -> Self {
        LAST_RESULT.with(|last_result| {
            {
                *last_result.borrow_mut() = None;
            }

            match catch_unwind(f) {
                // when no panic
                Ok(ffi_result) =>  {
                    let extract_err = || ffi_result.as_err().map(Into::into);
                    last_result
                        .borrow_mut()
                        .map_mut(|last_result| {
                            last_result.value = ffi_result;
                            last_result.err.or_else_mut(extract_err);
                        })
                        .get_or_insert_with(|| LastResult {
                            value: ffi_result,
                            err: extract_err(),
                        })
                        .value
                },
                // when panic
                Err(e) => {
                    let extract_panic = || extract_panic(&e).map(|s| format!("Internal panic with {}", s));
                    last_result
                        .borrow_mut()
                        .map_mut(|last_result| {
                            last_result.err.or_else_mut(extract_panic);
                        })
                        .get_or_insert_with(|| LastResult {
                            value: FFIResult::internal_error(),
                            err: extract_panic(),
                        })
                        .value
                },
            }
        })
    }

    /// Access the last result returned on the calling thread.
    /// First argument for the closure is the last FFI result.
    /// Second is its error message (if any).
    pub(super) fn with_last_result<R>(f: impl FnOnce(Option<(FFIResult, Option<&str>)>) -> R) -> R {
        LAST_RESULT.with(|last_result| {
            let last_result = last_result.borrow();
            let last_result_and_its_err_msg = last_result.as_ref().map(|r| {
                let v = r.value;
                let msg = v.as_err().and_then(|_| r.err.as_ref().map(|msg| msg.as_ref()));
                (v, msg)
            });
            f(last_result_and_its_err_msg)
        })
    }
}

#[derive(Debug)]
struct LastResult {
    value: FFIResult,
    err: Option<String>,
}

#[cfg(test)]
mod tests {
    use std::{
        mem,
        fmt,
        thread,
    };
    use std::fmt::Display;
    use super::*;

    use crate::test_utils::*;

    #[derive(Debug)]
    enum TestInnerError {
        Variant
    }

    impl fmt::Display for TestInnerError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str(&format!("{:?}", self))
        }
    }
    impl Error for TestInnerError {}
    #[derive(Debug)]
    enum TestError {
        Variant(TestInnerError)
    }
    impl Display for TestError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str(&format!("{:?}", self))
        }
    }
    impl Error for TestError {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            match *self {
                TestError::Variant(ref inner) => Some(inner),
            }
        }
    }

    #[test]
    fn ffi_result_is_u64_sized() {
        assert_eq!(mem::size_of::<u64>(), mem::size_of::<FFIResult>());
    }

    #[test]
    fn ffi_result_err_is_none_if_kind_is_ok() {
        thread::spawn(|| {
            // Set the last result for this thread
            // Normally you'd return from here
            // But we're just going to leave the error
            let _ = FFIResult::catch(|| {
                FFIResult::internal_error().context(TestInnerError::Variant);
                FFIResult::ok()
            });

            // We should have an error stored
            LAST_RESULT.with(|last_result|{
                let lr = last_result.borrow();
                assert!(lr.as_ref().unwrap().err.is_some());
            });

            // We don't surface that error in with_last_result
            FFIResult::with_last_result(|last_result| {
                let (_, err) = last_result.unwrap();

                assert!(err.is_none());
            });
        })
        .join()
        .unwrap()
    }

    #[test]
    fn last_result_check_ok() {
        let result = FFIResult::catch(|| FFIResult::ok());

        assert_eq!(Kind::Ok, result.kind);

        FFIResult::with_last_result(|last_result| {
            assert_match!(Some((result, err)) = last_result => {
                assert_eq!(Kind::Ok, result.kind);

                assert!(err.is_none());
            });
        });
    }

    #[test]
    fn last_result_catch_err_carrier() {
        let result = FFIResult::catch(|| {
            Err(TestError::Variant(TestInnerError::Variant))?;
            unreachable!()
        });

        assert_eq!(Kind::InternalError, result.kind);

        FFIResult::with_last_result(|last_result| {
            assert_match!(Some((result, err)) = last_result => {
                assert_eq!(Kind::InternalError, result.kind);
                assert!(err.is_some());
            });
        });
    }

    #[test]
    fn last_result_catch_err_return() {
        let result = FFIResult::catch(|| FFIResult::empty_pointer_provided());
        assert_eq!(Kind::EmptyPointerProvided, result.kind);
        FFIResult::with_last_result(|last_result| {
            assert_match!(Some((result, err)) = last_result => {
                assert_eq!(Kind::EmptyPointerProvided, result.kind);
                assert!(err.is_some());
            });
        });
    }

    #[test]
    fn last_result_catch_panic() {
        let result = FFIResult::catch(|| panic!("something didn't work"));
        assert_eq!(Kind::InternalError, result.kind);

        FFIResult::with_last_result(|last_result| {
            assert_match!(Some((result, err)) = last_result => {
                assert_eq!(Kind::InternalError, result.kind);

                assert!(err.is_some());
            });
        });
    }
}