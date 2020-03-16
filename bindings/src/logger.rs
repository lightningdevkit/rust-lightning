use crate::adaptors::*;
use crate::handle::{Ref, Out, HandleShared};
use crate::error::FFIResult;
use lightning::util::logger::Logger;

pub type FFILoggerHandle<'a> = HandleShared<'a, FFILogger>;

ffi! {
    fn create_logger(log_ref: Ref<ffilogger_fn::LogExtern>, out: Out<FFILoggerHandle>) -> FFIResult {
        let log = unsafe_block!("" => log_ref.as_ref());
        unsafe_block!("We know logger handle is not null by wrapper macro. And we know `Out` is writable" => out.init(FFILoggerHandle::alloc( FFILogger { log_ptr: *log })));
        FFIResult::ok()
    }

    fn release_logger(handle: FFILoggerHandle) -> FFIResult {
        unsafe_block!("The upstream caller guarantees the handle will not be accessed after being freed" => FFILoggerHandle::dealloc(handle, |mut handle| {
            FFIResult::ok()
        }))
    }
}

use lightning::util::logger::{Record, Level};

use std::fmt::Arguments;
/// Useful for testing low-level interoperability.
#[cfg(debug_assertions)]
ffi! {
    fn test_logger(handle: FFILoggerHandle) -> FFIResult {
        let logger: &FFILogger = unsafe_block!("" => handle.as_ref());
        logger.log(&Record::new(Level::Warn, std::format_args!("{}", "warn_msg"), "module_path", "logger.rs", 29));
        FFIResult::ok()
    }
}
