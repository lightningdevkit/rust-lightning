//! FFI interface for rust-lightning.

// Unsafe is explicitly allowed through `unsafe_*` macros
#![deny(unsafe_code)]
// For converting rust-lightning results into FFI results
#![feature(try_trait)]
#![feature(backtrace)]

extern crate bitcoin_hashes;
extern crate lightning;

#[cfg(debug_assertions)]
extern crate hex;

#[macro_use]
pub(crate) mod test_utils;
#[macro_use]
pub(crate) mod utils;

#[macro_use]
pub(crate) mod lazy_static;

pub(crate) mod is_null;

mod adaptors;

mod channelmanager;
mod peermanager;
mod blocknotifier;
mod channelmonitor;
mod error;
mod handle;

#[cfg(debug_assertions)]
mod ffi_test_utils;

pub use handle::*;
pub use error::*;

ffi_no_catch! {
    fn ffi_last_result(
        message_buf: Out<u8>,
        message_buf_len: usize,
        actual_message_len: Out<usize>,
        result: Out<FFIResult>
    ) -> FFIResult {
        FFIResult::with_last_result(|last_result| {
            let (value, error) = last_result.unwrap_or((FFIResult::ok(), None));

            unsafe_block!("The out pointer is valid and not mutably aliased elsewhere" => result.init(value));

            if let Some(error) = error {
                let error = error.as_bytes();

                unsafe_block!("The out pointer is valid and not mutably aliased elsewhere" => actual_message_len.init(error.len()));

                if message_buf_len < error.len() {
                    return FFIResult::buffer_too_small();
                }

                unsafe_block!("The buffer is valid for writes and the length is within the buffer" => message_buf.init_bytes(error));
            } else {
                unsafe_block!("The out pointer is valid and not mutably aliased elsewhere" => actual_message_len.init(0));
            }

            FFIResult::ok()
        })
    }
}
