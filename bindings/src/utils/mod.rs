use crate::{FFIResult, Out};
use lightning::util::ser::{Writeable};
use bitcoin_hashes::core::fmt::Formatter;

#[macro_use]
pub(crate) mod macros;
pub(crate) mod option_extensions;

#[derive(Debug)]
pub enum Error {
    ZeroSizedBuf
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for Error {
}

/// Read an byte array payload to a given buffer.
/// When we want to return a variable length data (i.e. pointer data such as `Vec` or `&[T]`),
/// There is no straightforward way to do so.
/// Usually for a fixed size data, we return a value by writing it to an address
/// given by pointer from the wrapper side. But if the wrapper does not know the actual length
/// we want to return, The data may exceed the buffer that pointer points.
/// So in that case, we will return `FFIResult::BufferTooSmall` with actual length we want to write.
/// The wrapper must call the function again with a pointer points to a longer buffer.
pub (crate) fn into_fixed_buffer<T: Writeable>(
    data: &T,
    buf: &mut [u8],
    actual_value_len: &mut Out<usize>
) -> FFIResult {
    // A zero-sized input buffer will cause an infinite  loop below.
    // if we let it through.
    if buf.len() == 0 {
        Err(Error::ZeroSizedBuf)?;
    }

    let data_vec = data.encode();
    let actual_len = data_vec.len();
    if actual_len > buf.len()
    {
        unsafe_block!("The out pointer is valid and not mutably aliased elsewhere" => actual_value_len.init(actual_len));
        FFIResult::buffer_too_small()
    } else {
        unsafe_block!("The out pointer is valid and not mutably aliased elsewhere" => actual_value_len.init(actual_len));
        let buf = &mut buf[..actual_len];
        buf.copy_from_slice(data_vec.as_ref());
        FFIResult::ok()
    }
}
