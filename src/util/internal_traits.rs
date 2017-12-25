/// A simple marker trait that indicates a type requires no deallocation. Implies we can set_len()
/// on a Vec of these things and will be safe to overwrite them with =.
pub unsafe trait NoDealloc {}

/// Just call with test_no_dealloc::<Type>(None)
#[inline]
pub fn test_no_dealloc<T : NoDealloc>(_: Option<T>) { }
