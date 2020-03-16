/**
Wrap an FFI function.

This macro ensures all arguments satisfy `NotNull::not_null`. It's also a simple way to work
around not having a stable catch expression yet so we can handle early returns from ffi functions.
The macro doesn't support generics or argument patterns that are more complex than simple identifiers.

A more advanced implementation could use a procedural macro, and generate bindings in high-level languages automatically.
*/

macro_rules! ffi {
    (
        $($(#[$meta:meta])*
          fn $name:ident ( $( $arg_ident:ident : $arg_ty:ty),* ) -> FFIResult $body:expr)*) => {
        $(
            $(#[$meta])*
            #[allow(unsafe_code, unused_attributes)]
            #[no_mangle]
            pub unsafe extern "cdecl" fn $name( $($arg_ident : $arg_ty),* ) -> FFIResult {
                #[allow(unused_mut)]
                #[deny(unsafe_code)]
                fn call( $(mut $arg_ident: $arg_ty),* ) -> FFIResult {
                    $(
                        if $crate::is_null::IsNull::is_null(&$arg_ident) {
                            return FFIResult::empty_pointer_provided().context($crate::is_null::Error { arg: stringify!($arg_ident) });
                        }
                    )*

                    $body
                }

                FFIResult::catch(move || call( $($arg_ident),* ))
            }
        )*
    };
}


macro_rules! ffi_no_catch {
    ($(fn $name:ident ( $( $arg_ident:ident : $arg_ty:ty),* ) -> FFIResult $body:expr)*) => {
        $(
            #[allow(unsafe_code, unused_attributes)]
            #[no_mangle]
            pub unsafe extern "cdecl" fn $name( $($arg_ident : $arg_ty),* ) -> FFIResult {
                #[allow(unused_mut)]
                #[deny(unsafe_code)]
                fn call( $(mut $arg_ident: $arg_ty),* ) -> FFIResult {
                    $(
                        if $crate::is_null::IsNull::is_null(&$arg_ident) {
                            return FFIResult::empty_pointer_provided().context($crate::is_null::Error { arg: stringify!($arg_ident) });
                        }
                    )*

                    $body
                }

                call( $($arg_ident),* )
            }
        )*
    };
}

/**
Allow a block of `unsafe` code with a reason.

The macro will expand to an `unsafe` block.
*/
macro_rules! unsafe_block {
    ($reason:tt => $body:expr) => {{
        #[allow(unsafe_code)]
        let __result = unsafe { $body };
        __result
    }};
}

/**
Allow an `unsafe` function with a reason.

The macro will expand to an `unsafe fn`.
*/
macro_rules! unsafe_fn {
    ($reason: tt => fn $name:ident $($body:tt)*) => {
        unsafe_fn!($reason => pub(self) fn $name $($body)*);
    };
    ($reason: tt => $publicity:vis fn $name:ident $($body:tt)*) => {
        #[allow(unsafe_code)]
        $publicity unsafe fn $name $($body)*
    };
}

/**
Allow an `unsafe` trait implementation with a reason.

The macro will expand to an `unsafe impl`.
*/
macro_rules! unsafe_impl {
    ($reason: tt => impl $($body:tt)*) => {
        #[allow(unsafe_code)]
        unsafe impl $($body)*
    };
}