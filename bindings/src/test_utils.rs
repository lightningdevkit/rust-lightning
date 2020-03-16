macro_rules! assert_match {
    ($bind:pat = $bind_from:expr) => {
        assert_match!($bind = $bind_from => ())
    };
    ($bind:pat = $bind_from:expr => $with:expr) => {
        match $bind_from {
            $bind => $with,
            _ => panic!("assertion failed: unexpected value `{:?}`", $bind_from),
        }
    };
}

pub mod static_assert {
    use std::panic::UnwindSafe;

    pub fn is_sync<T: Sync>() {}
    pub fn is_send<T: Send>() {}

    pub fn is_unwind_safe<T: UnwindSafe>() {}
}
