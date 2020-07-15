pub mod static_assert {
    use std::panic::UnwindSafe;

    pub fn is_sync<T: Sync>() {}
    pub fn is_send<T: Send>() {}

    pub fn is_unwind_safe<T: UnwindSafe>() {}
}
