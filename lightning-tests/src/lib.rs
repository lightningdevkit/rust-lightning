#[cfg_attr(test, macro_use)]
extern crate lightning;

#[cfg(all(test, not(taproot)))]
pub mod upgrade_downgrade_tests;
