#![crate_name = "lightning"]

extern crate bitcoin;
extern crate crypto;
extern crate rand;
extern crate secp256k1;
#[cfg(test)] extern crate hex;

pub mod chain;
pub mod ln;
pub mod util;
