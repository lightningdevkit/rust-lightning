#![crate_name = "lightning"]

extern crate bitcoin;
extern crate secp256k1;
extern crate rand;
extern crate crypto;
extern crate num; //TODO: Convince andrew to not rely on this for fucking casting...

pub mod chain;
pub mod ln;
pub mod util;
