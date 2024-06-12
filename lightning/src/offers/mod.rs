// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Implementation of Lightning Offers
//! ([BOLT 12](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)).
//!
//! Offers are a flexible protocol for Lightning payments.

#[macro_use]
pub mod offer;

pub mod invoice;
pub mod invoice_error;
mod invoice_macros;
pub mod invoice_request;
pub mod merkle;
pub mod parse;
mod payer;
pub mod refund;
pub(crate) mod signer;
#[allow(unused)]
pub(crate) mod static_invoice;
#[cfg(test)]
pub(crate) mod test_utils;
