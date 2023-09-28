// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Signing error types live here.

#[derive(Clone, Debug)]
pub enum SigningError {
    /// The signature is not immediately available from the signer but will be
    /// provided later when the signer is online.
    NotAvailable,
    /// The signer failed permanently and we should attempt to close the
    /// channel.
    PermanentFailure,
}