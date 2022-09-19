// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Data structures and encoding for `invoice_request_metadata` records.

use crate::prelude::*;

/// An unpredictable sequence of bytes typically containing information needed to derive
/// [`InvoiceRequestContents::payer_id`].
///
/// [`InvoiceRequestContents::payer_id`]: invoice_request::InvoiceRequestContents::payer_id
#[derive(Clone, Debug)]
pub(crate) struct PayerContents(pub Option<Vec<u8>>);
