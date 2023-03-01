// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Data structures and encoding for `invoice_request_metadata` records.

use crate::util::ser::WithoutLength;

use crate::prelude::*;

/// An unpredictable sequence of bytes typically containing information needed to derive
/// [`InvoiceRequest::payer_id`].
///
/// [`InvoiceRequest::payer_id`]: crate::offers::invoice_request::InvoiceRequest::payer_id
#[derive(Clone, Debug, PartialEq)]
pub(super) struct PayerContents(pub Vec<u8>);

tlv_stream!(PayerTlvStream, PayerTlvStreamRef, 0..1, {
	(0, metadata: (Vec<u8>, WithoutLength)),
});
