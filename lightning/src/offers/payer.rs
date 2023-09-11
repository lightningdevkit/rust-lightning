// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Data structures and encoding for `invoice_request_metadata` records.

use crate::offers::signer::Metadata;
use crate::util::ser::WithoutLength;

use crate::prelude::*;

/// An unpredictable sequence of bytes typically containing information needed to derive
/// [`InvoiceRequest::payer_id`].
///
/// [`InvoiceRequest::payer_id`]: crate::offers::invoice_request::InvoiceRequest::payer_id
#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub(super) struct PayerContents(pub Metadata);

/// TLV record type for [`InvoiceRequest::payer_metadata`] and [`Refund::payer_metadata`].
///
/// [`InvoiceRequest::payer_metadata`]: crate::offers::invoice_request::InvoiceRequest::payer_metadata
/// [`Refund::payer_metadata`]: crate::offers::refund::Refund::payer_metadata
pub(super) const PAYER_METADATA_TYPE: u64 = 0;

tlv_stream!(PayerTlvStream, PayerTlvStreamRef, 0..1, {
	(PAYER_METADATA_TYPE, metadata: (Vec<u8>, WithoutLength)),
});
