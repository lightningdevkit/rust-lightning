// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Contains LSPS5 webhook notification types
use serde::{Deserialize, Serialize};

pub(crate) const LSPS5_WEBHOOK_REGISTERED_METHOD_NAME: &str = "lsps5.webhook_registered";
pub(crate) const LSPS5_PAYMENT_INCOMING_METHOD_NAME: &str = "lsps5.payment_incoming";
pub(crate) const LSPS5_EXPIRY_SOON_METHOD_NAME: &str = "lsps5.expiry_soon";
pub(crate) const LSPS5_LIQUIDITY_MANAGEMENT_REQUEST_METHOD_NAME: &str =
	"lsps5.liquidity_management_request";
pub(crate) const LSPS5_FEES_CHANGE_INCOMING_METHOD_NAME: &str = "lsps5.fees_change_incoming";
pub(crate) const LSPS5_ONION_MESSAGE_INCOMING_METHOD_NAME: &str = "lsps5.onion_message_incoming";

/// The client has just recently successfully called the lsps5.set_webhook API. Only the newly-(re)registered webhook is notified.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct WebhookRegisteredParams {}

/// The client has one or more payments pending to be received.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct PaymentIncomingParams {}

/// There is an HTLC or other time-bound contract, in either direction, on one of the channels between the client and the LSP,
/// and it is within 24 blocks of being timed out, and the timeout would cause a channel closure
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct ExpirySoonParams {
	/// The blockheight at which the LSP would be forced to close the channel in order to enforce the HTLC or other time-bound contract.
	pub timeout: u32,
}

/// The LSP wants to take back some of the liquidity it has towards the client, for example by closing one or more of the channels it has with the client, or by splicing out.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct LiquidityManagementRequestParams {}

/// The direction of the incoming fee change.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum FeesChangeIncomingDirection {
	/// The incoming fee change will be lower than the current fee.
	Lower,
	/// There are a mix of lower and higher fee changes coming.
	Mixed,
	/// The incoming fee change will be higher than the current fee.
	Higher,
}

/// The LSP wants to change Lightning Network feerates, either for the LSP-to-client channel(s), or for other auto-management services.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct FeesChangeIncomingParams {
	/// A rough estimate of the direction of the fees.
	pub direction: FeesChangeIncomingDirection,
}

/// The client has one or more BOLT Onion Messages pending to be received.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct OnionMessageIncomingParams {}

/// A LPSP5 notification intended to wake-up the client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LSPS5Notification {
	/// The client has just recently successfully called the lsps5.set_webhook API. Only the newly-(re)registered webhook is notified.
	WebhookRegistered(WebhookRegisteredParams),
	/// The client has one or more payments pending to be received.
	PaymentIncoming(PaymentIncomingParams),
	/// There is an HTLC or other time-bound contract, in either direction, on one of the channels between the client and the LSP,
	/// and it is within 24 blocks of being timed out, and the timeout would cause a channel closure
	ExpirySoon(ExpirySoonParams),
	/// The LSP wants to take back some of the liquidity it has towards the client, for example by closing one or more of the channels it has with the client, or by splicing out.
	LiquidityManagementRequest(LiquidityManagementRequestParams),
	/// The LSP wants to change Lightning Network feerates, either for the LSP-to-client channel(s), or for other auto-management services.
	FeesChangeIncoming(FeesChangeIncomingParams),
	/// The client has one or more BOLT Onion Messages pending to be received.
	OnionMessageIncoming(OnionMessageIncomingParams),
}
