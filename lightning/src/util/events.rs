// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Events are returned from various bits in the library which indicate some action must be taken
//! by the client.
//!
//! Because we don't have a built-in runtime, it's up to the client to call events at a time in the
//! future, as well as generate and broadcast funding transactions handle payment preimages and a
//! few other things.

use chain::keysinterface::SpendableOutputDescriptor;
use ln::channelmanager::PaymentId;
use ln::channel::FUNDING_CONF_DEADLINE_BLOCKS;
use ln::msgs;
use ln::msgs::DecodeError;
use ln::{PaymentPreimage, PaymentHash, PaymentSecret};
use routing::network_graph::NetworkUpdate;
use util::ser::{BigSize, FixedLengthReader, Writeable, Writer, MaybeReadable, Readable, VecReadWrapper, VecWriteWrapper};
use routing::router::{RouteHop, RouteParameters};

use bitcoin::Transaction;
use bitcoin::blockdata::script::Script;
use bitcoin::hashes::Hash;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::secp256k1::key::PublicKey;

use io;
use prelude::*;
use core::time::Duration;
use core::ops::Deref;
use sync::Arc;

/// Some information provided on receipt of payment depends on whether the payment received is a
/// spontaneous payment or a "conventional" lightning payment that's paying an invoice.
#[derive(Clone, Debug)]
pub enum PaymentPurpose {
	/// Information for receiving a payment that we generated an invoice for.
	InvoicePayment {
		/// The preimage to the payment_hash, if the payment hash (and secret) were fetched via
		/// [`ChannelManager::create_inbound_payment`]. If provided, this can be handed directly to
		/// [`ChannelManager::claim_funds`].
		///
		/// [`ChannelManager::create_inbound_payment`]: crate::ln::channelmanager::ChannelManager::create_inbound_payment
		/// [`ChannelManager::claim_funds`]: crate::ln::channelmanager::ChannelManager::claim_funds
		payment_preimage: Option<PaymentPreimage>,
		/// The "payment secret". This authenticates the sender to the recipient, preventing a
		/// number of deanonymization attacks during the routing process.
		/// It is provided here for your reference, however its accuracy is enforced directly by
		/// [`ChannelManager`] using the values you previously provided to
		/// [`ChannelManager::create_inbound_payment`] or
		/// [`ChannelManager::create_inbound_payment_for_hash`].
		///
		/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
		/// [`ChannelManager::create_inbound_payment`]: crate::ln::channelmanager::ChannelManager::create_inbound_payment
		/// [`ChannelManager::create_inbound_payment_for_hash`]: crate::ln::channelmanager::ChannelManager::create_inbound_payment_for_hash
		payment_secret: PaymentSecret,
	},
	/// Because this is a spontaneous payment, the payer generated their own preimage rather than us
	/// (the payee) providing a preimage.
	SpontaneousPayment(PaymentPreimage),
}

#[derive(Clone, Debug, PartialEq)]
/// The reason the channel was closed. See individual variants more details.
pub enum ClosureReason {
	/// Closure generated from receiving a peer error message.
	///
	/// Our counterparty may have broadcasted their latest commitment state, and we have
	/// as well.
	CounterpartyForceClosed {
		/// The error which the peer sent us.
		///
		/// The string should be sanitized before it is used (e.g emitted to logs
		/// or printed to stdout). Otherwise, a well crafted error message may exploit
		/// a security vulnerability in the terminal emulator or the logging subsystem.
		peer_msg: String,
	},
	/// Closure generated from [`ChannelManager::force_close_channel`], called by the user.
	///
	/// [`ChannelManager::force_close_channel`]: crate::ln::channelmanager::ChannelManager::force_close_channel.
	HolderForceClosed,
	/// The channel was closed after negotiating a cooperative close and we've now broadcasted
	/// the cooperative close transaction. Note the shutdown may have been initiated by us.
	//TODO: split between CounterpartyInitiated/LocallyInitiated
	CooperativeClosure,
	/// A commitment transaction was confirmed on chain, closing the channel. Most likely this
	/// commitment transaction came from our counterparty, but it may also have come from
	/// a copy of our own `ChannelMonitor`.
	CommitmentTxConfirmed,
	/// The funding transaction failed to confirm in a timely manner on an inbound channel.
	FundingTimedOut,
	/// Closure generated from processing an event, likely a HTLC forward/relay/reception.
	ProcessingError {
		/// A developer-readable error message which we generated.
		err: String,
	},
	/// The `PeerManager` informed us that we've disconnected from the peer. We close channels
	/// if the `PeerManager` informed us that it is unlikely we'll be able to connect to the
	/// peer again in the future or if the peer disconnected before we finished negotiating
	/// the channel open. The first case may be caused by incompatible features which our
	/// counterparty, or we, require.
	//TODO: split between PeerUnconnectable/PeerDisconnected ?
	DisconnectedPeer,
	/// Closure generated from `ChannelManager::read` if the ChannelMonitor is newer than
	/// the ChannelManager deserialized.
	OutdatedChannelManager
}

impl core::fmt::Display for ClosureReason {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
		f.write_str("Channel closed because ")?;
		match self {
			ClosureReason::CounterpartyForceClosed { peer_msg } => {
				f.write_str("counterparty force-closed with message ")?;
				f.write_str(&peer_msg)
			},
			ClosureReason::HolderForceClosed => f.write_str("user manually force-closed the channel"),
			ClosureReason::CooperativeClosure => f.write_str("the channel was cooperatively closed"),
			ClosureReason::CommitmentTxConfirmed => f.write_str("commitment or closing transaction was confirmed on chain."),
			ClosureReason::FundingTimedOut => write!(f, "funding transaction failed to confirm within {} blocks", FUNDING_CONF_DEADLINE_BLOCKS),
			ClosureReason::ProcessingError { err } => {
				f.write_str("of an exception: ")?;
				f.write_str(&err)
			},
			ClosureReason::DisconnectedPeer => f.write_str("the peer disconnected prior to the channel being funded"),
			ClosureReason::OutdatedChannelManager => f.write_str("the ChannelManager read from disk was stale compared to ChannelMonitor(s)"),
		}
	}
}

impl_writeable_tlv_based_enum_upgradable!(ClosureReason,
	(0, CounterpartyForceClosed) => { (1, peer_msg, required) },
	(1, FundingTimedOut) => {},
	(2, HolderForceClosed) => {},
	(6, CommitmentTxConfirmed) => {},
	(4, CooperativeClosure) => {},
	(8, ProcessingError) => { (1, err, required) },
	(10, DisconnectedPeer) => {},
	(12, OutdatedChannelManager) => {},
);

/// An Event which you should probably take some action in response to.
///
/// Note that while Writeable and Readable are implemented for Event, you probably shouldn't use
/// them directly as they don't round-trip exactly (for example FundingGenerationReady is never
/// written as it makes no sense to respond to it after reconnecting to peers).
#[derive(Clone, Debug)]
pub enum Event {
	/// Used to indicate that the client should generate a funding transaction with the given
	/// parameters and then call ChannelManager::funding_transaction_generated.
	/// Generated in ChannelManager message handling.
	/// Note that *all inputs* in the funding transaction must spend SegWit outputs or your
	/// counterparty can steal your funds!
	FundingGenerationReady {
		/// The random channel_id we picked which you'll need to pass into
		/// ChannelManager::funding_transaction_generated.
		temporary_channel_id: [u8; 32],
		/// The value, in satoshis, that the output should have.
		channel_value_satoshis: u64,
		/// The script which should be used in the transaction output.
		output_script: Script,
		/// The `user_channel_id` value passed in to [`ChannelManager::create_channel`], or 0 for
		/// an inbound channel.
		///
		/// [`ChannelManager::create_channel`]: crate::ln::channelmanager::ChannelManager::create_channel
		user_channel_id: u64,
	},
	/// Indicates we've received money! Just gotta dig out that payment preimage and feed it to
	/// [`ChannelManager::claim_funds`] to get it....
	/// Note that if the preimage is not known, you should call
	/// [`ChannelManager::fail_htlc_backwards`] to free up resources for this HTLC and avoid
	/// network congestion.
	/// If you fail to call either [`ChannelManager::claim_funds`] or
	/// [`ChannelManager::fail_htlc_backwards`] within the HTLC's timeout, the HTLC will be
	/// automatically failed.
	///
	/// [`ChannelManager::claim_funds`]: crate::ln::channelmanager::ChannelManager::claim_funds
	/// [`ChannelManager::fail_htlc_backwards`]: crate::ln::channelmanager::ChannelManager::fail_htlc_backwards
	PaymentReceived {
		/// The hash for which the preimage should be handed to the ChannelManager.
		payment_hash: PaymentHash,
		/// The value, in thousandths of a satoshi, that this payment is for.
		amt: u64,
		/// Information for claiming this received payment, based on whether the purpose of the
		/// payment is to pay an invoice or to send a spontaneous payment.
		purpose: PaymentPurpose,
	},
	/// Indicates an outbound payment we made succeeded (i.e. it made it all the way to its target
	/// and we got back the payment preimage for it).
	///
	/// Note for MPP payments: in rare cases, this event may be preceded by a `PaymentPathFailed`
	/// event. In this situation, you SHOULD treat this payment as having succeeded.
	PaymentSent {
		/// The id returned by [`ChannelManager::send_payment`] and used with
		/// [`ChannelManager::retry_payment`].
		///
		/// [`ChannelManager::send_payment`]: crate::ln::channelmanager::ChannelManager::send_payment
		/// [`ChannelManager::retry_payment`]: crate::ln::channelmanager::ChannelManager::retry_payment
		payment_id: Option<PaymentId>,
		/// The preimage to the hash given to ChannelManager::send_payment.
		/// Note that this serves as a payment receipt, if you wish to have such a thing, you must
		/// store it somehow!
		payment_preimage: PaymentPreimage,
		/// The hash that was given to [`ChannelManager::send_payment`].
		///
		/// [`ChannelManager::send_payment`]: crate::ln::channelmanager::ChannelManager::send_payment
		payment_hash: PaymentHash,
		/// The total fee which was spent at intermediate hops in this payment, across all paths.
		///
		/// Note that, like [`Route::get_total_fees`] this does *not* include any potential
		/// overpayment to the recipient node.
		///
		/// If the recipient or an intermediate node misbehaves and gives us free money, this may
		/// overstate the amount paid, though this is unlikely.
		///
		/// [`Route::get_total_fees`]: crate::routing::router::Route::get_total_fees
		fee_paid_msat: Option<u64>,
	},
	/// Indicates an outbound payment we made failed. Probably some intermediary node dropped
	/// something. You may wish to retry with a different route.
	PaymentPathFailed {
		/// The id returned by [`ChannelManager::send_payment`] and used with
		/// [`ChannelManager::retry_payment`].
		///
		/// [`ChannelManager::send_payment`]: crate::ln::channelmanager::ChannelManager::send_payment
		/// [`ChannelManager::retry_payment`]: crate::ln::channelmanager::ChannelManager::retry_payment
		payment_id: Option<PaymentId>,
		/// The hash that was given to [`ChannelManager::send_payment`].
		///
		/// [`ChannelManager::send_payment`]: crate::ln::channelmanager::ChannelManager::send_payment
		payment_hash: PaymentHash,
		/// Indicates the payment was rejected for some reason by the recipient. This implies that
		/// the payment has failed, not just the route in question. If this is not set, you may
		/// retry the payment via a different route.
		rejected_by_dest: bool,
		/// Any failure information conveyed via the Onion return packet by a node along the failed
		/// payment route.
		///
		/// Should be applied to the [`NetworkGraph`] so that routing decisions can take into
		/// account the update. [`NetGraphMsgHandler`] is capable of doing this.
		///
		/// [`NetworkGraph`]: crate::routing::network_graph::NetworkGraph
		/// [`NetGraphMsgHandler`]: crate::routing::network_graph::NetGraphMsgHandler
		network_update: Option<NetworkUpdate>,
		/// For both single-path and multi-path payments, this is set if all paths of the payment have
		/// failed. This will be set to false if (1) this is an MPP payment and (2) other parts of the
		/// larger MPP payment were still in flight when this event was generated.
		all_paths_failed: bool,
		/// The payment path that failed.
		path: Vec<RouteHop>,
		/// The channel responsible for the failed payment path.
		///
		/// If this is `Some`, then the corresponding channel should be avoided when the payment is
		/// retried. May be `None` for older [`Event`] serializations.
		short_channel_id: Option<u64>,
		/// Parameters needed to compute a new [`Route`] when retrying the failed payment path.
		///
		/// See [`find_route`] for details.
		///
		/// [`Route`]: crate::routing::router::Route
		/// [`find_route`]: crate::routing::router::find_route
		retry: Option<RouteParameters>,
#[cfg(test)]
		error_code: Option<u16>,
#[cfg(test)]
		error_data: Option<Vec<u8>>,
	},
	/// Used to indicate that ChannelManager::process_pending_htlc_forwards should be called at a
	/// time in the future.
	PendingHTLCsForwardable {
		/// The minimum amount of time that should be waited prior to calling
		/// process_pending_htlc_forwards. To increase the effort required to correlate payments,
		/// you should wait a random amount of time in roughly the range (now + time_forwardable,
		/// now + 5*time_forwardable).
		time_forwardable: Duration,
	},
	/// Used to indicate that an output which you should know how to spend was confirmed on chain
	/// and is now spendable.
	/// Such an output will *not* ever be spent by rust-lightning, and are not at risk of your
	/// counterparty spending them due to some kind of timeout. Thus, you need to store them
	/// somewhere and spend them when you create on-chain transactions.
	SpendableOutputs {
		/// The outputs which you should store as spendable by you.
		outputs: Vec<SpendableOutputDescriptor>,
	},
	/// This event is generated when a payment has been successfully forwarded through us and a
	/// forwarding fee earned.
	PaymentForwarded {
		/// The fee, in milli-satoshis, which was earned as a result of the payment.
		///
		/// Note that if we force-closed the channel over which we forwarded an HTLC while the HTLC
		/// was pending, the amount the next hop claimed will have been rounded down to the nearest
		/// whole satoshi. Thus, the fee calculated here may be higher than expected as we still
		/// claimed the full value in millisatoshis from the source. In this case,
		/// `claim_from_onchain_tx` will be set.
		///
		/// If the channel which sent us the payment has been force-closed, we will claim the funds
		/// via an on-chain transaction. In that case we do not yet know the on-chain transaction
		/// fees which we will spend and will instead set this to `None`. It is possible duplicate
		/// `PaymentForwarded` events are generated for the same payment iff `fee_earned_msat` is
		/// `None`.
		fee_earned_msat: Option<u64>,
		/// If this is `true`, the forwarded HTLC was claimed by our counterparty via an on-chain
		/// transaction.
		claim_from_onchain_tx: bool,
	},
	/// Used to indicate that a channel with the given `channel_id` is in the process of closure.
	ChannelClosed  {
		/// The channel_id of the channel which has been closed. Note that on-chain transactions
		/// resolving the channel are likely still awaiting confirmation.
		channel_id: [u8; 32],
		/// The `user_channel_id` value passed in to [`ChannelManager::create_channel`], or 0 for
		/// an inbound channel. This will always be zero for objects serialized with LDK versions
		/// prior to 0.0.102.
		///
		/// [`ChannelManager::create_channel`]: crate::ln::channelmanager::ChannelManager::create_channel
		user_channel_id: u64,
		/// The reason the channel was closed.
		reason: ClosureReason
	},
	/// Used to indicate to the user that they can abandon the funding transaction and recycle the
	/// inputs for another purpose.
	DiscardFunding {
		/// The channel_id of the channel which has been closed.
		channel_id: [u8; 32],
		/// The full transaction received from the user
		transaction: Transaction
	},
	/// Indicates that a path for an outbound payment was successful.
	///
	/// Always generated after [`Event::PaymentSent`] and thus useful for scoring channels. See
	/// [`Event::PaymentSent`] for obtaining the payment preimage.
	PaymentPathSuccessful {
		/// The id returned by [`ChannelManager::send_payment`] and used with
		/// [`ChannelManager::retry_payment`].
		///
		/// [`ChannelManager::send_payment`]: crate::ln::channelmanager::ChannelManager::send_payment
		/// [`ChannelManager::retry_payment`]: crate::ln::channelmanager::ChannelManager::retry_payment
		payment_id: PaymentId,
		/// The hash that was given to [`ChannelManager::send_payment`].
		///
		/// [`ChannelManager::send_payment`]: crate::ln::channelmanager::ChannelManager::send_payment
		payment_hash: Option<PaymentHash>,
		/// The payment path that was successful.
		///
		/// May contain a closed channel if the HTLC sent along the path was fulfilled on chain.
		path: Vec<RouteHop>,
	},
}

impl Writeable for Event {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		match self {
			&Event::FundingGenerationReady { .. } => {
				0u8.write(writer)?;
				// We never write out FundingGenerationReady events as, upon disconnection, peers
				// drop any channels which have not yet exchanged funding_signed.
			},
			&Event::PaymentReceived { ref payment_hash, ref amt, ref purpose } => {
				1u8.write(writer)?;
				let mut payment_secret = None;
				let payment_preimage;
				match &purpose {
					PaymentPurpose::InvoicePayment { payment_preimage: preimage, payment_secret: secret } => {
						payment_secret = Some(secret);
						payment_preimage = *preimage;
					},
					PaymentPurpose::SpontaneousPayment(preimage) => {
						payment_preimage = Some(*preimage);
					}
				}
				write_tlv_fields!(writer, {
					(0, payment_hash, required),
					(2, payment_secret, option),
					(4, amt, required),
					(6, 0u64, required), // user_payment_id required for compatibility with 0.0.103 and earlier
					(8, payment_preimage, option),
				});
			},
			&Event::PaymentSent { ref payment_id, ref payment_preimage, ref payment_hash, ref fee_paid_msat } => {
				2u8.write(writer)?;
				write_tlv_fields!(writer, {
					(0, payment_preimage, required),
					(1, payment_hash, required),
					(3, payment_id, option),
					(5, fee_paid_msat, option),
				});
			},
			&Event::PaymentPathFailed {
				ref payment_id, ref payment_hash, ref rejected_by_dest, ref network_update,
				ref all_paths_failed, ref path, ref short_channel_id, ref retry,
				#[cfg(test)]
				ref error_code,
				#[cfg(test)]
				ref error_data,
			} => {
				3u8.write(writer)?;
				#[cfg(test)]
				error_code.write(writer)?;
				#[cfg(test)]
				error_data.write(writer)?;
				write_tlv_fields!(writer, {
					(0, payment_hash, required),
					(1, network_update, option),
					(2, rejected_by_dest, required),
					(3, all_paths_failed, required),
					(5, path, vec_type),
					(7, short_channel_id, option),
					(9, retry, option),
					(11, payment_id, option),
				});
			},
			&Event::PendingHTLCsForwardable { time_forwardable: _ } => {
				4u8.write(writer)?;
				// Note that we now ignore these on the read end as we'll re-generate them in
				// ChannelManager, we write them here only for backwards compatibility.
			},
			&Event::SpendableOutputs { ref outputs } => {
				5u8.write(writer)?;
				write_tlv_fields!(writer, {
					(0, VecWriteWrapper(outputs), required),
				});
			},
			&Event::PaymentForwarded { fee_earned_msat, claim_from_onchain_tx } => {
				7u8.write(writer)?;
				write_tlv_fields!(writer, {
					(0, fee_earned_msat, option),
					(2, claim_from_onchain_tx, required),
				});
			},
			&Event::ChannelClosed { ref channel_id, ref user_channel_id, ref reason } => {
				9u8.write(writer)?;
				write_tlv_fields!(writer, {
					(0, channel_id, required),
					(1, user_channel_id, required),
					(2, reason, required)
				});
			},
			&Event::DiscardFunding { ref channel_id, ref transaction } => {
				11u8.write(writer)?;
				write_tlv_fields!(writer, {
					(0, channel_id, required),
					(2, transaction, required)
				})
			},
			&Event::PaymentPathSuccessful { ref payment_id, ref payment_hash, ref path } => {
				13u8.write(writer)?;
				write_tlv_fields!(writer, {
					(0, payment_id, required),
					(2, payment_hash, option),
					(4, path, vec_type)
				})
			},
			// Note that, going forward, all new events must only write data inside of
			// `write_tlv_fields`. Versions 0.0.101+ will ignore odd-numbered events that write
			// data via `write_tlv_fields`.
		}
		Ok(())
	}
}
impl MaybeReadable for Event {
	fn read<R: io::Read>(reader: &mut R) -> Result<Option<Self>, msgs::DecodeError> {
		match Readable::read(reader)? {
			// Note that we do not write a length-prefixed TLV for FundingGenerationReady events,
			// unlike all other events, thus we return immediately here.
			0u8 => Ok(None),
			1u8 => {
				let f = || {
					let mut payment_hash = PaymentHash([0; 32]);
					let mut payment_preimage = None;
					let mut payment_secret = None;
					let mut amt = 0;
					let mut _user_payment_id = None::<u64>; // For compatibility with 0.0.103 and earlier
					read_tlv_fields!(reader, {
						(0, payment_hash, required),
						(2, payment_secret, option),
						(4, amt, required),
						(6, _user_payment_id, option),
						(8, payment_preimage, option),
					});
					let purpose = match payment_secret {
						Some(secret) => PaymentPurpose::InvoicePayment {
							payment_preimage,
							payment_secret: secret
						},
						None if payment_preimage.is_some() => PaymentPurpose::SpontaneousPayment(payment_preimage.unwrap()),
						None => return Err(msgs::DecodeError::InvalidValue),
					};
					Ok(Some(Event::PaymentReceived {
						payment_hash,
						amt,
						purpose,
					}))
				};
				f()
			},
			2u8 => {
				let f = || {
					let mut payment_preimage = PaymentPreimage([0; 32]);
					let mut payment_hash = None;
					let mut payment_id = None;
					let mut fee_paid_msat = None;
					read_tlv_fields!(reader, {
						(0, payment_preimage, required),
						(1, payment_hash, option),
						(3, payment_id, option),
						(5, fee_paid_msat, option),
					});
					if payment_hash.is_none() {
						payment_hash = Some(PaymentHash(Sha256::hash(&payment_preimage.0[..]).into_inner()));
					}
					Ok(Some(Event::PaymentSent {
						payment_id,
						payment_preimage,
						payment_hash: payment_hash.unwrap(),
						fee_paid_msat,
					}))
				};
				f()
			},
			3u8 => {
				let f = || {
					#[cfg(test)]
					let error_code = Readable::read(reader)?;
					#[cfg(test)]
					let error_data = Readable::read(reader)?;
					let mut payment_hash = PaymentHash([0; 32]);
					let mut rejected_by_dest = false;
					let mut network_update = None;
					let mut all_paths_failed = Some(true);
					let mut path: Option<Vec<RouteHop>> = Some(vec![]);
					let mut short_channel_id = None;
					let mut retry = None;
					let mut payment_id = None;
					read_tlv_fields!(reader, {
						(0, payment_hash, required),
						(1, network_update, ignorable),
						(2, rejected_by_dest, required),
						(3, all_paths_failed, option),
						(5, path, vec_type),
						(7, short_channel_id, option),
						(9, retry, option),
						(11, payment_id, option),
					});
					Ok(Some(Event::PaymentPathFailed {
						payment_id,
						payment_hash,
						rejected_by_dest,
						network_update,
						all_paths_failed: all_paths_failed.unwrap(),
						path: path.unwrap(),
						short_channel_id,
						retry,
						#[cfg(test)]
						error_code,
						#[cfg(test)]
						error_data,
					}))
				};
				f()
			},
			4u8 => Ok(None),
			5u8 => {
				let f = || {
					let mut outputs = VecReadWrapper(Vec::new());
					read_tlv_fields!(reader, {
						(0, outputs, required),
					});
					Ok(Some(Event::SpendableOutputs { outputs: outputs.0 }))
				};
				f()
			},
			7u8 => {
				let f = || {
					let mut fee_earned_msat = None;
					let mut claim_from_onchain_tx = false;
					read_tlv_fields!(reader, {
						(0, fee_earned_msat, option),
						(2, claim_from_onchain_tx, required),
					});
					Ok(Some(Event::PaymentForwarded { fee_earned_msat, claim_from_onchain_tx }))
				};
				f()
			},
			9u8 => {
				let f = || {
					let mut channel_id = [0; 32];
					let mut reason = None;
					let mut user_channel_id_opt = None;
					read_tlv_fields!(reader, {
						(0, channel_id, required),
						(1, user_channel_id_opt, option),
						(2, reason, ignorable),
					});
					if reason.is_none() { return Ok(None); }
					let user_channel_id = if let Some(id) = user_channel_id_opt { id } else { 0 };
					Ok(Some(Event::ChannelClosed { channel_id, user_channel_id, reason: reason.unwrap() }))
				};
				f()
			},
			11u8 => {
				let f = || {
					let mut channel_id = [0; 32];
					let mut transaction = Transaction{ version: 2, lock_time: 0, input: Vec::new(), output: Vec::new() };
					read_tlv_fields!(reader, {
						(0, channel_id, required),
						(2, transaction, required),
					});
					Ok(Some(Event::DiscardFunding { channel_id, transaction } ))
				};
				f()
			},
			13u8 => {
				let f = || {
					let mut payment_id = PaymentId([0; 32]);
					let mut payment_hash = None;
					let mut path: Option<Vec<RouteHop>> = Some(vec![]);
					read_tlv_fields!(reader, {
						(0, payment_id, required),
						(2, payment_hash, option),
						(4, path, vec_type),
					});
					Ok(Some(Event::PaymentPathSuccessful {
						payment_id,
						payment_hash,
						path: path.unwrap(),
					}))
				};
				f()
			},
			// Versions prior to 0.0.100 did not ignore odd types, instead returning InvalidValue.
			// Version 0.0.100 failed to properly ignore odd types, possibly resulting in corrupt
			// reads.
			x if x % 2 == 1 => {
				// If the event is of unknown type, assume it was written with `write_tlv_fields`,
				// which prefixes the whole thing with a length BigSize. Because the event is
				// odd-type unknown, we should treat it as `Ok(None)` even if it has some TLV
				// fields that are even. Thus, we avoid using `read_tlv_fields` and simply read
				// exactly the number of bytes specified, ignoring them entirely.
				let tlv_len: BigSize = Readable::read(reader)?;
				FixedLengthReader::new(reader, tlv_len.0)
					.eat_remaining().map_err(|_| msgs::DecodeError::ShortRead)?;
				Ok(None)
			},
			_ => Err(msgs::DecodeError::InvalidValue)
		}
	}
}

/// An event generated by ChannelManager which indicates a message should be sent to a peer (or
/// broadcast to most peers).
/// These events are handled by PeerManager::process_events if you are using a PeerManager.
#[derive(Clone, Debug)]
pub enum MessageSendEvent {
	/// Used to indicate that we've accepted a channel open and should send the accept_channel
	/// message provided to the given peer.
	SendAcceptChannel {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The message which should be sent.
		msg: msgs::AcceptChannel,
	},
	/// Used to indicate that we've initiated a channel open and should send the open_channel
	/// message provided to the given peer.
	SendOpenChannel {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The message which should be sent.
		msg: msgs::OpenChannel,
	},
	/// Used to indicate that a funding_created message should be sent to the peer with the given node_id.
	SendFundingCreated {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The message which should be sent.
		msg: msgs::FundingCreated,
	},
	/// Used to indicate that a funding_signed message should be sent to the peer with the given node_id.
	SendFundingSigned {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The message which should be sent.
		msg: msgs::FundingSigned,
	},
	/// Used to indicate that a funding_locked message should be sent to the peer with the given node_id.
	SendFundingLocked {
		/// The node_id of the node which should receive these message(s)
		node_id: PublicKey,
		/// The funding_locked message which should be sent.
		msg: msgs::FundingLocked,
	},
	/// Used to indicate that an announcement_signatures message should be sent to the peer with the given node_id.
	SendAnnouncementSignatures {
		/// The node_id of the node which should receive these message(s)
		node_id: PublicKey,
		/// The announcement_signatures message which should be sent.
		msg: msgs::AnnouncementSignatures,
	},
	/// Used to indicate that a series of HTLC update messages, as well as a commitment_signed
	/// message should be sent to the peer with the given node_id.
	UpdateHTLCs {
		/// The node_id of the node which should receive these message(s)
		node_id: PublicKey,
		/// The update messages which should be sent. ALL messages in the struct should be sent!
		updates: msgs::CommitmentUpdate,
	},
	/// Used to indicate that a revoke_and_ack message should be sent to the peer with the given node_id.
	SendRevokeAndACK {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The message which should be sent.
		msg: msgs::RevokeAndACK,
	},
	/// Used to indicate that a closing_signed message should be sent to the peer with the given node_id.
	SendClosingSigned {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The message which should be sent.
		msg: msgs::ClosingSigned,
	},
	/// Used to indicate that a shutdown message should be sent to the peer with the given node_id.
	SendShutdown {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The message which should be sent.
		msg: msgs::Shutdown,
	},
	/// Used to indicate that a channel_reestablish message should be sent to the peer with the given node_id.
	SendChannelReestablish {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The message which should be sent.
		msg: msgs::ChannelReestablish,
	},
	/// Used to indicate that a channel_announcement and channel_update should be broadcast to all
	/// peers (except the peer with node_id either msg.contents.node_id_1 or msg.contents.node_id_2).
	///
	/// Note that after doing so, you very likely (unless you did so very recently) want to call
	/// ChannelManager::broadcast_node_announcement to trigger a BroadcastNodeAnnouncement event.
	/// This ensures that any nodes which see our channel_announcement also have a relevant
	/// node_announcement, including relevant feature flags which may be important for routing
	/// through or to us.
	BroadcastChannelAnnouncement {
		/// The channel_announcement which should be sent.
		msg: msgs::ChannelAnnouncement,
		/// The followup channel_update which should be sent.
		update_msg: msgs::ChannelUpdate,
	},
	/// Used to indicate that a node_announcement should be broadcast to all peers.
	BroadcastNodeAnnouncement {
		/// The node_announcement which should be sent.
		msg: msgs::NodeAnnouncement,
	},
	/// Used to indicate that a channel_update should be broadcast to all peers.
	BroadcastChannelUpdate {
		/// The channel_update which should be sent.
		msg: msgs::ChannelUpdate,
	},
	/// Used to indicate that a channel_update should be sent to a single peer.
	/// In contrast to [`Self::BroadcastChannelUpdate`], this is used when the channel is a
	/// private channel and we shouldn't be informing all of our peers of channel parameters.
	SendChannelUpdate {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The channel_update which should be sent.
		msg: msgs::ChannelUpdate,
	},
	/// Broadcast an error downstream to be handled
	HandleError {
		/// The node_id of the node which should receive this message
		node_id: PublicKey,
		/// The action which should be taken.
		action: msgs::ErrorAction
	},
	/// Query a peer for channels with funding transaction UTXOs in a block range.
	SendChannelRangeQuery {
		/// The node_id of this message recipient
		node_id: PublicKey,
		/// The query_channel_range which should be sent.
		msg: msgs::QueryChannelRange,
	},
	/// Request routing gossip messages from a peer for a list of channels identified by
	/// their short_channel_ids.
	SendShortIdsQuery {
		/// The node_id of this message recipient
		node_id: PublicKey,
		/// The query_short_channel_ids which should be sent.
		msg: msgs::QueryShortChannelIds,
	},
	/// Sends a reply to a channel range query. This may be one of several SendReplyChannelRange events
	/// emitted during processing of the query.
	SendReplyChannelRange {
		/// The node_id of this message recipient
		node_id: PublicKey,
		/// The reply_channel_range which should be sent.
		msg: msgs::ReplyChannelRange,
	}
}

/// A trait indicating an object may generate message send events
pub trait MessageSendEventsProvider {
	/// Gets the list of pending events which were generated by previous actions, clearing the list
	/// in the process.
	fn get_and_clear_pending_msg_events(&self) -> Vec<MessageSendEvent>;
}

/// A trait indicating an object may generate events.
///
/// Events are processed by passing an [`EventHandler`] to [`process_pending_events`].
///
/// # Requirements
///
/// See [`process_pending_events`] for requirements around event processing.
///
/// When using this trait, [`process_pending_events`] will call [`handle_event`] for each pending
/// event since the last invocation. The handler must either act upon the event immediately
/// or preserve it for later handling.
///
/// Note, handlers may call back into the provider and thus deadlocking must be avoided. Be sure to
/// consult the provider's documentation on the implication of processing events and how a handler
/// may safely use the provider (e.g., see [`ChannelManager::process_pending_events`] and
/// [`ChainMonitor::process_pending_events`]).
///
/// (C-not implementable) As there is likely no reason for a user to implement this trait on their
/// own type(s).
///
/// [`process_pending_events`]: Self::process_pending_events
/// [`handle_event`]: EventHandler::handle_event
/// [`ChannelManager::process_pending_events`]: crate::ln::channelmanager::ChannelManager#method.process_pending_events
/// [`ChainMonitor::process_pending_events`]: crate::chain::chainmonitor::ChainMonitor#method.process_pending_events
pub trait EventsProvider {
	/// Processes any events generated since the last call using the given event handler.
	///
	/// Subsequent calls must only process new events. However, handlers must be capable of handling
	/// duplicate events across process restarts. This may occur if the provider was recovered from
	/// an old state (i.e., it hadn't been successfully persisted after processing pending events).
	fn process_pending_events<H: Deref>(&self, handler: H) where H::Target: EventHandler;
}

/// A trait implemented for objects handling events from [`EventsProvider`].
pub trait EventHandler {
	/// Handles the given [`Event`].
	///
	/// See [`EventsProvider`] for details that must be considered when implementing this method.
	fn handle_event(&self, event: &Event);
}

impl<F> EventHandler for F where F: Fn(&Event) {
	fn handle_event(&self, event: &Event) {
		self(event)
	}
}

impl<T: EventHandler> EventHandler for Arc<T> {
	fn handle_event(&self, event: &Event) {
		self.deref().handle_event(event)
	}
}
