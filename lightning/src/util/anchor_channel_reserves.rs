//! Defines anchor channel reserve requirements.
//!
//! The Lightning protocol advances the state of the channel based on commitment and HTLC
//! transactions, which allow each participant to unilaterally close the channel with the correct
//! state and resolve pending HTLCs on-chain. Originally, these transactions are signed by both
//! counterparties over the entire transaction and therefore contain a fixed fee, which can be
//! updated with the `update_fee` message by the funder. However, these fees can lead to
//! disagreements and can diverge from the prevailing fee rate if a party is disconnected.
//!
//! To address these issues, fees are provided exogenously for anchor output channels.
//! Anchor outputs are negotiated on channel opening to add outputs to each commitment transaction.
//! These outputs can be spent in a child transaction with additional fees to incentivize the
//! mining of the parent transaction, this technique is called Child Pays For Parent (CPFP).
//! Similarly, HTLC transactions will be signed with `SIGHASH_SINGLE|SIGHASH_ANYONECANPAY` so
//! additional inputs and outputs can be added to pay for fees.
//!
//! UTXO reserves will therefore be required to supply commitment transactions and HTLC
//! transactions with fees to be confirmed in a timely manner. If HTLCs are not resolved
//! appropriately, it can lead to loss of funds of the in-flight HLTCs as mentioned above. Only
//! partially satisfying UTXO requirements incurs the risk of not being able to resolve a subset of
//! HTLCs.
use crate::chain::chaininterface::BroadcasterInterface;
use crate::chain::chaininterface::FeeEstimator;
use crate::chain::chainmonitor::ChainMonitor;
use crate::chain::chainmonitor::Persist;
use crate::chain::Filter;
use crate::events::bump_transaction::Utxo;
use crate::ln::chan_utils::max_htlcs;
use crate::ln::channelmanager::AChannelManager;
use crate::prelude::new_hash_set;
use crate::sign::ecdsa::EcdsaChannelSigner;
use crate::sign::EntropySource;
use crate::types::features::ChannelTypeFeatures;
use crate::util::logger::Logger;
use bitcoin::constants::WITNESS_SCALE_FACTOR;
use bitcoin::Amount;
use bitcoin::FeeRate;
use bitcoin::Weight;
use core::cmp::min;
use core::ops::Deref;

// Transaction weights based on:
// https://github.com/lightning/bolts/blob/master/03-transactions.md#appendix-a-expected-weights
const COMMITMENT_TRANSACTION_BASE_WEIGHT: u64 = 900 + 224;
const COMMITMENT_TRANSACTION_PER_HTLC_WEIGHT: u64 = 172;
const PER_HTLC_TIMEOUT_WEIGHT: u64 = 666;
const PER_HTLC_SUCCESS_WEIGHT: u64 = 706;

// The transaction at least contains:
// - 4 bytes for the version
// - 4 bytes for the locktime
// - 1 byte for the number of inputs
// - 1 byte for the number of outputs
// - 2 bytes for the witness header
//   - 1 byte for the flag
//   - 1 byte for the marker
const TRANSACTION_BASE_WEIGHT: u64 = (4 + 4 + 1 + 1) * WITNESS_SCALE_FACTOR as u64 + 2;

// A P2WPKH input consists of:
// - 36 bytes for the previous outpoint:
//   - 32 bytes transaction hash
//   - 4 bytes index
// - 4 bytes for the sequence
// - 1 byte for the script sig length
// - the witness:
//   - 1 byte for witness items count
//   - 1 byte for the signature length
//   - 72 bytes for the signature
//   - 1 byte for the public key length
//   - 33 bytes for the public key
const P2WPKH_INPUT_WEIGHT: u64 = (36 + 4 + 1) * WITNESS_SCALE_FACTOR as u64 + (1 + 1 + 72 + 1 + 33);

// A P2WPKH output consists of:
// - 8 bytes for the output amount
// - 1 byte for the script length
// - 22 bytes for the script (OP_0 OP_PUSH20 20 byte public key hash)
const P2WPKH_OUTPUT_WEIGHT: u64 = (8 + 1 + 22) * WITNESS_SCALE_FACTOR as u64;

// A P2TR key path input consists of:
// - 36 bytes for the previous outpoint:
//   - 32 bytes transaction hash
//   - 4 bytes index
// - 4 bytes for the sequence
// - 1 byte for the script sig length
// - the witness:
//   - 1 byte for witness items count
//   - 1 byte for the signature length
//   - 64 bytes for the Schnorr signature
const P2TR_KEYPATH_INPUT_WEIGHT: u64 = (36 + 4 + 1) * WITNESS_SCALE_FACTOR as u64 + (1 + 1 + 64);
// A P2TR output consists of:
// - 8 bytes for the output amount
// - 1 byte for the script length
// - 34 bytes for the script (OP_1 OP_PUSH32 32 byte Schnorr public key)
const P2TR_OUTPUT_WEIGHT: u64 = (8 + 1 + 34) * WITNESS_SCALE_FACTOR as u64;

// An P2WSH anchor input consists of:
// - 36 bytes for the previous outpoint:
//   - 32 bytes transaction hash
//   - 4 bytes index
// - 4 bytes for the sequence
// - 1 byte for the script sig length
// - the witness:
//   - 1 byte for witness item count
//   - 1 byte for signature length
//   - 72 bytes signature
//   - 1 byte for script length
//   - 40 byte script
//     <pubkey> OP_CHECKSIG OP_IFDUP OP_NOTIF OP_16 OP_CHECKSEQUENCEVERIFY OP_ENDIF
//     - 33 byte pubkey with 1 byte OP_PUSHBYTES_33.
//     - 6 1-byte opcodes
const ANCHOR_INPUT_WEIGHT: u64 = (36 + 4 + 1) * WITNESS_SCALE_FACTOR as u64 + (1 + 1 + 72 + 1 + 40);

fn htlc_success_transaction_weight(context: &AnchorChannelReserveContext) -> u64 {
	PER_HTLC_SUCCESS_WEIGHT
		+ if context.taproot_wallet {
			P2TR_KEYPATH_INPUT_WEIGHT + P2TR_OUTPUT_WEIGHT
		} else {
			P2WPKH_INPUT_WEIGHT + P2WPKH_OUTPUT_WEIGHT
		}
}

fn htlc_timeout_transaction_weight(context: &AnchorChannelReserveContext) -> u64 {
	PER_HTLC_TIMEOUT_WEIGHT
		+ if context.taproot_wallet {
			P2TR_KEYPATH_INPUT_WEIGHT + P2TR_OUTPUT_WEIGHT
		} else {
			P2WPKH_INPUT_WEIGHT + P2WPKH_OUTPUT_WEIGHT
		}
}

fn anchor_output_spend_transaction_weight(
	context: &AnchorChannelReserveContext, input_weight: Weight,
) -> u64 {
	TRANSACTION_BASE_WEIGHT
		+ ANCHOR_INPUT_WEIGHT
		+ input_weight.to_wu()
		+ if context.taproot_wallet { P2TR_OUTPUT_WEIGHT } else { P2WPKH_OUTPUT_WEIGHT }
}

/// Parameters defining the context around the anchor channel reserve requirement calculation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorChannelReserveContext {
	/// An upper bound fee rate estimate used to calculate the anchor channel reserve that is
	/// sufficient to provide fees for all required transactions.
	pub upper_bound_fee_rate: FeeRate,
	/// The expected number of accepted in-flight HTLCs per channel.
	///
	/// Note that malicious counterparties can saturate the number of accepted in-flight HTLCs up to
	/// the maximum prior to forcing a unilateral closure. This estimate can include that case as a
	/// weighted average, assuming some percentage of channels are controlled by malicious peers and
	/// have the maximum number of accepted in-flight HTLCs.
	///
	/// See [ChannelHandshakeConfig::our_max_accepted_htlcs] to configure the maximum number of
	/// accepted in-flight HTLCs.
	///
	/// [ChannelHandshakeConfig::our_max_accepted_htlcs]: crate::util::config::ChannelHandshakeConfig::our_max_accepted_htlcs
	pub expected_accepted_htlcs: u16,
	/// Whether the wallet handling anchor channel reserves creates Taproot P2TR outputs for any new
	/// outputs, or Segwit P2WPKH outputs otherwise.
	pub taproot_wallet: bool,
}

/// A default for the [AnchorChannelReserveContext] parameters is provided as follows:
/// - The upper bound fee rate is set to the 99th percentile of the median block fee rate since 2019:
///   ~50 sats/vbyte.
/// - The number of accepted in-flight HTLCs per channel is set to 10, providing additional margin
///   above the number seen for a large routing node over a month (average <1, maximum 10
///   accepted in-flight HTLCS aggregated across all channels).
/// - The wallet is assumed to be a Segwit wallet.
impl Default for AnchorChannelReserveContext {
	fn default() -> Self {
		AnchorChannelReserveContext {
			upper_bound_fee_rate: FeeRate::from_sat_per_kwu(50 * 250),
			expected_accepted_htlcs: 10,
			taproot_wallet: false,
		}
	}
}

fn get_reserve_per_channel_with_input(
	context: &AnchorChannelReserveContext, initial_input_weight: Weight,
) -> Amount {
	let max_max_htlcs = max_htlcs(&ChannelTypeFeatures::only_static_remote_key());
	let expected_accepted_htlcs = min(context.expected_accepted_htlcs, max_max_htlcs) as u64;
	let weight = Weight::from_wu(
		COMMITMENT_TRANSACTION_BASE_WEIGHT +
		// Reserves are calculated in terms of accepted HTLCs, as their timeout defines the urgency of
		// on-chain resolution. Each accepted HTLC is assumed to be forwarded to calculate an upper
		// bound for the reserve, resulting in `expected_accepted_htlcs` inbound HTLCs and
		// `expected_accepted_htlcs` outbound HTLCs per channel in aggregate.
		2 * expected_accepted_htlcs * COMMITMENT_TRANSACTION_PER_HTLC_WEIGHT +
		anchor_output_spend_transaction_weight(context, initial_input_weight) +
		// As an upper bound, it is assumed that each HTLC is resolved in a separate transaction.
		// However, they might be aggregated when possible depending on timelocks and expiries.
		htlc_success_transaction_weight(context) * expected_accepted_htlcs +
		htlc_timeout_transaction_weight(context) * expected_accepted_htlcs,
	);
	context.upper_bound_fee_rate.fee_wu(weight).unwrap_or(Amount::MAX)
}

/// Returns the amount that needs to be maintained as a reserve per anchor channel.
///
/// This reserve currently needs to be allocated as a disjoint set of at least 1 UTXO per channel,
/// as claims are not yet aggregated across channels.
///
/// To only require 1 UTXO per channel, it is assumed that, on average, transactions are able to
/// get confirmed within 1 block with [ConfirmationTarget::UrgentOnChainSweep], or that only a
/// portion of channels will go through unilateral closure at the same time, allowing UTXOs to be
/// shared. Otherwise, multiple UTXOs would be needed per channel:
/// - HTLC time-out transactions with different expiries cannot be aggregated. This could result in
/// many individual transactions that need to be confirmed starting from different, but potentially
/// sequential block heights.
/// - If each transaction takes N blocks to confirm, at least N UTXOs per channel are needed to
/// provide the necessary concurrency.
///
/// The returned amount includes the fee to spend a single UTXO of the type indicated by
/// [AnchorChannelReserveContext::taproot_wallet]. Larger sets of UTXOs with more complex witnesses
/// will need to include the corresponding fee required to spend them.
///
/// [ConfirmationTarget::UrgentOnChainSweep]: crate::chain::chaininterface::ConfirmationTarget::UrgentOnChainSweep
pub fn get_reserve_per_channel(context: &AnchorChannelReserveContext) -> Amount {
	get_reserve_per_channel_with_input(
		context,
		if context.taproot_wallet {
			Weight::from_wu(P2TR_KEYPATH_INPUT_WEIGHT)
		} else {
			Weight::from_wu(P2WPKH_INPUT_WEIGHT)
		},
	)
}

/// Calculates the number of anchor channels that can be supported by the reserve provided
/// by `utxos`.
pub fn get_supportable_anchor_channels(
	context: &AnchorChannelReserveContext, utxos: &[Utxo],
) -> u64 {
	// Get the reserve needed per channel, accounting for the actual satisfaction weight below.
	let reserve_per_channel = get_reserve_per_channel_with_input(context, Weight::ZERO);

	let mut total_fractional_amount = Amount::from_sat(0);
	let mut num_whole_utxos = 0;
	for utxo in utxos {
		let satisfaction_fee = context
			.upper_bound_fee_rate
			.fee_wu(Weight::from_wu(utxo.satisfaction_weight))
			.unwrap_or(Amount::MAX);
		let amount = utxo.output.value.checked_sub(satisfaction_fee).unwrap_or(Amount::MIN);
		if amount >= reserve_per_channel {
			num_whole_utxos += 1;
		} else {
			total_fractional_amount =
				total_fractional_amount.checked_add(amount).unwrap_or(Amount::MAX);
		}
	}
	// We require disjoint sets of UTXOs for the reserve of each channel,
	// as claims are currently only aggregated per channel.
	//
	// A worst-case coin selection is assumed for fractional UTXOs, selecting up to double the
	// required amount.
	num_whole_utxos + total_fractional_amount.to_sat() / reserve_per_channel.to_sat() / 2
}

/// Verifies whether the anchor channel reserve provided by `utxos` is sufficient to support
/// an additional anchor channel.
///
/// This should be verified:
/// - Before opening a new outbound anchor channel with [ChannelManager::create_channel].
/// - Before accepting a new inbound anchor channel while handling [Event::OpenChannelRequest].
///
/// [ChannelManager::create_channel]: crate::ln::channelmanager::ChannelManager::create_channel
/// [Event::OpenChannelRequest]: crate::events::Event::OpenChannelRequest
pub fn can_support_additional_anchor_channel<
	AChannelManagerRef: Deref,
	ChannelSigner: EcdsaChannelSigner,
	FI: Filter,
	B: BroadcasterInterface,
	FE: FeeEstimator,
	L: Logger,
	PersistRef: Deref,
	ES: EntropySource,
	ChainMonitorRef: Deref<Target = ChainMonitor<ChannelSigner, FI, B, FE, L, PersistRef, ES>>,
>(
	context: &AnchorChannelReserveContext, utxos: &[Utxo], a_channel_manager: AChannelManagerRef,
	chain_monitor: ChainMonitorRef,
) -> bool
where
	AChannelManagerRef::Target: AChannelManager,
	PersistRef::Target: Persist<ChannelSigner>,
{
	let mut anchor_channels = new_hash_set();
	// Calculate the number of in-progress anchor channels by inspecting ChannelMonitors with balance.
	// This includes channels that are in the process of being resolved on-chain.
	for channel_id in chain_monitor.list_monitors() {
		let channel_monitor = if let Ok(channel_monitor) = chain_monitor.get_monitor(channel_id) {
			channel_monitor
		} else {
			continue;
		};
		if channel_monitor.channel_type_features().supports_anchors_zero_fee_htlc_tx()
			&& !channel_monitor.get_claimable_balances().is_empty()
		{
			anchor_channels.insert(channel_id);
		}
	}
	// Also include channels that are in the middle of negotiation or anchor channels that don't have
	// a ChannelMonitor yet.
	for channel in a_channel_manager.get_cm().list_channels() {
		if channel.channel_type.map_or(true, |ct| ct.supports_anchors_zero_fee_htlc_tx()) {
			anchor_channels.insert(channel.channel_id);
		}
	}
	get_supportable_anchor_channels(context, utxos) > anchor_channels.len() as u64
}

#[cfg(test)]
mod test {
	use super::*;
	use bitcoin::{OutPoint, ScriptBuf, Sequence, TxOut, Txid};
	use std::str::FromStr;

	#[test]
	fn test_get_reserve_per_channel() {
		// At a 1000 sats/kw, with 4 expected transactions at ~1kw (commitment transaction, anchor
		// output spend transaction, 2 HTLC transactions), we expect the reserve to be around 4k sats.
		assert_eq!(
			get_reserve_per_channel(&AnchorChannelReserveContext {
				upper_bound_fee_rate: FeeRate::from_sat_per_kwu(1000),
				expected_accepted_htlcs: 1,
				taproot_wallet: false,
			}),
			Amount::from_sat(4349)
		);
	}

	fn make_p2wpkh_utxo(amount: Amount) -> Utxo {
		Utxo {
			outpoint: OutPoint {
				txid: Txid::from_str(
					"4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
				)
				.unwrap(),
				vout: 0,
			},
			output: TxOut { value: amount, script_pubkey: ScriptBuf::new() },
			satisfaction_weight: 1 * 4 + (1 + 1 + 72 + 1 + 33),
			sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
		}
	}

	#[test]
	fn test_get_supportable_anchor_channels() {
		let context = AnchorChannelReserveContext::default();
		let reserve_per_channel = get_reserve_per_channel(&context);
		// Only 3 disjoint sets with a value greater than the required reserve can be created.
		let utxos = vec![
			make_p2wpkh_utxo(reserve_per_channel * 3 / 2),
			make_p2wpkh_utxo(reserve_per_channel),
			make_p2wpkh_utxo(reserve_per_channel * 99 / 100),
			make_p2wpkh_utxo(reserve_per_channel * 99 / 100),
			make_p2wpkh_utxo(reserve_per_channel * 20 / 100),
		];
		assert_eq!(get_supportable_anchor_channels(&context, utxos.as_slice()), 3);
	}

	#[test]
	fn test_anchor_output_spend_transaction_weight() {
		// Example with smaller signatures:
		// https://mempool.space/tx/188b0f9f26999a48611dba4e2a88507251eba31f3695d005023de3514cba34bd
		// DER-encoded ECDSA signatures vary in size and can be 71-73 bytes.
		assert_eq!(
			anchor_output_spend_transaction_weight(
				&AnchorChannelReserveContext { taproot_wallet: false, ..Default::default() },
				Weight::from_wu(P2WPKH_INPUT_WEIGHT),
			),
			717
		);

		// Example:
		// https://mempool.space/tx/9c493177e395ec77d9e725e1cfd465c5f06d4a5816dd0274c3a8c2442d854a85
		assert_eq!(
			anchor_output_spend_transaction_weight(
				&AnchorChannelReserveContext { taproot_wallet: true, ..Default::default() },
				Weight::from_wu(P2TR_KEYPATH_INPUT_WEIGHT),
			),
			723
		);
	}

	#[test]
	fn test_htlc_success_transaction_weight() {
		assert_eq!(
			htlc_success_transaction_weight(&AnchorChannelReserveContext {
				taproot_wallet: false,
				..Default::default()
			}),
			1102
		);

		assert_eq!(
			htlc_success_transaction_weight(&AnchorChannelReserveContext {
				taproot_wallet: true,
				..Default::default()
			}),
			1108
		);
	}

	#[test]
	fn test_htlc_timeout_transaction_weight() {
		// Example with smaller signatures:
		// https://mempool.space/tx/37185342f9f088bd12376599b245dbc02eb0bb6c4b99568b75a8cd775ddfd1f4
		assert_eq!(
			htlc_timeout_transaction_weight(&AnchorChannelReserveContext {
				taproot_wallet: false,
				..Default::default()
			}),
			1062
		);

		assert_eq!(
			htlc_timeout_transaction_weight(&AnchorChannelReserveContext {
				taproot_wallet: true,
				..Default::default()
			}),
			1068
		);
	}
}
