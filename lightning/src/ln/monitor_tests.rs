// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Further functional tests which test blockchain reorganizations.

#[cfg(anchors)]
use crate::chain::keysinterface::BaseSign;
#[cfg(anchors)]
use crate::chain::channelmonitor::LATENCY_GRACE_PERIOD_BLOCKS;
use crate::chain::channelmonitor::{ANTI_REORG_DELAY, Balance};
use crate::chain::transaction::OutPoint;
use crate::chain::chaininterface::LowerBoundedFeeEstimator;
use crate::ln::channel;
#[cfg(anchors)]
use crate::ln::chan_utils;
use crate::ln::channelmanager::{BREAKDOWN_TIMEOUT, PaymentId};
use crate::ln::msgs::ChannelMessageHandler;
#[cfg(anchors)]
use crate::util::config::UserConfig;
#[cfg(anchors)]
use crate::util::events::BumpTransactionEvent;
use crate::util::events::{Event, MessageSendEvent, MessageSendEventsProvider, ClosureReason, HTLCDestination};

use bitcoin::blockdata::script::Builder;
use bitcoin::blockdata::opcodes;
use bitcoin::secp256k1::Secp256k1;
#[cfg(anchors)]
use bitcoin::{Amount, Script, TxIn, TxOut, PackedLockTime};
use bitcoin::Transaction;

use crate::prelude::*;

use crate::ln::functional_test_utils::*;

#[test]
fn chanmon_fail_from_stale_commitment() {
	// If we forward an HTLC to our counterparty, but we force-closed the channel before our
	// counterparty provides us an updated commitment transaction, we'll end up with a commitment
	// transaction that does not contain the HTLC which we attempted to forward. In this case, we
	// need to wait `ANTI_REORG_DELAY` blocks and then fail back the HTLC as there is no way for us
	// to learn the preimage and the confirmed commitment transaction paid us the value of the
	// HTLC.
	//
	// However, previously, we did not do this, ignoring the HTLC entirely.
	//
	// This could lead to channel closure if the sender we received the HTLC from decides to go on
	// chain to get their HTLC back before it times out.
	//
	// Here, we check exactly this case, forwarding a payment from A, through B, to C, before B
	// broadcasts its latest commitment transaction, which should result in it eventually failing
	// the HTLC back off-chain to A.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes(&nodes, 0, 1);
	let (update_a, _, chan_id_2, _) = create_announced_chan_between_nodes(&nodes, 1, 2);

	let (route, payment_hash, _, payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[2], 1_000_000);
	nodes[0].node.send_payment(&route, payment_hash, &Some(payment_secret), PaymentId(payment_hash.0)).unwrap();
	check_added_monitors!(nodes[0], 1);

	let bs_txn = get_local_commitment_txn!(nodes[1], chan_id_2);

	let updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);
	commitment_signed_dance!(nodes[1], nodes[0], updates.commitment_signed, false);

	expect_pending_htlcs_forwardable!(nodes[1]);
	get_htlc_update_msgs!(nodes[1], nodes[2].node.get_our_node_id());
	check_added_monitors!(nodes[1], 1);

	// Don't bother delivering the new HTLC add/commits, instead confirming the pre-HTLC commitment
	// transaction for nodes[1].
	mine_transaction(&nodes[1], &bs_txn[0]);
	check_added_monitors!(nodes[1], 1);
	check_closed_broadcast!(nodes[1], true);
	check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);
	expect_pending_htlcs_forwardable_and_htlc_handling_failed!(nodes[1], vec![HTLCDestination::NextHopChannel { node_id: Some(nodes[2].node.get_our_node_id()), channel_id: chan_id_2 }]);
	check_added_monitors!(nodes[1], 1);
	let fail_updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());

	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &fail_updates.update_fail_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], fail_updates.commitment_signed, true, true);
	expect_payment_failed_with_update!(nodes[0], payment_hash, false, update_a.contents.short_channel_id, true);
}

fn test_spendable_output<'a, 'b, 'c, 'd>(node: &'a Node<'b, 'c, 'd>, spendable_tx: &Transaction) {
	let mut spendable = node.chain_monitor.chain_monitor.get_and_clear_pending_events();
	assert_eq!(spendable.len(), 1);
	if let Event::SpendableOutputs { outputs } = spendable.pop().unwrap() {
		assert_eq!(outputs.len(), 1);
		let spend_tx = node.keys_manager.backing.spend_spendable_outputs(&[&outputs[0]], Vec::new(),
			Builder::new().push_opcode(opcodes::all::OP_RETURN).into_script(), 253, &Secp256k1::new()).unwrap();
		check_spends!(spend_tx, spendable_tx);
	} else { panic!(); }
}

#[test]
fn revoked_output_htlc_resolution_timing() {
	// Tests that HTLCs which were present in a broadcasted remote revoked commitment transaction
	// are resolved only after a spend of the HTLC output reaches six confirmations. Preivously
	// they would resolve after the revoked commitment transaction itself reaches six
	// confirmations.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let chan = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 500_000_000);

	let payment_hash_1 = route_payment(&nodes[1], &[&nodes[0]], 1_000_000).1;

	// Get a commitment transaction which contains the HTLC we care about, but which we'll revoke
	// before forwarding.
	let revoked_local_txn = get_local_commitment_txn!(nodes[0], chan.2);
	assert_eq!(revoked_local_txn.len(), 1);

	// Route a dust payment to revoke the above commitment transaction
	route_payment(&nodes[0], &[&nodes[1]], 1_000);

	// Confirm the revoked commitment transaction, closing the channel.
	mine_transaction(&nodes[1], &revoked_local_txn[0]);
	check_added_monitors!(nodes[1], 1);
	check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed);
	check_closed_broadcast!(nodes[1], true);

	let bs_spend_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	assert_eq!(bs_spend_txn.len(), 1);
	check_spends!(bs_spend_txn[0], revoked_local_txn[0]);

	// After the commitment transaction confirms, we should still wait on the HTLC spend
	// transaction to confirm before resolving the HTLC.
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());

	// Spend the HTLC output, generating a HTLC failure event after ANTI_REORG_DELAY confirmations.
	mine_transaction(&nodes[1], &bs_spend_txn[0]);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());

	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);
	expect_payment_failed!(nodes[1], payment_hash_1, false);
}

#[test]
fn chanmon_claim_value_coop_close() {
	// Tests `get_claimable_balances` returns the correct values across a simple cooperative claim.
	// Specifically, this tests that the channel non-HTLC balances show up in
	// `get_claimable_balances` until the cooperative claims have confirmed and generated a
	// `SpendableOutputs` event, and no longer.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let (_, _, chan_id, funding_tx) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 1_000_000);
	let funding_outpoint = OutPoint { txid: funding_tx.txid(), index: 0 };
	assert_eq!(funding_outpoint.to_channel_id(), chan_id);

	let chan_feerate = get_feerate!(nodes[0], nodes[1], chan_id) as u64;
	let opt_anchors = get_opt_anchors!(nodes[0], nodes[1], chan_id);

	assert_eq!(vec![Balance::ClaimableOnChannelClose {
			claimable_amount_satoshis: 1_000_000 - 1_000 - chan_feerate * channel::commitment_tx_base_weight(opt_anchors) / 1000
		}],
		nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances());
	assert_eq!(vec![Balance::ClaimableOnChannelClose { claimable_amount_satoshis: 1_000, }],
		nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances());

	nodes[0].node.close_channel(&chan_id, &nodes[1].node.get_our_node_id()).unwrap();
	let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &node_0_shutdown);
	let node_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &node_1_shutdown);

	let node_0_closing_signed = get_event_msg!(nodes[0], MessageSendEvent::SendClosingSigned, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_closing_signed);
	let node_1_closing_signed = get_event_msg!(nodes[1], MessageSendEvent::SendClosingSigned, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_closing_signed(&nodes[1].node.get_our_node_id(), &node_1_closing_signed);
	let (_, node_0_2nd_closing_signed) = get_closing_signed_broadcast!(nodes[0].node, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_closing_signed(&nodes[0].node.get_our_node_id(), &node_0_2nd_closing_signed.unwrap());
	let (_, node_1_none) = get_closing_signed_broadcast!(nodes[1].node, nodes[0].node.get_our_node_id());
	assert!(node_1_none.is_none());

	let shutdown_tx = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	assert_eq!(shutdown_tx, nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0));
	assert_eq!(shutdown_tx.len(), 1);

	mine_transaction(&nodes[0], &shutdown_tx[0]);
	mine_transaction(&nodes[1], &shutdown_tx[0]);

	assert!(nodes[0].node.list_channels().is_empty());
	assert!(nodes[1].node.list_channels().is_empty());

	assert!(nodes[0].chain_monitor.chain_monitor.get_and_clear_pending_events().is_empty());
	assert!(nodes[1].chain_monitor.chain_monitor.get_and_clear_pending_events().is_empty());

	assert_eq!(vec![Balance::ClaimableAwaitingConfirmations {
			claimable_amount_satoshis: 1_000_000 - 1_000 - chan_feerate * channel::commitment_tx_base_weight(opt_anchors) / 1000,
			confirmation_height: nodes[0].best_block_info().1 + ANTI_REORG_DELAY - 1,
		}],
		nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances());
	assert_eq!(vec![Balance::ClaimableAwaitingConfirmations {
			claimable_amount_satoshis: 1000,
			confirmation_height: nodes[1].best_block_info().1 + ANTI_REORG_DELAY - 1,
		}],
		nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances());

	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);

	assert_eq!(Vec::<Balance>::new(),
		nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances());
	assert_eq!(Vec::<Balance>::new(),
		nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances());

	test_spendable_output(&nodes[0], &shutdown_tx[0]);
	test_spendable_output(&nodes[1], &shutdown_tx[0]);

	check_closed_event!(nodes[0], 1, ClosureReason::CooperativeClosure);
	check_closed_event!(nodes[1], 1, ClosureReason::CooperativeClosure);
}

fn sorted_vec<T: Ord>(mut v: Vec<T>) -> Vec<T> {
	v.sort_unstable();
	v
}

/// Asserts that `a` and `b` are close, but maybe off by up to 5.
/// This is useful when checking fees and weights on transactions as things may vary by a few based
/// on signature size and signature size estimation being non-exact.
fn fuzzy_assert_eq<V: core::convert::TryInto<u64>>(a: V, b: V) {
	let a_u64 = a.try_into().map_err(|_| ()).unwrap();
	let b_u64 = b.try_into().map_err(|_| ()).unwrap();
	eprintln!("Checking {} and {} for fuzzy equality", a_u64, b_u64);
	assert!(a_u64 >= b_u64 - 5);
	assert!(b_u64 >= a_u64 - 5);
}

fn do_test_claim_value_force_close(prev_commitment_tx: bool) {
	// Tests `get_claimable_balances` with an HTLC across a force-close.
	// We build a channel with an HTLC pending, then force close the channel and check that the
	// `get_claimable_balances` return value is correct as transactions confirm on-chain.
	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	if prev_commitment_tx {
		// We broadcast a second-to-latest commitment transaction, without providing the revocation
		// secret to the counterparty. However, because we always immediately take the revocation
		// secret from the keys_manager, we would panic at broadcast as we're trying to sign a
		// transaction which, from the point of view of our keys_manager, is revoked.
		chanmon_cfgs[1].keys_manager.disable_revocation_policy_check = true;
	}
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let (_, _, chan_id, funding_tx) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 1_000_000);
	let funding_outpoint = OutPoint { txid: funding_tx.txid(), index: 0 };
	assert_eq!(funding_outpoint.to_channel_id(), chan_id);

	// This HTLC is immediately claimed, giving node B the preimage
	let (payment_preimage, payment_hash, _) = route_payment(&nodes[0], &[&nodes[1]], 3_000_000);
	// This HTLC is allowed to time out, letting A claim it. However, in order to test claimable
	// balances more fully we also give B the preimage for this HTLC.
	let (timeout_payment_preimage, timeout_payment_hash, _) = route_payment(&nodes[0], &[&nodes[1]], 4_000_000);
	// This HTLC will be dust, and not be claimable at all:
	let (dust_payment_preimage, dust_payment_hash, _) = route_payment(&nodes[0], &[&nodes[1]], 3_000);

	let htlc_cltv_timeout = nodes[0].best_block_info().1 + TEST_FINAL_CLTV + 1; // Note ChannelManager adds one to CLTV timeouts for safety

	let chan_feerate = get_feerate!(nodes[0], nodes[1], chan_id) as u64;
	let opt_anchors = get_opt_anchors!(nodes[0], nodes[1], chan_id);

	let remote_txn = get_local_commitment_txn!(nodes[1], chan_id);
	// Before B receives the payment preimage, it only suggests the push_msat value of 1_000 sats
	// as claimable. A lists both its to-self balance and the (possibly-claimable) HTLCs.
	assert_eq!(sorted_vec(vec![Balance::ClaimableOnChannelClose {
			claimable_amount_satoshis: 1_000_000 - 3_000 - 4_000 - 1_000 - 3 - chan_feerate *
				(channel::commitment_tx_base_weight(opt_anchors) + 2 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
		}, Balance::MaybeTimeoutClaimableHTLC {
			claimable_amount_satoshis: 3_000,
			claimable_height: htlc_cltv_timeout,
		}, Balance::MaybeTimeoutClaimableHTLC {
			claimable_amount_satoshis: 4_000,
			claimable_height: htlc_cltv_timeout,
		}]),
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));
	assert_eq!(sorted_vec(vec![Balance::ClaimableOnChannelClose {
			claimable_amount_satoshis: 1_000,
		}, Balance::MaybePreimageClaimableHTLC {
			claimable_amount_satoshis: 3_000,
			expiry_height: htlc_cltv_timeout,
		}, Balance::MaybePreimageClaimableHTLC {
			claimable_amount_satoshis: 4_000,
			expiry_height: htlc_cltv_timeout,
		}]),
		sorted_vec(nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	nodes[1].node.claim_funds(payment_preimage);
	check_added_monitors!(nodes[1], 1);
	expect_payment_claimed!(nodes[1], payment_hash, 3_000_000);

	let b_htlc_msgs = get_htlc_update_msgs!(&nodes[1], nodes[0].node.get_our_node_id());
	// We claim the dust payment here as well, but it won't impact our claimable balances as its
	// dust and thus doesn't appear on chain at all.
	nodes[1].node.claim_funds(dust_payment_preimage);
	check_added_monitors!(nodes[1], 1);
	expect_payment_claimed!(nodes[1], dust_payment_hash, 3_000);

	nodes[1].node.claim_funds(timeout_payment_preimage);
	check_added_monitors!(nodes[1], 1);
	expect_payment_claimed!(nodes[1], timeout_payment_hash, 4_000_000);

	if prev_commitment_tx {
		// To build a previous commitment transaction, deliver one round of commitment messages.
		nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &b_htlc_msgs.update_fulfill_htlcs[0]);
		expect_payment_sent_without_paths!(nodes[0], payment_preimage);
		nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &b_htlc_msgs.commitment_signed);
		check_added_monitors!(nodes[0], 1);
		let (as_raa, as_cs) = get_revoke_commit_msgs!(nodes[0], nodes[1].node.get_our_node_id());
		nodes[1].node.handle_revoke_and_ack(&nodes[0].node.get_our_node_id(), &as_raa);
		let _htlc_updates = get_htlc_update_msgs!(&nodes[1], nodes[0].node.get_our_node_id());
		check_added_monitors!(nodes[1], 1);
		nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &as_cs);
		let _bs_raa = get_event_msg!(nodes[1], MessageSendEvent::SendRevokeAndACK, nodes[0].node.get_our_node_id());
		check_added_monitors!(nodes[1], 1);
	}

	// Once B has received the payment preimage, it includes the value of the HTLC in its
	// "claimable if you were to close the channel" balance.
	let mut a_expected_balances = vec![Balance::ClaimableOnChannelClose {
			claimable_amount_satoshis: 1_000_000 - // Channel funding value in satoshis
				4_000 - // The to-be-failed HTLC value in satoshis
				3_000 - // The claimed HTLC value in satoshis
				1_000 - // The push_msat value in satoshis
				3 - // The dust HTLC value in satoshis
				// The commitment transaction fee with two HTLC outputs:
				chan_feerate * (channel::commitment_tx_base_weight(opt_anchors) +
								if prev_commitment_tx { 1 } else { 2 } *
								channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
		}, Balance::MaybeTimeoutClaimableHTLC {
			claimable_amount_satoshis: 4_000,
			claimable_height: htlc_cltv_timeout,
		}];
	if !prev_commitment_tx {
		a_expected_balances.push(Balance::MaybeTimeoutClaimableHTLC {
			claimable_amount_satoshis: 3_000,
			claimable_height: htlc_cltv_timeout,
		});
	}
	assert_eq!(sorted_vec(a_expected_balances),
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));
	assert_eq!(vec![Balance::ClaimableOnChannelClose {
			claimable_amount_satoshis: 1_000 + 3_000 + 4_000,
		}],
		nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances());

	// Broadcast the closing transaction (which has both pending HTLCs in it) and get B's
	// broadcasted HTLC claim transaction with preimage.
	let node_b_commitment_claimable = nodes[1].best_block_info().1 + BREAKDOWN_TIMEOUT as u32;
	mine_transaction(&nodes[0], &remote_txn[0]);
	mine_transaction(&nodes[1], &remote_txn[0]);

	let b_broadcast_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	assert_eq!(b_broadcast_txn.len(), 2);
	// b_broadcast_txn should spend the HTLCs output of the commitment tx for 3_000 and 4_000 sats
	check_spends!(b_broadcast_txn[0], remote_txn[0]);
	check_spends!(b_broadcast_txn[1], remote_txn[0]);
	assert_eq!(b_broadcast_txn[0].input.len(), 1);
	assert_eq!(b_broadcast_txn[1].input.len(), 1);
	assert_eq!(remote_txn[0].output[b_broadcast_txn[0].input[0].previous_output.vout as usize].value, 3_000);
	assert_eq!(remote_txn[0].output[b_broadcast_txn[1].input[0].previous_output.vout as usize].value, 4_000);

	assert!(nodes[0].node.list_channels().is_empty());
	check_closed_broadcast!(nodes[0], true);
	check_added_monitors!(nodes[0], 1);
	check_closed_event!(nodes[0], 1, ClosureReason::CommitmentTxConfirmed);
	assert!(nodes[1].node.list_channels().is_empty());
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors!(nodes[1], 1);
	check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed);
	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());

	// Once the commitment transaction confirms, we will wait until ANTI_REORG_DELAY until we
	// generate any `SpendableOutputs` events. Thus, the same balances will still be listed
	// available in `get_claimable_balances`. However, both will swap from `ClaimableOnClose` to
	// other Balance variants, as close has already happened.
	assert!(nodes[0].chain_monitor.chain_monitor.get_and_clear_pending_events().is_empty());
	assert!(nodes[1].chain_monitor.chain_monitor.get_and_clear_pending_events().is_empty());

	assert_eq!(sorted_vec(vec![Balance::ClaimableAwaitingConfirmations {
			claimable_amount_satoshis: 1_000_000 - 3_000 - 4_000 - 1_000 - 3 - chan_feerate *
				(channel::commitment_tx_base_weight(opt_anchors) + 2 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
			confirmation_height: nodes[0].best_block_info().1 + ANTI_REORG_DELAY - 1,
		}, Balance::MaybeTimeoutClaimableHTLC {
			claimable_amount_satoshis: 3_000,
			claimable_height: htlc_cltv_timeout,
		}, Balance::MaybeTimeoutClaimableHTLC {
			claimable_amount_satoshis: 4_000,
			claimable_height: htlc_cltv_timeout,
		}]),
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));
	// The main non-HTLC balance is just awaiting confirmations, but the claimable height is the
	// CSV delay, not ANTI_REORG_DELAY.
	assert_eq!(sorted_vec(vec![Balance::ClaimableAwaitingConfirmations {
			claimable_amount_satoshis: 1_000,
			confirmation_height: node_b_commitment_claimable,
		},
		// Both HTLC balances are "contentious" as our counterparty could claim them if we wait too
		// long.
		Balance::ContentiousClaimable {
			claimable_amount_satoshis: 3_000,
			timeout_height: htlc_cltv_timeout,
		}, Balance::ContentiousClaimable {
			claimable_amount_satoshis: 4_000,
			timeout_height: htlc_cltv_timeout,
		}]),
		sorted_vec(nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);
	expect_payment_failed!(nodes[0], dust_payment_hash, false);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);

	// After ANTI_REORG_DELAY, A will consider its balance fully spendable and generate a
	// `SpendableOutputs` event. However, B still has to wait for the CSV delay.
	assert_eq!(sorted_vec(vec![Balance::MaybeTimeoutClaimableHTLC {
			claimable_amount_satoshis: 3_000,
			claimable_height: htlc_cltv_timeout,
		}, Balance::MaybeTimeoutClaimableHTLC {
			claimable_amount_satoshis: 4_000,
			claimable_height: htlc_cltv_timeout,
		}]),
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));
	assert_eq!(sorted_vec(vec![Balance::ClaimableAwaitingConfirmations {
			claimable_amount_satoshis: 1_000,
			confirmation_height: node_b_commitment_claimable,
		}, Balance::ContentiousClaimable {
			claimable_amount_satoshis: 3_000,
			timeout_height: htlc_cltv_timeout,
		}, Balance::ContentiousClaimable {
			claimable_amount_satoshis: 4_000,
			timeout_height: htlc_cltv_timeout,
		}]),
		sorted_vec(nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	test_spendable_output(&nodes[0], &remote_txn[0]);
	assert!(nodes[1].chain_monitor.chain_monitor.get_and_clear_pending_events().is_empty());

	// After broadcasting the HTLC claim transaction, node A will still consider the HTLC
	// possibly-claimable up to ANTI_REORG_DELAY, at which point it will drop it.
	mine_transaction(&nodes[0], &b_broadcast_txn[0]);
	if prev_commitment_tx {
		expect_payment_path_successful!(nodes[0]);
	} else {
		expect_payment_sent!(nodes[0], payment_preimage);
	}
	assert_eq!(sorted_vec(vec![Balance::MaybeTimeoutClaimableHTLC {
			claimable_amount_satoshis: 3_000,
			claimable_height: htlc_cltv_timeout,
		}, Balance::MaybeTimeoutClaimableHTLC {
			claimable_amount_satoshis: 4_000,
			claimable_height: htlc_cltv_timeout,
		}]),
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));
	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);
	assert_eq!(vec![Balance::MaybeTimeoutClaimableHTLC {
			claimable_amount_satoshis: 4_000,
			claimable_height: htlc_cltv_timeout,
		}],
		nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances());

	// When the HTLC timeout output is spendable in the next block, A should broadcast it
	connect_blocks(&nodes[0], htlc_cltv_timeout - nodes[0].best_block_info().1 - 1);
	let a_broadcast_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	assert_eq!(a_broadcast_txn.len(), 2);
	assert_eq!(a_broadcast_txn[0].input.len(), 1);
	check_spends!(a_broadcast_txn[0], remote_txn[0]);
	assert_eq!(a_broadcast_txn[1].input.len(), 1);
	check_spends!(a_broadcast_txn[1], remote_txn[0]);
	assert_ne!(a_broadcast_txn[0].input[0].previous_output.vout,
	           a_broadcast_txn[1].input[0].previous_output.vout);
	// a_broadcast_txn [0] and [1] should spend the HTLC outputs of the commitment tx
	assert_eq!(remote_txn[0].output[a_broadcast_txn[0].input[0].previous_output.vout as usize].value, 3_000);
	assert_eq!(remote_txn[0].output[a_broadcast_txn[1].input[0].previous_output.vout as usize].value, 4_000);

	// Once the HTLC-Timeout transaction confirms, A will no longer consider the HTLC
	// "MaybeClaimable", but instead move it to "AwaitingConfirmations".
	mine_transaction(&nodes[0], &a_broadcast_txn[1]);
	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
	assert_eq!(vec![Balance::ClaimableAwaitingConfirmations {
			claimable_amount_satoshis: 4_000,
			confirmation_height: nodes[0].best_block_info().1 + ANTI_REORG_DELAY - 1,
		}],
		nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances());
	// After ANTI_REORG_DELAY, A will generate a SpendableOutputs event and drop the claimable
	// balance entry.
	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);
	assert_eq!(Vec::<Balance>::new(),
		nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances());
	expect_payment_failed!(nodes[0], timeout_payment_hash, false);

	test_spendable_output(&nodes[0], &a_broadcast_txn[1]);

	// Node B will no longer consider the HTLC "contentious" after the HTLC claim transaction
	// confirms, and consider it simply "awaiting confirmations". Note that it has to wait for the
	// standard revocable transaction CSV delay before receiving a `SpendableOutputs`.
	let node_b_htlc_claimable = nodes[1].best_block_info().1 + BREAKDOWN_TIMEOUT as u32;
	mine_transaction(&nodes[1], &b_broadcast_txn[0]);

	assert_eq!(sorted_vec(vec![Balance::ClaimableAwaitingConfirmations {
			claimable_amount_satoshis: 1_000,
			confirmation_height: node_b_commitment_claimable,
		}, Balance::ClaimableAwaitingConfirmations {
			claimable_amount_satoshis: 3_000,
			confirmation_height: node_b_htlc_claimable,
		}, Balance::ContentiousClaimable {
			claimable_amount_satoshis: 4_000,
			timeout_height: htlc_cltv_timeout,
		}]),
		sorted_vec(nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	// After reaching the commitment output CSV, we'll get a SpendableOutputs event for it and have
	// only the HTLCs claimable on node B.
	connect_blocks(&nodes[1], node_b_commitment_claimable - nodes[1].best_block_info().1);
	test_spendable_output(&nodes[1], &remote_txn[0]);

	assert_eq!(sorted_vec(vec![Balance::ClaimableAwaitingConfirmations {
			claimable_amount_satoshis: 3_000,
			confirmation_height: node_b_htlc_claimable,
		}, Balance::ContentiousClaimable {
			claimable_amount_satoshis: 4_000,
			timeout_height: htlc_cltv_timeout,
		}]),
		sorted_vec(nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	// After reaching the claimed HTLC output CSV, we'll get a SpendableOutptus event for it and
	// have only one HTLC output left spendable.
	connect_blocks(&nodes[1], node_b_htlc_claimable - nodes[1].best_block_info().1);
	test_spendable_output(&nodes[1], &b_broadcast_txn[0]);

	assert_eq!(vec![Balance::ContentiousClaimable {
			claimable_amount_satoshis: 4_000,
			timeout_height: htlc_cltv_timeout,
		}],
		nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances());

	// Finally, mine the HTLC timeout transaction that A broadcasted (even though B should be able
	// to claim this HTLC with the preimage it knows!). It will remain listed as a claimable HTLC
	// until ANTI_REORG_DELAY confirmations on the spend.
	mine_transaction(&nodes[1], &a_broadcast_txn[1]);
	assert_eq!(vec![Balance::ContentiousClaimable {
			claimable_amount_satoshis: 4_000,
			timeout_height: htlc_cltv_timeout,
		}],
		nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances());
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);
	assert_eq!(Vec::<Balance>::new(),
		nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances());

	// Ensure that even if we connect more blocks, potentially replaying the entire chain if we're
	// using `ConnectStyle::HighlyRedundantTransactionsFirstSkippingBlocks`, we don't get new
	// monitor events or claimable balances.
	for node in nodes.iter() {
		connect_blocks(node, 6);
		connect_blocks(node, 6);
		assert!(node.chain_monitor.chain_monitor.get_and_clear_pending_events().is_empty());
		assert!(node.chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances().is_empty());
	}
}

#[test]
fn test_claim_value_force_close() {
	do_test_claim_value_force_close(true);
	do_test_claim_value_force_close(false);
}

#[test]
fn test_balances_on_local_commitment_htlcs() {
	// Previously, when handling the broadcast of a local commitment transactions (with associated
	// CSV delays prior to spendability), we incorrectly handled the CSV delays on HTLC
	// transactions. This caused us to miss spendable outputs for HTLCs which were awaiting a CSV
	// delay prior to spendability.
	//
	// Further, because of this, we could hit an assertion as `get_claimable_balances` asserted
	// that HTLCs were resolved after the funding spend was resolved, which was not true if the
	// HTLC did not have a CSV delay attached (due to the above bug or due to it being an HTLC
	// claim by our counterparty).
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Create a single channel with two pending HTLCs from nodes[0] to nodes[1], one which nodes[1]
	// knows the preimage for, one which it does not.
	let (_, _, chan_id, funding_tx) = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	let funding_outpoint = OutPoint { txid: funding_tx.txid(), index: 0 };

	let (route, payment_hash, _, payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[1], 10_000_000);
	let htlc_cltv_timeout = nodes[0].best_block_info().1 + TEST_FINAL_CLTV + 1; // Note ChannelManager adds one to CLTV timeouts for safety
	nodes[0].node.send_payment(&route, payment_hash, &Some(payment_secret), PaymentId(payment_hash.0)).unwrap();
	check_added_monitors!(nodes[0], 1);

	let updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);
	commitment_signed_dance!(nodes[1], nodes[0], updates.commitment_signed, false);

	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_payment_claimable!(nodes[1], payment_hash, payment_secret, 10_000_000);

	let (route_2, payment_hash_2, payment_preimage_2, payment_secret_2) = get_route_and_payment_hash!(nodes[0], nodes[1], 20_000_000);
	nodes[0].node.send_payment(&route_2, payment_hash_2, &Some(payment_secret_2), PaymentId(payment_hash_2.0)).unwrap();
	check_added_monitors!(nodes[0], 1);

	let updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);
	commitment_signed_dance!(nodes[1], nodes[0], updates.commitment_signed, false);

	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_payment_claimable!(nodes[1], payment_hash_2, payment_secret_2, 20_000_000);
	nodes[1].node.claim_funds(payment_preimage_2);
	get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	check_added_monitors!(nodes[1], 1);
	expect_payment_claimed!(nodes[1], payment_hash_2, 20_000_000);

	let chan_feerate = get_feerate!(nodes[0], nodes[1], chan_id) as u64;
	let opt_anchors = get_opt_anchors!(nodes[0], nodes[1], chan_id);

	// Get nodes[0]'s commitment transaction and HTLC-Timeout transactions
	let as_txn = get_local_commitment_txn!(nodes[0], chan_id);
	assert_eq!(as_txn.len(), 3);
	check_spends!(as_txn[1], as_txn[0]);
	check_spends!(as_txn[2], as_txn[0]);
	check_spends!(as_txn[0], funding_tx);

	// First confirm the commitment transaction on nodes[0], which should leave us with three
	// claimable balances.
	let node_a_commitment_claimable = nodes[0].best_block_info().1 + BREAKDOWN_TIMEOUT as u32;
	mine_transaction(&nodes[0], &as_txn[0]);
	check_added_monitors!(nodes[0], 1);
	check_closed_broadcast!(nodes[0], true);
	check_closed_event!(nodes[0], 1, ClosureReason::CommitmentTxConfirmed);

	assert_eq!(sorted_vec(vec![Balance::ClaimableAwaitingConfirmations {
			claimable_amount_satoshis: 1_000_000 - 10_000 - 20_000 - chan_feerate *
				(channel::commitment_tx_base_weight(opt_anchors) + 2 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
			confirmation_height: node_a_commitment_claimable,
		}, Balance::MaybeTimeoutClaimableHTLC {
			claimable_amount_satoshis: 10_000,
			claimable_height: htlc_cltv_timeout,
		}, Balance::MaybeTimeoutClaimableHTLC {
			claimable_amount_satoshis: 20_000,
			claimable_height: htlc_cltv_timeout,
		}]),
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	// Get nodes[1]'s HTLC claim tx for the second HTLC
	mine_transaction(&nodes[1], &as_txn[0]);
	check_added_monitors!(nodes[1], 1);
	check_closed_broadcast!(nodes[1], true);
	check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed);
	let bs_htlc_claim_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	assert_eq!(bs_htlc_claim_txn.len(), 1);
	check_spends!(bs_htlc_claim_txn[0], as_txn[0]);

	// Connect blocks until the HTLCs expire, allowing us to (validly) broadcast the HTLC-Timeout
	// transaction.
	connect_blocks(&nodes[0], TEST_FINAL_CLTV - 1);
	assert_eq!(sorted_vec(vec![Balance::ClaimableAwaitingConfirmations {
			claimable_amount_satoshis: 1_000_000 - 10_000 - 20_000 - chan_feerate *
				(channel::commitment_tx_base_weight(opt_anchors) + 2 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
			confirmation_height: node_a_commitment_claimable,
		}, Balance::MaybeTimeoutClaimableHTLC {
			claimable_amount_satoshis: 10_000,
			claimable_height: htlc_cltv_timeout,
		}, Balance::MaybeTimeoutClaimableHTLC {
			claimable_amount_satoshis: 20_000,
			claimable_height: htlc_cltv_timeout,
		}]),
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));
	assert_eq!(as_txn[1].lock_time.0, nodes[0].best_block_info().1 + 1); // as_txn[1] can be included in the next block

	// Now confirm nodes[0]'s HTLC-Timeout transaction, which changes the claimable balance to an
	// "awaiting confirmations" one.
	let node_a_htlc_claimable = nodes[0].best_block_info().1 + BREAKDOWN_TIMEOUT as u32;
	mine_transaction(&nodes[0], &as_txn[1]);
	// Note that prior to the fix in the commit which introduced this test, this (and the next
	// balance) check failed. With this check removed, the code panicked in the `connect_blocks`
	// call, as described, two hunks down.
	assert_eq!(sorted_vec(vec![Balance::ClaimableAwaitingConfirmations {
			claimable_amount_satoshis: 1_000_000 - 10_000 - 20_000 - chan_feerate *
				(channel::commitment_tx_base_weight(opt_anchors) + 2 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
			confirmation_height: node_a_commitment_claimable,
		}, Balance::ClaimableAwaitingConfirmations {
			claimable_amount_satoshis: 10_000,
			confirmation_height: node_a_htlc_claimable,
		}, Balance::MaybeTimeoutClaimableHTLC {
			claimable_amount_satoshis: 20_000,
			claimable_height: htlc_cltv_timeout,
		}]),
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	// Now confirm nodes[1]'s HTLC claim, giving nodes[0] the preimage. Note that the "maybe
	// claimable" balance remains until we see ANTI_REORG_DELAY blocks.
	mine_transaction(&nodes[0], &bs_htlc_claim_txn[0]);
	expect_payment_sent!(nodes[0], payment_preimage_2);
	assert_eq!(sorted_vec(vec![Balance::ClaimableAwaitingConfirmations {
			claimable_amount_satoshis: 1_000_000 - 10_000 - 20_000 - chan_feerate *
				(channel::commitment_tx_base_weight(opt_anchors) + 2 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
			confirmation_height: node_a_commitment_claimable,
		}, Balance::ClaimableAwaitingConfirmations {
			claimable_amount_satoshis: 10_000,
			confirmation_height: node_a_htlc_claimable,
		}, Balance::MaybeTimeoutClaimableHTLC {
			claimable_amount_satoshis: 20_000,
			claimable_height: htlc_cltv_timeout,
		}]),
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	// Finally make the HTLC transactions have ANTI_REORG_DELAY blocks. This call previously
	// panicked as described in the test introduction. This will remove the "maybe claimable"
	// spendable output as nodes[1] has fully claimed the second HTLC.
	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);
	expect_payment_failed!(nodes[0], payment_hash, false);

	assert_eq!(sorted_vec(vec![Balance::ClaimableAwaitingConfirmations {
			claimable_amount_satoshis: 1_000_000 - 10_000 - 20_000 - chan_feerate *
				(channel::commitment_tx_base_weight(opt_anchors) + 2 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
			confirmation_height: node_a_commitment_claimable,
		}, Balance::ClaimableAwaitingConfirmations {
			claimable_amount_satoshis: 10_000,
			confirmation_height: node_a_htlc_claimable,
		}]),
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	// Connect blocks until the commitment transaction's CSV expires, providing us the relevant
	// `SpendableOutputs` event and removing the claimable balance entry.
	connect_blocks(&nodes[0], node_a_commitment_claimable - nodes[0].best_block_info().1);
	assert_eq!(vec![Balance::ClaimableAwaitingConfirmations {
			claimable_amount_satoshis: 10_000,
			confirmation_height: node_a_htlc_claimable,
		}],
		nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances());
	test_spendable_output(&nodes[0], &as_txn[0]);

	// Connect blocks until the HTLC-Timeout's CSV expires, providing us the relevant
	// `SpendableOutputs` event and removing the claimable balance entry.
	connect_blocks(&nodes[0], node_a_htlc_claimable - nodes[0].best_block_info().1);
	assert!(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances().is_empty());
	test_spendable_output(&nodes[0], &as_txn[1]);

	// Ensure that even if we connect more blocks, potentially replaying the entire chain if we're
	// using `ConnectStyle::HighlyRedundantTransactionsFirstSkippingBlocks`, we don't get new
	// monitor events or claimable balances.
	connect_blocks(&nodes[0], 6);
	connect_blocks(&nodes[0], 6);
	assert!(nodes[0].chain_monitor.chain_monitor.get_and_clear_pending_events().is_empty());
	assert!(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances().is_empty());
}

#[test]
fn test_no_preimage_inbound_htlc_balances() {
	// Tests that MaybePreimageClaimableHTLC are generated for inbound HTLCs for which we do not
	// have a preimage.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let (_, _, chan_id, funding_tx) = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 500_000_000);
	let funding_outpoint = OutPoint { txid: funding_tx.txid(), index: 0 };

	// Send two HTLCs, one from A to B, and one from B to A.
	let to_b_failed_payment_hash = route_payment(&nodes[0], &[&nodes[1]], 10_000_000).1;
	let to_a_failed_payment_hash = route_payment(&nodes[1], &[&nodes[0]], 20_000_000).1;
	let htlc_cltv_timeout = nodes[0].best_block_info().1 + TEST_FINAL_CLTV + 1; // Note ChannelManager adds one to CLTV timeouts for safety

	let chan_feerate = get_feerate!(nodes[0], nodes[1], chan_id) as u64;
	let opt_anchors = get_opt_anchors!(nodes[0], nodes[1], chan_id);

	// Both A and B will have an HTLC that's claimable on timeout and one that's claimable if they
	// receive the preimage. These will remain the same through the channel closure and until the
	// HTLC output is spent.

	assert_eq!(sorted_vec(vec![Balance::ClaimableOnChannelClose {
			claimable_amount_satoshis: 1_000_000 - 500_000 - 10_000 - chan_feerate *
				(channel::commitment_tx_base_weight(opt_anchors) + 2 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
		}, Balance::MaybePreimageClaimableHTLC {
			claimable_amount_satoshis: 20_000,
			expiry_height: htlc_cltv_timeout,
		}, Balance::MaybeTimeoutClaimableHTLC {
			claimable_amount_satoshis: 10_000,
			claimable_height: htlc_cltv_timeout,
		}]),
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	assert_eq!(sorted_vec(vec![Balance::ClaimableOnChannelClose {
			claimable_amount_satoshis: 500_000 - 20_000,
		}, Balance::MaybePreimageClaimableHTLC {
			claimable_amount_satoshis: 10_000,
			expiry_height: htlc_cltv_timeout,
		}, Balance::MaybeTimeoutClaimableHTLC {
			claimable_amount_satoshis: 20_000,
			claimable_height: htlc_cltv_timeout,
		}]),
		sorted_vec(nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	// Get nodes[0]'s commitment transaction and HTLC-Timeout transaction
	let as_txn = get_local_commitment_txn!(nodes[0], chan_id);
	assert_eq!(as_txn.len(), 2);
	check_spends!(as_txn[1], as_txn[0]);
	check_spends!(as_txn[0], funding_tx);

	// Now close the channel by confirming A's commitment transaction on both nodes, checking the
	// claimable balances remain the same except for the non-HTLC balance changing variant.
	let node_a_commitment_claimable = nodes[0].best_block_info().1 + BREAKDOWN_TIMEOUT as u32;
	let as_pre_spend_claims = sorted_vec(vec![Balance::ClaimableAwaitingConfirmations {
			claimable_amount_satoshis: 1_000_000 - 500_000 - 10_000 - chan_feerate *
				(channel::commitment_tx_base_weight(opt_anchors) + 2 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
			confirmation_height: node_a_commitment_claimable,
		}, Balance::MaybePreimageClaimableHTLC {
			claimable_amount_satoshis: 20_000,
			expiry_height: htlc_cltv_timeout,
		}, Balance::MaybeTimeoutClaimableHTLC {
			claimable_amount_satoshis: 10_000,
			claimable_height: htlc_cltv_timeout,
		}]);

	mine_transaction(&nodes[0], &as_txn[0]);
	nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().clear();
	check_added_monitors!(nodes[0], 1);
	check_closed_broadcast!(nodes[0], true);
	check_closed_event!(nodes[0], 1, ClosureReason::CommitmentTxConfirmed);

	assert_eq!(as_pre_spend_claims,
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	mine_transaction(&nodes[1], &as_txn[0]);
	check_added_monitors!(nodes[1], 1);
	check_closed_broadcast!(nodes[1], true);
	check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed);

	let node_b_commitment_claimable = nodes[1].best_block_info().1 + ANTI_REORG_DELAY - 1;
	let mut bs_pre_spend_claims = sorted_vec(vec![Balance::ClaimableAwaitingConfirmations {
			claimable_amount_satoshis: 500_000 - 20_000,
			confirmation_height: node_b_commitment_claimable,
		}, Balance::MaybePreimageClaimableHTLC {
			claimable_amount_satoshis: 10_000,
			expiry_height: htlc_cltv_timeout,
		}, Balance::MaybeTimeoutClaimableHTLC {
			claimable_amount_satoshis: 20_000,
			claimable_height: htlc_cltv_timeout,
		}]);
	assert_eq!(bs_pre_spend_claims,
		sorted_vec(nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	// We'll broadcast the HTLC-Timeout transaction one block prior to the htlc's expiration (as it
	// is confirmable in the next block), but will still include the same claimable balances as no
	// HTLC has been spent, even after the HTLC expires. We'll also fail the inbound HTLC, but it
	// won't do anything as the channel is already closed.

	connect_blocks(&nodes[0], TEST_FINAL_CLTV - 1);
	let as_htlc_timeout_claim = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	assert_eq!(as_htlc_timeout_claim.len(), 1);
	check_spends!(as_htlc_timeout_claim[0], as_txn[0]);
	expect_pending_htlcs_forwardable_conditions!(nodes[0],
		[HTLCDestination::FailedPayment { payment_hash: to_a_failed_payment_hash }]);

	assert_eq!(as_pre_spend_claims,
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	connect_blocks(&nodes[0], 1);
	assert_eq!(as_pre_spend_claims,
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	// For node B, we'll get the non-HTLC funds claimable after ANTI_REORG_DELAY confirmations
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);
	test_spendable_output(&nodes[1], &as_txn[0]);
	bs_pre_spend_claims.retain(|e| if let Balance::ClaimableAwaitingConfirmations { .. } = e { false } else { true });

	// The next few blocks for B look the same as for A, though for the opposite HTLC
	nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clear();
	connect_blocks(&nodes[1], TEST_FINAL_CLTV - (ANTI_REORG_DELAY - 1) - 1);
	expect_pending_htlcs_forwardable_conditions!(nodes[1],
		[HTLCDestination::FailedPayment { payment_hash: to_b_failed_payment_hash }]);
	let bs_htlc_timeout_claim = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	assert_eq!(bs_htlc_timeout_claim.len(), 1);
	check_spends!(bs_htlc_timeout_claim[0], as_txn[0]);

	assert_eq!(bs_pre_spend_claims,
		sorted_vec(nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	connect_blocks(&nodes[1], 1);
	assert_eq!(bs_pre_spend_claims,
		sorted_vec(nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	// Now confirm the two HTLC timeout transactions for A, checking that the inbound HTLC resolves
	// after ANTI_REORG_DELAY confirmations and the other takes BREAKDOWN_TIMEOUT confirmations.
	mine_transaction(&nodes[0], &as_htlc_timeout_claim[0]);
	let as_timeout_claimable_height = nodes[0].best_block_info().1 + (BREAKDOWN_TIMEOUT as u32) - 1;
	assert_eq!(sorted_vec(vec![Balance::ClaimableAwaitingConfirmations {
			claimable_amount_satoshis: 1_000_000 - 500_000 - 10_000 - chan_feerate *
				(channel::commitment_tx_base_weight(opt_anchors) + 2 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
			confirmation_height: node_a_commitment_claimable,
		}, Balance::MaybePreimageClaimableHTLC {
			claimable_amount_satoshis: 20_000,
			expiry_height: htlc_cltv_timeout,
		}, Balance::ClaimableAwaitingConfirmations {
			claimable_amount_satoshis: 10_000,
			confirmation_height: as_timeout_claimable_height,
		}]),
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	mine_transaction(&nodes[0], &bs_htlc_timeout_claim[0]);
	assert_eq!(sorted_vec(vec![Balance::ClaimableAwaitingConfirmations {
			claimable_amount_satoshis: 1_000_000 - 500_000 - 10_000 - chan_feerate *
				(channel::commitment_tx_base_weight(opt_anchors) + 2 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
			confirmation_height: node_a_commitment_claimable,
		}, Balance::MaybePreimageClaimableHTLC {
			claimable_amount_satoshis: 20_000,
			expiry_height: htlc_cltv_timeout,
		}, Balance::ClaimableAwaitingConfirmations {
			claimable_amount_satoshis: 10_000,
			confirmation_height: as_timeout_claimable_height,
		}]),
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	// Once as_htlc_timeout_claim[0] reaches ANTI_REORG_DELAY confirmations, we should get a
	// payment failure event.
	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 2);
	expect_payment_failed!(nodes[0], to_b_failed_payment_hash, false);

	connect_blocks(&nodes[0], 1);
	assert_eq!(sorted_vec(vec![Balance::ClaimableAwaitingConfirmations {
			claimable_amount_satoshis: 1_000_000 - 500_000 - 10_000 - chan_feerate *
				(channel::commitment_tx_base_weight(opt_anchors) + 2 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
			confirmation_height: node_a_commitment_claimable,
		}, Balance::ClaimableAwaitingConfirmations {
			claimable_amount_satoshis: 10_000,
			confirmation_height: core::cmp::max(as_timeout_claimable_height, htlc_cltv_timeout),
		}]),
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	connect_blocks(&nodes[0], node_a_commitment_claimable - nodes[0].best_block_info().1);
	assert_eq!(vec![Balance::ClaimableAwaitingConfirmations {
			claimable_amount_satoshis: 10_000,
			confirmation_height: core::cmp::max(as_timeout_claimable_height, htlc_cltv_timeout),
		}],
		nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances());
	test_spendable_output(&nodes[0], &as_txn[0]);

	connect_blocks(&nodes[0], as_timeout_claimable_height - nodes[0].best_block_info().1);
	assert!(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances().is_empty());
	test_spendable_output(&nodes[0], &as_htlc_timeout_claim[0]);

	// The process for B should be completely identical as well, noting that the non-HTLC-balance
	// was already claimed.
	mine_transaction(&nodes[1], &bs_htlc_timeout_claim[0]);
	let bs_timeout_claimable_height = nodes[1].best_block_info().1 + ANTI_REORG_DELAY - 1;
	assert_eq!(sorted_vec(vec![Balance::MaybePreimageClaimableHTLC {
			claimable_amount_satoshis: 10_000,
			expiry_height: htlc_cltv_timeout,
		}, Balance::ClaimableAwaitingConfirmations {
			claimable_amount_satoshis: 20_000,
			confirmation_height: bs_timeout_claimable_height,
		}]),
		sorted_vec(nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	mine_transaction(&nodes[1], &as_htlc_timeout_claim[0]);
	assert_eq!(sorted_vec(vec![Balance::MaybePreimageClaimableHTLC {
			claimable_amount_satoshis: 10_000,
			expiry_height: htlc_cltv_timeout,
		}, Balance::ClaimableAwaitingConfirmations {
			claimable_amount_satoshis: 20_000,
			confirmation_height: bs_timeout_claimable_height,
		}]),
		sorted_vec(nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 2);
	expect_payment_failed!(nodes[1], to_a_failed_payment_hash, false);

	assert_eq!(vec![Balance::MaybePreimageClaimableHTLC {
			claimable_amount_satoshis: 10_000,
			expiry_height: htlc_cltv_timeout,
		}],
		nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances());
	test_spendable_output(&nodes[1], &bs_htlc_timeout_claim[0]);

	connect_blocks(&nodes[1], 1);
	assert!(nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances().is_empty());

	// Ensure that even if we connect more blocks, potentially replaying the entire chain if we're
	// using `ConnectStyle::HighlyRedundantTransactionsFirstSkippingBlocks`, we don't get new
	// monitor events or claimable balances.
	connect_blocks(&nodes[1], 6);
	connect_blocks(&nodes[1], 6);
	assert!(nodes[1].chain_monitor.chain_monitor.get_and_clear_pending_events().is_empty());
	assert!(nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances().is_empty());
}

fn sorted_vec_with_additions<T: Ord + Clone>(v_orig: &Vec<T>, extra_ts: &[&T]) -> Vec<T> {
	let mut v = v_orig.clone();
	for t in extra_ts {
		v.push((*t).clone());
	}
	v.sort_unstable();
	v
}

fn do_test_revoked_counterparty_commitment_balances(confirm_htlc_spend_first: bool) {
	// Tests `get_claimable_balances` for revoked counterparty commitment transactions.
	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	// We broadcast a second-to-latest commitment transaction, without providing the revocation
	// secret to the counterparty. However, because we always immediately take the revocation
	// secret from the keys_manager, we would panic at broadcast as we're trying to sign a
	// transaction which, from the point of view of our keys_manager, is revoked.
	chanmon_cfgs[1].keys_manager.disable_revocation_policy_check = true;
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let (_, _, chan_id, funding_tx) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 100_000_000);
	let funding_outpoint = OutPoint { txid: funding_tx.txid(), index: 0 };
	assert_eq!(funding_outpoint.to_channel_id(), chan_id);

	// We create five HTLCs for B to claim against A's revoked commitment transaction:
	//
	// (1) one for which A is the originator and B knows the preimage
	// (2) one for which B is the originator where the HTLC has since timed-out
	// (3) one for which B is the originator but where the HTLC has not yet timed-out
	// (4) one dust HTLC which is lost in the channel closure
	// (5) one that actually isn't in the revoked commitment transaction at all, but was added in
	//     later commitment transaction updates
	//
	// Though they could all be claimed in a single claim transaction, due to CLTV timeouts they
	// are all currently claimed in separate transactions, which helps us test as we can claim
	// HTLCs individually.

	let (claimed_payment_preimage, claimed_payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1]], 3_000_000);
	let timeout_payment_hash = route_payment(&nodes[1], &[&nodes[0]], 4_000_000).1;
	let dust_payment_hash = route_payment(&nodes[1], &[&nodes[0]], 3_000).1;

	let htlc_cltv_timeout = nodes[0].best_block_info().1 + TEST_FINAL_CLTV + 1; // Note ChannelManager adds one to CLTV timeouts for safety

	connect_blocks(&nodes[0], 10);
	connect_blocks(&nodes[1], 10);

	let live_htlc_cltv_timeout = nodes[0].best_block_info().1 + TEST_FINAL_CLTV + 1; // Note ChannelManager adds one to CLTV timeouts for safety
	let live_payment_hash = route_payment(&nodes[1], &[&nodes[0]], 5_000_000).1;

	// Get the latest commitment transaction from A and then update the fee to revoke it
	let as_revoked_txn = get_local_commitment_txn!(nodes[0], chan_id);
	let opt_anchors = get_opt_anchors!(nodes[0], nodes[1], chan_id);

	let chan_feerate = get_feerate!(nodes[0], nodes[1], chan_id) as u64;

	let missing_htlc_cltv_timeout = nodes[0].best_block_info().1 + TEST_FINAL_CLTV + 1; // Note ChannelManager adds one to CLTV timeouts for safety
	let missing_htlc_payment_hash = route_payment(&nodes[1], &[&nodes[0]], 2_000_000).1;

	nodes[1].node.claim_funds(claimed_payment_preimage);
	expect_payment_claimed!(nodes[1], claimed_payment_hash, 3_000_000);
	check_added_monitors!(nodes[1], 1);
	let _b_htlc_msgs = get_htlc_update_msgs!(&nodes[1], nodes[0].node.get_our_node_id());

	connect_blocks(&nodes[0], htlc_cltv_timeout + 1 - 10);
	check_closed_broadcast!(nodes[0], true);
	check_added_monitors!(nodes[0], 1);

	let mut events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 6);
	let mut failed_payments: HashSet<_> =
		[timeout_payment_hash, dust_payment_hash, live_payment_hash, missing_htlc_payment_hash]
		.iter().map(|a| *a).collect();
	events.retain(|ev| {
		match ev {
			Event::HTLCHandlingFailed { failed_next_destination: HTLCDestination::NextHopChannel { node_id, channel_id }, .. } => {
				assert_eq!(*channel_id, chan_id);
				assert_eq!(*node_id, Some(nodes[1].node.get_our_node_id()));
				false
			},
			Event::HTLCHandlingFailed { failed_next_destination: HTLCDestination::FailedPayment { payment_hash }, .. } => {
				assert!(failed_payments.remove(payment_hash));
				false
			},
			_ => true,
		}
	});
	assert!(failed_payments.is_empty());
	if let Event::PendingHTLCsForwardable { .. } = events[0] {} else { panic!(); }
	match &events[1] {
		Event::ChannelClosed { reason: ClosureReason::CommitmentTxConfirmed, .. } => {},
		_ => panic!(),
	}

	connect_blocks(&nodes[1], htlc_cltv_timeout + 1 - 10);
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors!(nodes[1], 1);
	check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed);

	// Prior to channel closure, B considers the preimage HTLC as its own, and otherwise only
	// lists the two on-chain timeout-able HTLCs as claimable balances.
	assert_eq!(sorted_vec(vec![Balance::ClaimableOnChannelClose {
			claimable_amount_satoshis: 100_000 - 5_000 - 4_000 - 3 - 2_000 + 3_000,
		}, Balance::MaybeTimeoutClaimableHTLC {
			claimable_amount_satoshis: 2_000,
			claimable_height: missing_htlc_cltv_timeout,
		}, Balance::MaybeTimeoutClaimableHTLC {
			claimable_amount_satoshis: 4_000,
			claimable_height: htlc_cltv_timeout,
		}, Balance::MaybeTimeoutClaimableHTLC {
			claimable_amount_satoshis: 5_000,
			claimable_height: live_htlc_cltv_timeout,
		}]),
		sorted_vec(nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	mine_transaction(&nodes[1], &as_revoked_txn[0]);
	let mut claim_txn: Vec<_> = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().drain(..).filter(|tx| tx.input.iter().any(|inp| inp.previous_output.txid == as_revoked_txn[0].txid())).collect();
	// Currently the revoked commitment is claimed in four transactions as the HTLCs all expire
	// quite soon.
	assert_eq!(claim_txn.len(), 4);
	claim_txn.sort_unstable_by_key(|tx| tx.output.iter().map(|output| output.value).sum::<u64>());

	// The following constants were determined experimentally
	const BS_TO_SELF_CLAIM_EXP_WEIGHT: usize = 483;
	const OUTBOUND_HTLC_CLAIM_EXP_WEIGHT: usize = 571;
	const INBOUND_HTLC_CLAIM_EXP_WEIGHT: usize = 578;

	// Check that the weight is close to the expected weight. Note that signature sizes vary
	// somewhat so it may not always be exact.
	fuzzy_assert_eq(claim_txn[0].weight(), OUTBOUND_HTLC_CLAIM_EXP_WEIGHT);
	fuzzy_assert_eq(claim_txn[1].weight(), INBOUND_HTLC_CLAIM_EXP_WEIGHT);
	fuzzy_assert_eq(claim_txn[2].weight(), INBOUND_HTLC_CLAIM_EXP_WEIGHT);
	fuzzy_assert_eq(claim_txn[3].weight(), BS_TO_SELF_CLAIM_EXP_WEIGHT);

	// The expected balance for the next three checks, with the largest-HTLC and to_self output
	// claim balances separated out.
	let expected_balance = vec![Balance::ClaimableAwaitingConfirmations {
			// to_remote output in A's revoked commitment
			claimable_amount_satoshis: 100_000 - 5_000 - 4_000 - 3,
			confirmation_height: nodes[1].best_block_info().1 + 5,
		}, Balance::CounterpartyRevokedOutputClaimable {
			claimable_amount_satoshis: 3_000,
		}, Balance::CounterpartyRevokedOutputClaimable {
			claimable_amount_satoshis: 4_000,
		}];

	let to_self_unclaimed_balance = Balance::CounterpartyRevokedOutputClaimable {
		claimable_amount_satoshis: 1_000_000 - 100_000 - 3_000 - chan_feerate *
			(channel::commitment_tx_base_weight(opt_anchors) + 3 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
	};
	let to_self_claimed_avail_height;
	let largest_htlc_unclaimed_balance = Balance::CounterpartyRevokedOutputClaimable {
		claimable_amount_satoshis: 5_000,
	};
	let largest_htlc_claimed_avail_height;

	// Once the channel has been closed by A, B now considers all of the commitment transactions'
	// outputs as `CounterpartyRevokedOutputClaimable`.
	assert_eq!(sorted_vec_with_additions(&expected_balance, &[&to_self_unclaimed_balance, &largest_htlc_unclaimed_balance]),
		sorted_vec(nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	if confirm_htlc_spend_first {
		mine_transaction(&nodes[1], &claim_txn[2]);
		largest_htlc_claimed_avail_height = nodes[1].best_block_info().1 + 5;
		to_self_claimed_avail_height = nodes[1].best_block_info().1 + 6; // will be claimed in the next block
	} else {
		// Connect the to_self output claim, taking all of A's non-HTLC funds
		mine_transaction(&nodes[1], &claim_txn[3]);
		to_self_claimed_avail_height = nodes[1].best_block_info().1 + 5;
		largest_htlc_claimed_avail_height = nodes[1].best_block_info().1 + 6; // will be claimed in the next block
	}

	let largest_htlc_claimed_balance = Balance::ClaimableAwaitingConfirmations {
		claimable_amount_satoshis: 5_000 - chan_feerate * INBOUND_HTLC_CLAIM_EXP_WEIGHT as u64 / 1000,
		confirmation_height: largest_htlc_claimed_avail_height,
	};
	let to_self_claimed_balance = Balance::ClaimableAwaitingConfirmations {
		claimable_amount_satoshis: 1_000_000 - 100_000 - 3_000 - chan_feerate *
			(channel::commitment_tx_base_weight(opt_anchors) + 3 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000
			- chan_feerate * claim_txn[3].weight() as u64 / 1000,
		confirmation_height: to_self_claimed_avail_height,
	};

	if confirm_htlc_spend_first {
		assert_eq!(sorted_vec_with_additions(&expected_balance, &[&to_self_unclaimed_balance, &largest_htlc_claimed_balance]),
			sorted_vec(nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));
	} else {
		assert_eq!(sorted_vec_with_additions(&expected_balance, &[&to_self_claimed_balance, &largest_htlc_unclaimed_balance]),
			sorted_vec(nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));
	}

	if confirm_htlc_spend_first {
		mine_transaction(&nodes[1], &claim_txn[3]);
	} else {
		mine_transaction(&nodes[1], &claim_txn[2]);
	}
	assert_eq!(sorted_vec_with_additions(&expected_balance, &[&to_self_claimed_balance, &largest_htlc_claimed_balance]),
		sorted_vec(nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	// Finally, connect the last two remaining HTLC spends and check that they move to
	// `ClaimableAwaitingConfirmations`
	mine_transaction(&nodes[1], &claim_txn[0]);
	mine_transaction(&nodes[1], &claim_txn[1]);

	assert_eq!(sorted_vec(vec![Balance::ClaimableAwaitingConfirmations {
			// to_remote output in A's revoked commitment
			claimable_amount_satoshis: 100_000 - 5_000 - 4_000 - 3,
			confirmation_height: nodes[1].best_block_info().1 + 1,
		}, Balance::ClaimableAwaitingConfirmations {
			claimable_amount_satoshis: 1_000_000 - 100_000 - 3_000 - chan_feerate *
				(channel::commitment_tx_base_weight(opt_anchors) + 3 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000
				- chan_feerate * claim_txn[3].weight() as u64 / 1000,
			confirmation_height: to_self_claimed_avail_height,
		}, Balance::ClaimableAwaitingConfirmations {
			claimable_amount_satoshis: 3_000 - chan_feerate * OUTBOUND_HTLC_CLAIM_EXP_WEIGHT as u64 / 1000,
			confirmation_height: nodes[1].best_block_info().1 + 4,
		}, Balance::ClaimableAwaitingConfirmations {
			claimable_amount_satoshis: 4_000 - chan_feerate * INBOUND_HTLC_CLAIM_EXP_WEIGHT as u64 / 1000,
			confirmation_height: nodes[1].best_block_info().1 + 5,
		}, Balance::ClaimableAwaitingConfirmations {
			claimable_amount_satoshis: 5_000 - chan_feerate * INBOUND_HTLC_CLAIM_EXP_WEIGHT as u64 / 1000,
			confirmation_height: largest_htlc_claimed_avail_height,
		}]),
		sorted_vec(nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	connect_blocks(&nodes[1], 1);
	test_spendable_output(&nodes[1], &as_revoked_txn[0]);

	let mut payment_failed_events = nodes[1].node.get_and_clear_pending_events();
	expect_payment_failed_conditions_event(payment_failed_events[..2].to_vec(),
		missing_htlc_payment_hash, false, PaymentFailedConditions::new());
	expect_payment_failed_conditions_event(payment_failed_events[2..].to_vec(),
		dust_payment_hash, false, PaymentFailedConditions::new());

	connect_blocks(&nodes[1], 1);
	test_spendable_output(&nodes[1], &claim_txn[if confirm_htlc_spend_first { 2 } else { 3 }]);
	connect_blocks(&nodes[1], 1);
	test_spendable_output(&nodes[1], &claim_txn[if confirm_htlc_spend_first { 3 } else { 2 }]);
	expect_payment_failed!(nodes[1], live_payment_hash, false);
	connect_blocks(&nodes[1], 1);
	test_spendable_output(&nodes[1], &claim_txn[0]);
	connect_blocks(&nodes[1], 1);
	test_spendable_output(&nodes[1], &claim_txn[1]);
	expect_payment_failed!(nodes[1], timeout_payment_hash, false);
	assert_eq!(nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances(), Vec::new());

	// Ensure that even if we connect more blocks, potentially replaying the entire chain if we're
	// using `ConnectStyle::HighlyRedundantTransactionsFirstSkippingBlocks`, we don't get new
	// monitor events or claimable balances.
	connect_blocks(&nodes[1], 6);
	connect_blocks(&nodes[1], 6);
	assert!(nodes[1].chain_monitor.chain_monitor.get_and_clear_pending_events().is_empty());
	assert!(nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances().is_empty());
}

#[test]
fn test_revoked_counterparty_commitment_balances() {
	do_test_revoked_counterparty_commitment_balances(true);
	do_test_revoked_counterparty_commitment_balances(false);
}

#[test]
fn test_revoked_counterparty_htlc_tx_balances() {
	// Tests `get_claimable_balances` for revocation spends of HTLC transactions.
	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	chanmon_cfgs[1].keys_manager.disable_revocation_policy_check = true;
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Create some initial channels
	let (_, _, chan_id, funding_tx) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 11_000_000);
	let funding_outpoint = OutPoint { txid: funding_tx.txid(), index: 0 };
	assert_eq!(funding_outpoint.to_channel_id(), chan_id);

	let payment_preimage = route_payment(&nodes[0], &[&nodes[1]], 3_000_000).0;
	let failed_payment_hash = route_payment(&nodes[1], &[&nodes[0]], 1_000_000).1;
	let revoked_local_txn = get_local_commitment_txn!(nodes[1], chan_id);
	assert_eq!(revoked_local_txn[0].input.len(), 1);
	assert_eq!(revoked_local_txn[0].input[0].previous_output.txid, funding_tx.txid());

	// The to-be-revoked commitment tx should have two HTLCs and an output for both sides
	assert_eq!(revoked_local_txn[0].output.len(), 4);

	claim_payment(&nodes[0], &[&nodes[1]], payment_preimage);

	let chan_feerate = get_feerate!(nodes[0], nodes[1], chan_id) as u64;
	let opt_anchors = get_opt_anchors!(nodes[0], nodes[1], chan_id);

	// B will generate an HTLC-Success from its revoked commitment tx
	mine_transaction(&nodes[1], &revoked_local_txn[0]);
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors!(nodes[1], 1);
	check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed);
	let revoked_htlc_success_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);

	assert_eq!(revoked_htlc_success_txn.len(), 1);
	assert_eq!(revoked_htlc_success_txn[0].input.len(), 1);
	assert_eq!(revoked_htlc_success_txn[0].input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
	check_spends!(revoked_htlc_success_txn[0], revoked_local_txn[0]);

	connect_blocks(&nodes[1], TEST_FINAL_CLTV);
	let revoked_htlc_timeout_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	assert_eq!(revoked_htlc_timeout_txn.len(), 1);
	check_spends!(revoked_htlc_timeout_txn[0], revoked_local_txn[0]);
	assert_ne!(revoked_htlc_success_txn[0].input[0].previous_output, revoked_htlc_timeout_txn[0].input[0].previous_output);
	assert_eq!(revoked_htlc_success_txn[0].lock_time.0, 0);
	assert_ne!(revoked_htlc_timeout_txn[0].lock_time.0, 0);

	// A will generate justice tx from B's revoked commitment/HTLC tx
	mine_transaction(&nodes[0], &revoked_local_txn[0]);
	check_closed_broadcast!(nodes[0], true);
	check_added_monitors!(nodes[0], 1);
	check_closed_event!(nodes[0], 1, ClosureReason::CommitmentTxConfirmed);
	let to_remote_conf_height = nodes[0].best_block_info().1 + ANTI_REORG_DELAY - 1;

	let as_commitment_claim_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	assert_eq!(as_commitment_claim_txn.len(), 1);
	check_spends!(as_commitment_claim_txn[0], revoked_local_txn[0]);

	// The next two checks have the same balance set for A - even though we confirm a revoked HTLC
	// transaction our balance tracking doesn't use the on-chain value so the
	// `CounterpartyRevokedOutputClaimable` entry doesn't change.
	let as_balances = sorted_vec(vec![Balance::ClaimableAwaitingConfirmations {
			// to_remote output in B's revoked commitment
			claimable_amount_satoshis: 1_000_000 - 11_000 - 3_000 - chan_feerate *
				(channel::commitment_tx_base_weight(opt_anchors) + 2 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
			confirmation_height: to_remote_conf_height,
		}, Balance::CounterpartyRevokedOutputClaimable {
			// to_self output in B's revoked commitment
			claimable_amount_satoshis: 10_000,
		}, Balance::CounterpartyRevokedOutputClaimable { // HTLC 1
			claimable_amount_satoshis: 3_000,
		}, Balance::CounterpartyRevokedOutputClaimable { // HTLC 2
			claimable_amount_satoshis: 1_000,
		}]);
	assert_eq!(as_balances,
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	mine_transaction(&nodes[0], &revoked_htlc_success_txn[0]);
	let as_htlc_claim_tx = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	assert_eq!(as_htlc_claim_tx.len(), 2);
	check_spends!(as_htlc_claim_tx[0], revoked_htlc_success_txn[0]);
	check_spends!(as_htlc_claim_tx[1], revoked_local_txn[0]); // A has to generate a new claim for the remaining revoked
	                                                          // outputs (which no longer includes the spent HTLC output)

	assert_eq!(as_balances,
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	assert_eq!(as_htlc_claim_tx[0].output.len(), 1);
	fuzzy_assert_eq(as_htlc_claim_tx[0].output[0].value,
		3_000 - chan_feerate * (revoked_htlc_success_txn[0].weight() + as_htlc_claim_tx[0].weight()) as u64 / 1000);

	mine_transaction(&nodes[0], &as_htlc_claim_tx[0]);
	assert_eq!(sorted_vec(vec![Balance::ClaimableAwaitingConfirmations {
			// to_remote output in B's revoked commitment
			claimable_amount_satoshis: 1_000_000 - 11_000 - 3_000 - chan_feerate *
				(channel::commitment_tx_base_weight(opt_anchors) + 2 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
			confirmation_height: to_remote_conf_height,
		}, Balance::CounterpartyRevokedOutputClaimable {
			// to_self output in B's revoked commitment
			claimable_amount_satoshis: 10_000,
		}, Balance::CounterpartyRevokedOutputClaimable { // HTLC 2
			claimable_amount_satoshis: 1_000,
		}, Balance::ClaimableAwaitingConfirmations {
			claimable_amount_satoshis: as_htlc_claim_tx[0].output[0].value,
			confirmation_height: nodes[0].best_block_info().1 + ANTI_REORG_DELAY - 1,
		}]),
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 3);
	test_spendable_output(&nodes[0], &revoked_local_txn[0]);
	assert_eq!(sorted_vec(vec![Balance::CounterpartyRevokedOutputClaimable {
			// to_self output to B
			claimable_amount_satoshis: 10_000,
		}, Balance::CounterpartyRevokedOutputClaimable { // HTLC 2
			claimable_amount_satoshis: 1_000,
		}, Balance::ClaimableAwaitingConfirmations {
			claimable_amount_satoshis: as_htlc_claim_tx[0].output[0].value,
			confirmation_height: nodes[0].best_block_info().1 + 2,
		}]),
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	connect_blocks(&nodes[0], 2);
	test_spendable_output(&nodes[0], &as_htlc_claim_tx[0]);
	assert_eq!(sorted_vec(vec![Balance::CounterpartyRevokedOutputClaimable {
			// to_self output in B's revoked commitment
			claimable_amount_satoshis: 10_000,
		}, Balance::CounterpartyRevokedOutputClaimable { // HTLC 2
			claimable_amount_satoshis: 1_000,
		}]),
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	connect_blocks(&nodes[0], revoked_htlc_timeout_txn[0].lock_time.0 - nodes[0].best_block_info().1);
	expect_pending_htlcs_forwardable_and_htlc_handling_failed_ignore!(&nodes[0],
		[HTLCDestination::FailedPayment { payment_hash: failed_payment_hash }]);
	// As time goes on A may split its revocation claim transaction into multiple.
	let as_fewer_input_rbf = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	for tx in as_fewer_input_rbf.iter() {
		check_spends!(tx, revoked_local_txn[0]);
	}

	// Connect a number of additional blocks to ensure we don't forget the HTLC output needs
	// claiming.
	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);
	let as_fewer_input_rbf = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	for tx in as_fewer_input_rbf.iter() {
		check_spends!(tx, revoked_local_txn[0]);
	}

	mine_transaction(&nodes[0], &revoked_htlc_timeout_txn[0]);
	let as_second_htlc_claim_tx = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	assert_eq!(as_second_htlc_claim_tx.len(), 2);

	check_spends!(as_second_htlc_claim_tx[0], revoked_htlc_timeout_txn[0]);
	check_spends!(as_second_htlc_claim_tx[1], revoked_local_txn[0]);

	// Connect blocks to finalize the HTLC resolution with the HTLC-Timeout transaction. In a
	// previous iteration of the revoked balance handling this would result in us "forgetting" that
	// the revoked HTLC output still needed to be claimed.
	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);
	assert_eq!(sorted_vec(vec![Balance::CounterpartyRevokedOutputClaimable {
			// to_self output in B's revoked commitment
			claimable_amount_satoshis: 10_000,
		}, Balance::CounterpartyRevokedOutputClaimable { // HTLC 2
			claimable_amount_satoshis: 1_000,
		}]),
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	mine_transaction(&nodes[0], &as_second_htlc_claim_tx[0]);
	assert_eq!(sorted_vec(vec![Balance::CounterpartyRevokedOutputClaimable {
			// to_self output in B's revoked commitment
			claimable_amount_satoshis: 10_000,
		}, Balance::ClaimableAwaitingConfirmations {
			claimable_amount_satoshis: as_second_htlc_claim_tx[0].output[0].value,
			confirmation_height: nodes[0].best_block_info().1 + ANTI_REORG_DELAY - 1,
		}]),
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	mine_transaction(&nodes[0], &as_second_htlc_claim_tx[1]);
	assert_eq!(sorted_vec(vec![Balance::ClaimableAwaitingConfirmations {
			// to_self output in B's revoked commitment
			claimable_amount_satoshis: as_second_htlc_claim_tx[1].output[0].value,
			confirmation_height: nodes[0].best_block_info().1 + ANTI_REORG_DELAY - 1,
		}, Balance::ClaimableAwaitingConfirmations {
			claimable_amount_satoshis: as_second_htlc_claim_tx[0].output[0].value,
			confirmation_height: nodes[0].best_block_info().1 + ANTI_REORG_DELAY - 2,
		}]),
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 2);
	test_spendable_output(&nodes[0], &as_second_htlc_claim_tx[0]);
	connect_blocks(&nodes[0], 1);
	test_spendable_output(&nodes[0], &as_second_htlc_claim_tx[1]);

	assert_eq!(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances(), Vec::new());

	// Ensure that even if we connect more blocks, potentially replaying the entire chain if we're
	// using `ConnectStyle::HighlyRedundantTransactionsFirstSkippingBlocks`, we don't get new
	// monitor events or claimable balances.
	connect_blocks(&nodes[0], 6);
	connect_blocks(&nodes[0], 6);
	assert!(nodes[0].chain_monitor.chain_monitor.get_and_clear_pending_events().is_empty());
	assert!(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances().is_empty());
}

#[test]
fn test_revoked_counterparty_aggregated_claims() {
	// Tests `get_claimable_balances` for revoked counterparty commitment transactions when
	// claiming with an aggregated claim transaction.
	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	// We broadcast a second-to-latest commitment transaction, without providing the revocation
	// secret to the counterparty. However, because we always immediately take the revocation
	// secret from the keys_manager, we would panic at broadcast as we're trying to sign a
	// transaction which, from the point of view of our keys_manager, is revoked.
	chanmon_cfgs[1].keys_manager.disable_revocation_policy_check = true;
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let (_, _, chan_id, funding_tx) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 100_000_000);
	let funding_outpoint = OutPoint { txid: funding_tx.txid(), index: 0 };
	assert_eq!(funding_outpoint.to_channel_id(), chan_id);

	// We create two HTLCs, one which we will give A the preimage to to generate an HTLC-Success
	// transaction, and one which we will not, allowing B to claim the HTLC output in an aggregated
	// revocation-claim transaction.

	let (claimed_payment_preimage, claimed_payment_hash, ..) = route_payment(&nodes[1], &[&nodes[0]], 3_000_000);
	let revoked_payment_hash = route_payment(&nodes[1], &[&nodes[0]], 4_000_000).1;

	let htlc_cltv_timeout = nodes[1].best_block_info().1 + TEST_FINAL_CLTV + 1; // Note ChannelManager adds one to CLTV timeouts for safety

	// Cheat by giving A's ChannelMonitor the preimage to the to-be-claimed HTLC so that we have an
	// HTLC-claim transaction on the to-be-revoked state.
	get_monitor!(nodes[0], chan_id).provide_payment_preimage(&claimed_payment_hash, &claimed_payment_preimage,
		&node_cfgs[0].tx_broadcaster, &LowerBoundedFeeEstimator::new(node_cfgs[0].fee_estimator), &nodes[0].logger);

	// Now get the latest commitment transaction from A and then update the fee to revoke it
	let as_revoked_txn = get_local_commitment_txn!(nodes[0], chan_id);

	assert_eq!(as_revoked_txn.len(), 2);
	check_spends!(as_revoked_txn[0], funding_tx);
	check_spends!(as_revoked_txn[1], as_revoked_txn[0]); // The HTLC-Claim transaction

	let opt_anchors = get_opt_anchors!(nodes[0], nodes[1], chan_id);
	let chan_feerate = get_feerate!(nodes[0], nodes[1], chan_id) as u64;

	{
		let mut feerate = chanmon_cfgs[0].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate += 1;
	}
	nodes[0].node.timer_tick_occurred();
	check_added_monitors!(nodes[0], 1);

	let fee_update = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	nodes[1].node.handle_update_fee(&nodes[0].node.get_our_node_id(), &fee_update.update_fee.unwrap());
	commitment_signed_dance!(nodes[1], nodes[0], fee_update.commitment_signed, false);

	nodes[0].node.claim_funds(claimed_payment_preimage);
	expect_payment_claimed!(nodes[0], claimed_payment_hash, 3_000_000);
	check_added_monitors!(nodes[0], 1);
	let _a_htlc_msgs = get_htlc_update_msgs!(&nodes[0], nodes[1].node.get_our_node_id());

	assert_eq!(sorted_vec(vec![Balance::ClaimableOnChannelClose {
			claimable_amount_satoshis: 100_000 - 4_000 - 3_000,
		}, Balance::MaybeTimeoutClaimableHTLC {
			claimable_amount_satoshis: 4_000,
			claimable_height: htlc_cltv_timeout,
		}, Balance::MaybeTimeoutClaimableHTLC {
			claimable_amount_satoshis: 3_000,
			claimable_height: htlc_cltv_timeout,
		}]),
		sorted_vec(nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	mine_transaction(&nodes[1], &as_revoked_txn[0]);
	check_closed_broadcast!(nodes[1], true);
	check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed);
	check_added_monitors!(nodes[1], 1);

	let mut claim_txn: Vec<_> = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().drain(..).filter(|tx| tx.input.iter().any(|inp| inp.previous_output.txid == as_revoked_txn[0].txid())).collect();
	// Currently the revoked commitment outputs are all claimed in one aggregated transaction
	assert_eq!(claim_txn.len(), 1);
	assert_eq!(claim_txn[0].input.len(), 3);
	check_spends!(claim_txn[0], as_revoked_txn[0]);

	let to_remote_maturity = nodes[1].best_block_info().1 + ANTI_REORG_DELAY - 1;

	assert_eq!(sorted_vec(vec![Balance::ClaimableAwaitingConfirmations {
			// to_remote output in A's revoked commitment
			claimable_amount_satoshis: 100_000 - 4_000 - 3_000,
			confirmation_height: to_remote_maturity,
		}, Balance::CounterpartyRevokedOutputClaimable {
			// to_self output in A's revoked commitment
			claimable_amount_satoshis: 1_000_000 - 100_000 - chan_feerate *
				(channel::commitment_tx_base_weight(opt_anchors) + 2 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
		}, Balance::CounterpartyRevokedOutputClaimable { // HTLC 1
			claimable_amount_satoshis: 4_000,
		}, Balance::CounterpartyRevokedOutputClaimable { // HTLC 2
			claimable_amount_satoshis: 3_000,
		}]),
		sorted_vec(nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	// Confirm A's HTLC-Success tranasction which presumably raced B's claim, causing B to create a
	// new claim.
	mine_transaction(&nodes[1], &as_revoked_txn[1]);
	expect_payment_sent!(nodes[1], claimed_payment_preimage);
	let mut claim_txn_2: Vec<_> = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().clone();
	claim_txn_2.sort_unstable_by_key(|tx| if tx.input.iter().any(|inp| inp.previous_output.txid == as_revoked_txn[0].txid()) { 0 } else { 1 });
	// Once B sees the HTLC-Success transaction it splits its claim transaction into two, though in
	// theory it could re-aggregate the claims as well.
	assert_eq!(claim_txn_2.len(), 2);
	assert_eq!(claim_txn_2[0].input.len(), 2);
	check_spends!(claim_txn_2[0], as_revoked_txn[0]);
	assert_eq!(claim_txn_2[1].input.len(), 1);
	check_spends!(claim_txn_2[1], as_revoked_txn[1]);

	assert_eq!(sorted_vec(vec![Balance::ClaimableAwaitingConfirmations {
			// to_remote output in A's revoked commitment
			claimable_amount_satoshis: 100_000 - 4_000 - 3_000,
			confirmation_height: to_remote_maturity,
		}, Balance::CounterpartyRevokedOutputClaimable {
			// to_self output in A's revoked commitment
			claimable_amount_satoshis: 1_000_000 - 100_000 - chan_feerate *
				(channel::commitment_tx_base_weight(opt_anchors) + 2 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
		}, Balance::CounterpartyRevokedOutputClaimable { // HTLC 1
			claimable_amount_satoshis: 4_000,
		}, Balance::CounterpartyRevokedOutputClaimable { // HTLC 2
			// The amount here is a bit of a misnomer, really its been reduced by the HTLC
			// transaction fee, but the claimable amount is always a bit of an overshoot for HTLCs
			// anyway, so its not a big change.
			claimable_amount_satoshis: 3_000,
		}]),
		sorted_vec(nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	connect_blocks(&nodes[1], 5);
	test_spendable_output(&nodes[1], &as_revoked_txn[0]);

	assert_eq!(sorted_vec(vec![Balance::CounterpartyRevokedOutputClaimable {
			// to_self output in A's revoked commitment
			claimable_amount_satoshis: 1_000_000 - 100_000 - chan_feerate *
				(channel::commitment_tx_base_weight(opt_anchors) + 2 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
		}, Balance::CounterpartyRevokedOutputClaimable { // HTLC 1
			claimable_amount_satoshis: 4_000,
		}, Balance::CounterpartyRevokedOutputClaimable { // HTLC 2
			// The amount here is a bit of a misnomer, really its been reduced by the HTLC
			// transaction fee, but the claimable amount is always a bit of an overshoot for HTLCs
			// anyway, so its not a big change.
			claimable_amount_satoshis: 3_000,
		}]),
		sorted_vec(nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	mine_transaction(&nodes[1], &claim_txn_2[1]);
	let htlc_2_claim_maturity = nodes[1].best_block_info().1 + ANTI_REORG_DELAY - 1;

	assert_eq!(sorted_vec(vec![Balance::CounterpartyRevokedOutputClaimable {
			// to_self output in A's revoked commitment
			claimable_amount_satoshis: 1_000_000 - 100_000 - chan_feerate *
				(channel::commitment_tx_base_weight(opt_anchors) + 2 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
		}, Balance::CounterpartyRevokedOutputClaimable { // HTLC 1
			claimable_amount_satoshis: 4_000,
		}, Balance::ClaimableAwaitingConfirmations { // HTLC 2
			claimable_amount_satoshis: claim_txn_2[1].output[0].value,
			confirmation_height: htlc_2_claim_maturity,
		}]),
		sorted_vec(nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	connect_blocks(&nodes[1], 5);
	test_spendable_output(&nodes[1], &claim_txn_2[1]);

	assert_eq!(sorted_vec(vec![Balance::CounterpartyRevokedOutputClaimable {
			// to_self output in A's revoked commitment
			claimable_amount_satoshis: 1_000_000 - 100_000 - chan_feerate *
				(channel::commitment_tx_base_weight(opt_anchors) + 2 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
		}, Balance::CounterpartyRevokedOutputClaimable { // HTLC 1
			claimable_amount_satoshis: 4_000,
		}]),
		sorted_vec(nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	mine_transaction(&nodes[1], &claim_txn_2[0]);
	let rest_claim_maturity = nodes[1].best_block_info().1 + ANTI_REORG_DELAY - 1;

	assert_eq!(vec![Balance::ClaimableAwaitingConfirmations {
			claimable_amount_satoshis: claim_txn_2[0].output[0].value,
			confirmation_height: rest_claim_maturity,
		}],
		nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances());

	assert!(nodes[1].node.get_and_clear_pending_events().is_empty()); // We shouldn't fail the payment until we spend the output

	connect_blocks(&nodes[1], 5);
	expect_payment_failed!(nodes[1], revoked_payment_hash, false);
	test_spendable_output(&nodes[1], &claim_txn_2[0]);
	assert!(nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances().is_empty());

	// Ensure that even if we connect more blocks, potentially replaying the entire chain if we're
	// using `ConnectStyle::HighlyRedundantTransactionsFirstSkippingBlocks`, we don't get new
	// monitor events or claimable balances.
	connect_blocks(&nodes[1], 6);
	connect_blocks(&nodes[1], 6);
	assert!(nodes[1].chain_monitor.chain_monitor.get_and_clear_pending_events().is_empty());
	assert!(nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances().is_empty());
}

#[cfg(anchors)]
#[test]
fn test_yield_anchors_events() {
	// Tests that two parties supporting anchor outputs can open a channel, route payments over
	// it, and finalize its resolution uncooperatively. Once the HTLCs are locked in, one side will
	// force close once the HTLCs expire. The force close should stem from an event emitted by LDK,
	// allowing the consumer to provide additional fees to the commitment transaction to be
	// broadcast. Once the commitment transaction confirms, events for the HTLC resolution should be
	// emitted by LDK, such that the consumer can attach fees to the zero fee HTLC transactions.
	let secp = Secp256k1::new();
	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut anchors_config = UserConfig::default();
	anchors_config.channel_handshake_config.announced_channel = true;
	anchors_config.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = true;
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(anchors_config), Some(anchors_config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let chan_id = create_announced_chan_between_nodes_with_value(
		&nodes, 0, 1, 1_000_000, 500_000_000
	).2;
	route_payment(&nodes[0], &[&nodes[1]], 1_000_000);
	let (payment_preimage, payment_hash, _) = route_payment(&nodes[1], &[&nodes[0]], 1_000_000);

	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());

	connect_blocks(&nodes[0], TEST_FINAL_CLTV + LATENCY_GRACE_PERIOD_BLOCKS + 1);
	check_closed_broadcast!(&nodes[0], true);
	assert!(nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().is_empty());

	get_monitor!(nodes[0], chan_id).provide_payment_preimage(
		&payment_hash, &payment_preimage, &node_cfgs[0].tx_broadcaster,
		&LowerBoundedFeeEstimator::new(node_cfgs[0].fee_estimator), &nodes[0].logger
	);

	let mut holder_events = nodes[0].chain_monitor.chain_monitor.get_and_clear_pending_events();
	assert_eq!(holder_events.len(), 1);
	let (commitment_tx, anchor_tx) = match holder_events.pop().unwrap() {
		Event::BumpTransaction(BumpTransactionEvent::ChannelClose { commitment_tx, anchor_descriptor, .. })  => {
			assert_eq!(commitment_tx.input.len(), 1);
			assert_eq!(commitment_tx.output.len(), 6);
			let mut anchor_tx = Transaction {
				version: 2,
				lock_time: PackedLockTime::ZERO,
				input: vec![
					TxIn { previous_output: anchor_descriptor.outpoint, ..Default::default() },
					TxIn { ..Default::default() },
				],
				output: vec![TxOut {
					value: Amount::ONE_BTC.to_sat(),
					script_pubkey: Script::new_op_return(&[]),
				}],
			};
			let signer = nodes[0].keys_manager.derive_channel_keys(
				anchor_descriptor.channel_value_satoshis, &anchor_descriptor.channel_keys_id,
			);
			let funding_sig = signer.sign_holder_anchor_input(&mut anchor_tx, 0, &secp).unwrap();
			anchor_tx.input[0].witness = chan_utils::build_anchor_input_witness(
				&signer.pubkeys().funding_pubkey, &funding_sig
			);
			(commitment_tx, anchor_tx)
		},
		_ => panic!("Unexpected event"),
	};

	mine_transactions(&nodes[0], &[&commitment_tx, &anchor_tx]);
	check_added_monitors!(nodes[0], 1);

	let mut holder_events = nodes[0].chain_monitor.chain_monitor.get_and_clear_pending_events();
	// Certain block `ConnectStyle`s cause an extra `ChannelClose` event to be emitted since the
	// best block is being updated prior to the confirmed transactions.
	match *nodes[0].connect_style.borrow() {
		ConnectStyle::BestBlockFirst|ConnectStyle::BestBlockFirstReorgsOnlyTip|ConnectStyle::BestBlockFirstSkippingBlocks => {
			assert_eq!(holder_events.len(), 3);
			if let Event::BumpTransaction(BumpTransactionEvent::ChannelClose { .. }) = holder_events.remove(0) {}
			else { panic!("unexpected event"); }

		},
		_ => assert_eq!(holder_events.len(), 2),
	};
	let mut htlc_txs = Vec::with_capacity(2);
	for event in holder_events {
		match event {
			Event::BumpTransaction(BumpTransactionEvent::HTLCResolution { htlc_descriptors, .. }) => {
				assert_eq!(htlc_descriptors.len(), 1);
				let htlc_descriptor = &htlc_descriptors[0];
				let signer = nodes[0].keys_manager.derive_channel_keys(
					htlc_descriptor.channel_value_satoshis, &htlc_descriptor.channel_keys_id
				);
				let per_commitment_point = signer.get_per_commitment_point(htlc_descriptor.per_commitment_number, &secp);
				let mut htlc_tx = Transaction {
					version: 2,
					lock_time: if htlc_descriptor.htlc.offered {
						PackedLockTime(htlc_descriptor.htlc.cltv_expiry)
					} else {
						PackedLockTime::ZERO
					},
					input: vec![
						htlc_descriptor.unsigned_tx_input(), // HTLC input
						TxIn { ..Default::default() } // Fee input
					],
					output: vec![
						htlc_descriptor.tx_output(&per_commitment_point, &secp), // HTLC output
						TxOut { // Fee input change
							value: Amount::ONE_BTC.to_sat(),
							script_pubkey: Script::new_op_return(&[]),
						}
					]
				};
				let our_sig = signer.sign_holder_htlc_transaction(&mut htlc_tx, 0, htlc_descriptor, &secp).unwrap();
				let witness_script = htlc_descriptor.witness_script(&per_commitment_point, &secp);
				htlc_tx.input[0].witness = htlc_descriptor.tx_input_witness(&our_sig, &witness_script);
				htlc_txs.push(htlc_tx);
			},
			_ => panic!("Unexpected event"),
		}
	}

	mine_transactions(&nodes[0], &[&htlc_txs[0], &htlc_txs[1]]);
	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);

	assert!(nodes[0].chain_monitor.chain_monitor.get_and_clear_pending_events().is_empty());

	connect_blocks(&nodes[0], BREAKDOWN_TIMEOUT as u32);

	let holder_events = nodes[0].chain_monitor.chain_monitor.get_and_clear_pending_events();
	assert_eq!(holder_events.len(), 3);
	for event in holder_events {
		match event {
			Event::SpendableOutputs { .. } => {},
			_ => panic!("Unexpected event"),
		}
	}

	// Clear the remaining events as they're not relevant to what we're testing.
	nodes[0].node.get_and_clear_pending_events();
}
