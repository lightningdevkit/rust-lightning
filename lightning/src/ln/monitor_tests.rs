// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Further functional tests which test blockchain reorganizations.

use crate::sign::EcdsaChannelSigner;
use crate::chain::channelmonitor::{ANTI_REORG_DELAY, LATENCY_GRACE_PERIOD_BLOCKS, Balance};
use crate::chain::transaction::OutPoint;
use crate::chain::chaininterface::{LowerBoundedFeeEstimator, compute_feerate_sat_per_1000_weight};
use crate::events::bump_transaction::{BumpTransactionEvent, WalletSource};
use crate::events::{Event, MessageSendEvent, MessageSendEventsProvider, ClosureReason, HTLCDestination};
use crate::ln::channel;
use crate::ln::channelmanager::{BREAKDOWN_TIMEOUT, PaymentId, RecipientOnionFields};
use crate::ln::msgs::ChannelMessageHandler;
use crate::util::config::UserConfig;
use crate::util::crypto::sign;
use crate::util::ser::Writeable;
use crate::util::test_utils;

use bitcoin::blockdata::transaction::EcdsaSighashType;
use bitcoin::blockdata::script::Builder;
use bitcoin::blockdata::opcodes;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{Amount, PublicKey, Script, Transaction, TxIn, TxOut, PackedLockTime, Witness};
use bitcoin::util::sighash::SighashCache;

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
	nodes[0].node.send_payment_with_route(&route, payment_hash,
		RecipientOnionFields::secret_only(payment_secret), PaymentId(payment_hash.0)).unwrap();
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
	check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed, [nodes[2].node.get_our_node_id()], 100000);
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
	if let Event::SpendableOutputs { outputs, .. } = spendable.pop().unwrap() {
		assert_eq!(outputs.len(), 1);
		let spend_tx = node.keys_manager.backing.spend_spendable_outputs(&[&outputs[0]], Vec::new(),
			Builder::new().push_opcode(opcodes::all::OP_RETURN).into_script(), 253, None, &Secp256k1::new()).unwrap();
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
	check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed, [nodes[0].node.get_our_node_id()], 1000000);
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
	let channel_type_features = get_channel_type_features!(nodes[0], nodes[1], chan_id);

	assert_eq!(vec![Balance::ClaimableOnChannelClose {
			amount_satoshis: 1_000_000 - 1_000 - chan_feerate * channel::commitment_tx_base_weight(&channel_type_features) / 1000
		}],
		nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances());
	assert_eq!(vec![Balance::ClaimableOnChannelClose { amount_satoshis: 1_000, }],
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
			amount_satoshis: 1_000_000 - 1_000 - chan_feerate * channel::commitment_tx_base_weight(&channel_type_features) / 1000,
			confirmation_height: nodes[0].best_block_info().1 + ANTI_REORG_DELAY - 1,
		}],
		nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances());
	assert_eq!(vec![Balance::ClaimableAwaitingConfirmations {
			amount_satoshis: 1000,
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

	check_closed_event!(nodes[0], 1, ClosureReason::CooperativeClosure, [nodes[1].node.get_our_node_id()], 1000000);
	check_closed_event!(nodes[1], 1, ClosureReason::CooperativeClosure, [nodes[0].node.get_our_node_id()], 1000000);
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
	let (payment_preimage, payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1]], 3_000_000);
	// This HTLC is allowed to time out, letting A claim it. However, in order to test claimable
	// balances more fully we also give B the preimage for this HTLC.
	let (timeout_payment_preimage, timeout_payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1]], 4_000_000);
	// This HTLC will be dust, and not be claimable at all:
	let (dust_payment_preimage, dust_payment_hash, ..) = route_payment(&nodes[0], &[&nodes[1]], 3_000);

	let htlc_cltv_timeout = nodes[0].best_block_info().1 + TEST_FINAL_CLTV + 1; // Note ChannelManager adds one to CLTV timeouts for safety

	let chan_feerate = get_feerate!(nodes[0], nodes[1], chan_id) as u64;
	let channel_type_features = get_channel_type_features!(nodes[0], nodes[1], chan_id);

	let remote_txn = get_local_commitment_txn!(nodes[1], chan_id);
	let sent_htlc_balance = Balance::MaybeTimeoutClaimableHTLC {
		amount_satoshis: 3_000,
		claimable_height: htlc_cltv_timeout,
		payment_hash,
	};
	let sent_htlc_timeout_balance = Balance::MaybeTimeoutClaimableHTLC {
		amount_satoshis: 4_000,
		claimable_height: htlc_cltv_timeout,
		payment_hash: timeout_payment_hash,
	};
	let received_htlc_balance = Balance::MaybePreimageClaimableHTLC {
		amount_satoshis: 3_000,
		expiry_height: htlc_cltv_timeout,
		payment_hash,
	};
	let received_htlc_timeout_balance = Balance::MaybePreimageClaimableHTLC {
		amount_satoshis: 4_000,
		expiry_height: htlc_cltv_timeout,
		payment_hash: timeout_payment_hash,
	};
	let received_htlc_claiming_balance = Balance::ContentiousClaimable {
		amount_satoshis: 3_000,
		timeout_height: htlc_cltv_timeout,
		payment_hash,
		payment_preimage,
	};
	let received_htlc_timeout_claiming_balance = Balance::ContentiousClaimable {
		amount_satoshis: 4_000,
		timeout_height: htlc_cltv_timeout,
		payment_hash: timeout_payment_hash,
		payment_preimage: timeout_payment_preimage,
	};

	// Before B receives the payment preimage, it only suggests the push_msat value of 1_000 sats
	// as claimable. A lists both its to-self balance and the (possibly-claimable) HTLCs.
	assert_eq!(sorted_vec(vec![Balance::ClaimableOnChannelClose {
			amount_satoshis: 1_000_000 - 3_000 - 4_000 - 1_000 - 3 - chan_feerate *
				(channel::commitment_tx_base_weight(&channel_type_features) + 2 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
		}, sent_htlc_balance.clone(), sent_htlc_timeout_balance.clone()]),
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));
	assert_eq!(sorted_vec(vec![Balance::ClaimableOnChannelClose {
			amount_satoshis: 1_000,
		}, received_htlc_balance.clone(), received_htlc_timeout_balance.clone()]),
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
		expect_payment_sent(&nodes[0], payment_preimage, None, false, false);
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
			amount_satoshis: 1_000_000 - // Channel funding value in satoshis
				4_000 - // The to-be-failed HTLC value in satoshis
				3_000 - // The claimed HTLC value in satoshis
				1_000 - // The push_msat value in satoshis
				3 - // The dust HTLC value in satoshis
				// The commitment transaction fee with two HTLC outputs:
				chan_feerate * (channel::commitment_tx_base_weight(&channel_type_features) +
								if prev_commitment_tx { 1 } else { 2 } *
								channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
		}, sent_htlc_timeout_balance.clone()];
	if !prev_commitment_tx {
		a_expected_balances.push(sent_htlc_balance.clone());
	}
	assert_eq!(sorted_vec(a_expected_balances),
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));
	assert_eq!(vec![Balance::ClaimableOnChannelClose {
			amount_satoshis: 1_000 + 3_000 + 4_000,
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
	check_closed_event!(nodes[0], 1, ClosureReason::CommitmentTxConfirmed, [nodes[1].node.get_our_node_id()], 1000000);
	assert!(nodes[1].node.list_channels().is_empty());
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors!(nodes[1], 1);
	check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed, [nodes[0].node.get_our_node_id()], 1000000);
	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());

	// Once the commitment transaction confirms, we will wait until ANTI_REORG_DELAY until we
	// generate any `SpendableOutputs` events. Thus, the same balances will still be listed
	// available in `get_claimable_balances`. However, both will swap from `ClaimableOnClose` to
	// other Balance variants, as close has already happened.
	assert!(nodes[0].chain_monitor.chain_monitor.get_and_clear_pending_events().is_empty());
	assert!(nodes[1].chain_monitor.chain_monitor.get_and_clear_pending_events().is_empty());

	assert_eq!(sorted_vec(vec![Balance::ClaimableAwaitingConfirmations {
			amount_satoshis: 1_000_000 - 3_000 - 4_000 - 1_000 - 3 - chan_feerate *
				(channel::commitment_tx_base_weight(&channel_type_features) + 2 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
			confirmation_height: nodes[0].best_block_info().1 + ANTI_REORG_DELAY - 1,
		}, sent_htlc_balance.clone(), sent_htlc_timeout_balance.clone()]),
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));
	// The main non-HTLC balance is just awaiting confirmations, but the claimable height is the
	// CSV delay, not ANTI_REORG_DELAY.
	assert_eq!(sorted_vec(vec![Balance::ClaimableAwaitingConfirmations {
			amount_satoshis: 1_000,
			confirmation_height: node_b_commitment_claimable,
		},
		// Both HTLC balances are "contentious" as our counterparty could claim them if we wait too
		// long.
		received_htlc_claiming_balance.clone(), received_htlc_timeout_claiming_balance.clone()]),
		sorted_vec(nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);
	expect_payment_failed!(nodes[0], dust_payment_hash, false);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);

	// After ANTI_REORG_DELAY, A will consider its balance fully spendable and generate a
	// `SpendableOutputs` event. However, B still has to wait for the CSV delay.
	assert_eq!(sorted_vec(vec![sent_htlc_balance.clone(), sent_htlc_timeout_balance.clone()]),
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));
	assert_eq!(sorted_vec(vec![Balance::ClaimableAwaitingConfirmations {
			amount_satoshis: 1_000,
			confirmation_height: node_b_commitment_claimable,
		}, received_htlc_claiming_balance.clone(), received_htlc_timeout_claiming_balance.clone()]),
		sorted_vec(nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	test_spendable_output(&nodes[0], &remote_txn[0]);
	assert!(nodes[1].chain_monitor.chain_monitor.get_and_clear_pending_events().is_empty());

	// After broadcasting the HTLC claim transaction, node A will still consider the HTLC
	// possibly-claimable up to ANTI_REORG_DELAY, at which point it will drop it.
	mine_transaction(&nodes[0], &b_broadcast_txn[0]);
	if prev_commitment_tx {
		expect_payment_path_successful!(nodes[0]);
	} else {
		expect_payment_sent(&nodes[0], payment_preimage, None, true, false);
	}
	assert_eq!(sorted_vec(vec![sent_htlc_balance.clone(), sent_htlc_timeout_balance.clone()]),
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));
	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);
	assert_eq!(vec![sent_htlc_timeout_balance.clone()],
		nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances());

	// When the HTLC timeout output is spendable in the next block, A should broadcast it
	connect_blocks(&nodes[0], htlc_cltv_timeout - nodes[0].best_block_info().1);
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
			amount_satoshis: 4_000,
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
			amount_satoshis: 1_000,
			confirmation_height: node_b_commitment_claimable,
		}, Balance::ClaimableAwaitingConfirmations {
			amount_satoshis: 3_000,
			confirmation_height: node_b_htlc_claimable,
		}, received_htlc_timeout_claiming_balance.clone()]),
		sorted_vec(nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	// After reaching the commitment output CSV, we'll get a SpendableOutputs event for it and have
	// only the HTLCs claimable on node B.
	connect_blocks(&nodes[1], node_b_commitment_claimable - nodes[1].best_block_info().1);
	test_spendable_output(&nodes[1], &remote_txn[0]);

	assert_eq!(sorted_vec(vec![Balance::ClaimableAwaitingConfirmations {
			amount_satoshis: 3_000,
			confirmation_height: node_b_htlc_claimable,
		}, received_htlc_timeout_claiming_balance.clone()]),
		sorted_vec(nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	// After reaching the claimed HTLC output CSV, we'll get a SpendableOutptus event for it and
	// have only one HTLC output left spendable.
	connect_blocks(&nodes[1], node_b_htlc_claimable - nodes[1].best_block_info().1);
	test_spendable_output(&nodes[1], &b_broadcast_txn[0]);

	assert_eq!(vec![received_htlc_timeout_claiming_balance.clone()],
		nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances());

	// Finally, mine the HTLC timeout transaction that A broadcasted (even though B should be able
	// to claim this HTLC with the preimage it knows!). It will remain listed as a claimable HTLC
	// until ANTI_REORG_DELAY confirmations on the spend.
	mine_transaction(&nodes[1], &a_broadcast_txn[1]);
	assert_eq!(vec![received_htlc_timeout_claiming_balance.clone()],
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
	nodes[0].node.send_payment_with_route(&route, payment_hash,
		RecipientOnionFields::secret_only(payment_secret), PaymentId(payment_hash.0)).unwrap();
	check_added_monitors!(nodes[0], 1);

	let updates = get_htlc_update_msgs!(nodes[0], nodes[1].node.get_our_node_id());
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);
	commitment_signed_dance!(nodes[1], nodes[0], updates.commitment_signed, false);

	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_payment_claimable!(nodes[1], payment_hash, payment_secret, 10_000_000);

	let (route_2, payment_hash_2, payment_preimage_2, payment_secret_2) = get_route_and_payment_hash!(nodes[0], nodes[1], 20_000_000);
	nodes[0].node.send_payment_with_route(&route_2, payment_hash_2,
		RecipientOnionFields::secret_only(payment_secret_2), PaymentId(payment_hash_2.0)).unwrap();
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
	let channel_type_features = get_channel_type_features!(nodes[0], nodes[1], chan_id);

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
	check_closed_event!(nodes[0], 1, ClosureReason::CommitmentTxConfirmed, [nodes[1].node.get_our_node_id()], 1000000);

	let htlc_balance_known_preimage = Balance::MaybeTimeoutClaimableHTLC {
		amount_satoshis: 10_000,
		claimable_height: htlc_cltv_timeout,
		payment_hash,
	};
	let htlc_balance_unknown_preimage = Balance::MaybeTimeoutClaimableHTLC {
		amount_satoshis: 20_000,
		claimable_height: htlc_cltv_timeout,
		payment_hash: payment_hash_2,
	};

	assert_eq!(sorted_vec(vec![Balance::ClaimableAwaitingConfirmations {
			amount_satoshis: 1_000_000 - 10_000 - 20_000 - chan_feerate *
				(channel::commitment_tx_base_weight(&channel_type_features) + 2 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
			confirmation_height: node_a_commitment_claimable,
		}, htlc_balance_known_preimage.clone(), htlc_balance_unknown_preimage.clone()]),
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	// Get nodes[1]'s HTLC claim tx for the second HTLC
	mine_transaction(&nodes[1], &as_txn[0]);
	check_added_monitors!(nodes[1], 1);
	check_closed_broadcast!(nodes[1], true);
	check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed, [nodes[0].node.get_our_node_id()], 1000000);
	let bs_htlc_claim_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	assert_eq!(bs_htlc_claim_txn.len(), 1);
	check_spends!(bs_htlc_claim_txn[0], as_txn[0]);

	// Connect blocks until the HTLCs expire, allowing us to (validly) broadcast the HTLC-Timeout
	// transaction.
	connect_blocks(&nodes[0], TEST_FINAL_CLTV - 1);
	assert_eq!(sorted_vec(vec![Balance::ClaimableAwaitingConfirmations {
			amount_satoshis: 1_000_000 - 10_000 - 20_000 - chan_feerate *
				(channel::commitment_tx_base_weight(&channel_type_features) + 2 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
			confirmation_height: node_a_commitment_claimable,
		}, htlc_balance_known_preimage.clone(), htlc_balance_unknown_preimage.clone()]),
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
			amount_satoshis: 1_000_000 - 10_000 - 20_000 - chan_feerate *
				(channel::commitment_tx_base_weight(&channel_type_features) + 2 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
			confirmation_height: node_a_commitment_claimable,
		}, Balance::ClaimableAwaitingConfirmations {
			amount_satoshis: 10_000,
			confirmation_height: node_a_htlc_claimable,
		}, htlc_balance_unknown_preimage.clone()]),
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	// Now confirm nodes[1]'s HTLC claim, giving nodes[0] the preimage. Note that the "maybe
	// claimable" balance remains until we see ANTI_REORG_DELAY blocks.
	mine_transaction(&nodes[0], &bs_htlc_claim_txn[0]);
	expect_payment_sent(&nodes[0], payment_preimage_2, None, true, false);
	assert_eq!(sorted_vec(vec![Balance::ClaimableAwaitingConfirmations {
			amount_satoshis: 1_000_000 - 10_000 - 20_000 - chan_feerate *
				(channel::commitment_tx_base_weight(&channel_type_features) + 2 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
			confirmation_height: node_a_commitment_claimable,
		}, Balance::ClaimableAwaitingConfirmations {
			amount_satoshis: 10_000,
			confirmation_height: node_a_htlc_claimable,
		}, htlc_balance_unknown_preimage.clone()]),
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	// Finally make the HTLC transactions have ANTI_REORG_DELAY blocks. This call previously
	// panicked as described in the test introduction. This will remove the "maybe claimable"
	// spendable output as nodes[1] has fully claimed the second HTLC.
	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);
	expect_payment_failed!(nodes[0], payment_hash, false);

	assert_eq!(sorted_vec(vec![Balance::ClaimableAwaitingConfirmations {
			amount_satoshis: 1_000_000 - 10_000 - 20_000 - chan_feerate *
				(channel::commitment_tx_base_weight(&channel_type_features) + 2 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
			confirmation_height: node_a_commitment_claimable,
		}, Balance::ClaimableAwaitingConfirmations {
			amount_satoshis: 10_000,
			confirmation_height: node_a_htlc_claimable,
		}]),
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	// Connect blocks until the commitment transaction's CSV expires, providing us the relevant
	// `SpendableOutputs` event and removing the claimable balance entry.
	connect_blocks(&nodes[0], node_a_commitment_claimable - nodes[0].best_block_info().1);
	assert_eq!(vec![Balance::ClaimableAwaitingConfirmations {
			amount_satoshis: 10_000,
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
	let channel_type_features = get_channel_type_features!(nodes[0], nodes[1], chan_id);

	let a_sent_htlc_balance = Balance::MaybeTimeoutClaimableHTLC {
		amount_satoshis: 10_000,
		claimable_height: htlc_cltv_timeout,
		payment_hash: to_b_failed_payment_hash,
	};
	let a_received_htlc_balance = Balance::MaybePreimageClaimableHTLC {
		amount_satoshis: 20_000,
		expiry_height: htlc_cltv_timeout,
		payment_hash: to_a_failed_payment_hash,
	};
	let b_received_htlc_balance = Balance::MaybePreimageClaimableHTLC {
		amount_satoshis: 10_000,
		expiry_height: htlc_cltv_timeout,
		payment_hash: to_b_failed_payment_hash,
	};
	let b_sent_htlc_balance = Balance::MaybeTimeoutClaimableHTLC {
		amount_satoshis: 20_000,
		claimable_height: htlc_cltv_timeout,
		payment_hash: to_a_failed_payment_hash,
	};

	// Both A and B will have an HTLC that's claimable on timeout and one that's claimable if they
	// receive the preimage. These will remain the same through the channel closure and until the
	// HTLC output is spent.

	assert_eq!(sorted_vec(vec![Balance::ClaimableOnChannelClose {
			amount_satoshis: 1_000_000 - 500_000 - 10_000 - chan_feerate *
				(channel::commitment_tx_base_weight(&channel_type_features) + 2 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
		}, a_received_htlc_balance.clone(), a_sent_htlc_balance.clone()]),
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	assert_eq!(sorted_vec(vec![Balance::ClaimableOnChannelClose {
			amount_satoshis: 500_000 - 20_000,
		}, b_received_htlc_balance.clone(), b_sent_htlc_balance.clone()]),
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
			amount_satoshis: 1_000_000 - 500_000 - 10_000 - chan_feerate *
				(channel::commitment_tx_base_weight(&channel_type_features) + 2 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
			confirmation_height: node_a_commitment_claimable,
		}, a_received_htlc_balance.clone(), a_sent_htlc_balance.clone()]);

	mine_transaction(&nodes[0], &as_txn[0]);
	nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().clear();
	check_added_monitors!(nodes[0], 1);
	check_closed_broadcast!(nodes[0], true);
	check_closed_event!(nodes[0], 1, ClosureReason::CommitmentTxConfirmed, [nodes[1].node.get_our_node_id()], 1000000);

	assert_eq!(as_pre_spend_claims,
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	mine_transaction(&nodes[1], &as_txn[0]);
	check_added_monitors!(nodes[1], 1);
	check_closed_broadcast!(nodes[1], true);
	check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed, [nodes[0].node.get_our_node_id()], 1000000);

	let node_b_commitment_claimable = nodes[1].best_block_info().1 + ANTI_REORG_DELAY - 1;
	let mut bs_pre_spend_claims = sorted_vec(vec![Balance::ClaimableAwaitingConfirmations {
			amount_satoshis: 500_000 - 20_000,
			confirmation_height: node_b_commitment_claimable,
		}, b_received_htlc_balance.clone(), b_sent_htlc_balance.clone()]);
	assert_eq!(bs_pre_spend_claims,
		sorted_vec(nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	// We'll broadcast the HTLC-Timeout transaction one block prior to the htlc's expiration (as it
	// is confirmable in the next block), but will still include the same claimable balances as no
	// HTLC has been spent, even after the HTLC expires. We'll also fail the inbound HTLC, but it
	// won't do anything as the channel is already closed.

	connect_blocks(&nodes[0], TEST_FINAL_CLTV);
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
	connect_blocks(&nodes[1], TEST_FINAL_CLTV - (ANTI_REORG_DELAY - 1));
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
			amount_satoshis: 1_000_000 - 500_000 - 10_000 - chan_feerate *
				(channel::commitment_tx_base_weight(&channel_type_features) + 2 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
			confirmation_height: node_a_commitment_claimable,
		}, a_received_htlc_balance.clone(), Balance::ClaimableAwaitingConfirmations {
			amount_satoshis: 10_000,
			confirmation_height: as_timeout_claimable_height,
		}]),
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	mine_transaction(&nodes[0], &bs_htlc_timeout_claim[0]);
	assert_eq!(sorted_vec(vec![Balance::ClaimableAwaitingConfirmations {
			amount_satoshis: 1_000_000 - 500_000 - 10_000 - chan_feerate *
				(channel::commitment_tx_base_weight(&channel_type_features) + 2 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
			confirmation_height: node_a_commitment_claimable,
		}, a_received_htlc_balance.clone(), Balance::ClaimableAwaitingConfirmations {
			amount_satoshis: 10_000,
			confirmation_height: as_timeout_claimable_height,
		}]),
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	// Once as_htlc_timeout_claim[0] reaches ANTI_REORG_DELAY confirmations, we should get a
	// payment failure event.
	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 2);
	expect_payment_failed!(nodes[0], to_b_failed_payment_hash, false);

	connect_blocks(&nodes[0], 1);
	assert_eq!(sorted_vec(vec![Balance::ClaimableAwaitingConfirmations {
			amount_satoshis: 1_000_000 - 500_000 - 10_000 - chan_feerate *
				(channel::commitment_tx_base_weight(&channel_type_features) + 2 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
			confirmation_height: node_a_commitment_claimable,
		}, Balance::ClaimableAwaitingConfirmations {
			amount_satoshis: 10_000,
			confirmation_height: core::cmp::max(as_timeout_claimable_height, htlc_cltv_timeout),
		}]),
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	connect_blocks(&nodes[0], node_a_commitment_claimable - nodes[0].best_block_info().1);
	assert_eq!(vec![Balance::ClaimableAwaitingConfirmations {
			amount_satoshis: 10_000,
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
	assert_eq!(sorted_vec(vec![b_received_htlc_balance.clone(), Balance::ClaimableAwaitingConfirmations {
			amount_satoshis: 20_000,
			confirmation_height: bs_timeout_claimable_height,
		}]),
		sorted_vec(nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	mine_transaction(&nodes[1], &as_htlc_timeout_claim[0]);
	assert_eq!(sorted_vec(vec![b_received_htlc_balance.clone(), Balance::ClaimableAwaitingConfirmations {
			amount_satoshis: 20_000,
			confirmation_height: bs_timeout_claimable_height,
		}]),
		sorted_vec(nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 2);
	expect_payment_failed!(nodes[1], to_a_failed_payment_hash, false);

	assert_eq!(vec![b_received_htlc_balance.clone()],
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
	let channel_type_features = get_channel_type_features!(nodes[0], nodes[1], chan_id);

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
	check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed, [nodes[0].node.get_our_node_id()], 1000000);

	// Prior to channel closure, B considers the preimage HTLC as its own, and otherwise only
	// lists the two on-chain timeout-able HTLCs as claimable balances.
	assert_eq!(sorted_vec(vec![Balance::ClaimableOnChannelClose {
			amount_satoshis: 100_000 - 5_000 - 4_000 - 3 - 2_000 + 3_000,
		}, Balance::MaybeTimeoutClaimableHTLC {
			amount_satoshis: 2_000,
			claimable_height: missing_htlc_cltv_timeout,
			payment_hash: missing_htlc_payment_hash,
		}, Balance::MaybeTimeoutClaimableHTLC {
			amount_satoshis: 4_000,
			claimable_height: htlc_cltv_timeout,
			payment_hash: timeout_payment_hash,
		}, Balance::MaybeTimeoutClaimableHTLC {
			amount_satoshis: 5_000,
			claimable_height: live_htlc_cltv_timeout,
			payment_hash: live_payment_hash,
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
			amount_satoshis: 100_000 - 5_000 - 4_000 - 3,
			confirmation_height: nodes[1].best_block_info().1 + 5,
		}, Balance::CounterpartyRevokedOutputClaimable {
			amount_satoshis: 3_000,
		}, Balance::CounterpartyRevokedOutputClaimable {
			amount_satoshis: 4_000,
		}];

	let to_self_unclaimed_balance = Balance::CounterpartyRevokedOutputClaimable {
		amount_satoshis: 1_000_000 - 100_000 - 3_000 - chan_feerate *
			(channel::commitment_tx_base_weight(&channel_type_features) + 3 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
	};
	let to_self_claimed_avail_height;
	let largest_htlc_unclaimed_balance = Balance::CounterpartyRevokedOutputClaimable {
		amount_satoshis: 5_000,
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
		amount_satoshis: 5_000 - chan_feerate * INBOUND_HTLC_CLAIM_EXP_WEIGHT as u64 / 1000,
		confirmation_height: largest_htlc_claimed_avail_height,
	};
	let to_self_claimed_balance = Balance::ClaimableAwaitingConfirmations {
		amount_satoshis: 1_000_000 - 100_000 - 3_000 - chan_feerate *
			(channel::commitment_tx_base_weight(&channel_type_features) + 3 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000
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
			amount_satoshis: 100_000 - 5_000 - 4_000 - 3,
			confirmation_height: nodes[1].best_block_info().1 + 1,
		}, Balance::ClaimableAwaitingConfirmations {
			amount_satoshis: 1_000_000 - 100_000 - 3_000 - chan_feerate *
				(channel::commitment_tx_base_weight(&channel_type_features) + 3 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000
				- chan_feerate * claim_txn[3].weight() as u64 / 1000,
			confirmation_height: to_self_claimed_avail_height,
		}, Balance::ClaimableAwaitingConfirmations {
			amount_satoshis: 3_000 - chan_feerate * OUTBOUND_HTLC_CLAIM_EXP_WEIGHT as u64 / 1000,
			confirmation_height: nodes[1].best_block_info().1 + 4,
		}, Balance::ClaimableAwaitingConfirmations {
			amount_satoshis: 4_000 - chan_feerate * INBOUND_HTLC_CLAIM_EXP_WEIGHT as u64 / 1000,
			confirmation_height: nodes[1].best_block_info().1 + 5,
		}, Balance::ClaimableAwaitingConfirmations {
			amount_satoshis: 5_000 - chan_feerate * INBOUND_HTLC_CLAIM_EXP_WEIGHT as u64 / 1000,
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
	let channel_type_features = get_channel_type_features!(nodes[0], nodes[1], chan_id);

	// B will generate an HTLC-Success from its revoked commitment tx
	mine_transaction(&nodes[1], &revoked_local_txn[0]);
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors!(nodes[1], 1);
	check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed, [nodes[0].node.get_our_node_id()], 1000000);
	let revoked_htlc_success = {
		let mut txn = nodes[1].tx_broadcaster.txn_broadcast();
		assert_eq!(txn.len(), 1);
		assert_eq!(txn[0].input.len(), 1);
		assert_eq!(txn[0].input[0].witness.last().unwrap().len(), ACCEPTED_HTLC_SCRIPT_WEIGHT);
		check_spends!(txn[0], revoked_local_txn[0]);
		txn.pop().unwrap()
	};

	connect_blocks(&nodes[1], TEST_FINAL_CLTV);
	let revoked_htlc_timeout = {
		let mut txn = nodes[1].tx_broadcaster.unique_txn_broadcast();
		assert_eq!(txn.len(), 2);
		if txn[0].input[0].previous_output == revoked_htlc_success.input[0].previous_output {
			txn.remove(1)
		} else {
			txn.remove(0)
		}
	};
	check_spends!(revoked_htlc_timeout, revoked_local_txn[0]);
	assert_ne!(revoked_htlc_success.input[0].previous_output, revoked_htlc_timeout.input[0].previous_output);
	assert_eq!(revoked_htlc_success.lock_time.0, 0);
	assert_ne!(revoked_htlc_timeout.lock_time.0, 0);

	// A will generate justice tx from B's revoked commitment/HTLC tx
	mine_transaction(&nodes[0], &revoked_local_txn[0]);
	check_closed_broadcast!(nodes[0], true);
	check_added_monitors!(nodes[0], 1);
	check_closed_event!(nodes[0], 1, ClosureReason::CommitmentTxConfirmed, [nodes[1].node.get_our_node_id()], 1000000);
	let to_remote_conf_height = nodes[0].best_block_info().1 + ANTI_REORG_DELAY - 1;

	let as_commitment_claim_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	assert_eq!(as_commitment_claim_txn.len(), 1);
	check_spends!(as_commitment_claim_txn[0], revoked_local_txn[0]);

	// The next two checks have the same balance set for A - even though we confirm a revoked HTLC
	// transaction our balance tracking doesn't use the on-chain value so the
	// `CounterpartyRevokedOutputClaimable` entry doesn't change.
	let as_balances = sorted_vec(vec![Balance::ClaimableAwaitingConfirmations {
			// to_remote output in B's revoked commitment
			amount_satoshis: 1_000_000 - 11_000 - 3_000 - chan_feerate *
				(channel::commitment_tx_base_weight(&channel_type_features) + 2 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
			confirmation_height: to_remote_conf_height,
		}, Balance::CounterpartyRevokedOutputClaimable {
			// to_self output in B's revoked commitment
			amount_satoshis: 10_000,
		}, Balance::CounterpartyRevokedOutputClaimable { // HTLC 1
			amount_satoshis: 3_000,
		}, Balance::CounterpartyRevokedOutputClaimable { // HTLC 2
			amount_satoshis: 1_000,
		}]);
	assert_eq!(as_balances,
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	mine_transaction(&nodes[0], &revoked_htlc_success);
	let as_htlc_claim_tx = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	assert_eq!(as_htlc_claim_tx.len(), 2);
	check_spends!(as_htlc_claim_tx[0], revoked_htlc_success);
	check_spends!(as_htlc_claim_tx[1], revoked_local_txn[0]); // A has to generate a new claim for the remaining revoked
	                                                          // outputs (which no longer includes the spent HTLC output)

	assert_eq!(as_balances,
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	assert_eq!(as_htlc_claim_tx[0].output.len(), 1);
	fuzzy_assert_eq(as_htlc_claim_tx[0].output[0].value,
		3_000 - chan_feerate * (revoked_htlc_success.weight() + as_htlc_claim_tx[0].weight()) as u64 / 1000);

	mine_transaction(&nodes[0], &as_htlc_claim_tx[0]);
	assert_eq!(sorted_vec(vec![Balance::ClaimableAwaitingConfirmations {
			// to_remote output in B's revoked commitment
			amount_satoshis: 1_000_000 - 11_000 - 3_000 - chan_feerate *
				(channel::commitment_tx_base_weight(&channel_type_features) + 2 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
			confirmation_height: to_remote_conf_height,
		}, Balance::CounterpartyRevokedOutputClaimable {
			// to_self output in B's revoked commitment
			amount_satoshis: 10_000,
		}, Balance::CounterpartyRevokedOutputClaimable { // HTLC 2
			amount_satoshis: 1_000,
		}, Balance::ClaimableAwaitingConfirmations {
			amount_satoshis: as_htlc_claim_tx[0].output[0].value,
			confirmation_height: nodes[0].best_block_info().1 + ANTI_REORG_DELAY - 1,
		}]),
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 3);
	test_spendable_output(&nodes[0], &revoked_local_txn[0]);
	assert_eq!(sorted_vec(vec![Balance::CounterpartyRevokedOutputClaimable {
			// to_self output to B
			amount_satoshis: 10_000,
		}, Balance::CounterpartyRevokedOutputClaimable { // HTLC 2
			amount_satoshis: 1_000,
		}, Balance::ClaimableAwaitingConfirmations {
			amount_satoshis: as_htlc_claim_tx[0].output[0].value,
			confirmation_height: nodes[0].best_block_info().1 + 2,
		}]),
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	connect_blocks(&nodes[0], 2);
	test_spendable_output(&nodes[0], &as_htlc_claim_tx[0]);
	assert_eq!(sorted_vec(vec![Balance::CounterpartyRevokedOutputClaimable {
			// to_self output in B's revoked commitment
			amount_satoshis: 10_000,
		}, Balance::CounterpartyRevokedOutputClaimable { // HTLC 2
			amount_satoshis: 1_000,
		}]),
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	connect_blocks(&nodes[0], revoked_htlc_timeout.lock_time.0 - nodes[0].best_block_info().1);
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

	mine_transaction(&nodes[0], &revoked_htlc_timeout);
	let as_second_htlc_claim_tx = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	assert_eq!(as_second_htlc_claim_tx.len(), 2);

	check_spends!(as_second_htlc_claim_tx[0], revoked_htlc_timeout);
	check_spends!(as_second_htlc_claim_tx[1], revoked_local_txn[0]);

	// Connect blocks to finalize the HTLC resolution with the HTLC-Timeout transaction. In a
	// previous iteration of the revoked balance handling this would result in us "forgetting" that
	// the revoked HTLC output still needed to be claimed.
	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);
	assert_eq!(sorted_vec(vec![Balance::CounterpartyRevokedOutputClaimable {
			// to_self output in B's revoked commitment
			amount_satoshis: 10_000,
		}, Balance::CounterpartyRevokedOutputClaimable { // HTLC 2
			amount_satoshis: 1_000,
		}]),
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	mine_transaction(&nodes[0], &as_second_htlc_claim_tx[0]);
	assert_eq!(sorted_vec(vec![Balance::CounterpartyRevokedOutputClaimable {
			// to_self output in B's revoked commitment
			amount_satoshis: 10_000,
		}, Balance::ClaimableAwaitingConfirmations {
			amount_satoshis: as_second_htlc_claim_tx[0].output[0].value,
			confirmation_height: nodes[0].best_block_info().1 + ANTI_REORG_DELAY - 1,
		}]),
		sorted_vec(nodes[0].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	mine_transaction(&nodes[0], &as_second_htlc_claim_tx[1]);
	assert_eq!(sorted_vec(vec![Balance::ClaimableAwaitingConfirmations {
			// to_self output in B's revoked commitment
			amount_satoshis: as_second_htlc_claim_tx[1].output[0].value,
			confirmation_height: nodes[0].best_block_info().1 + ANTI_REORG_DELAY - 1,
		}, Balance::ClaimableAwaitingConfirmations {
			amount_satoshis: as_second_htlc_claim_tx[0].output[0].value,
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

	let channel_type_features = get_channel_type_features!(nodes[0], nodes[1], chan_id);
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
			amount_satoshis: 100_000 - 4_000 - 3_000,
		}, Balance::MaybeTimeoutClaimableHTLC {
			amount_satoshis: 4_000,
			claimable_height: htlc_cltv_timeout,
			payment_hash: revoked_payment_hash,
		}, Balance::MaybeTimeoutClaimableHTLC {
			amount_satoshis: 3_000,
			claimable_height: htlc_cltv_timeout,
			payment_hash: claimed_payment_hash,
		}]),
		sorted_vec(nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	mine_transaction(&nodes[1], &as_revoked_txn[0]);
	check_closed_broadcast!(nodes[1], true);
	check_closed_event!(nodes[1], 1, ClosureReason::CommitmentTxConfirmed, [nodes[0].node.get_our_node_id()], 1000000);
	check_added_monitors!(nodes[1], 1);

	let mut claim_txn: Vec<_> = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().drain(..).filter(|tx| tx.input.iter().any(|inp| inp.previous_output.txid == as_revoked_txn[0].txid())).collect();
	// Currently the revoked commitment outputs are all claimed in one aggregated transaction
	assert_eq!(claim_txn.len(), 1);
	assert_eq!(claim_txn[0].input.len(), 3);
	check_spends!(claim_txn[0], as_revoked_txn[0]);

	let to_remote_maturity = nodes[1].best_block_info().1 + ANTI_REORG_DELAY - 1;

	assert_eq!(sorted_vec(vec![Balance::ClaimableAwaitingConfirmations {
			// to_remote output in A's revoked commitment
			amount_satoshis: 100_000 - 4_000 - 3_000,
			confirmation_height: to_remote_maturity,
		}, Balance::CounterpartyRevokedOutputClaimable {
			// to_self output in A's revoked commitment
			amount_satoshis: 1_000_000 - 100_000 - chan_feerate *
				(channel::commitment_tx_base_weight(&channel_type_features) + 2 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
		}, Balance::CounterpartyRevokedOutputClaimable { // HTLC 1
			amount_satoshis: 4_000,
		}, Balance::CounterpartyRevokedOutputClaimable { // HTLC 2
			amount_satoshis: 3_000,
		}]),
		sorted_vec(nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	// Confirm A's HTLC-Success tranasction which presumably raced B's claim, causing B to create a
	// new claim.
	mine_transaction(&nodes[1], &as_revoked_txn[1]);
	expect_payment_sent(&nodes[1], claimed_payment_preimage, None, true, false);
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
			amount_satoshis: 100_000 - 4_000 - 3_000,
			confirmation_height: to_remote_maturity,
		}, Balance::CounterpartyRevokedOutputClaimable {
			// to_self output in A's revoked commitment
			amount_satoshis: 1_000_000 - 100_000 - chan_feerate *
				(channel::commitment_tx_base_weight(&channel_type_features) + 2 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
		}, Balance::CounterpartyRevokedOutputClaimable { // HTLC 1
			amount_satoshis: 4_000,
		}, Balance::CounterpartyRevokedOutputClaimable { // HTLC 2
			// The amount here is a bit of a misnomer, really its been reduced by the HTLC
			// transaction fee, but the claimable amount is always a bit of an overshoot for HTLCs
			// anyway, so its not a big change.
			amount_satoshis: 3_000,
		}]),
		sorted_vec(nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	connect_blocks(&nodes[1], 5);
	test_spendable_output(&nodes[1], &as_revoked_txn[0]);

	assert_eq!(sorted_vec(vec![Balance::CounterpartyRevokedOutputClaimable {
			// to_self output in A's revoked commitment
			amount_satoshis: 1_000_000 - 100_000 - chan_feerate *
				(channel::commitment_tx_base_weight(&channel_type_features) + 2 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
		}, Balance::CounterpartyRevokedOutputClaimable { // HTLC 1
			amount_satoshis: 4_000,
		}, Balance::CounterpartyRevokedOutputClaimable { // HTLC 2
			// The amount here is a bit of a misnomer, really its been reduced by the HTLC
			// transaction fee, but the claimable amount is always a bit of an overshoot for HTLCs
			// anyway, so its not a big change.
			amount_satoshis: 3_000,
		}]),
		sorted_vec(nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	mine_transaction(&nodes[1], &claim_txn_2[1]);
	let htlc_2_claim_maturity = nodes[1].best_block_info().1 + ANTI_REORG_DELAY - 1;

	assert_eq!(sorted_vec(vec![Balance::CounterpartyRevokedOutputClaimable {
			// to_self output in A's revoked commitment
			amount_satoshis: 1_000_000 - 100_000 - chan_feerate *
				(channel::commitment_tx_base_weight(&channel_type_features) + 2 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
		}, Balance::CounterpartyRevokedOutputClaimable { // HTLC 1
			amount_satoshis: 4_000,
		}, Balance::ClaimableAwaitingConfirmations { // HTLC 2
			amount_satoshis: claim_txn_2[1].output[0].value,
			confirmation_height: htlc_2_claim_maturity,
		}]),
		sorted_vec(nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	connect_blocks(&nodes[1], 5);
	test_spendable_output(&nodes[1], &claim_txn_2[1]);

	assert_eq!(sorted_vec(vec![Balance::CounterpartyRevokedOutputClaimable {
			// to_self output in A's revoked commitment
			amount_satoshis: 1_000_000 - 100_000 - chan_feerate *
				(channel::commitment_tx_base_weight(&channel_type_features) + 2 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
		}, Balance::CounterpartyRevokedOutputClaimable { // HTLC 1
			amount_satoshis: 4_000,
		}]),
		sorted_vec(nodes[1].chain_monitor.chain_monitor.get_monitor(funding_outpoint).unwrap().get_claimable_balances()));

	mine_transaction(&nodes[1], &claim_txn_2[0]);
	let rest_claim_maturity = nodes[1].best_block_info().1 + ANTI_REORG_DELAY - 1;

	assert_eq!(vec![Balance::ClaimableAwaitingConfirmations {
			amount_satoshis: claim_txn_2[0].output[0].value,
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

fn do_test_restored_packages_retry(check_old_monitor_retries_after_upgrade: bool) {
	// Tests that we'll retry packages that were previously timelocked after we've restored them.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let persister;
	let new_chain_monitor;

	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let node_deserialized;

	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Open a channel, lock in an HTLC, and immediately broadcast the commitment transaction. This
	// ensures that the HTLC timeout package is held until we reach its expiration height.
	let (_, _, chan_id, funding_tx) = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 50_000_000);
	route_payment(&nodes[0], &[&nodes[1]], 10_000_000);

	nodes[0].node.force_close_broadcasting_latest_txn(&chan_id, &nodes[1].node.get_our_node_id()).unwrap();
	check_added_monitors(&nodes[0], 1);
	check_closed_broadcast(&nodes[0], 1, true);
	check_closed_event!(&nodes[0], 1, ClosureReason::HolderForceClosed, false,
		 [nodes[1].node.get_our_node_id()], 100000);

	let commitment_tx = {
		let mut txn = nodes[0].tx_broadcaster.txn_broadcast();
		assert_eq!(txn.len(), 1);
		assert_eq!(txn[0].output.len(), 3);
		check_spends!(txn[0], funding_tx);
		txn.pop().unwrap()
	};

	mine_transaction(&nodes[0], &commitment_tx);

	// Connect blocks until the HTLC's expiration is met, expecting a transaction broadcast.
	connect_blocks(&nodes[0], TEST_FINAL_CLTV);
	let htlc_timeout_tx = {
		let mut txn = nodes[0].tx_broadcaster.txn_broadcast();
		assert_eq!(txn.len(), 1);
		check_spends!(txn[0], commitment_tx);
		txn.pop().unwrap()
	};

	// Check that we can still rebroadcast these packages/transactions if we're upgrading from an
	// old `ChannelMonitor` that did not exercise said rebroadcasting logic.
	if check_old_monitor_retries_after_upgrade {
		let serialized_monitor = hex::decode(
			"0101fffffffffffffffff9550f22c95100160014d5a9aa98b89acc215fc3d23d6fec0ad59ca3665f00002200204c5f18e5e95b184f34d02ba6de8a2a4e36ae3d4ec87299ad81f3284dc7195c6302d7dde8e10a5a22c9bd0d7ef5494d85683ac050253b917615d4f97af633f0a8e2035f5e9d58b4328566223c107d86cf853e6b9fae1d26ff6d969be0178d1423c4ea0016001467822698d782e8421ebdf96d010de99382b7ec2300160014caf6d80fe2bab80473b021f57588a9c384bf23170000000000000000000000004d49e5da0000000000000000000000000000002a0270b20ad0f2c2bb30a55590fc77778495bc1b38c96476901145dda57491237f0f74c52ab4f11296d62b66a6dba9513b04a3e7fb5a09a30cee22fce7294ab55b7e00000022002034c0cc0ad0dd5fe61dcf7ef58f995e3d34f8dbd24aa2a6fae68fefe102bf025c21391732ce658e1fe167300bb689a81e7db5399b9ee4095e217b0e997e8dd3d17a0000000000000000004a002103adde8029d3ee281a32e9db929b39f503ff9d7e93cd308eb157955344dc6def84022103205087e2dc1f6b9937e887dfa712c5bdfa950b01dbda3ebac4c85efdde48ee6a04020090004752210307a78def56cba9fc4db22a25928181de538ee59ba1a475ae113af7790acd0db32103c21e841cbc0b48197d060c71e116c185fa0ac281b7d0aa5924f535154437ca3b52ae00000000000186a0ffffffffffff0291e7c0a3232fb8650a6b4089568a81062b48a768780e5a74bb4a4a74e33aec2c029d5760248ec86c4a76d9df8308555785a06a65472fb995f5b392d520bbd000650090c1c94b11625690c9d84c5daa67b6ad19fcc7f9f23e194384140b08fcab9e8e810000ffffffffffff000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000002167c86cc0e598a6b541f7c9bf9ef17222e4a76f636e2d22185aeadd2b02d029c0000000000000000391732ce658e1fe167300bb689a81e7db5399b9ee4095e217b0e997e8dd3d17a00000000000000010000000000009896800000005166687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f29250500000000a0009d00202d704fbfe342a9ff6eaca14d80a24aaed0e680bbbdd36157b6f2798c61d906910120f9fe5e552aa0fc45020f0505efde432a4e373e5d393863973a6899f8c26d33d102080000000000989680044d4c00210355f8d2238a322d16b602bd0ceaad5b01019fb055971eaadcc9b29226a4da6c2302090007000000000241000408000001000000000006020000080800000000009896800a04000000460000000000000000000000000000000166687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925fffffffffffe01e3002004f8eda5676356f539169a8e9a1e86c7f125283328d6f4bded1b939b52a6a7e30108000000000000c299022103a1f98e85886df54add6908b4fc1ff515e44aedefe9eb9c02879c89994298fa79042103a650bf03971df0176c7b412247390ef717853e8bd487b204dccc2fe2078bb75206210390bbbcebe9f70ba5dfd98866a79f72f75e0a6ea550ef73b202dd87cd6477350a08210284152d57908488e666e872716a286eb670b3d06cbeebf3f2e4ad350e01ec5e5b0a2102295e2de39eb3dcc2882f8cc266df7882a8b6d2c32aa08799f49b693aad3be28e0c04000000fd0e00fd0202002045cfd42d0989e55b953f516ac7fd152bd90ec4438a2fc636f97ddd32a0c8fe0d01080000000000009b5e0221035f5e9d58b4328566223c107d86cf853e6b9fae1d26ff6d969be0178d1423c4ea04210230fde9c031f487db95ff55b7c0acbe0c7c26a8d82615e9184416bd350101616706210225afb4e88eac8b47b67adeaf085f5eb5d37d936f56138f0848de3d104edf113208210208e4687a95c172b86b920c3bc5dbd5f023094ec2cb0abdb74f9b624f45740df90a2102d7dde8e10a5a22c9bd0d7ef5494d85683ac050253b917615d4f97af633f0a8e20c04000000fd0efd011d3b00010102080000000000989680040400000051062066687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925080400000000417e2650c201383711eed2a7cb8652c3e77ee6a395e81849c5c222217ed68b333c0ca9f1e900662ae68a7359efa7ef9d90613f2a62f7c3ff90f8c25e2cc974c9d3a0009d00202d704fbfe342a9ff6eaca14d80a24aaed0e680bbbdd36157b6f2798c61d906910120f9fe5e552aa0fc45020f0505efde432a4e373e5d393863973a6899f8c26d33d102080000000000989680044d4c00210355f8d2238a322d16b602bd0ceaad5b01019fb055971eaadcc9b29226a4da6c2302090007000000000241000408000001000000000006020000080800000000009896800a0400000046fffffffffffefffffffffffe000000000000000000000000000000000000000000000000f1600ef6ea657b8d411d553516ae35cedfe86b0cd48d1f91b32772facbae757d0000000b0000000000000002fd01da002045cfd42d0989e55b953f516ac7fd152bd90ec4438a2fc636f97ddd32a0c8fe0d01fd01840200000000010174c52ab4f11296d62b66a6dba9513b04a3e7fb5a09a30cee22fce7294ab55b7e00000000000f55f9800310270000000000002200208309b406e3b96e76cde414fbb8f5159f5b25b24075656c6382cec797854d53495e9b0000000000002200204c5f18e5e95b184f34d02ba6de8a2a4e36ae3d4ec87299ad81f3284dc7195c6350c300000000000016001425df8ec4a074f80579fed67d4707d5ec8ed7e8d304004730440220671c9badf26bd3a1ebd2d17020c6be20587d7822530daacc52c28839875eaec602204b575a21729ed27311f6d79fdf6fe8702b0a798f7d842e39ede1b56f249a613401473044022016a0da36f70cbf5d889586af88f238982889dc161462c56557125c7acfcb69e9022036ae10c6cc8cbc3b27d9e9ef6babb556086585bc819f252208bd175286699fdd014752210307a78def56cba9fc4db22a25928181de538ee59ba1a475ae113af7790acd0db32103c21e841cbc0b48197d060c71e116c185fa0ac281b7d0aa5924f535154437ca3b52ae50c9222002040000000b0320f1600ef6ea657b8d411d553516ae35cedfe86b0cd48d1f91b32772facbae757d0406030400020090fd02a1002045cfd42d0989e55b953f516ac7fd152bd90ec4438a2fc636f97ddd32a0c8fe0d01fd01840200000000010174c52ab4f11296d62b66a6dba9513b04a3e7fb5a09a30cee22fce7294ab55b7e00000000000f55f9800310270000000000002200208309b406e3b96e76cde414fbb8f5159f5b25b24075656c6382cec797854d53495e9b0000000000002200204c5f18e5e95b184f34d02ba6de8a2a4e36ae3d4ec87299ad81f3284dc7195c6350c300000000000016001425df8ec4a074f80579fed67d4707d5ec8ed7e8d304004730440220671c9badf26bd3a1ebd2d17020c6be20587d7822530daacc52c28839875eaec602204b575a21729ed27311f6d79fdf6fe8702b0a798f7d842e39ede1b56f249a613401473044022016a0da36f70cbf5d889586af88f238982889dc161462c56557125c7acfcb69e9022036ae10c6cc8cbc3b27d9e9ef6babb556086585bc819f252208bd175286699fdd014752210307a78def56cba9fc4db22a25928181de538ee59ba1a475ae113af7790acd0db32103c21e841cbc0b48197d060c71e116c185fa0ac281b7d0aa5924f535154437ca3b52ae50c9222002040000000b0320f1600ef6ea657b8d411d553516ae35cedfe86b0cd48d1f91b32772facbae757d04cd01cb00c901c7002245cfd42d0989e55b953f516ac7fd152bd90ec4438a2fc636f97ddd32a0c8fe0d0001022102d7dde8e10a5a22c9bd0d7ef5494d85683ac050253b917615d4f97af633f0a8e204020090062b5e9b0000000000002200204c5f18e5e95b184f34d02ba6de8a2a4e36ae3d4ec87299ad81f3284dc7195c630821035f5e9d58b4328566223c107d86cf853e6b9fae1d26ff6d969be0178d1423c4ea0a200000000000000000000000004d49e5da0000000000000000000000000000002a0c0800000000000186a0000000000000000274c52ab4f11296d62b66a6dba9513b04a3e7fb5a09a30cee22fce7294ab55b7e0000000000000001000000000022002034c0cc0ad0dd5fe61dcf7ef58f995e3d34f8dbd24aa2a6fae68fefe102bf025c45cfd42d0989e55b953f516ac7fd152bd90ec4438a2fc636f97ddd32a0c8fe0d000000000000000100000000002200208309b406e3b96e76cde414fbb8f5159f5b25b24075656c6382cec797854d5349010100160014d5a9aa98b89acc215fc3d23d6fec0ad59ca3665ffd027100fd01e6fd01e300080000fffffffffffe02080000000000009b5e0408000000000000c3500604000000fd08b0af002102d7dde8e10a5a22c9bd0d7ef5494d85683ac050253b917615d4f97af633f0a8e20221035f5e9d58b4328566223c107d86cf853e6b9fae1d26ff6d969be0178d1423c4ea04210230fde9c031f487db95ff55b7c0acbe0c7c26a8d82615e9184416bd350101616706210225afb4e88eac8b47b67adeaf085f5eb5d37d936f56138f0848de3d104edf113208210208e4687a95c172b86b920c3bc5dbd5f023094ec2cb0abdb74f9b624f45740df90acdcc00a8020000000174c52ab4f11296d62b66a6dba9513b04a3e7fb5a09a30cee22fce7294ab55b7e00000000000f55f9800310270000000000002200208309b406e3b96e76cde414fbb8f5159f5b25b24075656c6382cec797854d53495e9b0000000000002200204c5f18e5e95b184f34d02ba6de8a2a4e36ae3d4ec87299ad81f3284dc7195c6350c300000000000016001425df8ec4a074f80579fed67d4707d5ec8ed7e8d350c92220022045cfd42d0989e55b953f516ac7fd152bd90ec4438a2fc636f97ddd32a0c8fe0d0c3c3b00010102080000000000989680040400000051062066687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f29250804000000000240671c9badf26bd3a1ebd2d17020c6be20587d7822530daacc52c28839875eaec64b575a21729ed27311f6d79fdf6fe8702b0a798f7d842e39ede1b56f249a613404010006407e2650c201383711eed2a7cb8652c3e77ee6a395e81849c5c222217ed68b333c0ca9f1e900662ae68a7359efa7ef9d90613f2a62f7c3ff90f8c25e2cc974c9d3010000000000000001010000000000000000090b2a953d93a124c600ecb1a0ccfed420169cdd37f538ad94a3e4e6318c93c14adf59cdfbb40bdd40950c9f8dd547d29d75a173e1376a7850743394c46dea2dfd01cefd01ca00fd017ffd017c00080000ffffffffffff0208000000000000c2990408000000000000c3500604000000fd08b0af002102295e2de39eb3dcc2882f8cc266df7882a8b6d2c32aa08799f49b693aad3be28e022103a1f98e85886df54add6908b4fc1ff515e44aedefe9eb9c02879c89994298fa79042103a650bf03971df0176c7b412247390ef717853e8bd487b204dccc2fe2078bb75206210390bbbcebe9f70ba5dfd98866a79f72f75e0a6ea550ef73b202dd87cd6477350a08210284152d57908488e666e872716a286eb670b3d06cbeebf3f2e4ad350e01ec5e5b0aa2a1007d020000000174c52ab4f11296d62b66a6dba9513b04a3e7fb5a09a30cee22fce7294ab55b7e00000000000f55f9800299c2000000000000220020740e108cfbc93967b6ab242a351ebee7de51814cf78d366adefd78b10281f17e50c300000000000016001425df8ec4a074f80579fed67d4707d5ec8ed7e8d351c92220022004f8eda5676356f539169a8e9a1e86c7f125283328d6f4bded1b939b52a6a7e30c00024045cb2485594bb1ec08e7bb6af4f89c912bd53f006d7876ea956773e04a4aad4a40e2b8d4fc612102f0b54061b3c1239fb78783053e8e6f9d92b1b99f81ae9ec2040100060000fd019600b0af002103c21e841cbc0b48197d060c71e116c185fa0ac281b7d0aa5924f535154437ca3b02210270b20ad0f2c2bb30a55590fc77778495bc1b38c96476901145dda57491237f0f042103b4e59df102747edc3a3e2283b42b88a8c8218ffd0dcfb52f2524b371d64cadaa062103d902b7b8b3434076d2b210e912c76645048b71e28995aad227a465a65ccd817608210301e9a52f923c157941de4a7692e601f758660969dcf5abdb67817efe84cce2ef0202009004010106b7b600b0af00210307a78def56cba9fc4db22a25928181de538ee59ba1a475ae113af7790acd0db30221034d0f817cb19b4a3bd144b615459bd06cbab3b4bdc96d73e18549a992cee80e8104210380542b59a9679890cba529fe155a9508ef57dac7416d035b23666e3fb98c3814062103adde8029d3ee281a32e9db929b39f503ff9d7e93cd308eb157955344dc6def84082103205087e2dc1f6b9937e887dfa712c5bdfa950b01dbda3ebac4c85efdde48ee6a02020090082274c52ab4f11296d62b66a6dba9513b04a3e7fb5a09a30cee22fce7294ab55b7e000000000287010108d30df34e3a1e00ecdd03a2c843db062479a81752c4dfd0cc4baef0f81e7bc7ef8820990daf8d8e8d30a3b4b08af12c9f5cd71e45c7238103e0c80ca13850862e4fd2c56b69b7195312518de1bfe9aed63c80bb7760d70b2a870d542d815895fd12423d11e2adb0cdf55d776dac8f487c9b3b7ea12f1b150eb15889cf41333ade465692bf1cdc360b9c2a19bf8c1ca4fed7639d8bc953d36c10d8c6c9a8c0a57608788979bcf145e61b308006896e21d03e92084f93bd78740c20639134a7a8fd019afd019600b0af002103c21e841cbc0b48197d060c71e116c185fa0ac281b7d0aa5924f535154437ca3b02210270b20ad0f2c2bb30a55590fc77778495bc1b38c96476901145dda57491237f0f042103b4e59df102747edc3a3e2283b42b88a8c8218ffd0dcfb52f2524b371d64cadaa062103d902b7b8b3434076d2b210e912c76645048b71e28995aad227a465a65ccd817608210301e9a52f923c157941de4a7692e601f758660969dcf5abdb67817efe84cce2ef0202009004010106b7b600b0af00210307a78def56cba9fc4db22a25928181de538ee59ba1a475ae113af7790acd0db30221034d0f817cb19b4a3bd144b615459bd06cbab3b4bdc96d73e18549a992cee80e8104210380542b59a9679890cba529fe155a9508ef57dac7416d035b23666e3fb98c3814062103adde8029d3ee281a32e9db929b39f503ff9d7e93cd308eb157955344dc6def84082103205087e2dc1f6b9937e887dfa712c5bdfa950b01dbda3ebac4c85efdde48ee6a02020090082274c52ab4f11296d62b66a6dba9513b04a3e7fb5a09a30cee22fce7294ab55b7e000000000000000186a00000000000000000000000004d49e5da0000000000000000000000000000002a00000000000000000000000000000000000000000000000001000000510000000000000001000000000000000145cfd42d0989e55b953f516ac7fd152bd90ec4438a2fc636f97ddd32a0c8fe0d00000000041000080000000000989680020400000051160004000000510208000000000000000004040000000b0000000000000000000101300300050007010109210355f8d2238a322d16b602bd0ceaad5b01019fb055971eaadcc9b29226a4da6c230d000f020000",
		).unwrap();
		reload_node!(nodes[0], &nodes[0].node.encode(), &[&serialized_monitor], persister, new_chain_monitor, node_deserialized);
	}

	// Connecting more blocks should result in the HTLC transactions being rebroadcast.
	connect_blocks(&nodes[0], 6);
	if check_old_monitor_retries_after_upgrade {
		check_added_monitors(&nodes[0], 1);
	}
	{
		let txn = nodes[0].tx_broadcaster.txn_broadcast();
		if !nodes[0].connect_style.borrow().skips_blocks() {
			assert_eq!(txn.len(), 6);
		} else {
			assert!(txn.len() < 6);
		}
		for tx in txn {
			assert_eq!(tx.input.len(), htlc_timeout_tx.input.len());
			assert_eq!(tx.output.len(), htlc_timeout_tx.output.len());
			assert_eq!(tx.input[0].previous_output, htlc_timeout_tx.input[0].previous_output);
			assert_eq!(tx.output[0], htlc_timeout_tx.output[0]);
		}
	}
}

#[test]
fn test_restored_packages_retry() {
	do_test_restored_packages_retry(false);
	do_test_restored_packages_retry(true);
}

fn do_test_monitor_rebroadcast_pending_claims(anchors: bool) {
	// Test that we will retry broadcasting pending claims for a force-closed channel on every
	// `ChainMonitor::rebroadcast_pending_claims` call.
	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut config = test_default_channel_config();
	if anchors {
		config.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = true;
		config.manually_accept_inbound_channels = true;
	}
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let (_, _, _, chan_id, funding_tx) = create_chan_between_nodes_with_value(
		&nodes[0], &nodes[1], 1_000_000, 500_000_000
	);
	const HTLC_AMT_MSAT: u64 = 1_000_000;
	const HTLC_AMT_SAT: u64 = HTLC_AMT_MSAT / 1000;
	route_payment(&nodes[0], &[&nodes[1]], HTLC_AMT_MSAT);

	let htlc_expiry = nodes[0].best_block_info().1 + TEST_FINAL_CLTV + 1;

	let commitment_txn = get_local_commitment_txn!(&nodes[0], &chan_id);
	assert_eq!(commitment_txn.len(), if anchors { 1 /* commitment tx only */} else { 2 /* commitment and htlc timeout tx */ });
	check_spends!(&commitment_txn[0], &funding_tx);
	mine_transaction(&nodes[0], &commitment_txn[0]);
	check_closed_broadcast!(&nodes[0], true);
	check_closed_event!(&nodes[0], 1, ClosureReason::CommitmentTxConfirmed,
		 false, [nodes[1].node.get_our_node_id()], 1000000);
	check_added_monitors(&nodes[0], 1);

	let coinbase_tx = Transaction {
		version: 2,
		lock_time: PackedLockTime::ZERO,
		input: vec![TxIn { ..Default::default() }],
		output: vec![TxOut { // UTXO to attach fees to `htlc_tx` on anchors
			value: Amount::ONE_BTC.to_sat(),
			script_pubkey: nodes[0].wallet_source.get_change_script().unwrap(),
		}],
	};
	nodes[0].wallet_source.add_utxo(bitcoin::OutPoint { txid: coinbase_tx.txid(), vout: 0 }, coinbase_tx.output[0].value);

	// Set up a helper closure we'll use throughout our test. We should only expect retries without
	// bumps if fees have not increased after a block has been connected (assuming the height timer
	// re-evaluates at every block) or after `ChainMonitor::rebroadcast_pending_claims` is called.
	let mut prev_htlc_tx_feerate = None;
	let mut check_htlc_retry = |should_retry: bool, should_bump: bool| -> Option<Transaction> {
		let (htlc_tx, htlc_tx_feerate) = if anchors {
			assert!(nodes[0].tx_broadcaster.txn_broadcast().is_empty());
			let events = nodes[0].chain_monitor.chain_monitor.get_and_clear_pending_events();
			assert_eq!(events.len(), if should_retry { 1 } else { 0 });
			if !should_retry {
				return None;
			}
			match &events[0] {
				Event::BumpTransaction(event) => {
					nodes[0].bump_tx_handler.handle_event(&event);
					let mut txn = nodes[0].tx_broadcaster.unique_txn_broadcast();
					assert_eq!(txn.len(), 1);
					let htlc_tx = txn.pop().unwrap();
					check_spends!(&htlc_tx, &commitment_txn[0], &coinbase_tx);
					let htlc_tx_fee = HTLC_AMT_SAT + coinbase_tx.output[0].value -
						htlc_tx.output.iter().map(|output| output.value).sum::<u64>();
					let htlc_tx_weight = htlc_tx.weight() as u64;
					(htlc_tx, compute_feerate_sat_per_1000_weight(htlc_tx_fee, htlc_tx_weight))
				}
				_ => panic!("Unexpected event"),
			}
		} else {
			assert!(nodes[0].chain_monitor.chain_monitor.get_and_clear_pending_events().is_empty());
			let mut txn = nodes[0].tx_broadcaster.txn_broadcast();
			assert_eq!(txn.len(), if should_retry { 1 } else { 0 });
			if !should_retry {
				return None;
			}
			let htlc_tx = txn.pop().unwrap();
			check_spends!(htlc_tx, commitment_txn[0]);
			let htlc_tx_fee = HTLC_AMT_SAT - htlc_tx.output[0].value;
			let htlc_tx_weight = htlc_tx.weight() as u64;
			(htlc_tx, compute_feerate_sat_per_1000_weight(htlc_tx_fee, htlc_tx_weight))
		};
		if should_bump {
			assert!(htlc_tx_feerate > prev_htlc_tx_feerate.take().unwrap());
		} else if let Some(prev_feerate) = prev_htlc_tx_feerate.take() {
			assert_eq!(htlc_tx_feerate, prev_feerate);
		}
		prev_htlc_tx_feerate = Some(htlc_tx_feerate);
		Some(htlc_tx)
	};

	// Connect blocks up to one before the HTLC expires. This should not result in a claim/retry.
	connect_blocks(&nodes[0], htlc_expiry - nodes[0].best_block_info().1 - 1);
	check_htlc_retry(false, false);

	// Connect one more block, producing our first claim.
	connect_blocks(&nodes[0], 1);
	check_htlc_retry(true, false);

	// Connect one more block, expecting a retry with a fee bump. Unfortunately, we cannot bump HTLC
	// transactions pre-anchors.
	connect_blocks(&nodes[0], 1);
	check_htlc_retry(true, anchors);

	// Trigger a call and we should have another retry, but without a bump.
	nodes[0].chain_monitor.chain_monitor.rebroadcast_pending_claims();
	check_htlc_retry(true, false);

	// Double the feerate and trigger a call, expecting a fee-bumped retry.
	*nodes[0].fee_estimator.sat_per_kw.lock().unwrap() *= 2;
	nodes[0].chain_monitor.chain_monitor.rebroadcast_pending_claims();
	check_htlc_retry(true, anchors);

	// Connect one more block, expecting a retry with a fee bump. Unfortunately, we cannot bump HTLC
	// transactions pre-anchors.
	connect_blocks(&nodes[0], 1);
	let htlc_tx = check_htlc_retry(true, anchors).unwrap();

	// Mine the HTLC transaction to ensure we don't retry claims while they're confirmed.
	mine_transaction(&nodes[0], &htlc_tx);
	// If we have a `ConnectStyle` that advertises the new block first without the transactions,
	// we'll receive an extra bumped claim.
	if nodes[0].connect_style.borrow().updates_best_block_first() {
		nodes[0].wallet_source.add_utxo(bitcoin::OutPoint { txid: coinbase_tx.txid(), vout: 0 }, coinbase_tx.output[0].value);
		nodes[0].wallet_source.remove_utxo(bitcoin::OutPoint { txid: htlc_tx.txid(), vout: 1 });
		check_htlc_retry(true, anchors);
	}
	nodes[0].chain_monitor.chain_monitor.rebroadcast_pending_claims();
	check_htlc_retry(false, false);
}

#[test]
fn test_monitor_timer_based_claim() {
	do_test_monitor_rebroadcast_pending_claims(false);
	do_test_monitor_rebroadcast_pending_claims(true);
}

#[test]
fn test_yield_anchors_events() {
	// Tests that two parties supporting anchor outputs can open a channel, route payments over
	// it, and finalize its resolution uncooperatively. Once the HTLCs are locked in, one side will
	// force close once the HTLCs expire. The force close should stem from an event emitted by LDK,
	// allowing the consumer to provide additional fees to the commitment transaction to be
	// broadcast. Once the commitment transaction confirms, events for the HTLC resolution should be
	// emitted by LDK, such that the consumer can attach fees to the zero fee HTLC transactions.
	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut anchors_config = UserConfig::default();
	anchors_config.channel_handshake_config.announced_channel = true;
	anchors_config.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = true;
	anchors_config.manually_accept_inbound_channels = true;
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(anchors_config), Some(anchors_config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let chan_id = create_announced_chan_between_nodes_with_value(
		&nodes, 0, 1, 1_000_000, 500_000_000
	).2;
	route_payment(&nodes[0], &[&nodes[1]], 1_000_000);
	let (payment_preimage, payment_hash, ..) = route_payment(&nodes[1], &[&nodes[0]], 1_000_000);

	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());

	*nodes[0].fee_estimator.sat_per_kw.lock().unwrap() *= 2;
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
		Event::BumpTransaction(event) => {
			let coinbase_tx = Transaction {
				version: 2,
				lock_time: PackedLockTime::ZERO,
				input: vec![TxIn { ..Default::default() }],
				output: vec![TxOut { // UTXO to attach fees to `anchor_tx`
					value: Amount::ONE_BTC.to_sat(),
					script_pubkey: nodes[0].wallet_source.get_change_script().unwrap(),
				}],
			};
			nodes[0].wallet_source.add_utxo(bitcoin::OutPoint { txid: coinbase_tx.txid(), vout: 0 }, coinbase_tx.output[0].value);
			nodes[0].bump_tx_handler.handle_event(&event);
			let mut txn = nodes[0].tx_broadcaster.unique_txn_broadcast();
			assert_eq!(txn.len(), 2);
			let anchor_tx = txn.pop().unwrap();
			let commitment_tx = txn.pop().unwrap();
			check_spends!(anchor_tx, coinbase_tx, commitment_tx);
			(commitment_tx, anchor_tx)
		},
		_ => panic!("Unexpected event"),
	};

	mine_transactions(&nodes[0], &[&commitment_tx, &anchor_tx]);
	check_added_monitors!(nodes[0], 1);

	let mut holder_events = nodes[0].chain_monitor.chain_monitor.get_and_clear_pending_events();
	// Certain block `ConnectStyle`s cause an extra `ChannelClose` event to be emitted since the
	// best block is updated before the confirmed transactions are notified.
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
			Event::BumpTransaction(event) => {
				nodes[0].bump_tx_handler.handle_event(&event);
				let mut txn = nodes[0].tx_broadcaster.unique_txn_broadcast();
				assert_eq!(txn.len(), 1);
				let htlc_tx = txn.pop().unwrap();
				check_spends!(htlc_tx, commitment_tx, anchor_tx);
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

#[test]
fn test_anchors_aggregated_revoked_htlc_tx() {
	// Test that `ChannelMonitor`s can properly detect and claim funds from a counterparty claiming
	// multiple HTLCs from multiple channels in a single transaction via the success path from a
	// revoked commitment.
	let secp = Secp256k1::new();
	let mut chanmon_cfgs = create_chanmon_cfgs(2);
	// Required to sign a revoked commitment transaction
	chanmon_cfgs[1].keys_manager.disable_revocation_policy_check = true;
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let bob_persister;
	let bob_chain_monitor;

	let mut anchors_config = UserConfig::default();
	anchors_config.channel_handshake_config.announced_channel = true;
	anchors_config.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = true;
	anchors_config.manually_accept_inbound_channels = true;
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(anchors_config), Some(anchors_config)]);
	let bob_deserialized;

	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let chan_a = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 20_000_000);
	let chan_b = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 20_000_000);

	// Serialize Bob with the initial state of both channels, which we'll use later.
	let bob_serialized = nodes[1].node.encode();

	// Route two payments for each channel from Alice to Bob to lock in the HTLCs.
	let payment_a = route_payment(&nodes[0], &[&nodes[1]], 50_000_000);
	let payment_b = route_payment(&nodes[0], &[&nodes[1]], 50_000_000);
	let payment_c = route_payment(&nodes[0], &[&nodes[1]], 50_000_000);
	let payment_d = route_payment(&nodes[0], &[&nodes[1]], 50_000_000);

	// Serialize Bob's monitors with the HTLCs locked in. We'll restart Bob later on with the state
	// at this point such that he broadcasts a revoked commitment transaction with the HTLCs
	// present.
	let bob_serialized_monitor_a = get_monitor!(nodes[1], chan_a.2).encode();
	let bob_serialized_monitor_b = get_monitor!(nodes[1], chan_b.2).encode();

	// Bob claims all the HTLCs...
	claim_payment(&nodes[0], &[&nodes[1]], payment_a.0);
	claim_payment(&nodes[0], &[&nodes[1]], payment_b.0);
	claim_payment(&nodes[0], &[&nodes[1]], payment_c.0);
	claim_payment(&nodes[0], &[&nodes[1]], payment_d.0);

	// ...and sends one back through each channel such that he has a motive to broadcast his
	// revoked state.
	send_payment(&nodes[1], &[&nodes[0]], 30_000_000);
	send_payment(&nodes[1], &[&nodes[0]], 30_000_000);

	// Restart Bob with the revoked state and provide the HTLC preimages he claimed.
	reload_node!(
		nodes[1], anchors_config, bob_serialized, &[&bob_serialized_monitor_a, &bob_serialized_monitor_b],
		bob_persister, bob_chain_monitor, bob_deserialized
	);
	for chan_id in [chan_a.2, chan_b.2].iter() {
		let monitor = get_monitor!(nodes[1], chan_id);
		for payment in [payment_a, payment_b, payment_c, payment_d].iter() {
			monitor.provide_payment_preimage(
				&payment.1, &payment.0, &node_cfgs[1].tx_broadcaster,
				&LowerBoundedFeeEstimator::new(node_cfgs[1].fee_estimator), &nodes[1].logger
			);
		}
	}

	// Bob force closes by restarting with the outdated state, prompting the ChannelMonitors to
	// broadcast the latest commitment transaction known to them, which in our case is the one with
	// the HTLCs still pending.
	*nodes[1].fee_estimator.sat_per_kw.lock().unwrap() *= 2;
	nodes[1].node.timer_tick_occurred();
	check_added_monitors(&nodes[1], 2);
	check_closed_event!(&nodes[1], 2, ClosureReason::OutdatedChannelManager, [nodes[0].node.get_our_node_id(); 2], 1000000);
	let (revoked_commitment_a, revoked_commitment_b) = {
		let txn = nodes[1].tx_broadcaster.unique_txn_broadcast();
		assert_eq!(txn.len(), 2);
		assert_eq!(txn[0].output.len(), 6); // 2 HTLC outputs + 1 to_self output + 1 to_remote output + 2 anchor outputs
		assert_eq!(txn[1].output.len(), 6); // 2 HTLC outputs + 1 to_self output + 1 to_remote output + 2 anchor outputs
		if txn[0].input[0].previous_output.txid == chan_a.3.txid() {
			check_spends!(&txn[0], &chan_a.3);
			check_spends!(&txn[1], &chan_b.3);
			(txn[0].clone(), txn[1].clone())
		} else {
			check_spends!(&txn[1], &chan_a.3);
			check_spends!(&txn[0], &chan_b.3);
			(txn[1].clone(), txn[0].clone())
		}
	};

	// Bob should now receive two events to bump his revoked commitment transaction fees.
	assert!(nodes[0].chain_monitor.chain_monitor.get_and_clear_pending_events().is_empty());
	let events = nodes[1].chain_monitor.chain_monitor.get_and_clear_pending_events();
	assert_eq!(events.len(), 2);
	let mut anchor_txs = Vec::with_capacity(events.len());
	for (idx, event) in events.into_iter().enumerate() {
		let utxo_value = Amount::ONE_BTC.to_sat() * (idx + 1) as u64;
		let coinbase_tx = Transaction {
			version: 2,
			lock_time: PackedLockTime::ZERO,
			input: vec![TxIn { ..Default::default() }],
			output: vec![TxOut { // UTXO to attach fees to `anchor_tx`
				value: utxo_value,
				script_pubkey: nodes[1].wallet_source.get_change_script().unwrap(),
			}],
		};
		nodes[1].wallet_source.add_utxo(bitcoin::OutPoint { txid: coinbase_tx.txid(), vout: 0 }, utxo_value);
		match event {
			Event::BumpTransaction(event) => nodes[1].bump_tx_handler.handle_event(&event),
			_ => panic!("Unexpected event"),
		};
		let txn = nodes[1].tx_broadcaster.txn_broadcast();
		assert_eq!(txn.len(), 2);
		let (commitment_tx, anchor_tx) = (&txn[0], &txn[1]);
		check_spends!(anchor_tx, coinbase_tx, commitment_tx);
		anchor_txs.push(anchor_tx.clone());
	};

	for node in &nodes {
		mine_transactions(node, &[&revoked_commitment_a, &anchor_txs[0], &revoked_commitment_b, &anchor_txs[1]]);
	}
	check_added_monitors!(&nodes[0], 2);
	check_closed_broadcast(&nodes[0], 2, true);
	check_closed_event!(&nodes[0], 2, ClosureReason::CommitmentTxConfirmed, [nodes[1].node.get_our_node_id(); 2], 1000000);

	// Alice should detect the confirmed revoked commitments, and attempt to claim all of the
	// revoked outputs.
	{
		let txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
		assert_eq!(txn.len(), 4);

		let (revoked_htlc_claim_a, revoked_htlc_claim_b) = if txn[0].input[0].previous_output.txid == revoked_commitment_a.txid() {
			(if txn[0].input.len() == 2 { &txn[0] } else { &txn[1] }, if txn[2].input.len() == 2 { &txn[2] } else { &txn[3] })
		} else {
			(if txn[2].input.len() == 2 { &txn[2] } else { &txn[3] }, if txn[0].input.len() == 2 { &txn[0] } else { &txn[1] })
		};

		assert_eq!(revoked_htlc_claim_a.input.len(), 2); // Spends both HTLC outputs
		assert_eq!(revoked_htlc_claim_a.output.len(), 1);
		check_spends!(revoked_htlc_claim_a, revoked_commitment_a);
		assert_eq!(revoked_htlc_claim_b.input.len(), 2); // Spends both HTLC outputs
		assert_eq!(revoked_htlc_claim_b.output.len(), 1);
		check_spends!(revoked_htlc_claim_b, revoked_commitment_b);
	}

	// Since Bob was able to confirm his revoked commitment, he'll now try to claim the HTLCs
	// through the success path.
	assert!(nodes[0].chain_monitor.chain_monitor.get_and_clear_pending_events().is_empty());
	let mut events = nodes[1].chain_monitor.chain_monitor.get_and_clear_pending_events();
	// Certain block `ConnectStyle`s cause an extra `ChannelClose` event to be emitted since the
	// best block is updated before the confirmed transactions are notified.
	match *nodes[1].connect_style.borrow() {
		ConnectStyle::BestBlockFirst|ConnectStyle::BestBlockFirstReorgsOnlyTip|ConnectStyle::BestBlockFirstSkippingBlocks => {
			assert_eq!(events.len(), 4);
			if let Event::BumpTransaction(BumpTransactionEvent::ChannelClose { .. }) = events.remove(0) {}
			else { panic!("unexpected event"); }
			if let Event::BumpTransaction(BumpTransactionEvent::ChannelClose { .. }) = events.remove(1) {}
			else { panic!("unexpected event"); }

		},
		_ => assert_eq!(events.len(), 2),
	};
	let htlc_tx = {
		let secret_key = SecretKey::from_slice(&[1; 32]).unwrap();
		let public_key = PublicKey::new(secret_key.public_key(&secp));
		let fee_utxo_script = Script::new_v0_p2wpkh(&public_key.wpubkey_hash().unwrap());
		let coinbase_tx = Transaction {
			version: 2,
			lock_time: PackedLockTime::ZERO,
			input: vec![TxIn { ..Default::default() }],
			output: vec![TxOut { // UTXO to attach fees to `htlc_tx`
				value: Amount::ONE_BTC.to_sat(),
				script_pubkey: fee_utxo_script.clone(),
			}],
		};
		let mut htlc_tx = Transaction {
			version: 2,
			lock_time: PackedLockTime::ZERO,
			input: vec![TxIn { // Fee input
				previous_output: bitcoin::OutPoint { txid: coinbase_tx.txid(), vout: 0 },
				..Default::default()
			}],
			output: vec![TxOut { // Fee input change
				value: coinbase_tx.output[0].value / 2 ,
				script_pubkey: Script::new_op_return(&[]),
			}],
		};
		let mut descriptors = Vec::with_capacity(4);
		for event in events {
			// We don't use the `BumpTransactionEventHandler` here because it does not support
			// creating one transaction from multiple `HTLCResolution` events.
			if let Event::BumpTransaction(BumpTransactionEvent::HTLCResolution { mut htlc_descriptors, tx_lock_time, .. }) = event {
				assert_eq!(htlc_descriptors.len(), 2);
				for htlc_descriptor in &htlc_descriptors {
					assert!(!htlc_descriptor.htlc.offered);
					htlc_tx.input.push(htlc_descriptor.unsigned_tx_input());
					htlc_tx.output.push(htlc_descriptor.tx_output(&secp));
				}
				descriptors.append(&mut htlc_descriptors);
				htlc_tx.lock_time = tx_lock_time;
			} else {
				panic!("Unexpected event");
			}
		}
		for (idx, htlc_descriptor) in descriptors.into_iter().enumerate() {
			let htlc_input_idx = idx + 1;
			let signer = htlc_descriptor.derive_channel_signer(&nodes[1].keys_manager);
			let our_sig = signer.sign_holder_htlc_transaction(&htlc_tx, htlc_input_idx, &htlc_descriptor, &secp).unwrap();
			let witness_script = htlc_descriptor.witness_script(&secp);
			htlc_tx.input[htlc_input_idx].witness = htlc_descriptor.tx_input_witness(&our_sig, &witness_script);
		}
		let fee_utxo_sig = {
			let witness_script = Script::new_p2pkh(&public_key.pubkey_hash());
			let sighash = hash_to_message!(&SighashCache::new(&htlc_tx).segwit_signature_hash(
				0, &witness_script, coinbase_tx.output[0].value, EcdsaSighashType::All
			).unwrap()[..]);
			let sig = sign(&secp, &sighash, &secret_key);
			let mut sig = sig.serialize_der().to_vec();
			sig.push(EcdsaSighashType::All as u8);
			sig
		};
		htlc_tx.input[0].witness = Witness::from_vec(vec![fee_utxo_sig, public_key.to_bytes()]);
		check_spends!(htlc_tx, coinbase_tx, revoked_commitment_a, revoked_commitment_b);
		htlc_tx
	};

	for node in &nodes {
		mine_transaction(node, &htlc_tx);
	}

	// Alice should see that Bob is trying to claim to HTLCs, so she should now try to claim them at
	// the second level instead.
	let revoked_claim_transactions = {
		let txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
		assert_eq!(txn.len(), 2);

		let revoked_htlc_claims = txn.iter().filter(|tx|
			tx.input.len() == 2 &&
			tx.output.len() == 1 &&
			tx.input[0].previous_output.txid == htlc_tx.txid()
		).collect::<Vec<_>>();
		assert_eq!(revoked_htlc_claims.len(), 2);
		for revoked_htlc_claim in revoked_htlc_claims {
			check_spends!(revoked_htlc_claim, htlc_tx);
		}

		let mut revoked_claim_transaction_map = HashMap::new();
		for current_tx in txn.into_iter() {
			revoked_claim_transaction_map.insert(current_tx.txid(), current_tx);
		}
		revoked_claim_transaction_map
	};
	for node in &nodes {
		mine_transactions(node, &revoked_claim_transactions.values().collect::<Vec<_>>());
	}


	// Connect one block to make sure the HTLC events are not yielded while ANTI_REORG_DELAY has not
	// been reached.
	connect_blocks(&nodes[0], 1);
	connect_blocks(&nodes[1], 1);

	assert!(nodes[0].chain_monitor.chain_monitor.get_and_clear_pending_events().is_empty());
	assert!(nodes[1].chain_monitor.chain_monitor.get_and_clear_pending_events().is_empty());

	// Connect the remaining blocks to reach ANTI_REORG_DELAY.
	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 2);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 2);

	assert!(nodes[1].chain_monitor.chain_monitor.get_and_clear_pending_events().is_empty());
	let spendable_output_events = nodes[0].chain_monitor.chain_monitor.get_and_clear_pending_events();
	assert_eq!(spendable_output_events.len(), 2);
	for event in spendable_output_events.iter() {
		if let Event::SpendableOutputs { outputs, channel_id } = event {
			assert_eq!(outputs.len(), 1);
			assert!(vec![chan_b.2, chan_a.2].contains(&channel_id.unwrap()));
			let spend_tx = nodes[0].keys_manager.backing.spend_spendable_outputs(
				&[&outputs[0]], Vec::new(), Script::new_op_return(&[]), 253, None, &Secp256k1::new(),
			).unwrap();

			check_spends!(spend_tx, revoked_claim_transactions.get(&spend_tx.input[0].previous_output.txid).unwrap());
		} else {
			panic!("unexpected event");
		}
	}

	assert!(nodes[0].node.list_channels().is_empty());
	assert!(nodes[1].node.list_channels().is_empty());
	// On the Alice side, the individual to_self_claim are still pending confirmation.
	assert_eq!(nodes[0].chain_monitor.chain_monitor.get_claimable_balances(&[]).len(), 2);
	// TODO: From Bob's PoV, he still thinks he can claim the outputs from his revoked commitment.
	// This needs to be fixed before we enable pruning `ChannelMonitor`s once they don't have any
	// balances to claim.
	//
	// The 6 claimable balances correspond to his `to_self` outputs and the 2 HTLC outputs in each
	// revoked commitment which Bob has the preimage for.
	assert_eq!(nodes[1].chain_monitor.chain_monitor.get_claimable_balances(&[]).len(), 6);
}
