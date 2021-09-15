// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Further functional tests which test blockchain reorganizations.

use chain::channelmonitor::{ANTI_REORG_DELAY, Balance};
use chain::transaction::OutPoint;
use ln::{channel, PaymentPreimage, PaymentHash};
use ln::channelmanager::BREAKDOWN_TIMEOUT;
use ln::features::InitFeatures;
use ln::msgs::{ChannelMessageHandler, ErrorAction};
use util::events::{Event, MessageSendEvent, MessageSendEventsProvider};
use routing::network_graph::NetworkUpdate;
use routing::router::get_route;

use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;

use bitcoin::blockdata::script::Builder;
use bitcoin::blockdata::opcodes;
use bitcoin::secp256k1::Secp256k1;

use prelude::*;

use ln::functional_test_utils::*;

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

	create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	let (update_a, _, chan_id_2, _) = create_announced_chan_between_nodes(&nodes, 1, 2, InitFeatures::known(), InitFeatures::known());

	let (route, payment_hash, _, payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[2], 1_000_000);
	nodes[0].node.send_payment(&route, payment_hash, &Some(payment_secret)).unwrap();
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
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());

	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);
	expect_pending_htlcs_forwardable!(nodes[1]);
	check_added_monitors!(nodes[1], 1);
	let fail_updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());

	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &fail_updates.update_fail_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], fail_updates.commitment_signed, true, true);
	expect_payment_failed_with_update!(nodes[0], payment_hash, false, update_a.contents.short_channel_id, true);
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
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 1_000_000, InitFeatures::known(), InitFeatures::known());
	let funding_outpoint = OutPoint { txid: funding_tx.txid(), index: 0 };
	assert_eq!(funding_outpoint.to_channel_id(), chan_id);

	let chan_feerate = get_feerate!(nodes[0], chan_id) as u64;

	assert_eq!(vec![Balance::ClaimableOnChannelClose {
			claimable_amount_satoshis: 1_000_000 - 1_000 - chan_feerate * channel::COMMITMENT_TX_BASE_WEIGHT / 1000
		}],
		nodes[0].chain_monitor.chain_monitor.monitors.read().unwrap().get(&funding_outpoint).unwrap().get_claimable_balances());
	assert_eq!(vec![Balance::ClaimableOnChannelClose { claimable_amount_satoshis: 1_000, }],
		nodes[1].chain_monitor.chain_monitor.monitors.read().unwrap().get(&funding_outpoint).unwrap().get_claimable_balances());

	nodes[0].node.close_channel(&chan_id).unwrap();
	let node_0_shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_shutdown(&nodes[0].node.get_our_node_id(), &InitFeatures::known(), &node_0_shutdown);
	let node_1_shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_shutdown(&nodes[1].node.get_our_node_id(), &InitFeatures::known(), &node_1_shutdown);

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
			claimable_amount_satoshis: 1_000_000 - 1_000 - chan_feerate * channel::COMMITMENT_TX_BASE_WEIGHT / 1000,
			confirmation_height: nodes[0].best_block_info().1 + ANTI_REORG_DELAY - 1,
		}],
		nodes[0].chain_monitor.chain_monitor.monitors.read().unwrap().get(&funding_outpoint).unwrap().get_claimable_balances());
	assert_eq!(vec![Balance::ClaimableAwaitingConfirmations {
			claimable_amount_satoshis: 1000,
			confirmation_height: nodes[1].best_block_info().1 + ANTI_REORG_DELAY - 1,
		}],
		nodes[1].chain_monitor.chain_monitor.monitors.read().unwrap().get(&funding_outpoint).unwrap().get_claimable_balances());

	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);

	assert_eq!(Vec::<Balance>::new(),
		nodes[0].chain_monitor.chain_monitor.monitors.read().unwrap().get(&funding_outpoint).unwrap().get_claimable_balances());
	assert_eq!(Vec::<Balance>::new(),
		nodes[1].chain_monitor.chain_monitor.monitors.read().unwrap().get(&funding_outpoint).unwrap().get_claimable_balances());

	let mut node_a_spendable = nodes[0].chain_monitor.chain_monitor.get_and_clear_pending_events();
	assert_eq!(node_a_spendable.len(), 1);
	if let Event::SpendableOutputs { outputs } = node_a_spendable.pop().unwrap() {
		assert_eq!(outputs.len(), 1);
		let spend_tx = nodes[0].keys_manager.backing.spend_spendable_outputs(&[&outputs[0]], Vec::new(),
			Builder::new().push_opcode(opcodes::all::OP_RETURN).into_script(), 253, &Secp256k1::new()).unwrap();
		check_spends!(spend_tx, shutdown_tx[0]);
	}

	let mut node_b_spendable = nodes[1].chain_monitor.chain_monitor.get_and_clear_pending_events();
	assert_eq!(node_b_spendable.len(), 1);
	if let Event::SpendableOutputs { outputs } = node_b_spendable.pop().unwrap() {
		assert_eq!(outputs.len(), 1);
		let spend_tx = nodes[1].keys_manager.backing.spend_spendable_outputs(&[&outputs[0]], Vec::new(),
			Builder::new().push_opcode(opcodes::all::OP_RETURN).into_script(), 253, &Secp256k1::new()).unwrap();
		check_spends!(spend_tx, shutdown_tx[0]);
	}
}

fn sorted_vec<T: Ord>(mut v: Vec<T>) -> Vec<T> {
	v.sort_unstable();
	v
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
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 1_000_000, InitFeatures::known(), InitFeatures::known());
	let funding_outpoint = OutPoint { txid: funding_tx.txid(), index: 0 };
	assert_eq!(funding_outpoint.to_channel_id(), chan_id);

	// This HTLC is immediately claimed, giving node B the preimage
	let payment_preimage = route_payment(&nodes[0], &[&nodes[1]], 3_000_000).0;
	// This HTLC is allowed to time out, letting A claim it. However, in order to test claimable
	// balances more fully we also give B the preimage for this HTLC.
	let (timeout_payment_preimage, timeout_payment_hash, _) = route_payment(&nodes[0], &[&nodes[1]], 4_000_000);
	// This HTLC will be dust, and not be claimable at all:
	let (dust_payment_preimage, dust_payment_hash, _) = route_payment(&nodes[0], &[&nodes[1]], 3_000);

	let htlc_cltv_timeout = nodes[0].best_block_info().1 + TEST_FINAL_CLTV + 1; // Note ChannelManager adds one to CLTV timeouts for safety

	let chan_feerate = get_feerate!(nodes[0], chan_id) as u64;

	let remote_txn = get_local_commitment_txn!(nodes[1], chan_id);
	// Before B receives the payment preimage, it only suggests the push_msat value of 1_000 sats
	// as claimable. A lists both its to-self balance and the (possibly-claimable) HTLCs.
	assert_eq!(sorted_vec(vec![Balance::ClaimableOnChannelClose {
			claimable_amount_satoshis: 1_000_000 - 3_000 - 4_000 - 1_000 - 3 - chan_feerate *
				(channel::COMMITMENT_TX_BASE_WEIGHT + 2 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
		}, Balance::MaybeClaimableHTLCAwaitingTimeout {
			claimable_amount_satoshis: 3_000,
			claimable_height: htlc_cltv_timeout,
		}, Balance::MaybeClaimableHTLCAwaitingTimeout {
			claimable_amount_satoshis: 4_000,
			claimable_height: htlc_cltv_timeout,
		}]),
		sorted_vec(nodes[0].chain_monitor.chain_monitor.monitors.read().unwrap().get(&funding_outpoint).unwrap().get_claimable_balances()));
	assert_eq!(vec![Balance::ClaimableOnChannelClose {
			claimable_amount_satoshis: 1_000,
		}],
		nodes[1].chain_monitor.chain_monitor.monitors.read().unwrap().get(&funding_outpoint).unwrap().get_claimable_balances());

	nodes[1].node.claim_funds(payment_preimage);
	check_added_monitors!(nodes[1], 1);
	let b_htlc_msgs = get_htlc_update_msgs!(&nodes[1], nodes[0].node.get_our_node_id());
	// We claim the dust payment here as well, but it won't impact our claimable balances as its
	// dust and thus doesn't appear on chain at all.
	nodes[1].node.claim_funds(dust_payment_preimage);
	check_added_monitors!(nodes[1], 1);
	nodes[1].node.claim_funds(timeout_payment_preimage);
	check_added_monitors!(nodes[1], 1);

	if prev_commitment_tx {
		// To build a previous commitment transaction, deliver one round of commitment messages.
		nodes[0].node.handle_update_fulfill_htlc(&nodes[1].node.get_our_node_id(), &b_htlc_msgs.update_fulfill_htlcs[0]);
		expect_payment_sent!(nodes[0], payment_preimage);
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
				chan_feerate * (channel::COMMITMENT_TX_BASE_WEIGHT +
								if prev_commitment_tx { 1 } else { 2 } *
								channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
		}, Balance::MaybeClaimableHTLCAwaitingTimeout {
			claimable_amount_satoshis: 4_000,
			claimable_height: htlc_cltv_timeout,
		}];
	if !prev_commitment_tx {
		a_expected_balances.push(Balance::MaybeClaimableHTLCAwaitingTimeout {
			claimable_amount_satoshis: 3_000,
			claimable_height: htlc_cltv_timeout,
		});
	}
	assert_eq!(sorted_vec(a_expected_balances),
		sorted_vec(nodes[0].chain_monitor.chain_monitor.monitors.read().unwrap().get(&funding_outpoint).unwrap().get_claimable_balances()));
	assert_eq!(vec![Balance::ClaimableOnChannelClose {
			claimable_amount_satoshis: 1_000 + 3_000 + 4_000,
		}],
		nodes[1].chain_monitor.chain_monitor.monitors.read().unwrap().get(&funding_outpoint).unwrap().get_claimable_balances());

	// Broadcast the closing transaction (which has both pending HTLCs in it) and get B's
	// broadcasted HTLC claim transaction with preimage.
	let node_b_commitment_claimable = nodes[1].best_block_info().1 + BREAKDOWN_TIMEOUT as u32;
	mine_transaction(&nodes[0], &remote_txn[0]);
	mine_transaction(&nodes[1], &remote_txn[0]);

	let b_broadcast_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	assert_eq!(b_broadcast_txn.len(), if prev_commitment_tx { 4 } else { 5 });
	if prev_commitment_tx {
		check_spends!(b_broadcast_txn[3], b_broadcast_txn[2]);
	} else {
		assert_eq!(b_broadcast_txn[0], b_broadcast_txn[3]);
		assert_eq!(b_broadcast_txn[1], b_broadcast_txn[4]);
	}
	// b_broadcast_txn[0] should spend the HTLC output of the commitment tx for 3_000 sats
	check_spends!(b_broadcast_txn[0], remote_txn[0]);
	check_spends!(b_broadcast_txn[1], remote_txn[0]);
	assert_eq!(b_broadcast_txn[0].input.len(), 1);
	assert_eq!(b_broadcast_txn[1].input.len(), 1);
	assert_eq!(remote_txn[0].output[b_broadcast_txn[0].input[0].previous_output.vout as usize].value, 3_000);
	assert_eq!(remote_txn[0].output[b_broadcast_txn[1].input[0].previous_output.vout as usize].value, 4_000);
	check_spends!(b_broadcast_txn[2], funding_tx);

	assert!(nodes[0].node.list_channels().is_empty());
	check_closed_broadcast!(nodes[0], true);
	check_added_monitors!(nodes[0], 1);
	assert!(nodes[1].node.list_channels().is_empty());
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors!(nodes[1], 1);
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
				(channel::COMMITMENT_TX_BASE_WEIGHT + 2 * channel::COMMITMENT_TX_WEIGHT_PER_HTLC) / 1000,
			confirmation_height: nodes[0].best_block_info().1 + ANTI_REORG_DELAY - 1,
		}, Balance::MaybeClaimableHTLCAwaitingTimeout {
			claimable_amount_satoshis: 3_000,
			claimable_height: htlc_cltv_timeout,
		}, Balance::MaybeClaimableHTLCAwaitingTimeout {
			claimable_amount_satoshis: 4_000,
			claimable_height: htlc_cltv_timeout,
		}]),
		sorted_vec(nodes[0].chain_monitor.chain_monitor.monitors.read().unwrap().get(&funding_outpoint).unwrap().get_claimable_balances()));
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
		sorted_vec(nodes[1].chain_monitor.chain_monitor.monitors.read().unwrap().get(&funding_outpoint).unwrap().get_claimable_balances()));

	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);
	expect_payment_failed!(nodes[0], dust_payment_hash, true);
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);

	// After ANTI_REORG_DELAY, A will consider its balance fully spendable and generate a
	// `SpendableOutputs` event. However, B still has to wait for the CSV delay.
	assert_eq!(sorted_vec(vec![Balance::MaybeClaimableHTLCAwaitingTimeout {
			claimable_amount_satoshis: 3_000,
			claimable_height: htlc_cltv_timeout,
		}, Balance::MaybeClaimableHTLCAwaitingTimeout {
			claimable_amount_satoshis: 4_000,
			claimable_height: htlc_cltv_timeout,
		}]),
		sorted_vec(nodes[0].chain_monitor.chain_monitor.monitors.read().unwrap().get(&funding_outpoint).unwrap().get_claimable_balances()));
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
		sorted_vec(nodes[1].chain_monitor.chain_monitor.monitors.read().unwrap().get(&funding_outpoint).unwrap().get_claimable_balances()));

	let mut node_a_spendable = nodes[0].chain_monitor.chain_monitor.get_and_clear_pending_events();
	assert_eq!(node_a_spendable.len(), 1);
	if let Event::SpendableOutputs { outputs } = node_a_spendable.pop().unwrap() {
		assert_eq!(outputs.len(), 1);
		let spend_tx = nodes[0].keys_manager.backing.spend_spendable_outputs(&[&outputs[0]], Vec::new(),
			Builder::new().push_opcode(opcodes::all::OP_RETURN).into_script(), 253, &Secp256k1::new()).unwrap();
		check_spends!(spend_tx, remote_txn[0]);
	}

	assert!(nodes[1].chain_monitor.chain_monitor.get_and_clear_pending_events().is_empty());

	// After broadcasting the HTLC claim transaction, node A will still consider the HTLC
	// possibly-claimable up to ANTI_REORG_DELAY, at which point it will drop it.
	mine_transaction(&nodes[0], &b_broadcast_txn[0]);
	if !prev_commitment_tx {
		expect_payment_sent!(nodes[0], payment_preimage);
	}
	assert_eq!(sorted_vec(vec![Balance::MaybeClaimableHTLCAwaitingTimeout {
			claimable_amount_satoshis: 3_000,
			claimable_height: htlc_cltv_timeout,
		}, Balance::MaybeClaimableHTLCAwaitingTimeout {
			claimable_amount_satoshis: 4_000,
			claimable_height: htlc_cltv_timeout,
		}]),
		sorted_vec(nodes[0].chain_monitor.chain_monitor.monitors.read().unwrap().get(&funding_outpoint).unwrap().get_claimable_balances()));
	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);
	assert_eq!(vec![Balance::MaybeClaimableHTLCAwaitingTimeout {
			claimable_amount_satoshis: 4_000,
			claimable_height: htlc_cltv_timeout,
		}],
		nodes[0].chain_monitor.chain_monitor.monitors.read().unwrap().get(&funding_outpoint).unwrap().get_claimable_balances());

	// When the HTLC timeout output is spendable in the next block, A should broadcast it
	connect_blocks(&nodes[0], htlc_cltv_timeout - nodes[0].best_block_info().1 - 1);
	let a_broadcast_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	assert_eq!(a_broadcast_txn.len(), 3);
	check_spends!(a_broadcast_txn[0], funding_tx);
	assert_eq!(a_broadcast_txn[1].input.len(), 1);
	check_spends!(a_broadcast_txn[1], remote_txn[0]);
	assert_eq!(a_broadcast_txn[2].input.len(), 1);
	check_spends!(a_broadcast_txn[2], remote_txn[0]);
	assert_ne!(a_broadcast_txn[1].input[0].previous_output.vout,
	           a_broadcast_txn[2].input[0].previous_output.vout);
	// a_broadcast_txn [1] and [2] should spend the HTLC outputs of the commitment tx
	assert_eq!(remote_txn[0].output[a_broadcast_txn[1].input[0].previous_output.vout as usize].value, 3_000);
	assert_eq!(remote_txn[0].output[a_broadcast_txn[2].input[0].previous_output.vout as usize].value, 4_000);

	// Once the HTLC-Timeout transaction confirms, A will no longer consider the HTLC
	// "MaybeClaimable", but instead move it to "AwaitingConfirmations".
	mine_transaction(&nodes[0], &a_broadcast_txn[2]);
	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
	assert_eq!(vec![Balance::ClaimableAwaitingConfirmations {
			claimable_amount_satoshis: 4_000,
			confirmation_height: nodes[0].best_block_info().1 + ANTI_REORG_DELAY - 1,
		}],
		nodes[0].chain_monitor.chain_monitor.monitors.read().unwrap().get(&funding_outpoint).unwrap().get_claimable_balances());
	// After ANTI_REORG_DELAY, A will generate a SpendableOutputs event and drop the claimable
	// balance entry.
	connect_blocks(&nodes[0], ANTI_REORG_DELAY - 1);
	assert_eq!(Vec::<Balance>::new(),
		nodes[0].chain_monitor.chain_monitor.monitors.read().unwrap().get(&funding_outpoint).unwrap().get_claimable_balances());
	expect_payment_failed!(nodes[0], timeout_payment_hash, true);

	let mut node_a_spendable = nodes[0].chain_monitor.chain_monitor.get_and_clear_pending_events();
	assert_eq!(node_a_spendable.len(), 1);
	if let Event::SpendableOutputs { outputs } = node_a_spendable.pop().unwrap() {
		assert_eq!(outputs.len(), 1);
		let spend_tx = nodes[0].keys_manager.backing.spend_spendable_outputs(&[&outputs[0]], Vec::new(),
			Builder::new().push_opcode(opcodes::all::OP_RETURN).into_script(), 253, &Secp256k1::new()).unwrap();
		check_spends!(spend_tx, a_broadcast_txn[2]);
	} else { panic!(); }

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
		sorted_vec(nodes[1].chain_monitor.chain_monitor.monitors.read().unwrap().get(&funding_outpoint).unwrap().get_claimable_balances()));

	// After reaching the commitment output CSV, we'll get a SpendableOutputs event for it and have
	// only the HTLCs claimable on node B.
	connect_blocks(&nodes[1], node_b_commitment_claimable - nodes[1].best_block_info().1);

	let mut node_b_spendable = nodes[1].chain_monitor.chain_monitor.get_and_clear_pending_events();
	assert_eq!(node_b_spendable.len(), 1);
	if let Event::SpendableOutputs { outputs } = node_b_spendable.pop().unwrap() {
		assert_eq!(outputs.len(), 1);
		let spend_tx = nodes[1].keys_manager.backing.spend_spendable_outputs(&[&outputs[0]], Vec::new(),
			Builder::new().push_opcode(opcodes::all::OP_RETURN).into_script(), 253, &Secp256k1::new()).unwrap();
		check_spends!(spend_tx, remote_txn[0]);
	}

	assert_eq!(sorted_vec(vec![Balance::ClaimableAwaitingConfirmations {
			claimable_amount_satoshis: 3_000,
			confirmation_height: node_b_htlc_claimable,
		}, Balance::ContentiousClaimable {
			claimable_amount_satoshis: 4_000,
			timeout_height: htlc_cltv_timeout,
		}]),
		sorted_vec(nodes[1].chain_monitor.chain_monitor.monitors.read().unwrap().get(&funding_outpoint).unwrap().get_claimable_balances()));

	// After reaching the claimed HTLC output CSV, we'll get a SpendableOutptus event for it and
	// have only one HTLC output left spendable.
	connect_blocks(&nodes[1], node_b_htlc_claimable - nodes[1].best_block_info().1);

	let mut node_b_spendable = nodes[1].chain_monitor.chain_monitor.get_and_clear_pending_events();
	assert_eq!(node_b_spendable.len(), 1);
	if let Event::SpendableOutputs { outputs } = node_b_spendable.pop().unwrap() {
		assert_eq!(outputs.len(), 1);
		let spend_tx = nodes[1].keys_manager.backing.spend_spendable_outputs(&[&outputs[0]], Vec::new(),
			Builder::new().push_opcode(opcodes::all::OP_RETURN).into_script(), 253, &Secp256k1::new()).unwrap();
		check_spends!(spend_tx, b_broadcast_txn[0]);
	} else { panic!(); }

	assert_eq!(vec![Balance::ContentiousClaimable {
			claimable_amount_satoshis: 4_000,
			timeout_height: htlc_cltv_timeout,
		}],
	nodes[1].chain_monitor.chain_monitor.monitors.read().unwrap().get(&funding_outpoint).unwrap().get_claimable_balances());

	// Finally, mine the HTLC timeout transaction that A broadcasted (even though B should be able
	// to claim this HTLC with the preimage it knows!). It will remain listed as a claimable HTLC
	// until ANTI_REORG_DELAY confirmations on the spend.
	mine_transaction(&nodes[1], &a_broadcast_txn[2]);
	assert_eq!(vec![Balance::ContentiousClaimable {
			claimable_amount_satoshis: 4_000,
			timeout_height: htlc_cltv_timeout,
		}],
	nodes[1].chain_monitor.chain_monitor.monitors.read().unwrap().get(&funding_outpoint).unwrap().get_claimable_balances());
	connect_blocks(&nodes[1], ANTI_REORG_DELAY - 1);
	assert_eq!(Vec::<Balance>::new(),
		nodes[1].chain_monitor.chain_monitor.monitors.read().unwrap().get(&funding_outpoint).unwrap().get_claimable_balances());
}

#[test]
fn test_claim_value_force_close() {
	do_test_claim_value_force_close(true);
	do_test_claim_value_force_close(false);
}
