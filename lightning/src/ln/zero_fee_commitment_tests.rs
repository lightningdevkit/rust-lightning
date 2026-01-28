use crate::events::{ClosureReason, Event};
use crate::ln::chan_utils;
use crate::ln::chan_utils::{
	BASE_INPUT_WEIGHT, BASE_TX_SIZE, EMPTY_SCRIPT_SIG_WEIGHT, EMPTY_WITNESS_WEIGHT,
	P2WSH_TXOUT_WEIGHT, SEGWIT_MARKER_FLAG_WEIGHT, TRUC_CHILD_MAX_WEIGHT,
};
use crate::ln::functional_test_utils::*;
use crate::ln::msgs::BaseMessageHandler;
use crate::prelude::*;

use bitcoin::constants::WITNESS_SCALE_FACTOR;
use bitcoin::Amount;

#[test]
fn test_p2a_anchor_values_under_trims_and_rounds() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut user_cfg = test_default_channel_config();
	user_cfg.channel_handshake_config.our_htlc_minimum_msat = 1;
	user_cfg.channel_handshake_config.negotiate_anchor_zero_fee_commitments = true;

	let configs = [Some(user_cfg.clone()), Some(user_cfg)];
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &configs);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let _coinbase_tx = provide_anchor_reserves(&nodes);

	let _node_a_id = nodes[0].node.get_our_node_id();
	let _node_b_id = nodes[1].node.get_our_node_id();

	const CHAN_CAPACITY: u64 = 10_000_000;
	let chan_id = create_announced_chan_between_nodes_with_value(
		&nodes,
		0,
		1,
		CHAN_CAPACITY,
		(CHAN_CAPACITY / 2) * 1000,
	)
	.2;

	macro_rules! p2a_value_test {
		([$($node_0_1_amt_msat:expr),*], $expected_p2a_value_sat:expr) => {
			p2a_value_test!([$($node_0_1_amt_msat),*], [], $expected_p2a_value_sat)
		};
		([$($node_0_1_amt_msat:expr),*], [$($node_1_0_amt_msat:expr),*], $expected_p2a_value_sat:expr) => {
			let mut node_0_1_hashes = Vec::new();
			#[allow(unused_mut)]
			let mut node_1_0_hashes = Vec::new();

			$(
				node_0_1_hashes.push(route_payment(&nodes[0], &[&nodes[1]], $node_0_1_amt_msat).1);
			)*
			$(
				node_1_0_hashes.push(route_payment(&nodes[1], &[&nodes[0]], $node_1_0_amt_msat).1);
			)*
			let txn = get_local_commitment_txn!(nodes[0], chan_id);
			assert_eq!(txn.len(), 1);
			assert_eq!(txn[0].output.iter().find(|output| output.script_pubkey == chan_utils::shared_anchor_script_pubkey()).unwrap().value.to_sat(), $expected_p2a_value_sat);
			let txn = get_local_commitment_txn!(nodes[1], chan_id);
			assert_eq!(txn.len(), 1);
			assert_eq!(txn[0].output.iter().find(|output| output.script_pubkey == chan_utils::shared_anchor_script_pubkey()).unwrap().value.to_sat(), $expected_p2a_value_sat);
			for hash in node_0_1_hashes {
				fail_payment(&nodes[0], &[&nodes[1]], hash);
			}
			for hash in node_1_0_hashes {
				fail_payment(&nodes[1], &[&nodes[0]], hash);
			}
		};
	}

	p2a_value_test!([1], 1);
	p2a_value_test!([238_000], 238);
	p2a_value_test!([238_001], 239);
	p2a_value_test!([240_000], 240);
	p2a_value_test!([240_001], 240);
	p2a_value_test!([353_000], 240);
	p2a_value_test!([353_999], 240);
	p2a_value_test!([354_000], 0);
	p2a_value_test!([354_001], 1);

	p2a_value_test!([1, 1], 1);
	p2a_value_test!([1, 999], 1);
	p2a_value_test!([1, 1000], 2);
	p2a_value_test!([354_001], 1);
	p2a_value_test!([354_001, 999], 1);
	p2a_value_test!([354_001, 1000], 2);
	p2a_value_test!([354_001, 1999], 2);
	p2a_value_test!([354_002, 1999], 3);

	p2a_value_test!([1], [1], 2);
	p2a_value_test!([1], [999], 2);
	p2a_value_test!([1], [1000], 2);
	p2a_value_test!([354_001], 1);
	p2a_value_test!([354_001], [999], 2);
	p2a_value_test!([354_001], [1000], 2);
	p2a_value_test!([354_001], [1999], 3);
	p2a_value_test!([354_002], [1999], 3);

	p2a_value_test!([353_000], [353_000], 240);
	p2a_value_test!([353_001], [353_000], 240);
	p2a_value_test!([353_000], [353_001], 240);
	p2a_value_test!([353_001], [353_001], 240);
}

#[test]
fn test_htlc_claim_chunking() {
	// Assert we split an overall HolderHTLCOutput claim into constituent
	// HTLC claim transactions such that each transaction is under TRUC_MAX_WEIGHT.
	// Assert we reduce the number of HTLCs in a batch transaction by 2 if the
	// coin selection algorithm fails to meet the target weight.
	// Assert the claim_id of the first batch transaction is the claim
	// id assigned to the overall claim.
	// Assert we give up bumping a HTLC transaction once the batch size is
	// 0 or negative.
	//
	// Route a bunch of HTLCs, force close the channel, assert two HTLC transactions
	// get broadcasted, confirm only one of them, assert a new one gets broadcasted
	// to sweep the remaining HTLCs, confirm a block without that transaction while
	// dropping all available coin selection utxos, and assert we give up creating
	// another HTLC transaction when handling the third HTLC bump.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut user_cfg = test_default_channel_config();
	user_cfg.channel_handshake_config.our_htlc_minimum_msat = 1;
	user_cfg.channel_handshake_config.negotiate_anchor_zero_fee_commitments = true;
	user_cfg.channel_handshake_config.our_max_accepted_htlcs = 114;

	let configs = [Some(user_cfg.clone()), Some(user_cfg)];
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &configs);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let coinbase_tx = provide_anchor_utxo_reserves(&nodes, 50, Amount::from_sat(500));

	const CHAN_CAPACITY: u64 = 10_000_000;
	let (_, _, chan_id, _funding_tx) = create_announced_chan_between_nodes_with_value(
		&nodes,
		0,
		1,
		CHAN_CAPACITY,
		(CHAN_CAPACITY / 2) * 1000,
	);

	let mut node_1_preimages = Vec::new();
	const NONDUST_HTLC_AMT_MSAT: u64 = 1_000_000;
	for _ in 0..75 {
		let (preimage, payment_hash, _, _) =
			route_payment(&nodes[0], &[&nodes[1]], NONDUST_HTLC_AMT_MSAT);
		node_1_preimages.push((preimage, payment_hash));
	}
	let node_0_commit_tx = get_local_commitment_txn!(nodes[0], chan_id);
	assert_eq!(node_0_commit_tx.len(), 1);
	assert_eq!(node_0_commit_tx[0].output.len(), 75 + 2 + 1);
	let node_1_commit_tx = get_local_commitment_txn!(nodes[1], chan_id);
	assert_eq!(node_1_commit_tx.len(), 1);
	assert_eq!(node_1_commit_tx[0].output.len(), 75 + 2 + 1);

	for (preimage, payment_hash) in node_1_preimages {
		nodes[1].node.claim_funds(preimage);
		check_added_monitors(&nodes[1], 1);
		expect_payment_claimed!(nodes[1], payment_hash, NONDUST_HTLC_AMT_MSAT);
	}
	nodes[0].node.get_and_clear_pending_msg_events();
	nodes[1].node.get_and_clear_pending_msg_events();

	mine_transaction(&nodes[0], &node_1_commit_tx[0]);
	mine_transaction(&nodes[1], &node_1_commit_tx[0]);

	let mut events = nodes[1].chain_monitor.chain_monitor.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events.pop().unwrap() {
		Event::BumpTransaction(bump_event) => {
			nodes[1].bump_tx_handler.handle_event(&bump_event);
		},
		_ => panic!("Unexpected event"),
	}

	let htlc_claims = nodes[1].tx_broadcaster.txn_broadcast();
	assert_eq!(htlc_claims.len(), 2);

	check_spends!(htlc_claims[0], node_1_commit_tx[0], coinbase_tx);
	check_spends!(htlc_claims[1], node_1_commit_tx[0], coinbase_tx);

	assert_eq!(htlc_claims[0].input.len(), 71);
	assert_eq!(htlc_claims[0].output.len(), 51);
	assert_eq!(htlc_claims[1].input.len(), 34);
	assert_eq!(htlc_claims[1].output.len(), 24);

	check_closed_broadcast!(nodes[0], true);
	check_added_monitors(&nodes[0], 1);
	let reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[0], 1, reason, &[nodes[1].node.get_our_node_id()], CHAN_CAPACITY);
	assert!(nodes[0].node.list_channels().is_empty());
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors(&nodes[1], 1);
	let reason = ClosureReason::CommitmentTxConfirmed;
	check_closed_event(&nodes[1], 1, reason, &[nodes[0].node.get_our_node_id()], CHAN_CAPACITY);
	assert!(nodes[1].node.list_channels().is_empty());
	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());

	mine_transaction(&nodes[1], &htlc_claims[0]);

	let mut events = nodes[1].chain_monitor.chain_monitor.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events.pop().unwrap() {
		Event::BumpTransaction(bump_event) => {
			nodes[1].bump_tx_handler.handle_event(&bump_event);
		},
		_ => panic!("Unexpected event"),
	}

	let fresh_htlc_claims = nodes[1].tx_broadcaster.txn_broadcast();
	assert_eq!(fresh_htlc_claims.len(), 1);
	check_spends!(fresh_htlc_claims[0], node_1_commit_tx[0], coinbase_tx);
	// We are targeting a higher feerate here,
	// so we need more utxos here compared to `htlc_claims[1]` above.
	assert_eq!(fresh_htlc_claims[0].input.len(), 37);
	assert_eq!(fresh_htlc_claims[0].output.len(), 25);

	let log_entries = nodes[1].logger.lines.lock().unwrap();
	let batch_tx_id_assignments: Vec<_> = log_entries
		.keys()
		.map(|key| &key.1)
		.filter(|log_msg| log_msg.contains("Batch transaction assigned to UTXO id"))
		.collect();
	assert_eq!(batch_tx_id_assignments.len(), 7);

	let mut unique_claim_ids: Vec<(&str, u8)> = Vec::new();
	for claim_id in batch_tx_id_assignments
		.iter()
		.map(|assignment| assignment.split_whitespace().nth(6).unwrap())
	{
		if let Some((_, count)) = unique_claim_ids.iter_mut().find(|(id, _count)| &claim_id == id) {
			*count += 1;
		} else {
			unique_claim_ids.push((claim_id, 1));
		}
	}
	unique_claim_ids.sort_unstable_by_key(|(_id, count)| *count);
	assert_eq!(unique_claim_ids.len(), 2);
	let (og_claim_id, og_claim_id_count) = unique_claim_ids.pop().unwrap();
	assert_eq!(og_claim_id_count, 6);
	assert_eq!(unique_claim_ids.pop().unwrap().1, 1);

	let handling_htlc_bumps: Vec<_> = log_entries
		.keys()
		.map(|key| &key.1)
		.filter(|log_msg| log_msg.contains("Handling HTLC bump"))
		.map(|log_msg| {
			log_msg
				.split_whitespace()
				.nth(5)
				.unwrap()
				.trim_matches(|c: char| c.is_ascii_punctuation())
		})
		.collect();
	assert_eq!(handling_htlc_bumps.len(), 2);
	assert_eq!(handling_htlc_bumps[0], og_claim_id);
	assert_eq!(handling_htlc_bumps[1], og_claim_id);

	let mut batch_sizes: Vec<u8> = batch_tx_id_assignments
		.iter()
		.map(|assignment| assignment.split_whitespace().nth(8).unwrap().parse().unwrap())
		.collect();
	batch_sizes.sort_unstable();
	batch_sizes.reverse();
	assert_eq!(batch_sizes.len(), 7);
	assert_eq!(batch_sizes.pop().unwrap(), 24);
	assert_eq!(batch_sizes.pop().unwrap(), 24);
	for i in (51..=59).step_by(2) {
		assert_eq!(batch_sizes.pop().unwrap(), i);
	}
	drop(log_entries);

	nodes[1].wallet_source.clear_utxos();
	nodes[1].chain_monitor.chain_monitor.rebroadcast_pending_claims();

	let mut events = nodes[1].chain_monitor.chain_monitor.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events.pop().unwrap() {
		Event::BumpTransaction(bump_event) => {
			nodes[1].bump_tx_handler.handle_event(&bump_event);
		},
		_ => panic!("Unexpected event"),
	}

	nodes[1].logger.assert_log(
		"lightning::events::bump_transaction",
		format!(
			"Failed bumping HTLC transaction fee for commitment {}",
			node_1_commit_tx[0].compute_txid()
		),
		1,
	);
}

#[test]
fn test_anchor_tx_too_big() {
	// Assert all V3 anchor tx transactions are below TRUC_CHILD_MAX_WEIGHT.
	//
	// Provide a bunch of small utxos, fail to bump the commitment,
	// then provide a single big-value utxo, and successfully broadcast
	// the commitment.
	const FEERATE: u32 = 500;
	let chanmon_cfgs = create_chanmon_cfgs(2);
	{
		let mut feerate_lock = chanmon_cfgs[1].fee_estimator.sat_per_kw.lock().unwrap();
		*feerate_lock = FEERATE;
	}
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut user_cfg = test_default_channel_config();
	user_cfg.channel_handshake_config.our_htlc_minimum_msat = 1;
	user_cfg.channel_handshake_config.negotiate_anchor_zero_fee_commitments = true;
	user_cfg.channel_handshake_config.our_max_accepted_htlcs = 114;

	let configs = [Some(user_cfg.clone()), Some(user_cfg)];
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &configs);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let node_a_id = nodes[0].node.get_our_node_id();

	let _coinbase_tx_a = provide_anchor_utxo_reserves(&nodes, 50, Amount::from_sat(500));

	const CHAN_CAPACITY: u64 = 10_000_000;
	let (_, _, chan_id, _funding_tx) = create_announced_chan_between_nodes_with_value(
		&nodes,
		0,
		1,
		CHAN_CAPACITY,
		(CHAN_CAPACITY / 2) * 1000,
	);

	let mut node_1_preimages = Vec::new();
	const NONDUST_HTLC_AMT_MSAT: u64 = 1_000_000;
	for _ in 0..50 {
		let (preimage, payment_hash, _, _) =
			route_payment(&nodes[0], &[&nodes[1]], NONDUST_HTLC_AMT_MSAT);
		node_1_preimages.push((preimage, payment_hash));
	}
	let commitment_tx = get_local_commitment_txn!(nodes[1], chan_id).pop().unwrap();
	let commitment_txid = commitment_tx.compute_txid();

	let message = "Channel force-closed".to_owned();
	nodes[1]
		.node
		.force_close_broadcasting_latest_txn(&chan_id, &node_a_id, message.clone())
		.unwrap();
	check_added_monitors(&nodes[1], 1);
	check_closed_broadcast!(nodes[1], true);

	let reason = ClosureReason::HolderForceClosed { broadcasted_latest_txn: Some(true), message };
	check_closed_event(&nodes[1], 1, reason, &[node_a_id], CHAN_CAPACITY);

	let mut events = nodes[1].chain_monitor.chain_monitor.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events.pop().unwrap() {
		Event::BumpTransaction(bump_event) => {
			nodes[1].bump_tx_handler.handle_event(&bump_event);
		},
		_ => panic!("Unexpected event"),
	}
	assert!(nodes[1].tx_broadcaster.txn_broadcast().is_empty());
	let max_coin_selection_weight = TRUC_CHILD_MAX_WEIGHT
		- BASE_TX_SIZE * WITNESS_SCALE_FACTOR as u64
		- SEGWIT_MARKER_FLAG_WEIGHT
		- BASE_INPUT_WEIGHT
		- EMPTY_SCRIPT_SIG_WEIGHT
		- EMPTY_WITNESS_WEIGHT
		- P2WSH_TXOUT_WEIGHT;
	nodes[1].logger.assert_log(
		"lightning::events::bump_transaction",
		format!(
			"Insufficient funds to meet target feerate {} sat/kW while remaining under {} WU",
			FEERATE, max_coin_selection_weight
		),
		4,
	);
	nodes[1].logger.assert_log(
		"lightning::events::bump_transaction",
		format!("Failed bumping commitment transaction fee for {}", commitment_txid),
		1,
	);

	let coinbase_tx_b = provide_anchor_reserves(&nodes);

	nodes[1].chain_monitor.chain_monitor.rebroadcast_pending_claims();

	let mut events = nodes[1].chain_monitor.chain_monitor.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events.pop().unwrap() {
		Event::BumpTransaction(bump_event) => {
			nodes[1].bump_tx_handler.handle_event(&bump_event);
		},
		_ => panic!("Unexpected event"),
	}
	let txns = nodes[1].tx_broadcaster.txn_broadcast();
	assert_eq!(txns.len(), 2);
	check_spends!(txns[1], txns[0], coinbase_tx_b);
	assert!(txns[1].weight().to_wu() < TRUC_CHILD_MAX_WEIGHT);

	assert_eq!(txns[0].compute_txid(), commitment_txid);
	assert_eq!(txns[1].input.len(), 2);
	assert_eq!(txns[1].output.len(), 1);
	nodes[1].logger.assert_log(
		"lightning::events::bump_transaction",
		format!(
			"Insufficient funds to meet target feerate {} sat/kW while remaining under {} WU",
			FEERATE, max_coin_selection_weight
		),
		4,
	);
	nodes[1].logger.assert_log(
		"lightning::events::bump_transaction",
		format!("Failed bumping commitment transaction fee for {}", txns[0].compute_txid()),
		1,
	);
	nodes[1].logger.assert_log(
		"lightning::events::bump_transaction",
		format!(
			"Broadcasting anchor transaction {} to bump channel close with txid {}",
			txns[1].compute_txid(),
			txns[0].compute_txid()
		),
		1,
	);
}
