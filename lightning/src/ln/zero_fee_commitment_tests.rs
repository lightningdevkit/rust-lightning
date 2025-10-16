use crate::events::{ClosureReason, Event};
use crate::ln::chan_utils;
use crate::ln::functional_test_utils::*;
use crate::ln::msgs::BaseMessageHandler;

#[test]
fn test_p2a_anchor_values_under_trims_and_rounds() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut user_cfg = test_default_channel_config();
	user_cfg.channel_handshake_config.our_htlc_minimum_msat = 1;
	user_cfg.channel_handshake_config.negotiate_anchor_zero_fee_commitments = true;
	user_cfg.manually_accept_inbound_channels = true;

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
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut user_cfg = test_default_channel_config();
	user_cfg.channel_handshake_config.our_htlc_minimum_msat = 1;
	user_cfg.channel_handshake_config.negotiate_anchor_zero_fee_commitments = true;
	user_cfg.channel_handshake_config.our_max_accepted_htlcs = 114;
	user_cfg.manually_accept_inbound_channels = true;

	let configs = [Some(user_cfg.clone()), Some(user_cfg)];
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &configs);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let coinbase_tx = provide_anchor_reserves(&nodes);

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
		check_added_monitors!(nodes[1], 1);
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

	assert_eq!(htlc_claims[0].input.len(), 60);
	assert_eq!(htlc_claims[0].output.len(), 60);
	assert_eq!(htlc_claims[1].input.len(), 17);
	assert_eq!(htlc_claims[1].output.len(), 17);

	check_closed_broadcast!(nodes[0], true);
	check_added_monitors!(nodes[0], 1);
	check_closed_event!(
		nodes[0],
		1,
		ClosureReason::CommitmentTxConfirmed,
		[nodes[1].node.get_our_node_id()],
		CHAN_CAPACITY
	);
	assert!(nodes[0].node.list_channels().is_empty());
	check_closed_broadcast!(nodes[1], true);
	check_added_monitors!(nodes[1], 1);
	check_closed_event!(
		nodes[1],
		1,
		ClosureReason::CommitmentTxConfirmed,
		[nodes[0].node.get_our_node_id()],
		CHAN_CAPACITY
	);
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
	check_spends!(fresh_htlc_claims[0], node_1_commit_tx[0], htlc_claims[0]);
	assert_eq!(fresh_htlc_claims[0].input.len(), 17);
	assert_eq!(fresh_htlc_claims[0].output.len(), 17);

	let log_entries = &nodes[1].logger.lines.lock().unwrap();
	let mut keys: Vec<_> = log_entries
		.keys()
		.filter(|key| key.1.contains("Batch transaction assigned to UTXO id"))
		.map(|key| key.1.split_whitespace().nth(6))
		.collect();
	assert_eq!(keys.len(), 3);
	keys.sort_unstable();
	// Assert that the fresh HTLC claim has the same `ClaimId` as the first chunk of the first HTLC claim.
	// Also assert that the second chunk in the first HTLC claim has a different `ClaimId` as the first chunk.
	assert!(keys[0] == keys[1] && keys[1] != keys[2] || keys[0] != keys[1] && keys[1] == keys[2]);
}
