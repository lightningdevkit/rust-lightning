use crate::ln::chan_utils::shared_anchor_script_pubkey;
use crate::ln::functional_test_utils::*;

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
			assert_eq!(txn[0].output.iter().find(|output| output.script_pubkey == shared_anchor_script_pubkey()).unwrap().value.to_sat(), $expected_p2a_value_sat);
			let txn = get_local_commitment_txn!(nodes[1], chan_id);
			assert_eq!(txn.len(), 1);
			assert_eq!(txn[0].output.iter().find(|output| output.script_pubkey == shared_anchor_script_pubkey()).unwrap().value.to_sat(), $expected_p2a_value_sat);
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
