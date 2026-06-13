// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use crate::ln::functional_test_utils::*;
use crate::ln::outbound_payment::ProbeSendFailure;
use crate::types::payment::PaymentHash;

#[test]
fn send_probe_to_node_happy_path() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes(&nodes, 0, 1);
	create_announced_chan_between_nodes(&nodes, 1, 2);

	let res =
		nodes[0].node.send_probe_to_node(nodes[2].node.get_our_node_id(), 50_000, 40).unwrap();
	assert!(nodes[0].node.payment_is_probe(&res.0, &res.1));

	let expected_route: &[(&[&Node], PaymentHash)] = &[(&[&nodes[1], &nodes[2]], res.0)];

	send_probe_along_route(&nodes[0], expected_route);

	expect_probe_successful_events(&nodes[0], vec![res]);

	assert!(!nodes[0].node.has_pending_payments());
}

#[test]
fn send_probe_to_node_single_hop_fails() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes(&nodes, 0, 1);

	assert!(matches!(
		nodes[0].node.send_probe_to_node(nodes[1].node.get_our_node_id(), 50_000, 40),
		Err(ProbeSendFailure::RouteNotFound)
	));
}
