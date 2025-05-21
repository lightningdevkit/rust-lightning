// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Tests which test upgrading from previous versions of LDK or downgrading to previous versions of
//! LDK.

use lightning_0_1::get_monitor as get_monitor_0_1;
use lightning_0_1::ln::functional_test_utils as lightning_0_1_utils;
use lightning_0_1::util::ser::Writeable;

use lightning::ln::functional_test_utils::*;

use lightning_types::payment::PaymentPreimage;

#[test]
fn simple_upgrade() {
	// Tests a simple case of upgrading from LDK 0.1 with a pending payment
	let (node_a_ser, node_b_ser, mon_a_ser, mon_b_ser, preimage);
	{
		let chanmon_cfgs = lightning_0_1_utils::create_chanmon_cfgs(2);
		let node_cfgs = lightning_0_1_utils::create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = lightning_0_1_utils::create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = lightning_0_1_utils::create_network(2, &node_cfgs, &node_chanmgrs);

		let chan_id = lightning_0_1_utils::create_announced_chan_between_nodes(&nodes, 0, 1).2;

		let payment_preimage =
			lightning_0_1_utils::route_payment(&nodes[0], &[&nodes[1]], 1_000_000);
		preimage = PaymentPreimage(payment_preimage.0 .0);

		node_a_ser = nodes[0].node.encode();
		node_b_ser = nodes[1].node.encode();
		mon_a_ser = get_monitor_0_1!(nodes[0], chan_id).encode();
		mon_b_ser = get_monitor_0_1!(nodes[1], chan_id).encode();
	}

	// Create a dummy node to reload over with the 0.1 state

	let mut chanmon_cfgs = create_chanmon_cfgs(2);

	// Our TestChannelSigner will fail as we're jumping ahead, so disable its state-based checks
	chanmon_cfgs[0].keys_manager.disable_all_state_policy_checks = true;
	chanmon_cfgs[1].keys_manager.disable_all_state_policy_checks = true;

	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let (persister_a, persister_b, chain_mon_a, chain_mon_b);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let (node_a, node_b);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let config = test_default_channel_config();
	let a_mons = &[&mon_a_ser[..]];
	reload_node!(nodes[0], config.clone(), &node_a_ser, a_mons, persister_a, chain_mon_a, node_a);
	reload_node!(nodes[1], config, &node_b_ser, &[&mon_b_ser], persister_b, chain_mon_b, node_b);

	reconnect_nodes(ReconnectArgs::new(&nodes[0], &nodes[1]));

	claim_payment(&nodes[0], &[&nodes[1]], preimage);
}
