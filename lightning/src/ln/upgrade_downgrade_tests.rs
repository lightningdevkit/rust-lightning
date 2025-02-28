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

use crate::ln::functional_test_utils::*;
use crate::types::payment::PaymentPreimage;
use crate::util::ser::Writeable;

#[test]
fn simple_upgrade() {
	let (persister, chain_monitor);
	let nodes_0_deserialized;


	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	let chan_id = create_announced_chan_between_nodes(&nodes, 0, 1).2;

	let payment_preimage = route_payment(&nodes[0], &[&nodes[1]], 1_000_000);
	let preimage = PaymentPreimage(payment_preimage.0.0);

	let node_a = nodes[0].node.encode();
	let mon_a = get_monitor!(nodes[0], chan_id).encode();

	reload_node!(nodes[0], test_default_channel_config(), &node_a, &[&mon_a], persister, chain_monitor, nodes_0_deserialized);

	reconnect_nodes(ReconnectArgs::new(&nodes[0], &nodes[1]));

	claim_payment(&nodes[0], &[&nodes[1]], preimage);
}
