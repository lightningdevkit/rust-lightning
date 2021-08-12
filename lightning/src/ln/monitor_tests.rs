// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Further functional tests which test blockchain reorganizations.

use chain::channelmonitor::ANTI_REORG_DELAY;
use ln::{PaymentPreimage, PaymentHash};
use ln::features::InitFeatures;
use ln::msgs::{ChannelMessageHandler, ErrorAction};
use util::events::{Event, MessageSendEvent, MessageSendEventsProvider};
use routing::network_graph::NetworkUpdate;
use routing::router::get_route;

use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;

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
