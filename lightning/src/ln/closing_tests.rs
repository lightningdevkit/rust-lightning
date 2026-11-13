// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Tests of our closing_signed handling, including when the counterparty
//! deviates from the output set we proposed.

use crate::events::ClosureReason;
use crate::ln::functional_test_utils::*;
use crate::ln::msgs::{BaseMessageHandler, ChannelMessageHandler, MessageSendEvent};
use crate::sign::ecdsa::EcdsaChannelSigner;

#[test]
fn closing_signed_same_fee_alternate_output_set() {
	// If the counterparty responds to our closing_signed with a signature over the closing
	// transaction which omits its own output, at the same fee we quoted for the transaction
	// which includes it, we must not pair its signature with our cached signature over the
	// other output set. Instead, we re-sign the transaction the counterparty signed.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let node_0_id = nodes[0].node.get_our_node_id();
	let node_1_id = nodes[1].node.get_our_node_id();
	let (_, _, chan_id, funding_tx) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 20_000_000);

	nodes[0].node.close_channel(&chan_id, &node_1_id).unwrap();
	let shutdown = get_event_msg!(nodes[0], MessageSendEvent::SendShutdown, node_1_id);
	nodes[1].node.handle_shutdown(node_0_id, &shutdown);
	let shutdown = get_event_msg!(nodes[1], MessageSendEvent::SendShutdown, node_0_id);
	nodes[0].node.handle_shutdown(node_1_id, &shutdown);
	let mut closing_signed =
		get_event_msg!(nodes[0], MessageSendEvent::SendClosingSigned, node_1_id);

	let alternate_output_set_tx = {
		let per_peer_lock;
		let mut peer_state_lock;
		let chan = get_channel_ref!(nodes[0], nodes[1], per_peer_lock, peer_state_lock, chan_id)
			.as_funded()
			.unwrap();
		assert_eq!(
			chan.build_closing_transaction(closing_signed.fee_satoshis, false)
				.unwrap()
				.0
				.trust()
				.built_transaction()
				.output
				.len(),
			2,
		);
		chan.build_closing_transaction(closing_signed.fee_satoshis, true).unwrap().0
	};
	closing_signed.signature = {
		let per_peer_lock;
		let mut peer_state_lock;
		let chan = get_channel_ref!(nodes[1], nodes[0], per_peer_lock, peer_state_lock, chan_id)
			.as_funded()
			.unwrap();
		chan.get_signer()
			.as_ecdsa()
			.unwrap()
			.sign_closing_transaction(
				&chan.funding.channel_transaction_parameters,
				&alternate_output_set_tx,
				&nodes[1].node.secp_ctx,
			)
			.unwrap()
	};
	closing_signed.fee_range = None;
	nodes[0].node.handle_closing_signed(node_1_id, &closing_signed);

	let broadcasts = nodes[0].tx_broadcaster.txn_broadcast();
	assert_eq!(broadcasts.len(), 1);
	check_spends!(broadcasts[0], funding_tx);
	assert!(nodes[0].node.list_channels().is_empty());

	// We re-signed the transaction the counterparty signed, so it can complete the close too.
	let (_, response) = get_closing_signed_broadcast!(&nodes[0].node, node_1_id);
	assert!(response.is_some());
	check_closed_event(
		&nodes[0],
		1,
		ClosureReason::LocallyInitiatedCooperativeClosure,
		false,
		&[node_1_id],
		100_000,
	);
}
