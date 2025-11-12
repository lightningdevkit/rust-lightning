use crate::ln::channelmanager::{PaymentId, RecipientOnionFields, Retry};
use crate::ln::functional_test_utils::*;
use crate::ln::msgs::{accountable_from_bool, ChannelMessageHandler, ExperimentalAccountable};
use crate::routing::router::{PaymentParameters, RouteParameters};

fn test_accountable_forwarding_with_override(
	override_accountable: ExperimentalAccountable, expected_forwarded: ExperimentalAccountable,
) {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let _chan_ab = create_announced_chan_between_nodes(&nodes, 0, 1);
	let _chan_bc = create_announced_chan_between_nodes(&nodes, 1, 2);

	let (payment_preimage, payment_hash, payment_secret) = get_payment_preimage_hash!(nodes[2]);
	let route_params = RouteParameters::from_payment_params_and_value(
		PaymentParameters::from_node_id(nodes[2].node.get_our_node_id(), TEST_FINAL_CLTV),
		100_000,
	);
	let onion_fields = RecipientOnionFields::secret_only(payment_secret);
	let payment_id = PaymentId(payment_hash.0);
	nodes[0]
		.node
		.send_payment(payment_hash, onion_fields, payment_id, route_params, Retry::Attempts(0))
		.unwrap();
	check_added_monitors(&nodes[0], 1);

	let updates_ab = get_htlc_update_msgs(&nodes[0], &nodes[1].node.get_our_node_id());
	assert_eq!(updates_ab.update_add_htlcs.len(), 1);
	let mut htlc_ab = updates_ab.update_add_htlcs[0].clone();
	assert_eq!(htlc_ab.accountable, accountable_from_bool(false));

	// Override accountable value if requested
	if let Some(override_value) = override_accountable {
		htlc_ab.accountable = Some(override_value);
	}

	nodes[1].node.handle_update_add_htlc(nodes[0].node.get_our_node_id(), &htlc_ab);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &updates_ab.commitment_signed, false, false);
	expect_and_process_pending_htlcs(&nodes[1], false);
	check_added_monitors(&nodes[1], 1);

	let updates_bc = get_htlc_update_msgs(&nodes[1], &nodes[2].node.get_our_node_id());
	assert_eq!(updates_bc.update_add_htlcs.len(), 1);
	let htlc_bc = &updates_bc.update_add_htlcs[0];
	assert_eq!(
		htlc_bc.accountable, expected_forwarded,
		"B -> C should have accountable = {:?}",
		expected_forwarded
	);

	nodes[2].node.handle_update_add_htlc(nodes[1].node.get_our_node_id(), htlc_bc);
	do_commitment_signed_dance(&nodes[2], &nodes[1], &updates_bc.commitment_signed, false, false);
	expect_and_process_pending_htlcs(&nodes[2], false);
	check_added_monitors(&nodes[2], 0);
	expect_payment_claimable!(nodes[2], payment_hash, payment_secret, 100_000);
	claim_payment(&nodes[0], &[&nodes[1], &nodes[2]], payment_preimage);
}

#[test]
fn test_accountable_signal() {
	// Tests forwarding of accountable signal for various incoming signal values.
	test_accountable_forwarding_with_override(None, accountable_from_bool(false));
	test_accountable_forwarding_with_override(Some(7), accountable_from_bool(true));
	test_accountable_forwarding_with_override(Some(3), accountable_from_bool(false));
}
