//! Convenient utilities to create an invoice.
use {Currency, Invoice, InvoiceBuilder, SignOrCreationError, RawInvoice};
use bech32::ToBase32;
use bitcoin_hashes::Hash;
use lightning::chain;
use lightning::chain::chaininterface::{BroadcasterInterface, FeeEstimator};
use lightning::chain::keysinterface::{Sign, KeysInterface};
use lightning::ln::channelmanager::{ChannelManager, MIN_FINAL_CLTV_EXPIRY};
use lightning::routing::network_graph::RoutingFees;
use lightning::routing::router::RouteHintHop;
use lightning::util::logger::Logger;
use std::ops::Deref;

/// Utility to construct an invoice. Generally, unless you want to do something like a custom
/// cltv_expiry, this is what you should be using to create an invoice. The reason being, this
/// method stores the invoice's payment secret and preimage in `ChannelManager`, so (a) the user
/// doesn't have to store preimage/payment secret information and (b) `ChannelManager` can verify
/// that the payment secret is valid when the invoice is paid.
pub fn create_invoice_from_channelmanager<Signer: Sign, M: Deref, T: Deref, K: Deref, F: Deref, L: Deref>(
	channelmanager: &ChannelManager<Signer, M, T, K, F, L>, keys_manager: K, network: Currency,
	amt_msat: Option<u64>, description: String
) -> Result<Invoice, SignOrCreationError<()>>
where
	M::Target: chain::Watch<Signer>,
	T::Target: BroadcasterInterface,
	K::Target: KeysInterface<Signer = Signer>,
	F::Target: FeeEstimator,
	L::Target: Logger,
{
	// Marshall route hints.
	let our_channels = channelmanager.list_usable_channels();
	let mut route_hints = vec![];
	for channel in our_channels {
		let short_channel_id = match channel.short_channel_id {
			Some(id) => id,
			None => continue,
		};
		let forwarding_info = match channel.counterparty_forwarding_info {
			Some(info) => info,
			None => continue,
		};
		route_hints.push(vec![RouteHintHop {
			src_node_id: channel.remote_network_id,
			short_channel_id,
			fees: RoutingFees {
				base_msat: forwarding_info.fee_base_msat,
				proportional_millionths: forwarding_info.fee_proportional_millionths,
			},
			cltv_expiry_delta: forwarding_info.cltv_expiry_delta,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None,
		}]);
	}

	let (payment_hash, payment_secret) = channelmanager.create_inbound_payment(
		amt_msat,
		7200, // default invoice expiry is 2 hours
		0,
	);
	let our_node_pubkey = channelmanager.get_our_node_id();
	let mut invoice = InvoiceBuilder::new(network)
		.description(description)
		.current_timestamp()
		.payee_pub_key(our_node_pubkey)
		.payment_hash(Hash::from_slice(&payment_hash.0).unwrap())
		.payment_secret(payment_secret)
		.basic_mpp()
		.min_final_cltv_expiry(MIN_FINAL_CLTV_EXPIRY.into());
	if let Some(amt) = amt_msat {
		invoice = invoice.amount_pico_btc(amt * 10);
	}
	for hint in route_hints.drain(..) {
		invoice = invoice.route(hint);
	}

	let raw_invoice = match invoice.build_raw() {
		Ok(inv) => inv,
		Err(e) => return Err(SignOrCreationError::CreationError(e))
	};
	let hrp_str = raw_invoice.hrp.to_string();
	let hrp_bytes = hrp_str.as_bytes();
	let data_without_signature = raw_invoice.data.to_base32();
	let invoice_preimage = RawInvoice::construct_invoice_preimage(hrp_bytes, &data_without_signature);
	let signed_raw_invoice = raw_invoice.sign(|_| keys_manager.sign_invoice(invoice_preimage));
	match signed_raw_invoice {
		Ok(inv) => Ok(Invoice::from_signed(inv).unwrap()),
		Err(e) => Err(SignOrCreationError::SignError(e))
	}
}

#[cfg(test)]
mod test {
	use {Currency, Description, InvoiceDescription};
	use lightning::ln::PaymentHash;
	use lightning::ln::functional_test_utils::*;
	use lightning::ln::features::InitFeatures;
	use lightning::ln::msgs::ChannelMessageHandler;
	use lightning::routing::router;
	use lightning::util::events::MessageSendEventsProvider;
	use lightning::util::test_utils;
	#[test]
	fn test_from_channelmanager() {
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
		let _chan = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
		let invoice = ::utils::create_invoice_from_channelmanager(&nodes[1].node, nodes[1].keys_manager, Currency::BitcoinTestnet, Some(10_000), "test".to_string()).unwrap();
		assert_eq!(invoice.amount_pico_btc(), Some(100_000));
		assert_eq!(invoice.min_final_cltv_expiry(), 9);
		assert_eq!(invoice.description(), InvoiceDescription::Direct(&Description("test".to_string())));

		let mut route_hints = invoice.routes().clone();
		let mut last_hops = Vec::new();
		for hint in route_hints.drain(..) {
			last_hops.push(hint[hint.len() - 1].clone());
		}
		let amt_msat = invoice.amount_pico_btc().unwrap() / 10;

		let first_hops = nodes[0].node.list_usable_channels();
		let network_graph = nodes[0].net_graph_msg_handler.network_graph.read().unwrap();
		let logger = test_utils::TestLogger::new();
		let route = router::get_route(
			&nodes[0].node.get_our_node_id(),
			&network_graph,
			&invoice.recover_payee_pub_key(),
			Some(invoice.features().unwrap().clone()),
			Some(&first_hops.iter().collect::<Vec<_>>()),
			&last_hops.iter().collect::<Vec<_>>(),
			amt_msat,
			invoice.min_final_cltv_expiry() as u32,
			&logger,
		).unwrap();

		let payment_event = {
			let mut payment_hash = PaymentHash([0; 32]);
			payment_hash.0.copy_from_slice(&invoice.payment_hash().as_ref()[0..32]);
			nodes[0].node.send_payment(&route, payment_hash, &Some(invoice.payment_secret().unwrap().clone())).unwrap();
			let mut added_monitors = nodes[0].chain_monitor.added_monitors.lock().unwrap();
			assert_eq!(added_monitors.len(), 1);
			added_monitors.clear();

			let mut events = nodes[0].node.get_and_clear_pending_msg_events();
			assert_eq!(events.len(), 1);
			SendEvent::from_event(events.remove(0))

		};
		nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
		nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &payment_event.commitment_msg);
		let mut added_monitors = nodes[1].chain_monitor.added_monitors.lock().unwrap();
		assert_eq!(added_monitors.len(), 1);
		added_monitors.clear();
		let events = nodes[1].node.get_and_clear_pending_msg_events();
		assert_eq!(events.len(), 2);
	}
}
