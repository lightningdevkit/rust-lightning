//! A simple crate which uses [`dnssec_prover`] to create DNSSEC Proofs in response to bLIP 32
//! Onion Message DNSSEC Proof Queries.

#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]

use std::net::SocketAddr;
use std::ops::Deref;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use dnssec_prover::query::build_txt_proof_async;

use lightning::blinded_path::message::DNSResolverContext;
use lightning::ln::peer_handler::IgnoringMessageHandler;
use lightning::onion_message::dns_resolution::{
	DNSResolverMessage, DNSResolverMessageHandler, DNSSECProof, DNSSECQuery,
};
use lightning::onion_message::messenger::{
	MessageSendInstructions, Responder, ResponseInstruction,
};

use lightning_types::features::NodeFeatures;

use tokio::runtime::Handle;

#[cfg(not(any(target_pointer_width = "32", target_pointer_width = "64")))]
const WE_REQUIRE_32_OR_64_BIT_USIZE: u8 = 424242;

/// A resolver which implements [`DNSResolverMessageHandler`] and replies to [`DNSSECQuery`]
/// messages with with [`DNSSECProof`]s.
pub struct OMDomainResolver<PH: Deref>
where
	PH::Target: DNSResolverMessageHandler,
{
	state: Arc<OMResolverState>,
	proof_handler: Option<PH>,
	runtime_handle: Mutex<Option<Handle>>,
}

const MAX_PENDING_RESPONSES: usize = 1024;
struct OMResolverState {
	resolver: SocketAddr,
	pending_replies: Mutex<Vec<(DNSResolverMessage, MessageSendInstructions)>>,
	pending_query_count: AtomicUsize,
}

impl OMDomainResolver<IgnoringMessageHandler> {
	/// Creates a new [`OMDomainResolver`] given the [`SocketAddr`] of a DNS resolver listening on
	/// TCP (e.g. 8.8.8.8:53, 1.1.1.1:53 or your local DNS resolver).
	///
	/// Ignores any incoming [`DNSSECProof`] messages.
	pub fn ignoring_incoming_proofs(resolver: SocketAddr) -> Self {
		Self::new(resolver, None)
	}
}

impl<PH: Deref> OMDomainResolver<PH>
where
	PH::Target: DNSResolverMessageHandler,
{
	/// Creates a new [`OMDomainResolver`] given the [`SocketAddr`] of a DNS resolver listening on
	/// TCP (e.g. 8.8.8.8:53, 1.1.1.1:53 or your local DNS resolver).
	///
	/// Uses `tokio`'s [`Handle::current`] to fetch the async runtime on which futures will be
	/// spawned.
	///
	/// The optional `proof_handler` can be provided to pass proofs coming back to us to the
	/// underlying handler. This is useful when this resolver is handling incoming resolution
	/// requests but some other handler is making proof requests of remote nodes and wants to get
	/// results.
	pub fn new(resolver: SocketAddr, proof_handler: Option<PH>) -> Self {
		Self::with_runtime(resolver, proof_handler, Some(Handle::current()))
	}

	/// Creates a new [`OMDomainResolver`] given the [`SocketAddr`] of a DNS resolver listening on
	/// TCP (e.g. 8.8.8.8:53, 1.1.1.1:53 or your local DNS resolver) and a `tokio` runtime
	/// [`Handle`] on which futures will be spawned. If no runtime is provided, `set_runtime` must
	/// be called before any queries will be handled.
	///
	/// The optional `proof_handler` can be provided to pass proofs coming back to us to the
	/// underlying handler. This is useful when this resolver is handling incoming resolution
	/// requests but some other handler is making proof requests of remote nodes and wants to get
	/// results.
	pub fn with_runtime(
		resolver: SocketAddr, proof_handler: Option<PH>, runtime_handle: Option<Handle>,
	) -> Self {
		Self {
			state: Arc::new(OMResolverState {
				resolver,
				pending_replies: Mutex::new(Vec::new()),
				pending_query_count: AtomicUsize::new(0),
			}),
			proof_handler,
			runtime_handle: Mutex::new(runtime_handle),
		}
	}

	/// Sets the runtime on which futures will be spawned.
	pub fn set_runtime(&self, runtime_handle: Handle) {
		*self.runtime_handle.lock().unwrap() = Some(runtime_handle);
	}
}

impl<PH: Deref> DNSResolverMessageHandler for OMDomainResolver<PH>
where
	PH::Target: DNSResolverMessageHandler,
{
	fn handle_dnssec_proof(&self, proof: DNSSECProof, context: DNSResolverContext) {
		if let Some(proof_handler) = &self.proof_handler {
			proof_handler.handle_dnssec_proof(proof, context);
		}
	}

	fn handle_dnssec_query(
		&self, q: DNSSECQuery, responder_opt: Option<Responder>,
	) -> Option<(DNSResolverMessage, ResponseInstruction)> {
		let responder = match responder_opt {
			Some(responder) => responder,
			None => return None,
		};
		let runtime = if let Some(runtime) = self.runtime_handle.lock().unwrap().clone() {
			runtime
		} else {
			return None;
		};
		if self.state.pending_query_count.fetch_add(1, Ordering::Relaxed) > MAX_PENDING_RESPONSES {
			self.state.pending_query_count.fetch_sub(1, Ordering::Relaxed);
			return None;
		}
		let us = Arc::clone(&self.state);
		runtime.spawn(async move {
			if let Ok((proof, _ttl)) = build_txt_proof_async(us.resolver, &q.0).await {
				let contents = DNSResolverMessage::DNSSECProof(DNSSECProof { name: q.0, proof });
				let instructions = responder.respond().into_instructions();
				us.pending_replies.lock().unwrap().push((contents, instructions));
				us.pending_query_count.fetch_sub(1, Ordering::Relaxed);
			}
		});
		None
	}

	fn provided_node_features(&self) -> NodeFeatures {
		let mut features = NodeFeatures::empty();
		features.set_dns_resolution_optional();
		features
	}

	fn release_pending_messages(&self) -> Vec<(DNSResolverMessage, MessageSendInstructions)> {
		core::mem::take(&mut *self.state.pending_replies.lock().unwrap())
	}
}

#[cfg(test)]
mod test {
	use super::*;

	use bitcoin::secp256k1::{self, PublicKey, Secp256k1};
	use bitcoin::Block;

	use lightning::blinded_path::message::{
		BlindedMessagePath, MessageContext, MessageForwardNode,
	};
	use lightning::blinded_path::NodeIdLookUp;
	use lightning::events::{Event, PaymentPurpose};
	use lightning::ln::channelmanager::{PaymentId, Retry};
	use lightning::ln::functional_test_utils::*;
	use lightning::ln::msgs::{
		BaseMessageHandler, ChannelMessageHandler, Init, OnionMessageHandler,
	};
	use lightning::ln::peer_handler::IgnoringMessageHandler;
	use lightning::offers::offer::Offer;
	use lightning::onion_message::dns_resolution::{HumanReadableName, OMNameResolver};
	use lightning::onion_message::messenger::{
		AOnionMessenger, Destination, MessageRouter, OnionMessagePath, OnionMessenger,
	};
	use lightning::routing::router::RouteParametersConfig;
	use lightning::sign::{KeysManager, NodeSigner, ReceiveAuthKey, Recipient};
	use lightning::types::features::InitFeatures;
	use lightning::types::payment::PaymentHash;
	use lightning::util::logger::{Logger, Span};

	use lightning::{commitment_signed_dance, expect_payment_claimed, get_htlc_update_msgs};
	use lightning_types::string::UntrustedString;

	use std::ops::Deref;
	use std::sync::Mutex;
	use std::time::{Duration, Instant, SystemTime};

	struct TestLogger {
		node: &'static str,
	}
	impl Logger for TestLogger {
		type UserSpan = ();

		fn log(&self, record: lightning::util::logger::Record) {
			eprintln!("{}: {}", self.node, record.args);
		}

		fn start(&self, _span: Span, _parent: Option<&()>) -> () {}
	}
	impl Deref for TestLogger {
		type Target = TestLogger;
		fn deref(&self) -> &TestLogger {
			self
		}
	}

	struct DummyNodeLookup {}
	impl NodeIdLookUp for DummyNodeLookup {
		fn next_node_id(&self, _: u64) -> Option<PublicKey> {
			None
		}
	}
	impl Deref for DummyNodeLookup {
		type Target = DummyNodeLookup;
		fn deref(&self) -> &DummyNodeLookup {
			self
		}
	}

	struct DirectlyConnectedRouter {}
	impl MessageRouter for DirectlyConnectedRouter {
		fn find_path(
			&self, _sender: PublicKey, _peers: Vec<PublicKey>, destination: Destination,
		) -> Result<OnionMessagePath, ()> {
			Ok(OnionMessagePath {
				destination,
				first_node_addresses: None,
				intermediate_nodes: Vec::new(),
			})
		}

		fn create_blinded_paths<T: secp256k1::Signing + secp256k1::Verification>(
			&self, recipient: PublicKey, local_node_receive_key: ReceiveAuthKey,
			context: MessageContext, _peers: Vec<MessageForwardNode>, secp_ctx: &Secp256k1<T>,
		) -> Result<Vec<BlindedMessagePath>, ()> {
			let keys = KeysManager::new(&[0; 32], 42, 43);
			Ok(vec![BlindedMessagePath::one_hop(
				recipient,
				local_node_receive_key,
				context,
				&keys,
				secp_ctx,
			)
			.unwrap()])
		}
	}
	impl Deref for DirectlyConnectedRouter {
		type Target = DirectlyConnectedRouter;
		fn deref(&self) -> &DirectlyConnectedRouter {
			self
		}
	}

	struct URIResolver {
		resolved_uri: Mutex<Option<(HumanReadableName, PaymentId, String)>>,
		resolver: OMNameResolver,
		pending_messages: Mutex<Vec<(DNSResolverMessage, MessageSendInstructions)>>,
	}
	impl DNSResolverMessageHandler for URIResolver {
		fn handle_dnssec_query(
			&self, _: DNSSECQuery, _: Option<Responder>,
		) -> Option<(DNSResolverMessage, ResponseInstruction)> {
			panic!();
		}

		fn handle_dnssec_proof(&self, msg: DNSSECProof, context: DNSResolverContext) {
			let mut proof = self.resolver.handle_dnssec_proof_for_uri(msg, context).unwrap();
			assert_eq!(proof.0.len(), 1);
			let payment = proof.0.pop().unwrap();
			let mut result = Some((payment.0, payment.1, proof.1));
			core::mem::swap(&mut *self.resolved_uri.lock().unwrap(), &mut result);
			assert!(result.is_none());
		}
		fn release_pending_messages(&self) -> Vec<(DNSResolverMessage, MessageSendInstructions)> {
			core::mem::take(&mut *self.pending_messages.lock().unwrap())
		}
	}

	fn create_resolver() -> (impl AOnionMessenger, PublicKey) {
		let resolver_keys = Arc::new(KeysManager::new(&[99; 32], 42, 43));
		let resolver_logger = TestLogger { node: "resolver" };
		let resolver = OMDomainResolver::ignoring_incoming_proofs("8.8.8.8:53".parse().unwrap());
		let resolver = Arc::new(resolver);
		(
			OnionMessenger::new(
				Arc::clone(&resolver_keys),
				Arc::clone(&resolver_keys),
				resolver_logger,
				DummyNodeLookup {},
				DirectlyConnectedRouter {},
				IgnoringMessageHandler {},
				IgnoringMessageHandler {},
				Arc::clone(&resolver),
				IgnoringMessageHandler {},
			),
			resolver_keys.get_node_id(Recipient::Node).unwrap(),
		)
	}

	fn get_om_init() -> Init {
		let mut init_msg =
			Init { features: InitFeatures::empty(), networks: None, remote_network_address: None };
		init_msg.features.set_onion_messages_optional();
		init_msg
	}

	#[tokio::test]
	async fn resolution_test() {
		let secp_ctx = Secp256k1::new();

		let (resolver_messenger, resolver_id) = create_resolver();

		let resolver_dest = Destination::Node(resolver_id);
		let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();

		let payment_id = PaymentId([42; 32]);
		let name = HumanReadableName::from_encoded("matt@mattcorallo.com").unwrap();

		let payer_keys = Arc::new(KeysManager::new(&[2; 32], 42, 43));
		let payer_logger = TestLogger { node: "payer" };
		let payer_id = payer_keys.get_node_id(Recipient::Node).unwrap();
		let payer = Arc::new(URIResolver {
			resolved_uri: Mutex::new(None),
			resolver: OMNameResolver::new(now as u32, 1),
			pending_messages: Mutex::new(Vec::new()),
		});
		let payer_messenger = Arc::new(OnionMessenger::new(
			Arc::clone(&payer_keys),
			Arc::clone(&payer_keys),
			payer_logger,
			DummyNodeLookup {},
			DirectlyConnectedRouter {},
			IgnoringMessageHandler {},
			IgnoringMessageHandler {},
			Arc::clone(&payer),
			IgnoringMessageHandler {},
		));

		let init_msg = get_om_init();
		payer_messenger.peer_connected(resolver_id, &init_msg, true).unwrap();
		resolver_messenger.get_om().peer_connected(payer_id, &init_msg, false).unwrap();

		let (msg, context) =
			payer.resolver.resolve_name(payment_id, name.clone(), &*payer_keys).unwrap();
		let query_context = MessageContext::DNSResolver(context);
		let receive_key = payer_keys.get_receive_auth_key();
		let reply_path = BlindedMessagePath::one_hop(
			payer_id,
			receive_key,
			query_context,
			&*payer_keys,
			&secp_ctx,
		)
		.unwrap();
		payer.pending_messages.lock().unwrap().push((
			DNSResolverMessage::DNSSECQuery(msg),
			MessageSendInstructions::WithSpecifiedReplyPath {
				destination: resolver_dest,
				reply_path,
			},
		));

		let query = payer_messenger.next_onion_message_for_peer(resolver_id).unwrap();
		resolver_messenger.get_om().handle_onion_message(payer_id, &query);

		assert!(resolver_messenger.get_om().next_onion_message_for_peer(payer_id).is_none());
		let start = Instant::now();
		let response = loop {
			tokio::time::sleep(Duration::from_millis(10)).await;
			if let Some(msg) = resolver_messenger.get_om().next_onion_message_for_peer(payer_id) {
				break msg;
			}
			assert!(start.elapsed() < Duration::from_secs(10), "Resolution took too long");
		};

		payer_messenger.handle_onion_message(resolver_id, &response);
		let resolution = payer.resolved_uri.lock().unwrap().take().unwrap();
		assert_eq!(resolution.0, name);
		assert_eq!(resolution.1, payment_id);
		assert!(resolution.2[.."bitcoin:".len()].eq_ignore_ascii_case("bitcoin:"));
	}

	async fn pay_offer_flow<'a, 'b, 'c>(
		nodes: &[Node<'a, 'b, 'c>], resolver_messenger: &impl AOnionMessenger,
		resolver_id: PublicKey, payer_id: PublicKey, payee_id: PublicKey, offer: Offer,
		name: HumanReadableName, amt: u64, payment_id: PaymentId, payer_note: Option<String>,
		retry: Retry, params: RouteParametersConfig, resolvers: Vec<Destination>,
	) {
		// Override contents to offer provided
		let proof_override = &nodes[0].node.testing_dnssec_proof_offer_resolution_override;
		proof_override.lock().unwrap().insert(name.clone(), offer);
		nodes[0]
			.node
			.pay_for_offer_from_human_readable_name(
				name,
				amt,
				payment_id,
				payer_note.clone(),
				retry,
				params,
				resolvers,
			)
			.unwrap();

		let query = nodes[0].onion_messenger.next_onion_message_for_peer(resolver_id).unwrap();
		resolver_messenger.get_om().handle_onion_message(payer_id, &query);

		assert!(resolver_messenger.get_om().next_onion_message_for_peer(payer_id).is_none());
		let start = Instant::now();
		let response = loop {
			tokio::time::sleep(Duration::from_millis(10)).await;
			if let Some(msg) = resolver_messenger.get_om().next_onion_message_for_peer(payer_id) {
				break msg;
			}
			assert!(start.elapsed() < Duration::from_secs(10), "Resolution took too long");
		};

		nodes[0].onion_messenger.handle_onion_message(resolver_id, &response);

		let invreq = nodes[0].onion_messenger.next_onion_message_for_peer(payee_id).unwrap();
		nodes[1].onion_messenger.handle_onion_message(payer_id, &invreq);

		let inv = nodes[1].onion_messenger.next_onion_message_for_peer(payer_id).unwrap();
		nodes[0].onion_messenger.handle_onion_message(payee_id, &inv);

		check_added_monitors(&nodes[0], 1);
		let updates = get_htlc_update_msgs!(nodes[0], payee_id);
		nodes[1].node.handle_update_add_htlc(payer_id, &updates.update_add_htlcs[0]);
		commitment_signed_dance!(nodes[1], nodes[0], updates.commitment_signed, false);
		expect_and_process_pending_htlcs(&nodes[1], false);

		let claimable_events = nodes[1].node.get_and_clear_pending_events();
		assert_eq!(claimable_events.len(), 1);
		let our_payment_preimage;
		if let Event::PaymentClaimable { purpose, amount_msat, .. } = &claimable_events[0] {
			assert_eq!(*amount_msat, amt);
			if let PaymentPurpose::Bolt12OfferPayment {
				payment_preimage, payment_context, ..
			} = purpose
			{
				our_payment_preimage = payment_preimage.unwrap();
				nodes[1].node.claim_funds(our_payment_preimage);
				let payment_hash: PaymentHash = our_payment_preimage.into();
				expect_payment_claimed!(nodes[1], payment_hash, amt);
				if let Some(note) = payer_note {
					assert_eq!(
						payment_context.invoice_request.payer_note_truncated,
						Some(UntrustedString(note.into()))
					);
				} else {
					assert_eq!(payment_context.invoice_request.payer_note_truncated, None);
				}
			} else {
				panic!();
			}
		} else {
			panic!();
		}

		check_added_monitors(&nodes[1], 1);
		let mut updates = get_htlc_update_msgs!(nodes[1], payer_id);
		nodes[0].node.handle_update_fulfill_htlc(payee_id, updates.update_fulfill_htlcs.remove(0));
		commitment_signed_dance!(nodes[0], nodes[1], updates.commitment_signed, false);

		expect_payment_sent(&nodes[0], our_payment_preimage, None, true, true);
	}

	#[tokio::test]
	async fn end_to_end_test() {
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs_with_node_id_message_router(2, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

		create_announced_chan_between_nodes(&nodes, 0, 1);

		// The DNSSEC validation will only work with the current time, so set the time on the
		// resolver.
		let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
		let block = Block {
			header: create_dummy_header(nodes[0].best_block_hash(), now as u32),
			txdata: Vec::new(),
		};
		connect_block(&nodes[0], &block);
		connect_block(&nodes[1], &block);

		let payer_id = nodes[0].node.get_our_node_id();
		let payee_id = nodes[1].node.get_our_node_id();

		let (resolver_messenger, resolver_id) = create_resolver();
		let init_msg = get_om_init();
		nodes[0].onion_messenger.peer_connected(resolver_id, &init_msg, true).unwrap();
		resolver_messenger.get_om().peer_connected(payer_id, &init_msg, false).unwrap();

		let name = HumanReadableName::from_encoded("matt@mattcorallo.com").unwrap();

		let bs_offer = nodes[1].node.create_offer_builder().unwrap().build().unwrap();
		let resolvers = vec![Destination::Node(resolver_id)];
		let retry = Retry::Attempts(0);
		let amt = 42_000;
		let params = RouteParametersConfig::default();

		pay_offer_flow(
			&nodes,
			&resolver_messenger,
			resolver_id,
			payer_id,
			payee_id,
			bs_offer.clone(),
			name.clone(),
			amt,
			PaymentId([42; 32]),
			None,
			retry,
			params,
			resolvers.clone(),
		)
		.await;

		// Pay offer with payer_note
		pay_offer_flow(
			&nodes,
			&resolver_messenger,
			resolver_id,
			payer_id,
			payee_id,
			bs_offer,
			name,
			amt,
			PaymentId([21; 32]),
			Some("foo".into()),
			retry,
			params,
			resolvers,
		)
		.await;
	}
}
