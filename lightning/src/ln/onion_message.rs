// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Onion Messages: sending, receiving, forwarding, and ancillary utilities live here

pub(crate) const SMALL_PACKET_HOP_DATA_LEN: usize = 1300;
pub(crate) const BIG_PACKET_HOP_DATA_LEN: usize = 32768;

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Packet {
	pub(crate) version: u8,
	/// We don't want to disconnect a peer just because they provide a bogus public key, so we hold a
	/// Result instead of a PublicKey as we'd like.
	pub(crate) public_key: Result<PublicKey, secp256k1::Error>,
	// Unlike the onion packets used for payments, onion message packets can have payloads greater than 1300 bytes.
	pub(crate) hop_data: Vec<u8>,
	pub(crate) hmac: [u8; 32],
}

impl Packet {
	fn len(&self) -> u16 {
		// 32 (hmac) + 33 (public_key) + 1 (version) = 66
		self.hop_data.len() as u16 + 66
	}
}

impl Writeable for Packet {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {}
}

impl ReadableArgs<u16> for Packet {
	fn read<R: Read>(r: &mut R, len: u16) -> Result<Self, DecodeError> {}
}

/// The payload of an onion message.
pub(crate) struct Payload {
	/// Onion message payloads contain an encrypted TLV stream, containing both "control" TLVs and
	/// sometimes user-provided custom "data" TLVs. See [`EncryptedTlvs`] for more information.
	encrypted_tlvs: EncryptedTlvs,
	// Coming soon:
	// * custom TLVs
	// * `message: Message` field
	// * `reply_path: Option<BlindedRoute>` field
}

// Coming soon:
// enum Message {
// 	InvoiceRequest(InvoiceRequest),
// 	Invoice(Invoice),
//	InvoiceError(InvoiceError),
//	CustomMessage<T>,
// }

/// We want to avoid encoding and encrypting separately in order to avoid an intermediate Vec, thus
/// we encode and encrypt at the same time using the `SharedSecret` here.
impl Writeable for (Payload, SharedSecret) {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
	}
}

/// Reads of `Payload`s are parameterized by the `rho` of a `SharedSecret`, which is used to decrypt
/// the onion message payload's `encrypted_data` field.
impl ReadableArgs<SharedSecret> for Payload {
	fn read<R: Read>(mut r: &mut R, encrypted_tlvs_ss: SharedSecret) -> Result<Self, DecodeError> {
	}
}

/// Onion messages contain an encrypted TLV stream. This can be supplied by someone else, in the
/// case that we're sending to a blinded route, or created by us if we're constructing payloads for
/// unblinded hops in the onion message's path.
pub(crate) enum EncryptedTlvs {
	/// If we're sending to a blinded route, the node that constructed the blinded route has provided
	/// our onion message's `EncryptedTlvs`, already encrypted and encoded into bytes.
	Blinded(Vec<u8>),
	/// If we're receiving an onion message or constructing an onion message to send through any
	/// unblinded nodes, we'll need to construct the onion message's `EncryptedTlvs` in their
	/// unblinded state to avoid encoding them into an intermediate `Vec`.
	// Below will later have an additional Vec<CustomTlv>
	Unblinded(ControlTlvs),
}

/// Onion messages have "control" TLVs and "data" TLVs. Control TLVs are used to control the
/// direction and routing of an onion message from hop to hop, whereas data TLVs contain the onion
/// message content itself.
pub(crate) enum ControlTlvs {
	/// Control TLVs for the final recipient of an onion message.
	Receive {
		/// If `path_id` is `Some`, it is used to identify the blinded route that this onion message is
		/// sending to. This is useful for receivers to check that said blinded route is being used in
		/// the right context.
		path_id: Option<[u8; 32]>
	},
	/// Control TLVs for an intermediate forwarder of an onion message.
	Forward {
		/// The node id of the next hop in the onion message's path.
		next_node_id: PublicKey,
		/// Senders of onion messages have the option of specifying an overriding [`blinding_point`]
		/// for forwarding nodes along the path. If this field is absent, forwarding nodes will
		/// calculate the next hop's blinding point by multiplying the blinding point that they
		/// received by a blinding factor.
		///
		/// [`blinding_point`]: crate::ln::msgs::OnionMessage::blinding_point
		next_blinding_override: Option<PublicKey>,
	}
}

impl Writeable for ControlTlvs {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {}
}

impl Readable for ControlTlvs {
	fn read<R: Read>(mut r: &mut R) -> Result<Self, DecodeError> {}
}

/// Used to construct the blinded hops portion of a blinded route. These hops cannot be identified
/// by outside observers and thus can be used to hide the identity of the recipient.
pub struct BlindedNode {
	/// The blinded node id of this hop in a blinded route.
	pub blinded_node_id: PublicKey,
	/// The encrypted payload intended for this hop in a blinded route.
	// If we're sending to this blinded route, this payload will later be encoded into the
	// [`EncryptedTlvs`] for the hop when constructing the onion packet for sending.
	//
	// [`EncryptedTlvs`]: EncryptedTlvs
	pub encrypted_payload: Vec<u8>,
}

/// Onion messages can be sent and received to blinded routes, which serve to hide the identity of
/// the recipient.
pub struct BlindedRoute {
	/// To send to a blinded route, the sender first finds a route to the unblinded
	/// `introduction_node_id`, which can unblind its [`encrypted_payload`] to find out the onion
	/// message's next hop and forward it along.
	///
	/// [`encrypted_payload`]: BlindedNode::encrypted_payload
	pub introduction_node_id: PublicKey,
	/// Creators of blinded routes supply the introduction node id's `blinding_point`, which the
	/// introduction node will use in decrypting its [`encrypted_payload`] to forward the onion
	/// message.
	///
	/// [`encrypted_payload`]: BlindedNode::encrypted_payload
	pub blinding_point: PublicKey,
	/// The blinded hops of the blinded route.
	pub blinded_hops: Vec<BlindedNode>,
}

impl BlindedRoute {
	/// Create a blinded route to be forwarded along `hops`. The last node pubkey in `node_pks` will
	/// be the destination node.
	pub fn new<Signer: Sign, K: Deref>(node_pks: Vec<PublicKey>, keys_manager: &K) -> Result<Self, ()>
		where K::Target: KeysInterface<Signer = Signer>,
	{
		// calls Self::encrypt_payload
	}

	fn encrypt_payload(payload: ControlTlvs, encrypted_tlvs_ss: SharedSecret) -> Vec<u8> {}
}

/// The destination of an onion message.
pub enum Destination {
	/// We're sending this onion message to a node.
	Node(PublicKey),
	/// We're sending this onion message to a blinded route.
	BlindedRoute(BlindedRoute),
}

impl Destination {
	fn num_hops(&self) -> usize {
}

/// A sender, receiver and forwarder of onion messages. In upcoming releases, this object will be
/// used to retrieve invoices and fulfill invoice requests from offers.
pub struct OnionMessenger<Signer: Sign, K: Deref, L: Deref>
	where K::Target: KeysInterface<Signer = Signer>,
				L::Target: Logger,
{
	keys_manager: K,
	logger: L,
	pending_msg_events: Mutex<Vec<MessageSendEvent>>,
	secp_ctx: Secp256k1<secp256k1::All>,
	// Coming soon:
	// invoice_handler: InvoiceHandler,
	// custom_handler: CustomHandler, // handles custom onion messages
}

impl<Signer: Sign, K: Deref, L: Deref> OnionMessenger<Signer, K, L>
	where K::Target: KeysInterface<Signer = Signer>,
				L::Target: Logger,
{
	/// Constructs a new `OnionMessenger` to send, forward, and delegate received onion messages to
	/// their respective handlers.
	pub fn new(keys_manager: K, logger: L) -> Self {
		let mut secp_ctx = Secp256k1::new();
		secp_ctx.seeded_randomize(&keys_manager.get_secure_random_bytes());
		OnionMessenger {
			keys_manager,
			pending_msg_events: Mutex::new(Vec::new()),
			secp_ctx,
			logger,
		}
	}

	/// Send an empty onion message to `destination`, routing it through `intermediate_nodes`.
	pub fn send_onion_message(&self, intermediate_nodes: Vec<PublicKey>, destination: Destination) -> Result<(), secp256k1::Error> {
	}
}

impl<Signer: Sign, K: Deref, L: Deref> OnionMessageHandler for OnionMessenger<Signer, K, L>
	where K::Target: KeysInterface<Signer = Signer>,
				L::Target: Logger,
{
	fn handle_onion_message(&self, _peer_node_id: &PublicKey, msg: &msgs::OnionMessage) {}
}

impl<Signer: Sign, K: Deref, L: Deref> MessageSendEventsProvider for OnionMessenger<Signer, K, L>
	where K::Target: KeysInterface<Signer = Signer>,
				L::Target: Logger,
{
	fn get_and_clear_pending_msg_events(&self) -> Vec<MessageSendEvent> {
	}
}

/// Build an onion message's payloads for encoding in the onion packet.
fn build_payloads(intermediate_nodes: Vec<PublicKey>, destination: Destination, mut encrypted_tlvs_keys: Vec<SharedSecret>) -> Vec<(Payload, SharedSecret)> {
}

#[allow(unused_assignments)]
#[inline]
fn construct_keys_callback<T: secp256k1::Signing + secp256k1::Verification, FType: FnMut(PublicKey, SharedSecret, [u8; 32], PublicKey, SharedSecret)> (secp_ctx: &Secp256k1<T>, unblinded_path: &Vec<PublicKey>, destination: Option<&Destination>, session_priv: &SecretKey, mut callback: FType) -> Result<(), secp256k1::Error> {}

/// Construct keys for constructing a blinded route along the given `unblinded_path`.
///
/// Returns: `(encrypted_tlvs_keys, blinded_node_ids)`
/// where the encrypted tlvs keys are used to encrypt the blinded route's blinded payloads and the
/// blinded node ids are used to set the [`blinded_node_id`]s of the [`BlindedRoute`].
fn construct_blinded_route_keys<T: secp256k1::Signing + secp256k1::Verification>(
	secp_ctx: &Secp256k1<T>, unblinded_path: &Vec<PublicKey>, session_priv: &SecretKey
) -> Result<(Vec<SharedSecret>, Vec<PublicKey>), secp256k1::Error> {
	// calls construct_keys_callback
}

/// Construct keys for sending an onion message along the given `path`.
///
/// Returns: `(encrypted_tlvs_keys, onion_packet_keys)`
/// where the encrypted tlvs keys are used to encrypt the [`EncryptedTlvs`] of the onion message and the
/// onion packet keys are used to encrypt the onion packet.
fn construct_sending_keys<T: secp256k1::Signing + secp256k1::Verification>(
	secp_ctx: &Secp256k1<T>, unblinded_path: &Vec<PublicKey>, destination: &Destination, session_priv: &SecretKey
) -> Result<(Vec<SharedSecret>, Vec<onion_utils::OnionKeys>), secp256k1::Error> {
	// calls construct_keys_callback
}

/// Useful for simplifying the parameters of [`SimpleArcChannelManager`] and
/// [`SimpleArcPeerManager`]. See their docs for more details.
pub type SimpleArcOnionMessenger<L> = OnionMessenger<InMemorySigner, Arc<KeysManager>, Arc<L>>;
/// Useful for simplifying the parameters of [`SimpleRefChannelManager`] and
/// [`SimpleRefPeerManager`]. See their docs for more details.
pub type SimpleRefOnionMessenger<'a, 'b, L> = OnionMessenger<InMemorySigner, &'a KeysManager, &'b L>;
