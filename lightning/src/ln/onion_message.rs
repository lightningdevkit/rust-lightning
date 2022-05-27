// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Onion Messages: sending, receiving, forwarding, and ancillary utilities live here

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

#[allow(unused_assignments)]
#[inline]
fn construct_keys_callback<T: secp256k1::Signing + secp256k1::Verification, FType: FnMut(PublicKey, SharedSecret, [u8; 32], PublicKey, SharedSecret)> (secp_ctx: &Secp256k1<T>, unblinded_path: &Vec<PublicKey>, session_priv: &SecretKey, mut callback: FType) -> Result<(), secp256k1::Error> {}

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
