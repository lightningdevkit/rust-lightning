/// Helper macros that construct fake Messages. Useful in tests that don't care about the contents.

macro_rules! fake_public_key {
	() => {{
		let their_node_secret = SecretKey::from_slice(&[0x_11_u8; 32]).unwrap();
		PublicKey::from_secret_key(&Secp256k1::new(), &their_node_secret)
	}}
}

macro_rules! fake_valid_sig {
	() => {{
		use bitcoin::secp256k1::ffi::Signature as FFISignature;
		Signature::from(FFISignature::new())
	}}
}

macro_rules! fake_open_channel_msg {
	() => {{
		OpenChannel {
			chain_hash: Default::default(),
			temporary_channel_id: [0; 32],
			funding_satoshis: 0,
			push_msat: 0,
			dust_limit_satoshis: 0,
			max_htlc_value_in_flight_msat: 0,
			channel_reserve_satoshis: 0,
			htlc_minimum_msat: 0,
			feerate_per_kw: 0,
			to_self_delay: 0,
			max_accepted_htlcs: 0,
			funding_pubkey: fake_public_key!(),
			revocation_basepoint: fake_public_key!(),
			delayed_payment_basepoint: fake_public_key!(),
			htlc_basepoint: fake_public_key!(),
			payment_point: fake_public_key!(),
			first_per_commitment_point: fake_public_key!(),
			channel_flags: 0,
			shutdown_scriptpubkey: OptionalField::Absent
		}
	}}
}

macro_rules! fake_accept_channel_msg {
	() => {{
		AcceptChannel {
			temporary_channel_id: [0; 32],
			dust_limit_satoshis: 0,
			max_htlc_value_in_flight_msat: 0,
			channel_reserve_satoshis: 0,
			htlc_minimum_msat: 0,
			minimum_depth: 0,
			to_self_delay: 0,
			max_accepted_htlcs: 0,
			funding_pubkey: fake_public_key!(),
			revocation_basepoint: fake_public_key!(),
			payment_point: fake_public_key!(),
			delayed_payment_basepoint: fake_public_key!(),
			htlc_basepoint: fake_public_key!(),
			first_per_commitment_point: fake_public_key!(),
			shutdown_scriptpubkey: OptionalField::Absent
		}
	}}
}
macro_rules! fake_funding_created_msg {
	() => {{
		FundingCreated {
			temporary_channel_id: [0; 32],
			funding_txid: Default::default(),
			funding_output_index: 0,
			signature: fake_valid_sig!()
		}
	}}
}

macro_rules! fake_funding_signed_msg {
	() => {{
		FundingSigned {
			channel_id: [0; 32],
			signature: fake_valid_sig!()
		}
	}}
}

macro_rules! fake_funding_locked_msg {
	() => {{
		FundingLocked {
			channel_id: [0; 32],
			next_per_commitment_point: fake_public_key!()
		}
	}}
}

macro_rules! fake_shutdown_msg {
	() => {{
		Shutdown {
			channel_id: [0; 32],
			scriptpubkey: Default::default()
		}
	}}
}

macro_rules! fake_closing_signed_msg {
	() => {{
		ClosingSigned {
			channel_id: [0; 32],
			fee_satoshis: 0,
			signature: fake_valid_sig!()
		}
	}}
}

macro_rules! fake_update_add_htlc_msg {
	() => {{
		UpdateAddHTLC {
			channel_id: [0; 32],
			htlc_id: 0,
			amount_msat: 0,
			payment_hash: PaymentHash([0; 32]),
			cltv_expiry: 0,
			onion_routing_packet: OnionPacket {
				version: 0,
				public_key: Ok(fake_public_key!()),
				hop_data: [0; 1300],
				hmac: [0; 32]
			}
		}
	}}
}

macro_rules! fake_update_fulfill_htlc_msg {
	() => {{
		UpdateFulfillHTLC {
			channel_id: [0; 32],
			htlc_id: 0,
			payment_preimage: PaymentPreimage([0; 32])
		}
	}}
}


macro_rules! fake_update_fail_htlc_msg {
	() => {{
		UpdateFailHTLC {
			channel_id: [0; 32],
			htlc_id: 0,
			reason: OnionErrorPacket { data: vec![] }
		}
	}}
}

macro_rules! fake_update_fail_malformed_htlc_msg {
	() => {
		UpdateFailMalformedHTLC {
			channel_id: [0; 32],
			htlc_id: 0,
			sha256_of_onion: [0; 32],
			failure_code: 0
		}
	}
}

macro_rules! fake_commitment_signed_msg {
	() => {{
		CommitmentSigned {
			channel_id: [0; 32],
			signature: fake_valid_sig!(),
			htlc_signatures: vec![]
		}
	}}
}

macro_rules! fake_revoke_and_ack_msg {
	() => {{
		RevokeAndACK {
			channel_id: [0; 32],
			per_commitment_secret: [0; 32],
			next_per_commitment_point: fake_public_key!()
		}
	}}
}
macro_rules! fake_update_fee_msg {
	() => {{
		UpdateFee {
			channel_id: [0; 32],
			feerate_per_kw: 0
		}
	}}
}

macro_rules! fake_channel_reestablish_msg {
	() => {{
		ChannelReestablish {
			channel_id: [0; 32],
			next_local_commitment_number: 0,
			next_remote_commitment_number: 0,
			data_loss_protect: OptionalField::Absent
		}
	}}
}

macro_rules! fake_announcement_signatures_msg {
	() => {{
		AnnouncementSignatures {
			channel_id: [0;32],
			short_channel_id: 0,
			node_signature: fake_valid_sig!(),
			bitcoin_signature: fake_valid_sig!()
		}
	}}
}

macro_rules! fake_channel_announcement_msg {
	($channel_id: expr, $node_id_1: expr, $node_id_2: expr) => {{
		ChannelAnnouncement {
			node_signature_1: fake_valid_sig!(),
			node_signature_2: fake_valid_sig!(),
			bitcoin_signature_1: fake_valid_sig!(),
			bitcoin_signature_2: fake_valid_sig!(),
			contents: UnsignedChannelAnnouncement {
				features: ChannelFeatures::empty(),
				chain_hash: Default::default(),
				short_channel_id: $channel_id,
				node_id_1: $node_id_1,
				node_id_2: $node_id_2,
				bitcoin_key_1: fake_public_key!(),
				bitcoin_key_2: fake_public_key!(),
				excess_data: vec![]
			}
		}
	}}
}

macro_rules! fake_node_announcement_msg {
	() => {{
		NodeAnnouncement {
			signature: fake_valid_sig!(),
			contents: UnsignedNodeAnnouncement {
				features: NodeFeatures::empty(),
				timestamp: 0,
				node_id: fake_public_key!(),
				rgb: [0; 3],
				alias: [0; 32],
				addresses: vec![],
				excess_address_data: vec![],
				excess_data: vec![]
			}
		}
	}}
}

macro_rules! fake_channel_update_msg {
	() => {{
		ChannelUpdate {
			signature: fake_valid_sig!(),
			contents: UnsignedChannelUpdate {
				chain_hash: Default::default(),
				short_channel_id: 0,
				timestamp: 0,
				flags: 0,
				cltv_expiry_delta: 0,
				htlc_minimum_msat: 0,
				fee_base_msat: 0,
				fee_proportional_millionths: 0,
				excess_data: vec![]
			}
		}
	}}
}
