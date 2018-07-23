use ln::msgs::HandleError;
use ln::msgs;

use secp256k1::Secp256k1;
use secp256k1::key::{PublicKey,SecretKey};
use secp256k1::ecdh::SharedSecret;

use crypto::digest::Digest;
use crypto::hkdf::{hkdf_extract,hkdf_expand};

use crypto::aead::{AeadEncryptor, AeadDecryptor};

use util::chacha20poly1305rfc::ChaCha20Poly1305RFC;
use util::{byte_utils,rng};
use util::sha2::Sha256;

// Sha256("Noise_XK_secp256k1_ChaChaPoly_SHA256")
const NOISE_CK: [u8; 32] = [0x26, 0x40, 0xf5, 0x2e, 0xeb, 0xcd, 0x9e, 0x88, 0x29, 0x58, 0x95, 0x1c, 0x79, 0x42, 0x50, 0xee, 0xdb, 0x28, 0x00, 0x2c, 0x05, 0xd7, 0xdc, 0x2e, 0xa0, 0xf1, 0x95, 0x40, 0x60, 0x42, 0xca, 0xf1];
// Sha256(NOISE_CK || "lightning")
const NOISE_H: [u8; 32] = [0xd1, 0xfb, 0xf6, 0xde, 0xe4, 0xf6, 0x86, 0xf1, 0x32, 0xfd, 0x70, 0x2c, 0x4a, 0xbf, 0x8f, 0xba, 0x4b, 0xb4, 0x20, 0xd8, 0x9d, 0x2a, 0x04, 0x8a, 0x3c, 0x4f, 0x4c, 0x09, 0x2e, 0x37, 0xb6, 0x76];

pub enum NextNoiseStep {
	ActOne,
	ActTwo,
	ActThree,
	NoiseComplete,
}

#[derive(PartialEq)]
enum NoiseStep {
	PreActOne,
	PostActOne,
	PostActTwo,
	// When done swap noise_state for NoiseState::Finished
}

struct BidirectionalNoiseState {
	h: [u8; 32],
	ck: [u8; 32],
}
enum DirectionalNoiseState {
	Outbound {
		ie: SecretKey,
	},
	Inbound {
		ie: Option<PublicKey>, // filled in if state >= PostActOne
		re: Option<SecretKey>, // filled in if state >= PostActTwo
		temp_k2: Option<[u8; 32]>, // filled in if state >= PostActTwo
	}
}
enum NoiseState {
	InProgress {
		state: NoiseStep,
		directional_state: DirectionalNoiseState,
		bidirectional_state: BidirectionalNoiseState,
	},
	Finished {
		sk: [u8; 32],
		sn: u64,
		sck: [u8; 32],
		rk: [u8; 32],
		rn: u64,
		rck: [u8; 32],
	}
}

pub struct PeerChannelEncryptor {
	secp_ctx: Secp256k1,
	their_node_id: Option<PublicKey>, // filled in for outbound, or inbound after noise_state is Finished

	noise_state: NoiseState,
}

impl PeerChannelEncryptor {
	pub fn new_outbound(their_node_id: PublicKey) -> PeerChannelEncryptor {
		let mut key = [0u8; 32];
		rng::fill_bytes(&mut key);

		let secp_ctx = Secp256k1::new();
		let sec_key = SecretKey::from_slice(&secp_ctx, &key).unwrap(); //TODO: nicer rng-is-bad error message

		let mut sha = Sha256::new();
		sha.input(&NOISE_H);
		sha.input(&their_node_id.serialize()[..]);
		let mut h = [0; 32];
		sha.result(&mut h);

		PeerChannelEncryptor {
			their_node_id: Some(their_node_id),
			secp_ctx: secp_ctx,
			noise_state: NoiseState::InProgress {
				state: NoiseStep::PreActOne,
				directional_state: DirectionalNoiseState::Outbound {
					ie: sec_key,
				},
				bidirectional_state: BidirectionalNoiseState {
					h: h,
					ck: NOISE_CK,
				},
			}
		}
	}

	pub fn new_inbound(our_node_secret: &SecretKey) -> PeerChannelEncryptor {
		let secp_ctx = Secp256k1::new();

		let mut sha = Sha256::new();
		sha.input(&NOISE_H);
		let our_node_id = PublicKey::from_secret_key(&secp_ctx, our_node_secret).unwrap(); //TODO: nicer bad-node_secret error message
		sha.input(&our_node_id.serialize()[..]);
		let mut h = [0; 32];
		sha.result(&mut h);

		PeerChannelEncryptor {
			their_node_id: None,
			secp_ctx: secp_ctx,
			noise_state: NoiseState::InProgress {
				state: NoiseStep::PreActOne,
				directional_state: DirectionalNoiseState::Inbound {
					ie: None,
					re: None,
					temp_k2: None,
				},
				bidirectional_state: BidirectionalNoiseState {
					h: h,
					ck: NOISE_CK,
				},
			}
		}
	}

	#[inline]
	fn encrypt_with_ad(res: &mut[u8], n: u64, key: &[u8; 32], h: &[u8], plaintext: &[u8]) {
		let mut nonce = [0; 12];
		nonce[4..].copy_from_slice(&byte_utils::le64_to_array(n));

		let mut chacha = ChaCha20Poly1305RFC::new(key, &nonce, h);
		let mut tag = [0; 16];
		chacha.encrypt(plaintext, &mut res[0..plaintext.len()], &mut tag);
		res[plaintext.len()..].copy_from_slice(&tag);
	}

	#[inline]
	fn decrypt_with_ad(res: &mut[u8], n: u64, key: &[u8; 32], h: &[u8], cyphertext: &[u8]) -> Result<(), HandleError> {
		let mut nonce = [0; 12];
		nonce[4..].copy_from_slice(&byte_utils::le64_to_array(n));

		let mut chacha = ChaCha20Poly1305RFC::new(key, &nonce, h);
		if !chacha.decrypt(&cyphertext[0..cyphertext.len() - 16], res, &cyphertext[cyphertext.len() - 16..]) {
			return Err(HandleError{err: "Bad MAC", action: Some(msgs::ErrorAction::DisconnectPeer{ msg: None })});
		}
		Ok(())
	}

	#[inline]
	fn hkdf(state: &mut BidirectionalNoiseState, ss: SharedSecret) -> [u8; 32] {
		let mut hkdf = [0; 64];
		{
			let mut prk = [0; 32];
			hkdf_extract(Sha256::new(), &state.ck, &ss[..], &mut prk);
			hkdf_expand(Sha256::new(), &prk, &[0;0], &mut hkdf);
		}
		state.ck.copy_from_slice(&hkdf[0..32]);
		let mut res = [0; 32];
		res.copy_from_slice(&hkdf[32..]);
		res
	}

	#[inline]
	fn outbound_noise_act(secp_ctx: &Secp256k1, state: &mut BidirectionalNoiseState, our_key: &SecretKey, their_key: &PublicKey) -> ([u8; 50], [u8; 32]) {
		let our_pub = PublicKey::from_secret_key(secp_ctx, &our_key).unwrap(); //TODO: nicer rng-is-bad error message

		let mut sha = Sha256::new();
		sha.input(&state.h);
		sha.input(&our_pub.serialize()[..]);
		sha.result(&mut state.h);

		let ss = SharedSecret::new(secp_ctx, &their_key, &our_key);
		let temp_k = PeerChannelEncryptor::hkdf(state, ss);

		let mut res = [0; 50];
		res[1..34].copy_from_slice(&our_pub.serialize()[..]);
		PeerChannelEncryptor::encrypt_with_ad(&mut res[34..], 0, &temp_k, &state.h, &[0; 0]);

		sha.reset();
		sha.input(&state.h);
		sha.input(&res[34..]);
		sha.result(&mut state.h);

		(res, temp_k)
	}

	#[inline]
	fn inbound_noise_act(secp_ctx: &Secp256k1, state: &mut BidirectionalNoiseState, act: &[u8], our_key: &SecretKey) -> Result<(PublicKey, [u8; 32]), HandleError> {
		assert_eq!(act.len(), 50);

		if act[0] != 0 {
			return Err(HandleError{err: "Unknown handshake version number", action: Some(msgs::ErrorAction::DisconnectPeer{ msg: None })});
		}

		let their_pub = match PublicKey::from_slice(secp_ctx, &act[1..34]) {
			Err(_) => return Err(HandleError{err: "Invalid public key", action: Some(msgs::ErrorAction::DisconnectPeer{ msg: None })}),
			Ok(key) => key,
		};

		let mut sha = Sha256::new();
		sha.input(&state.h);
		sha.input(&their_pub.serialize()[..]);
		sha.result(&mut state.h);

		let ss = SharedSecret::new(secp_ctx, &their_pub, &our_key);
		let temp_k = PeerChannelEncryptor::hkdf(state, ss);

		let mut dec = [0; 0];
		PeerChannelEncryptor::decrypt_with_ad(&mut dec, 0, &temp_k, &state.h, &act[34..])?;

		sha.reset();
		sha.input(&state.h);
		sha.input(&act[34..]);
		sha.result(&mut state.h);

		Ok((their_pub, temp_k))
	}

	pub fn get_act_one(&mut self) -> [u8; 50] {
		match self.noise_state {
			NoiseState::InProgress { ref mut state, ref directional_state, ref mut bidirectional_state } =>
				match directional_state {
					&DirectionalNoiseState::Outbound { ref ie } => {
						if *state != NoiseStep::PreActOne {
							panic!("Requested act at wrong step");
						}

						let (res, _) = PeerChannelEncryptor::outbound_noise_act(&self.secp_ctx, bidirectional_state, &ie, &self.their_node_id.unwrap());
						*state = NoiseStep::PostActOne;
						res
					},
					_ => panic!("Wrong direction for act"),
				},
			_ => panic!("Cannot get act one after noise handshake completes"),
		}
	}

	// Separated for testing:
	fn process_act_one_with_ephemeral_key(&mut self, act_one: &[u8], our_node_secret: &SecretKey, our_ephemeral: SecretKey) -> Result<[u8; 50], HandleError> {
		assert_eq!(act_one.len(), 50);

		match self.noise_state {
			NoiseState::InProgress { ref mut state, ref mut directional_state, ref mut bidirectional_state } =>
				match directional_state {
					&mut DirectionalNoiseState::Inbound { ref mut ie, ref mut re, ref mut temp_k2 } => {
						if *state != NoiseStep::PreActOne {
							panic!("Requested act at wrong step");
						}

						let (their_pub, _) = PeerChannelEncryptor::inbound_noise_act(&self.secp_ctx, bidirectional_state, act_one, &our_node_secret)?;
						ie.get_or_insert(their_pub);

						re.get_or_insert(our_ephemeral);

						let (res, temp_k) = PeerChannelEncryptor::outbound_noise_act(&self.secp_ctx, bidirectional_state, &re.unwrap(), &ie.unwrap());
						*temp_k2 = Some(temp_k);
						*state = NoiseStep::PostActTwo;
						Ok(res)
					},
					_ => panic!("Wrong direction for act"),
				},
			_ => panic!("Cannot get act one after noise handshake completes"),
		}
	}

	pub fn process_act_one_with_key(&mut self, act_one: &[u8], our_node_secret: &SecretKey) -> Result<[u8; 50], HandleError> {
		assert_eq!(act_one.len(), 50);

		let mut key = [0u8; 32];
		rng::fill_bytes(&mut key);
		let our_ephemeral_key = SecretKey::from_slice(&self.secp_ctx, &key).unwrap(); //TODO: nicer rng-is-bad error message
		self.process_act_one_with_ephemeral_key(act_one, our_node_secret, our_ephemeral_key)
	}

	pub fn process_act_two(&mut self, act_two: &[u8], our_node_secret: &SecretKey) -> Result<[u8; 66], HandleError> {
		assert_eq!(act_two.len(), 50);

		let mut final_hkdf = [0; 64];
		let ck;
		let res: [u8; 66] = match self.noise_state {
			NoiseState::InProgress { ref state, ref directional_state, ref mut bidirectional_state } =>
				match directional_state {
					&DirectionalNoiseState::Outbound { ref ie } => {
						if *state != NoiseStep::PostActOne {
							panic!("Requested act at wrong step");
						}

						let (re, temp_k2) = PeerChannelEncryptor::inbound_noise_act(&self.secp_ctx, bidirectional_state, act_two, &ie)?;

						let mut res = [0; 66];
						let our_node_id = PublicKey::from_secret_key(&self.secp_ctx, &our_node_secret).unwrap(); //TODO: nicer rng-is-bad error message

						PeerChannelEncryptor::encrypt_with_ad(&mut res[1..50], 1, &temp_k2, &bidirectional_state.h, &our_node_id.serialize()[..]);

						let mut sha = Sha256::new();
						sha.input(&bidirectional_state.h);
						sha.input(&res[1..50]);
						sha.result(&mut bidirectional_state.h);

						let ss = SharedSecret::new(&self.secp_ctx, &re, our_node_secret);
						let temp_k = PeerChannelEncryptor::hkdf(bidirectional_state, ss);

						PeerChannelEncryptor::encrypt_with_ad(&mut res[50..], 0, &temp_k, &bidirectional_state.h, &[0; 0]);

						let mut prk = [0; 32];
						hkdf_extract(Sha256::new(), &bidirectional_state.ck, &[0; 0], &mut prk);
						hkdf_expand(Sha256::new(), &prk, &[0;0], &mut final_hkdf);
						ck = bidirectional_state.ck.clone();
						res
					},
					_ => panic!("Wrong direction for act"),
				},
			_ => panic!("Cannot get act one after noise handshake completes"),
		};

		let mut sk = [0; 32];
		let mut rk = [0; 32];
		sk.copy_from_slice(&final_hkdf[0..32]);
		rk.copy_from_slice(&final_hkdf[32..]);

		self.noise_state = NoiseState::Finished {
			sk: sk,
			sn: 0,
			sck: ck.clone(),
			rk: rk,
			rn: 0,
			rck: ck,
		};

		Ok(res)
	}

	pub fn process_act_three(&mut self, act_three: &[u8]) -> Result<PublicKey, HandleError> {
		assert_eq!(act_three.len(), 66);

		let mut final_hkdf = [0; 64];
		let ck;
		match self.noise_state {
			NoiseState::InProgress { ref state, ref directional_state, ref mut bidirectional_state } =>
				match directional_state {
					&DirectionalNoiseState::Inbound { ie: _, ref re, ref temp_k2 } => {
						if *state != NoiseStep::PostActTwo {
							panic!("Requested act at wrong step");
						}
						if act_three[0] != 0 {
							return Err(HandleError{err: "Unknown handshake version number", action: Some(msgs::ErrorAction::DisconnectPeer{ msg: None })});
						}

						let mut their_node_id = [0; 33];
						PeerChannelEncryptor::decrypt_with_ad(&mut their_node_id, 1, &temp_k2.unwrap(), &bidirectional_state.h, &act_three[1..50])?;
						self.their_node_id = Some(match PublicKey::from_slice(&self.secp_ctx, &their_node_id) {
							Ok(key) => key,
							Err(_) => return Err(HandleError{err: "Bad node_id from peer", action: Some(msgs::ErrorAction::DisconnectPeer{ msg: None })}),
						});

						let mut sha = Sha256::new();
						sha.input(&bidirectional_state.h);
						sha.input(&act_three[1..50]);
						sha.result(&mut bidirectional_state.h);

						let ss = SharedSecret::new(&self.secp_ctx, &self.their_node_id.unwrap(), &re.unwrap());
						let temp_k = PeerChannelEncryptor::hkdf(bidirectional_state, ss);

						PeerChannelEncryptor::decrypt_with_ad(&mut [0; 0], 0, &temp_k, &bidirectional_state.h, &act_three[50..])?;

						let mut prk = [0; 32];
						hkdf_extract(Sha256::new(), &bidirectional_state.ck, &[0; 0], &mut prk);
						hkdf_expand(Sha256::new(), &prk, &[0;0], &mut final_hkdf);
						ck = bidirectional_state.ck.clone();
					},
					_ => panic!("Wrong direction for act"),
				},
			_ => panic!("Cannot get act one after noise handshake completes"),
		}

		let mut rk = [0; 32];
		let mut sk = [0; 32];
		rk.copy_from_slice(&final_hkdf[0..32]);
		sk.copy_from_slice(&final_hkdf[32..]);

		self.noise_state = NoiseState::Finished {
			sk: sk,
			sn: 0,
			sck: ck.clone(),
			rk: rk,
			rn: 0,
			rck: ck,
		};

		Ok(self.their_node_id.unwrap().clone())
	}

	/// Encrypts the given message, returning the encrypted version
	/// panics if msg.len() > 65535 or Noise handshake has not finished.
	pub fn encrypt_message(&mut self, msg: &[u8]) -> Vec<u8> {
		if msg.len() > 65535 {
			panic!("Attempted to encrypt message longer than 65535 bytes!");
		}

		let mut res = Vec::with_capacity(msg.len() + 16*2 + 2);
		res.resize(msg.len() + 16*2 + 2, 0);

		match self.noise_state {
			NoiseState::Finished { ref mut sk, ref mut sn, ref mut sck, rk: _, rn: _, rck: _ } => {
				if *sn >= 1000 {
					let mut prk = [0; 32];
					hkdf_extract(Sha256::new(), sck, sk, &mut prk);
					let mut hkdf = [0; 64];
					hkdf_expand(Sha256::new(), &prk, &[0;0], &mut hkdf);

					sck[..].copy_from_slice(&hkdf[0..32]);
					sk[..].copy_from_slice(&hkdf[32..]);
					*sn = 0;
				}

				Self::encrypt_with_ad(&mut res[0..16+2], *sn, sk, &[0; 0], &byte_utils::be16_to_array(msg.len() as u16));
				*sn += 1;

				Self::encrypt_with_ad(&mut res[16+2..], *sn, sk, &[0; 0], msg);
				*sn += 1;
			},
			_ => panic!("Tried to encrypt a message prior to noise handshake completion"),
		}

		res
	}

	/// Decrypts a message length header from the remote peer.
	/// panics if noise handshake has not yet finished or msg.len() != 18
	pub fn decrypt_length_header(&mut self, msg: &[u8]) -> Result<u16, HandleError> {
		assert_eq!(msg.len(), 16+2);

		match self.noise_state {
			NoiseState::Finished { sk: _, sn: _, sck: _, ref mut rk, ref mut rn, ref mut rck } => {
				if *rn >= 1000 {
					let mut prk = [0; 32];
					hkdf_extract(Sha256::new(), rck, rk, &mut prk);
					let mut hkdf = [0; 64];
					hkdf_expand(Sha256::new(), &prk, &[0;0], &mut hkdf);

					rck[..].copy_from_slice(&hkdf[0..32]);
					rk[..].copy_from_slice(&hkdf[32..]);
					*rn = 0;
				}

				let mut res = [0; 2];
				Self::decrypt_with_ad(&mut res, *rn, rk, &[0; 0], msg)?;
				*rn += 1;
				Ok(byte_utils::slice_to_be16(&res))
			},
			_ => panic!("Tried to encrypt a message prior to noise handshake completion"),
		}
	}

	/// Decrypts the given message.
	/// panics if msg.len() > 65535 + 16
	pub fn decrypt_message(&mut self, msg: &[u8]) -> Result<Vec<u8>, HandleError> {
		if msg.len() > 65535 + 16 {
			panic!("Attempted to encrypt message longer than 65535 bytes!");
		}

		match self.noise_state {
			NoiseState::Finished { sk: _, sn: _, sck: _, ref rk, ref mut rn, rck: _ } => {
				let mut res = Vec::with_capacity(msg.len() - 16);
				res.resize(msg.len() - 16, 0);
				Self::decrypt_with_ad(&mut res[..], *rn, rk, &[0; 0], msg)?;
				*rn += 1;

				Ok(res)
			},
			_ => panic!("Tried to encrypt a message prior to noise handshake completion"),
		}
	}

	pub fn get_noise_step(&self) -> NextNoiseStep {
		match self.noise_state {
			NoiseState::InProgress {ref state, ..} => {
				match state {
					&NoiseStep::PreActOne => NextNoiseStep::ActOne,
					&NoiseStep::PostActOne => NextNoiseStep::ActTwo,
					&NoiseStep::PostActTwo => NextNoiseStep::ActThree,
				}
			},
			NoiseState::Finished {..} => NextNoiseStep::NoiseComplete,
		}
	}

	pub fn is_ready_for_encryption(&self) -> bool {
		match self.noise_state {
			NoiseState::InProgress {..} => { false },
			NoiseState::Finished {..} => { true }
		}
	}
}

#[cfg(test)]
mod tests {
	use secp256k1::Secp256k1;
	use secp256k1::key::{PublicKey,SecretKey};

	use bitcoin::util::misc::hex_bytes;

	use ln::peer_channel_encryptor::{PeerChannelEncryptor,NoiseState,DirectionalNoiseState};

	fn get_outbound_peer_for_initiator_test_vectors() -> PeerChannelEncryptor {
		let secp_ctx = Secp256k1::new();
		let their_node_id = PublicKey::from_slice(&secp_ctx, &hex_bytes("028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7").unwrap()[..]).unwrap();

		let mut outbound_peer = PeerChannelEncryptor::new_outbound(their_node_id);
		match outbound_peer.noise_state {
			NoiseState::InProgress { state: _, ref mut directional_state, bidirectional_state: _ } => {
				*directional_state = DirectionalNoiseState::Outbound { // overwrite ie...
					ie: SecretKey::from_slice(&secp_ctx, &hex_bytes("1212121212121212121212121212121212121212121212121212121212121212").unwrap()[..]).unwrap(),
				};
			},
			_ => panic!()
		}

		assert_eq!(outbound_peer.get_act_one()[..], hex_bytes("00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a").unwrap()[..]);
		outbound_peer
	}

	#[test]
	fn noise_initiator_test_vectors() {
		let secp_ctx = Secp256k1::new();
		let our_node_id = SecretKey::from_slice(&secp_ctx, &hex_bytes("1111111111111111111111111111111111111111111111111111111111111111").unwrap()[..]).unwrap();

		{
			// transport-initiator successful handshake
			let mut outbound_peer = get_outbound_peer_for_initiator_test_vectors();

			let act_two = hex_bytes("0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae").unwrap().to_vec();
			assert_eq!(outbound_peer.process_act_two(&act_two[..], &our_node_id).unwrap()[..], hex_bytes("00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba").unwrap()[..]);

			match outbound_peer.noise_state {
				NoiseState::Finished { sk, sn, sck, rk, rn, rck } => {
					assert_eq!(sk, hex_bytes("969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9").unwrap()[..]);
					assert_eq!(sn, 0);
					assert_eq!(sck, hex_bytes("919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01").unwrap()[..]);
					assert_eq!(rk, hex_bytes("bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442").unwrap()[..]);
					assert_eq!(rn, 0);
					assert_eq!(rck, hex_bytes("919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01").unwrap()[..]);
				},
				_ => panic!()
			}
		}
		{
			// transport-initiator act2 short read test
			// Can't actually test this cause process_act_two requires you pass the right length!
		}
		{
			// transport-initiator act2 bad version test
			let mut outbound_peer = get_outbound_peer_for_initiator_test_vectors();

			let act_two = hex_bytes("0102466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae").unwrap().to_vec();
			assert!(outbound_peer.process_act_two(&act_two[..], &our_node_id).is_err());
		}

		{
			// transport-initiator act2 bad key serialization test
			let mut outbound_peer = get_outbound_peer_for_initiator_test_vectors();

			let act_two = hex_bytes("0004466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae").unwrap().to_vec();
			assert!(outbound_peer.process_act_two(&act_two[..], &our_node_id).is_err());
		}

		{
			// transport-initiator act2 bad MAC test
			let mut outbound_peer = get_outbound_peer_for_initiator_test_vectors();

			let act_two = hex_bytes("0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730af").unwrap().to_vec();
			assert!(outbound_peer.process_act_two(&act_two[..], &our_node_id).is_err());
		}
	}

	#[test]
	fn noise_responder_test_vectors() {
		let secp_ctx = Secp256k1::new();
		let our_node_id = SecretKey::from_slice(&secp_ctx, &hex_bytes("2121212121212121212121212121212121212121212121212121212121212121").unwrap()[..]).unwrap();
		let our_ephemeral = SecretKey::from_slice(&secp_ctx, &hex_bytes("2222222222222222222222222222222222222222222222222222222222222222").unwrap()[..]).unwrap();

		{
			// transport-responder successful handshake
			let mut inbound_peer = PeerChannelEncryptor::new_inbound(&our_node_id);

			let act_one = hex_bytes("00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a").unwrap().to_vec();
			assert_eq!(inbound_peer.process_act_one_with_ephemeral_key(&act_one[..], &our_node_id, our_ephemeral.clone()).unwrap()[..], hex_bytes("0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae").unwrap()[..]);

			let act_three = hex_bytes("00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba").unwrap().to_vec();
			// test vector doesn't specify the initiator static key, but its the same as the one
			// from trasport-initiator successful handshake
			assert_eq!(inbound_peer.process_act_three(&act_three[..]).unwrap().serialize()[..], hex_bytes("034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa").unwrap()[..]);

			match inbound_peer.noise_state {
				NoiseState::Finished { sk, sn, sck, rk, rn, rck } => {
					assert_eq!(sk, hex_bytes("bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442").unwrap()[..]);
					assert_eq!(sn, 0);
					assert_eq!(sck, hex_bytes("919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01").unwrap()[..]);
					assert_eq!(rk, hex_bytes("969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9").unwrap()[..]);
					assert_eq!(rn, 0);
					assert_eq!(rck, hex_bytes("919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01").unwrap()[..]);
				},
				_ => panic!()
			}
		}
		{
			// transport-responder act1 short read test
			// Can't actually test this cause process_act_one requires you pass the right length!
		}
		{
			// transport-responder act1 bad version test
			let mut inbound_peer = PeerChannelEncryptor::new_inbound(&our_node_id);

			let act_one = hex_bytes("01036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a").unwrap().to_vec();
			assert!(inbound_peer.process_act_one_with_ephemeral_key(&act_one[..], &our_node_id, our_ephemeral.clone()).is_err());
		}
		{
			// transport-responder act1 bad key serialization test
			let mut inbound_peer = PeerChannelEncryptor::new_inbound(&our_node_id);

			let act_one =hex_bytes("00046360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a").unwrap().to_vec();
			assert!(inbound_peer.process_act_one_with_ephemeral_key(&act_one[..], &our_node_id, our_ephemeral.clone()).is_err());
		}
		{
			// transport-responder act1 bad MAC test
			let mut inbound_peer = PeerChannelEncryptor::new_inbound(&our_node_id);

			let act_one = hex_bytes("00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6b").unwrap().to_vec();
			assert!(inbound_peer.process_act_one_with_ephemeral_key(&act_one[..], &our_node_id, our_ephemeral.clone()).is_err());
		}
		{
			// transport-responder act3 bad version test
			let mut inbound_peer = PeerChannelEncryptor::new_inbound(&our_node_id);

			let act_one = hex_bytes("00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a").unwrap().to_vec();
			assert_eq!(inbound_peer.process_act_one_with_ephemeral_key(&act_one[..], &our_node_id, our_ephemeral.clone()).unwrap()[..], hex_bytes("0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae").unwrap()[..]);

			let act_three = hex_bytes("01b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba").unwrap().to_vec();
			assert!(inbound_peer.process_act_three(&act_three[..]).is_err());
		}
		{
			// transport-responder act3 short read test
			// Can't actually test this cause process_act_three requires you pass the right length!
		}
		{
			// transport-responder act3 bad MAC for ciphertext test
			let mut inbound_peer = PeerChannelEncryptor::new_inbound(&our_node_id);

			let act_one = hex_bytes("00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a").unwrap().to_vec();
			assert_eq!(inbound_peer.process_act_one_with_ephemeral_key(&act_one[..], &our_node_id, our_ephemeral.clone()).unwrap()[..], hex_bytes("0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae").unwrap()[..]);

			let act_three = hex_bytes("00c9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba").unwrap().to_vec();
			assert!(inbound_peer.process_act_three(&act_three[..]).is_err());
		}
		{
			// transport-responder act3 bad rs test
			let mut inbound_peer = PeerChannelEncryptor::new_inbound(&our_node_id);

			let act_one = hex_bytes("00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a").unwrap().to_vec();
			assert_eq!(inbound_peer.process_act_one_with_ephemeral_key(&act_one[..], &our_node_id, our_ephemeral.clone()).unwrap()[..], hex_bytes("0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae").unwrap()[..]);

			let act_three = hex_bytes("00bfe3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa2235536ad09a8ee351870c2bb7f78b754a26c6cef79a98d25139c856d7efd252c2ae73c").unwrap().to_vec();
			assert!(inbound_peer.process_act_three(&act_three[..]).is_err());
		}
		{
			// transport-responder act3 bad MAC test
			let mut inbound_peer = PeerChannelEncryptor::new_inbound(&our_node_id);

			let act_one = hex_bytes("00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a").unwrap().to_vec();
			assert_eq!(inbound_peer.process_act_one_with_ephemeral_key(&act_one[..], &our_node_id, our_ephemeral.clone()).unwrap()[..], hex_bytes("0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae").unwrap()[..]);

			let act_three = hex_bytes("00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139bb").unwrap().to_vec();
			assert!(inbound_peer.process_act_three(&act_three[..]).is_err());
		}
	}


	#[test]
	fn message_encryption_decryption_test_vectors() {
		let secp_ctx = Secp256k1::new();

		// We use the same keys as the initiator and responder test vectors, so we copy those tests
		// here and use them to encrypt.
		let mut outbound_peer = get_outbound_peer_for_initiator_test_vectors();

		{
			let our_node_id = SecretKey::from_slice(&secp_ctx, &hex_bytes("1111111111111111111111111111111111111111111111111111111111111111").unwrap()[..]).unwrap();

			let act_two = hex_bytes("0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae").unwrap().to_vec();
			assert_eq!(outbound_peer.process_act_two(&act_two[..], &our_node_id).unwrap()[..], hex_bytes("00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba").unwrap()[..]);

			match outbound_peer.noise_state {
				NoiseState::Finished { sk, sn, sck, rk, rn, rck } => {
					assert_eq!(sk, hex_bytes("969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9").unwrap()[..]);
					assert_eq!(sn, 0);
					assert_eq!(sck, hex_bytes("919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01").unwrap()[..]);
					assert_eq!(rk, hex_bytes("bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442").unwrap()[..]);
					assert_eq!(rn, 0);
					assert_eq!(rck, hex_bytes("919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01").unwrap()[..]);
				},
				_ => panic!()
			}
		}

		let mut inbound_peer;

		{
			// transport-responder successful handshake
			let our_node_id = SecretKey::from_slice(&secp_ctx, &hex_bytes("2121212121212121212121212121212121212121212121212121212121212121").unwrap()[..]).unwrap();
			let our_ephemeral = SecretKey::from_slice(&secp_ctx, &hex_bytes("2222222222222222222222222222222222222222222222222222222222222222").unwrap()[..]).unwrap();

			inbound_peer = PeerChannelEncryptor::new_inbound(&our_node_id);

			let act_one = hex_bytes("00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a").unwrap().to_vec();
			assert_eq!(inbound_peer.process_act_one_with_ephemeral_key(&act_one[..], &our_node_id, our_ephemeral.clone()).unwrap()[..], hex_bytes("0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae").unwrap()[..]);

			let act_three = hex_bytes("00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba").unwrap().to_vec();
			// test vector doesn't specify the initiator static key, but its the same as the one
			// from trasport-initiator successful handshake
			assert_eq!(inbound_peer.process_act_three(&act_three[..]).unwrap().serialize()[..], hex_bytes("034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa").unwrap()[..]);

			match inbound_peer.noise_state {
				NoiseState::Finished { sk, sn, sck, rk, rn, rck } => {
					assert_eq!(sk, hex_bytes("bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442").unwrap()[..]);
					assert_eq!(sn, 0);
					assert_eq!(sck, hex_bytes("919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01").unwrap()[..]);
					assert_eq!(rk, hex_bytes("969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9").unwrap()[..]);
					assert_eq!(rn, 0);
					assert_eq!(rck, hex_bytes("919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01").unwrap()[..]);
				},
				_ => panic!()
			}
		}

		for i in 0..1005 {
			let msg = [0x68, 0x65, 0x6c, 0x6c, 0x6f];
			let res = outbound_peer.encrypt_message(&msg);
			assert_eq!(res.len(), 5 + 2*16 + 2);

			let len_header = res[0..2+16].to_vec();
			assert_eq!(inbound_peer.decrypt_length_header(&len_header[..]).unwrap() as usize, msg.len());
			assert_eq!(inbound_peer.decrypt_message(&res[2+16..]).unwrap()[..], msg[..]);

			if i == 0 {
				assert_eq!(res, hex_bytes("cf2b30ddf0cf3f80e7c35a6e6730b59fe802473180f396d88a8fb0db8cbcf25d2f214cf9ea1d95").unwrap());
			} else if i == 1 {
				assert_eq!(res, hex_bytes("72887022101f0b6753e0c7de21657d35a4cb2a1f5cde2650528bbc8f837d0f0d7ad833b1a256a1").unwrap());
			} else if i == 500 {
				assert_eq!(res, hex_bytes("178cb9d7387190fa34db9c2d50027d21793c9bc2d40b1e14dcf30ebeeeb220f48364f7a4c68bf8").unwrap());
			} else if i == 501 {
				assert_eq!(res, hex_bytes("1b186c57d44eb6de4c057c49940d79bb838a145cb528d6e8fd26dbe50a60ca2c104b56b60e45bd").unwrap());
			} else if i == 1000 {
				assert_eq!(res, hex_bytes("4a2f3cc3b5e78ddb83dcb426d9863d9d9a723b0337c89dd0b005d89f8d3c05c52b76b29b740f09").unwrap());
			} else if i == 1001 {
				assert_eq!(res, hex_bytes("2ecd8c8a5629d0d02ab457a0fdd0f7b90a192cd46be5ecb6ca570bfc5e268338b1a16cf4ef2d36").unwrap());
			}
		}
	}
}
