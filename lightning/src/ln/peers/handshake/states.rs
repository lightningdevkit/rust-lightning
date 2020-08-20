use bitcoin::secp256k1;

use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::secp256k1::{SecretKey, PublicKey};

use ln::peers::handshake::states::HandshakeState::{InitiatorAwaitingActTwo, ResponderAwaitingActThree, Complete};
use ln::peers::{chacha, hkdf};
use ln::peers::conduit::{Conduit, SymmetricKey};

const ACT_ONE_TWO_LENGTH: usize = 50;
const ACT_THREE_LENGTH: usize = 66;

type ChainingKey = [u8; 32];

// Generate a SHA-256 hash from one or more elements concatenated together
macro_rules! concat_then_sha256 {
	( $( $x:expr ),+ ) => {{
		let mut sha = Sha256::engine();
		$(
			sha.input($x.as_ref());
		)+
		Sha256::from_engine(sha)
	}}
}

pub enum HandshakeState {
	InitiatorStarting(InitiatorStartingState),
	ResponderAwaitingActOne(ResponderAwaitingActOneState),
	InitiatorAwaitingActTwo(InitiatorAwaitingActTwoState),
	ResponderAwaitingActThree(ResponderAwaitingActThreeState),
	Complete(Option<(Conduit, PublicKey)>),
}

// Trait for all individual states to implement that ensure HandshakeState::next() can
// delegate to a common function signature.
trait IHandshakeState {
	fn next(self, input: &[u8]) -> Result<(Option<Vec<u8>>, HandshakeState), String>;
}

// Enum dispatch for state machine. Single public interface can statically dispatch to all states
impl HandshakeState {
	pub fn next(self, input: &[u8]) -> Result<(Option<Vec<u8>>, HandshakeState), String> {
		match self {
			HandshakeState::InitiatorStarting(state) => { state.next(input) },
			HandshakeState::ResponderAwaitingActOne(state) => { state.next(input) },
			HandshakeState::InitiatorAwaitingActTwo(state) => { state.next(input) },
			HandshakeState::ResponderAwaitingActThree(state) => { state.next(input) },
			HandshakeState::Complete(_conduit) => { panic!("no acts left to process") }
		}
	}
}

// Handshake state of the Initiator prior to generating Act 1
pub struct InitiatorStartingState {
	initiator_static_private_key: SecretKey,
	initiator_static_public_key: PublicKey,
	initiator_ephemeral_private_key: SecretKey,
	initiator_ephemeral_public_key: PublicKey,
	responder_static_public_key: PublicKey,
	chaining_key: Sha256,
	hash: Sha256
}

// Handshake state of the Responder prior to receiving Act 1
pub struct ResponderAwaitingActOneState {
	responder_static_private_key: SecretKey,
	responder_ephemeral_private_key: SecretKey,
	responder_ephemeral_public_key: PublicKey,
	chaining_key: Sha256,
	hash: Sha256,
	read_buffer: Vec<u8>
}

// Handshake state of the Initiator prior to receiving Act 2
pub struct InitiatorAwaitingActTwoState {
	initiator_static_private_key: SecretKey,
	initiator_static_public_key: PublicKey,
	initiator_ephemeral_private_key: SecretKey,
	responder_static_public_key: PublicKey,
	chaining_key: ChainingKey,
	hash: Sha256,
	read_buffer: Vec<u8>
}

// Handshake state of the Responder prior to receiving Act 3
pub struct ResponderAwaitingActThreeState {
	hash: Sha256,
	responder_ephemeral_private_key: SecretKey,
	chaining_key: ChainingKey,
	temporary_key: [u8; 32],
	read_buffer: Vec<u8>
}

impl InitiatorStartingState {
	pub(crate) fn new(initiator_static_private_key: SecretKey, initiator_ephemeral_private_key: SecretKey, responder_static_public_key: PublicKey) -> Self {
		let initiator_static_public_key = private_key_to_public_key(&initiator_static_private_key);
		let (hash, chaining_key) = handshake_state_initialization(&responder_static_public_key);
		let initiator_ephemeral_public_key = private_key_to_public_key(&initiator_ephemeral_private_key);
		InitiatorStartingState {
			initiator_static_private_key,
			initiator_static_public_key,
			initiator_ephemeral_private_key,
			initiator_ephemeral_public_key,
			responder_static_public_key,
			chaining_key,
			hash
		}
	}
}

impl IHandshakeState for InitiatorStartingState {
	// https://github.com/lightningnetwork/lightning-rfc/blob/master/08-transport.md#act-one (sender)
	fn next(self, _input: &[u8]) -> Result<(Option<Vec<u8>>, HandshakeState), String> {
		let initiator_static_private_key = self.initiator_static_private_key;
		let initiator_static_public_key = self.initiator_static_public_key;
		let initiator_ephemeral_private_key = self.initiator_ephemeral_private_key;
		let initiator_ephemeral_public_key = self.initiator_ephemeral_public_key;
		let responder_static_public_key = self.responder_static_public_key;
		let chaining_key = self.chaining_key;
		let hash = self.hash;

		// serialize act one
		let (act_one, hash, chaining_key, _) = calculate_act_message(
			&initiator_ephemeral_private_key,
			&initiator_ephemeral_public_key,
			&responder_static_public_key,
			chaining_key.into_inner(),
			hash,
		);

		Ok((
			Some(act_one.to_vec()),
			InitiatorAwaitingActTwo(InitiatorAwaitingActTwoState {
				initiator_static_private_key,
				initiator_static_public_key,
				initiator_ephemeral_private_key,
				responder_static_public_key,
				chaining_key,
				hash,
				read_buffer: Vec::new()
			})
		))
	}
}

impl ResponderAwaitingActOneState {
	pub(crate) fn new(responder_static_private_key: SecretKey, responder_ephemeral_private_key: SecretKey) -> Self {
		let responder_static_public_key = private_key_to_public_key(&responder_static_private_key);
		let (hash, chaining_key) = handshake_state_initialization(&responder_static_public_key);
		let responder_ephemeral_public_key = private_key_to_public_key(&responder_ephemeral_private_key);

		ResponderAwaitingActOneState {
			responder_static_private_key,
			responder_ephemeral_private_key,
			responder_ephemeral_public_key,
			chaining_key,
			hash,
			read_buffer: Vec::new()
		}
	}
}

impl IHandshakeState for ResponderAwaitingActOneState {
	// https://github.com/lightningnetwork/lightning-rfc/blob/master/08-transport.md#act-one (receiver)
	// https://github.com/lightningnetwork/lightning-rfc/blob/master/08-transport.md#act-two (sender)
	fn next(self, input: &[u8]) -> Result<(Option<Vec<u8>>, HandshakeState), String> {
		let mut read_buffer = self.read_buffer;
		read_buffer.extend_from_slice(input);

		let hash = self.hash;
		let responder_static_private_key = self.responder_static_private_key;
		let chaining_key = self.chaining_key;
		let responder_ephemeral_private_key = self.responder_ephemeral_private_key;
		let responder_ephemeral_public_key = self.responder_ephemeral_public_key;

		let (initiator_ephemeral_public_key, hash, chaining_key, _) = process_act_message(
			&mut read_buffer,
			&responder_static_private_key,
			chaining_key.into_inner(),
			hash,
		)?;

		let (act_two, hash, chaining_key, temporary_key) = calculate_act_message(
			&responder_ephemeral_private_key,
			&responder_ephemeral_public_key,
			&initiator_ephemeral_public_key,
			chaining_key,
			hash,
		);

		Ok((
			Some(act_two),
			ResponderAwaitingActThree(ResponderAwaitingActThreeState {
				hash,
				responder_ephemeral_private_key,
				chaining_key,
				temporary_key,
				read_buffer
			})
		))
	}
}

impl IHandshakeState for InitiatorAwaitingActTwoState {
	// https://github.com/lightningnetwork/lightning-rfc/blob/master/08-transport.md#act-two (receiver)
	// https://github.com/lightningnetwork/lightning-rfc/blob/master/08-transport.md#act-three (sender)
	fn next(self, input: &[u8]) -> Result<(Option<Vec<u8>>, HandshakeState), String> {
		let mut read_buffer = self.read_buffer;
		read_buffer.extend_from_slice(input);

		let initiator_static_private_key = self.initiator_static_private_key;
		let initiator_static_public_key = self.initiator_static_public_key;
		let initiator_ephemeral_private_key = self.initiator_ephemeral_private_key;
		let responder_static_public_key = self.responder_static_public_key;
		let hash = self.hash;
		let chaining_key = self.chaining_key;

		let (responder_ephemeral_public_key, hash, chaining_key, temporary_key) = process_act_message(
			&mut read_buffer,
			&initiator_ephemeral_private_key,
			chaining_key,
			hash,
		)?;

		// start serializing act three
		// 1. c = encryptWithAD(temp_k2, 1, h, s.pub.serializeCompressed())
		let tagged_encrypted_pubkey = chacha::encrypt(&temporary_key, 1, &hash, &initiator_static_public_key.serialize());

		// 2. h = SHA-256(h || c)
		let hash = concat_then_sha256!(hash, tagged_encrypted_pubkey);

		// 3. se = ECDH(s.priv, re)
		let ecdh = ecdh(&initiator_static_private_key, &responder_ephemeral_public_key);

		// 4. ck, temp_k3 = HKDF(ck, se)
		let (chaining_key, temporary_key) = hkdf::derive(&chaining_key, &ecdh);

		// 5. t = encryptWithAD(temp_k3, 0, h, zero)
		let authentication_tag = chacha::encrypt(&temporary_key, 0, &hash, &[0; 0]);

		// 6. sk, rk = HKDF(ck, zero)
		let (sending_key, receiving_key) = hkdf::derive(&chaining_key, &[0; 0]);

		// 7. rn = 0, sn = 0
		// - done by Conduit
		let mut conduit = Conduit::new(sending_key, receiving_key, chaining_key);

		// Send m = 0 || c || t over the network buffer
		let mut act_three = Vec::with_capacity(ACT_THREE_LENGTH);
		act_three.extend(&[0]);
		act_three.extend(&tagged_encrypted_pubkey);
		act_three.extend(&authentication_tag);
		assert_eq!(act_three.len(), ACT_THREE_LENGTH);

		// Any remaining data in the read buffer would be encrypted, so transfer ownership
		// to the Conduit for future use. In this case, it is unlikely that any valid data
		// exists, since the responder doesn't have Act3
		if read_buffer.len() > 0 {
			conduit.read(&read_buffer[..]);
			read_buffer.drain(..);
		}

		Ok((
			Some(act_three),
			Complete(Some((conduit, responder_static_public_key)))
		))
	}
}

impl IHandshakeState for ResponderAwaitingActThreeState {
	// https://github.com/lightningnetwork/lightning-rfc/blob/master/08-transport.md#act-three (receiver)
	fn next(self, input: &[u8]) -> Result<(Option<Vec<u8>>, HandshakeState), String> {
		let mut read_buffer = self.read_buffer;
		read_buffer.extend_from_slice(input);

		if read_buffer.len() < ACT_THREE_LENGTH {
			return Err("need at least 66 bytes".to_string());
		}

		let hash = self.hash;
		let temporary_key = self.temporary_key;
		let responder_ephemeral_private_key = self.responder_ephemeral_private_key;
		let chaining_key = self.chaining_key;

		// 1. Read exactly 66 bytes from the network buffer
		let mut act_three_bytes = [0u8; ACT_THREE_LENGTH];
		act_three_bytes.copy_from_slice(&read_buffer[..ACT_THREE_LENGTH]);
		read_buffer.drain(..ACT_THREE_LENGTH);

		// 2. Parse the read message (m) into v, c, and t
		let version = act_three_bytes[0];

		let mut tagged_encrypted_pubkey = [0u8; 49];
		tagged_encrypted_pubkey.copy_from_slice(&act_three_bytes[1..50]);

		let mut chacha_tag = [0u8; 16];
		chacha_tag.copy_from_slice(&act_three_bytes[50..66]);

		// 3. If v is an unrecognized handshake version, then the responder MUST abort the connection attempt.
		if version != 0 {
			// this should not crash the process, hence no panic
			return Err("unexpected version".to_string());
		}

		// 4. rs = decryptWithAD(temp_k2, 1, h, c)
		let remote_pubkey_vec = chacha::decrypt(&temporary_key, 1, &hash, &tagged_encrypted_pubkey)?;
		let mut initiator_pubkey_bytes = [0u8; 33];
		initiator_pubkey_bytes.copy_from_slice(remote_pubkey_vec.as_slice());
		let initiator_pubkey = if let Ok(public_key) = PublicKey::from_slice(&initiator_pubkey_bytes) {
			public_key
		} else {
			return Err("invalid remote public key".to_string());
		};

		// 5. h = SHA-256(h || c)
		let hash = concat_then_sha256!(hash, tagged_encrypted_pubkey);

		// 6. se = ECDH(e.priv, rs)
		let ecdh = ecdh(&responder_ephemeral_private_key, &initiator_pubkey);

		// 7. ck, temp_k3 = HKDF(ck, se)
		let (chaining_key, temporary_key) = hkdf::derive(&chaining_key, &ecdh);

		// 8. p = decryptWithAD(temp_k3, 0, h, t)
		let _tag_check = chacha::decrypt(&temporary_key, 0, &hash, &chacha_tag)?;

		// 9. rk, sk = HKDF(ck, zero)
		let (receiving_key, sending_key) = hkdf::derive(&chaining_key, &[0; 0]);

		// 10. rn = 0, sn = 0
		// - done by Conduit
		let mut conduit = Conduit::new(sending_key, receiving_key, chaining_key);

		// Any remaining data in the read buffer would be encrypted, so transfer ownership
		// to the Conduit for future use.
		if read_buffer.len() > 0 { // have we received more data still?
			conduit.read(&read_buffer[..]);
			read_buffer.drain(..);
		}

		Ok((
			None,
			Complete(Some((conduit, initiator_pubkey)))
		))
	}
}

// https://github.com/lightningnetwork/lightning-rfc/blob/master/08-transport.md#handshake-state-initialization
fn handshake_state_initialization(responder_static_public_key: &PublicKey) -> (Sha256, Sha256) {
	let protocol_name = b"Noise_XK_secp256k1_ChaChaPoly_SHA256";
	let prologue = b"lightning";

	// 1. h = SHA-256(protocolName)
	// 2. ck = h
	let chaining_key = concat_then_sha256!(protocol_name);

	// 3. h = SHA-256(h || prologue)
	let hash = concat_then_sha256!(chaining_key, prologue);

	// h = SHA-256(h || responderPublicKey)
	let hash = concat_then_sha256!(hash, responder_static_public_key.serialize());

	(hash, chaining_key)
}

// https://github.com/lightningnetwork/lightning-rfc/blob/master/08-transport.md#act-one (sender)
// https://github.com/lightningnetwork/lightning-rfc/blob/master/08-transport.md#act-two (sender)
fn calculate_act_message(local_private_ephemeral_key: &SecretKey, local_public_ephemeral_key: &PublicKey, remote_public_key: &PublicKey, chaining_key: ChainingKey, hash: Sha256) -> (Vec<u8>, Sha256, SymmetricKey, SymmetricKey) {
	// 1. e = generateKey() (passed in)
	// 2. h = SHA-256(h || e.pub.serializeCompressed())
	let serialized_local_public_key = local_public_ephemeral_key.serialize();
	let hash = concat_then_sha256!(hash, serialized_local_public_key);

	// 3. ACT1: es = ECDH(e.priv, rs)
	// 3. ACT2: es = ECDH(e.priv, re)
	let ecdh = ecdh(local_private_ephemeral_key, &remote_public_key);

	// 4. ACT1: ck, temp_k1 = HKDF(ck, es)
	// 4. ACT2: ck, temp_k2 = HKDF(ck, ee)
	let (chaining_key, temporary_key) = hkdf::derive(&chaining_key, &ecdh);

	// 5. ACT1: c = encryptWithAD(temp_k1, 0, h, zero)
	// 5. ACT2: c = encryptWithAD(temp_k2, 0, h, zero)
	let tagged_ciphertext = chacha::encrypt(&temporary_key, 0, &hash, &[0; 0]);

	// 6. h = SHA-256(h || c)
	let hash = concat_then_sha256!(hash, tagged_ciphertext);

	// Send m = 0 || e.pub.serializeCompressed() || c
	let mut act = Vec::with_capacity(ACT_ONE_TWO_LENGTH);
	act.extend(&[0]);
	act.extend_from_slice(&serialized_local_public_key);
	act.extend(&tagged_ciphertext);
	assert_eq!(act.len(), ACT_ONE_TWO_LENGTH);

	(act, hash, chaining_key, temporary_key)
}

// Due to the very high similarity of acts 1 and 2, this method is used to process both
// https://github.com/lightningnetwork/lightning-rfc/blob/master/08-transport.md#act-one (receiver)
// https://github.com/lightningnetwork/lightning-rfc/blob/master/08-transport.md#act-two (receiver)
fn process_act_message(read_buffer: &mut Vec<u8>, local_private_key: &SecretKey, chaining_key: ChainingKey, hash: Sha256) -> Result<(PublicKey, Sha256, SymmetricKey, SymmetricKey), String> {
	// 1. Read exactly 50 bytes from the network buffer
	if read_buffer.len() < ACT_ONE_TWO_LENGTH {
		return Err("need at least 50 bytes".to_string());
	}

	let mut act_bytes = [0u8; ACT_ONE_TWO_LENGTH];
	act_bytes.copy_from_slice(&read_buffer[..ACT_ONE_TWO_LENGTH]);
	read_buffer.drain(..ACT_ONE_TWO_LENGTH);

	// 2.Parse the read message (m) into v, re, and c
	let version = act_bytes[0];

	let mut ephemeral_public_key_bytes = [0u8; 33];
	ephemeral_public_key_bytes.copy_from_slice(&act_bytes[1..34]);
	let ephemeral_public_key = if let Ok(public_key) = PublicKey::from_slice(&ephemeral_public_key_bytes) {
		public_key
	} else {
		return Err("invalid remote ephemeral public key".to_string());
	};

	let mut chacha_tag = [0u8; 16];
	chacha_tag.copy_from_slice(&act_bytes[34..50]);

	// 3. If v is an unrecognized handshake version, then the responder MUST abort the connection attempt
	if version != 0 {
		// this should not crash the process, hence no panic
		return Err("unexpected version".to_string());
	}

	// 4. h = SHA-256(h || re.serializeCompressed())
	let hash = concat_then_sha256!(hash, ephemeral_public_key_bytes);

	// 5. Act1: es = ECDH(s.priv, re)
	// 5. Act2: ee = ECDH(e.priv, ee)
	let ecdh = ecdh(local_private_key, &ephemeral_public_key);

	// 6. Act1: ck, temp_k1 = HKDF(ck, es)
	// 6. Act2: ck, temp_k2 = HKDF(ck, ee)
	let (chaining_key, temporary_key) = hkdf::derive(&chaining_key, &ecdh);

	// 7. p = decryptWithAD(temp_k1, 0, h, c)
	let _tag_check = chacha::decrypt(&temporary_key, 0, &hash, &chacha_tag)?;

	// 8. h = SHA-256(h || c)
	let hash = concat_then_sha256!(hash, chacha_tag);

	Ok((ephemeral_public_key, hash, chaining_key, temporary_key))
}

fn private_key_to_public_key(private_key: &SecretKey) -> PublicKey {
	let curve = secp256k1::Secp256k1::new();
	let pk_object = PublicKey::from_secret_key(&curve, &private_key);
	pk_object
}

fn ecdh(private_key: &SecretKey, public_key: &PublicKey) -> SymmetricKey {
	let curve = secp256k1::Secp256k1::new();
	let mut pk_object = public_key.clone();
	pk_object.mul_assign(&curve, &private_key[..]).expect("invalid multiplication");

	let preimage = pk_object.serialize();
	concat_then_sha256!(preimage).into_inner()
}

#[cfg(test)]
mod test {
	use hex;

	use bitcoin::secp256k1;
	use bitcoin::secp256k1::{PublicKey, SecretKey};

	use ln::peers::handshake::states::{InitiatorStartingState, ResponderAwaitingActOneState, HandshakeState};
	use ln::peers::handshake::states::HandshakeState::{ResponderAwaitingActThree, InitiatorAwaitingActTwo, Complete};

	struct TestCtx {
		initiator: HandshakeState,
		initiator_public_key: PublicKey,
		responder: HandshakeState,
		responder_static_public_key: PublicKey
	}

	impl TestCtx {
		fn new() -> Self {
			let curve = secp256k1::Secp256k1::new();
			let initiator_static_private_key = SecretKey::from_slice(&[0x_11_u8; 32]).unwrap();
			let initiator_public_key = PublicKey::from_secret_key(&curve, &initiator_static_private_key);
			let initiator_ephemeral_private_key = SecretKey::from_slice(&[0x_12_u8; 32]).unwrap();

			let responder_static_private_key = SecretKey::from_slice(&[0x_21_u8; 32]).unwrap();
			let responder_static_public_key = PublicKey::from_secret_key(&curve, &responder_static_private_key);
			let responder_ephemeral_private_key = SecretKey::from_slice(&[0x_22_u8; 32]).unwrap();

			let initiator = InitiatorStartingState::new(initiator_static_private_key, initiator_ephemeral_private_key, responder_static_public_key);
			let responder = ResponderAwaitingActOneState::new(responder_static_private_key, responder_ephemeral_private_key);

			TestCtx {
				initiator: HandshakeState::InitiatorStarting(initiator),
				initiator_public_key,
				responder: HandshakeState::ResponderAwaitingActOne(responder),
				responder_static_public_key,
			}
		}
	}

	macro_rules! do_next_or_panic {
		($state:expr, $input:expr) => {
			if let (Some(output_act), next_state) = $state.next($input).unwrap() {
				(output_act, next_state)
			} else {
				panic!();
			}
		}
	}

	macro_rules! assert_matches {
		($e:expr, $state_match:pat) => {
			match $e {
				$state_match => (),
				_ => panic!()
			}
		}
	}

	// Initiator::Starting -> AwaitingActTwo
	#[test]
	fn starting_to_awaiting_act_two() {
		let test_ctx = TestCtx::new();

		assert_matches!(test_ctx.initiator.next(&[]).unwrap(), (Some(_), InitiatorAwaitingActTwo(_)));
	}

	// Initiator::Starting -> AwaitingActTwo (extra bytes in argument)
	#[test]
	fn starting_to_awaiting_act_two_extra_bytes() {
		let test_ctx = TestCtx::new();

		assert_matches!(test_ctx.initiator.next(&[1]).unwrap(), (Some(_), InitiatorAwaitingActTwo(_)));
	}

	// Responder::AwaitingActOne -> Error (input too small)
	#[test]
	fn awaiting_act_one_to_awaiting_act_three_input_too_small() {
		let test_ctx = TestCtx::new();
		assert_eq!(test_ctx.responder.next(&[]).err(), Some(String::from("need at least 50 bytes")))
	}

	// Responder::AwaitingActOne -> AwaitingActThree
	// TODO: Should this fail since we don't expect data > ACT_ONE_TWO_LENGTH and likely indicates
	// a bad peer?
	// TODO: Should the behavior be changed to handle act1 data that is striped across multiple
	// next() calls?
	#[test]
	fn awaiting_act_one_to_awaiting_act_three_input_extra_bytes() {
		let test_ctx = TestCtx::new();
		let (mut act1, _) = do_next_or_panic!(test_ctx.initiator, &[]);
		act1.extend_from_slice(&[1]);

		assert_matches!(test_ctx.responder.next(&act1).unwrap(), (Some(_), ResponderAwaitingActThree(_)));
	}

	// Responder::AwaitingActOne -> Error (bad version byte)
	#[test]
	fn awaiting_act_one_to_awaiting_act_three_input_bad_version() {
		let test_ctx = TestCtx::new();
		let (mut act1, _) = do_next_or_panic!(test_ctx.initiator, &[]);
		// set version byte to 1
		act1[0] = 1;

		assert_eq!(test_ctx.responder.next(&act1).err(), Some(String::from("unexpected version")));
	}

	// Responder::AwaitingActOne -> Error (invalid hmac)
	#[test]
	fn awaiting_act_one_to_awaiting_act_three_invalid_hmac() {
		let test_ctx = TestCtx::new();
		// Modify the initiator to point to a different responder
		let (mut act1, _) = do_next_or_panic!(test_ctx.initiator, &[]);
		// corrupt the ciphertext
		act1[34] = 0;

		assert_eq!(test_ctx.responder.next(&act1).err(), Some(String::from("invalid hmac")));
	}

	// Responder::AwaitingActOne -> Error (invalid remote ephemeral key)
	#[test]
	fn awaiting_act_one_to_awaiting_act_three_invalid_remote_ephemeral_key() {
		let test_ctx = TestCtx::new();
		// Modify the initiator to point to a different responder
		let (mut act1, _) = do_next_or_panic!(test_ctx.initiator, &[]);
		// corrupt the ephemeral public key
		act1[1] = 0;

		assert_eq!(test_ctx.responder.next(&act1).err(), Some(String::from("invalid remote ephemeral public key")));
	}

	// Responder::AwaitingActOne -> AwaitingActThree
	#[test]
	fn awaiting_act_one_to_awaiting_act_three() {
		let test_ctx = TestCtx::new();
		let (act1, _) = do_next_or_panic!(test_ctx.initiator, &[]);

		assert_matches!(test_ctx.responder.next(&act1).unwrap(), (Some(_), ResponderAwaitingActThree(_)));
	}

	// Initiator::AwaitingActTwo -> Complete
	#[test]
	fn awaiting_act_two_to_complete() {
		let test_ctx = TestCtx::new();
		let (act1, awaiting_act_two_state) = do_next_or_panic!(test_ctx.initiator, &[]);
		let (act2, _awaiting_act_three_state) = do_next_or_panic!(test_ctx.responder, &act1);

		let remote_pubkey = if let (Some(_), Complete(Some((_, remote_pubkey)))) = awaiting_act_two_state.next(&act2).unwrap() {
			remote_pubkey
		} else {
			panic!();
		};

		assert_eq!(remote_pubkey, test_ctx.responder_static_public_key);
	}

	// Initiator::AwaitingActTwo -> Complete (with extra data)
	// Ensures that any remaining data in the read buffer is transferred to the conduit once
	// the handshake is complete
	// TODO: Is this valid? Don't we expect peers to need ActThree before sending additional data?
	#[test]
	fn awaiting_act_two_to_complete_excess_bytes_are_in_conduit() {
		let test_ctx = TestCtx::new();
		let (act1, awaiting_act_two_state) = do_next_or_panic!(test_ctx.initiator, &[]);
		let (mut act2, _awaiting_act_three_state) = do_next_or_panic!(test_ctx.responder, &act1);
		act2.extend_from_slice(&[1; 100]);

		let (_act3, complete_state) = do_next_or_panic!(awaiting_act_two_state, &act2);

		let conduit = if let Complete(Some((conduit, _))) = complete_state {
			conduit
		} else {
			panic!();
		};

		assert_eq!(100, conduit.decryptor.read_buffer_length());
	}

	// Initiator::AwaitingActTwo -> Error (input too small)
	#[test]
	fn awaiting_act_two_input_too_small() {
		let test_ctx = TestCtx::new();
		let (_act1, awaiting_act_two_state) = do_next_or_panic!(test_ctx.initiator, &[]);

		assert_eq!(awaiting_act_two_state.next(&[]).err(), Some(String::from("need at least 50 bytes")));
	}

	// Initiator::AwaitingActTwo -> Error (bad version byte)
	#[test]
	fn awaiting_act_two_bad_version_byte() {
		let test_ctx = TestCtx::new();
		let (act1, awaiting_act_two_state) = do_next_or_panic!(test_ctx.initiator, &[]);
		let (mut act2, _awaiting_act_three_state) = do_next_or_panic!(test_ctx.responder, &act1);
		// set invalid version byte
		act2[0] = 1;

		assert_eq!(awaiting_act_two_state.next(&act2).err(), Some(String::from("unexpected version")));
	}

	// Initiator::AwaitingActTwo -> Error (invalid hmac)
	#[test]
	fn awaiting_act_two_invalid_hmac() {
		let test_ctx = TestCtx::new();
		let (act1, awaiting_act_two_state) = do_next_or_panic!(test_ctx.initiator, &[]);
		let (mut act2, _awaiting_act_three_state) = do_next_or_panic!(test_ctx.responder, &act1);
		// corrupt the ciphertext
		act2[34] = 0;

		assert_eq!(awaiting_act_two_state.next(&act2).err(), Some(String::from("invalid hmac")));
	}

	// Initiator::AwaitingActTwo -> Error (invalid ephemeral public key)
	#[test]
	fn awaiting_act_two_invalid_ephemeral_public_key() {
		let test_ctx = TestCtx::new();
		let (act1, awaiting_act_two_state) = do_next_or_panic!(test_ctx.initiator, &[]);
		let (mut act2, _awaiting_act_three_state) = do_next_or_panic!(test_ctx.responder, &act1);
		// corrupt the ephemeral public key
		act2[1] = 0;

		assert_eq!(awaiting_act_two_state.next(&act2).err(), Some(String::from("invalid remote ephemeral public key")));
	}

	// Responder::AwaitingActThree -> Complete
	#[test]
	fn awaiting_act_three_to_complete() {
		let test_ctx = TestCtx::new();
		let (act1, awaiting_act_two_state) = do_next_or_panic!(test_ctx.initiator, &[]);
		let (act2, awaiting_act_three_state) = do_next_or_panic!(test_ctx.responder, &act1);
		let (act3, _complete_state) = do_next_or_panic!(awaiting_act_two_state, &act2);

		let remote_pubkey = if let (None, Complete(Some((_, remote_pubkey)))) = awaiting_act_three_state.next(&act3).unwrap() {
			remote_pubkey
		} else {
			panic!();
		};

		assert_eq!(remote_pubkey, test_ctx.initiator_public_key);
	}

	// Responder::AwaitingActThree -> None (with extra bytes)
	// Ensures that any remaining data in the read buffer is transferred to the conduit once
	// the handshake is complete
	#[test]
	fn awaiting_act_three_excess_bytes_after_complete_are_in_conduit() {
		let test_ctx = TestCtx::new();
		let (act1, awaiting_act_two_state) = do_next_or_panic!(test_ctx.initiator, &[]);
		let (act2, awaiting_act_three_state) = do_next_or_panic!(test_ctx.responder, &act1);
		let (mut act3, _complete_state) = do_next_or_panic!(awaiting_act_two_state, &act2);
		act3.extend_from_slice(&[2; 100]);

		let conduit = if let (_, Complete(Some((conduit, _)))) = awaiting_act_three_state.next(&act3).unwrap() {
			conduit
		} else {
			panic!();
		};

		assert_eq!(100, conduit.decryptor.read_buffer_length());
	}

	// Responder::AwaitingActThree -> Error (input too small)
	#[test]
	fn awaiting_act_three_input_too_small() {
		let test_ctx = TestCtx::new();
		let (act1, awaiting_act_two_state) = do_next_or_panic!(test_ctx.initiator, &[]);
		let (act2, awaiting_act_three_state) = do_next_or_panic!(test_ctx.responder, &act1);
		let (act3, _complete) = do_next_or_panic!(awaiting_act_two_state, &act2);

		assert_eq!(awaiting_act_three_state.next(&act3[..65]).err(), Some(String::from("need at least 66 bytes")));
	}

	// Responder::AwaitingActThree -> Error (bad version bytes)
	#[test]
	fn awaiting_act_three_bad_version_bytes() {
		let test_ctx = TestCtx::new();
		let (act1, awaiting_act_two_state) = do_next_or_panic!(test_ctx.initiator, &[]);
		let (act2, awaiting_act_three_state) = do_next_or_panic!(test_ctx.responder, &act1);
		let (mut act3, _complete_state) = do_next_or_panic!(awaiting_act_two_state, &act2);
		// set version byte to 1
		act3[0] = 1;

		assert_eq!(awaiting_act_three_state.next(&act3).err(), Some(String::from("unexpected version")));
	}

	// Responder::AwaitingActThree -> Error (invalid hmac)
	#[test]
	fn awaiting_act_three_invalid_hmac() {
		let test_ctx = TestCtx::new();
		let (act1, awaiting_act_two_state) = do_next_or_panic!(test_ctx.initiator, &[]);
		let (act2, awaiting_act_three_state) = do_next_or_panic!(test_ctx.responder, &act1);
		let (mut act3, _complete_state) = do_next_or_panic!(awaiting_act_two_state, &act2);
		// corrupt encrypted pubkey
		act3[1] = 1;

		assert_eq!(awaiting_act_three_state.next(&act3).err(), Some(String::from("invalid hmac")));
	}

	// Responder::AwaitingActThree -> Error (invalid tag hmac)
	#[test]
	fn awaiting_act_three_invalid_tag_hmac() {
		let test_ctx = TestCtx::new();
		let (act1, awaiting_act_two_state) = do_next_or_panic!(test_ctx.initiator, &[]);
		let (act2, awaiting_act_three_state) = do_next_or_panic!(test_ctx.responder, &act1);
		let (mut act3, _complete_state) = do_next_or_panic!(awaiting_act_two_state, &act2);
		// corrupt tag
		act3[50] = 1;

		assert_eq!(awaiting_act_three_state.next(&act3).err(), Some(String::from("invalid hmac")));
	}

	// Initiator::Complete -> Error
	#[test]
	#[should_panic(expected = "no acts left to process")]
	fn initiator_complete_next_fail() {
		let test_ctx = TestCtx::new();
		let (act1, awaiting_act_two_state) = do_next_or_panic!(test_ctx.initiator, &[]);
		let (act2, _awaiting_act_three_state) = do_next_or_panic!(test_ctx.responder, &act1);
		let (_act3, complete_state) = do_next_or_panic!(awaiting_act_two_state, &act2);

		complete_state.next(&[]).unwrap();
	}

	// Initiator::Complete -> Error
	#[test]
	#[should_panic(expected = "no acts left to process")]
	fn responder_complete_next_fail() {
		let test_ctx = TestCtx::new();
		let (act1, awaiting_act_two_state) = do_next_or_panic!(test_ctx.initiator, &[]);
		let (act2, awaiting_act_three_state) = do_next_or_panic!(test_ctx.responder, &act1);
		let (act3, _complete_state) = do_next_or_panic!(awaiting_act_two_state, &act2);

		let complete_state = if let (None, complete_state) = awaiting_act_three_state.next(&act3).unwrap() {
			complete_state
		} else {
			panic!();
		};

		complete_state.next(&[]).unwrap();
	}

	// Test the Act byte generation against known good hard-coded values in case the implementation
	// changes in a symmetric way that makes the other tests useless
	#[test]
	fn test_acts_against_reference_bytes() {
		let test_ctx = TestCtx::new();
		let (act1, awaiting_act_two_state) = do_next_or_panic!(test_ctx.initiator, &[]);
		let (act2, _awaiting_act_three_state) = do_next_or_panic!(test_ctx.responder, &act1);
		let (act3, _complete_state) = do_next_or_panic!(awaiting_act_two_state, &act2);

		assert_eq!(hex::encode(&act1),
				   "00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a");
		assert_eq!(hex::encode(&act2),
				   "0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae");
		assert_eq!(hex::encode(&act3),
				   "00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba");
	}
}
