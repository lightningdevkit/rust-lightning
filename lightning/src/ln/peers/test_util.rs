/// Test library for test doubles used in the various peers unit tests

use bitcoin::secp256k1;
use bitcoin::secp256k1::key::{PublicKey, SecretKey};

use ln::peers::conduit::Conduit;
use ln::peers::handler::{SocketDescriptor, PayloadQueuer};
use ln::peers::transport::IPeerHandshake;

use std::rc::Rc;
use std::cell::RefCell;
use std::hash::Hash;
use std::cmp;

macro_rules! assert_matches {
	($actual:expr, $expected:pat) => {
		match $actual {
			$expected => (),
			_ => panic!()
		}
	}
}

/// Stub implementation of IPeerHandshake that returns an error for process_act()
pub(super) struct PeerHandshakeTestStubFail { }

impl IPeerHandshake for PeerHandshakeTestStubFail {
	fn new_outbound(_initiator_static_private_key: &SecretKey, _responder_static_public_key: &PublicKey, _initiator_ephemeral_private_key: &SecretKey) -> Self {
		PeerHandshakeTestStubFail { }
	}

	fn set_up_outbound(&mut self) -> Vec<u8> {
		vec![]
	}

	fn new_inbound(_responder_static_private_key: &SecretKey, _responder_ephemeral_private_key: &SecretKey) -> Self {
		PeerHandshakeTestStubFail { }
	}

	fn process_act(&mut self, _input: &[u8]) -> Result<(Option<Vec<u8>>, Option<(Conduit, PublicKey)>), String> {
		Err("Oh no!".to_string())
	}
}

/// Stub implementation of IPeerHandshake that returns &[1] from process_act()
pub(super) struct PeerHandshakeTestStubBytes { }

impl PeerHandshakeTestStubBytes {
	pub(crate) const RETURNED_BYTES: [u8; 1] = [1];
}

impl IPeerHandshake for PeerHandshakeTestStubBytes {

	fn new_outbound(_initiator_static_private_key: &SecretKey, _responder_static_public_key: &PublicKey, _initiator_ephemeral_private_key: &SecretKey) -> Self {
		PeerHandshakeTestStubBytes { }
	}

	fn set_up_outbound(&mut self) -> Vec<u8> {
		vec![]
	}

	fn new_inbound(_responder_static_private_key: &SecretKey, _responder_ephemeral_private_key: &SecretKey) -> Self {
		PeerHandshakeTestStubBytes { }
	}

	fn process_act(&mut self, _input: &[u8]) -> Result<(Option<Vec<u8>>, Option<(Conduit, PublicKey)>), String> {
		Ok((Some(Self::RETURNED_BYTES[..].to_vec()), None))
	}
}

/// Stub implementation of IPeerhandshake that returns Some(Conduit, PublicKey)
pub(super) struct PeerHandshakeTestStubComplete { }

impl IPeerHandshake for PeerHandshakeTestStubComplete {
	fn new_outbound(_initiator_static_private_key: &SecretKey, _responder_static_public_key: &PublicKey, _initiator_ephemeral_private_key: &SecretKey) -> Self {
		PeerHandshakeTestStubComplete { }
	}

	fn set_up_outbound(&mut self) -> Vec<u8> {
		vec![]
	}

	fn new_inbound(_responder_static_private_key: &SecretKey, _responder_ephemeral_private_key: &SecretKey) -> Self {
		PeerHandshakeTestStubComplete { }
	}

	fn process_act(&mut self, _input: &[u8]) -> Result<(Option<Vec<u8>>, Option<(Conduit, PublicKey)>), String> {
		let curve = secp256k1::Secp256k1::new();
		let private_key = SecretKey::from_slice(&[0x_21_u8; 32]).unwrap();
		let public_key = PublicKey::from_secret_key(&curve, &private_key);
		let conduit = Conduit::new([0;32], [0;32], [0;32]);

		Ok((None, Some((conduit, public_key))))
	}
}

/// Mock implementation of the SocketDescriptor trait that can be used in tests to finely control
/// the send_data() behavior.
///
/// Additionally, records the actual calls to send_data() for later validation.
#[derive(Debug, Eq)]
pub(super) struct SocketDescriptorMock {
	/// If true, all send_data() calls will succeed
	unbounded: Rc<RefCell<bool>>,

	/// Amount of free space in the descriptor for send_data() bytes
	free_space: Rc<RefCell<usize>>,

	/// Vector of arguments and return values to send_data() used for validation
	send_recording: Rc<RefCell<Vec<(Vec<u8>, bool)>>>,
}

impl SocketDescriptorMock {
	/// Basic unbounded implementation where send_data() will always succeed
	pub(super) fn new() -> Self {
		Self {
			unbounded: Rc::new(RefCell::new(true)),
			send_recording: Rc::new(RefCell::new(Vec::new())),
			free_space: Rc::new(RefCell::new(0))
		}
	}

	/// Used for tests that want to return partial sends after a certain amount of data is sent through send_data()
	pub(super) fn with_fixed_size(limit: usize) -> Self {
		let mut descriptor = Self::new();
		descriptor.unbounded = Rc::new(RefCell::new(false));
		descriptor.free_space = Rc::new(RefCell::new(limit));

		descriptor
	}

	/// Standard Mock api to verify actual vs. expected calls
	pub(super) fn assert_called_with(&self, expectation: Vec<(Vec<u8>, bool)>) {
		assert_eq!(expectation.as_slice(), self.send_recording.borrow().as_slice())
	}

	/// Allow future send_data() calls to succeed for the next added_room bytes. Not valid for
	/// unbounded mock descriptors
	pub(super) fn make_room(&mut self, added_room: usize) {
		assert!(!*self.unbounded.borrow());
		let mut free_space = self.free_space.borrow_mut();

		*free_space += added_room;
	}
}

impl SocketDescriptor for SocketDescriptorMock {
	fn send_data(&mut self, data: &[u8], resume_read: bool) -> usize {
		self.send_recording.borrow_mut().push((data.to_vec(), resume_read));

		let mut free_space = self.free_space.borrow_mut();

		// Unbounded just flush everything
		return if *self.unbounded.borrow() {
			data.len()
		}
		// Bounded flush up to the free_space limit
		else {
			let write_len = cmp::min(data.len(), *free_space);
			*free_space -= write_len;
			write_len
		}
	}

	fn disconnect_socket(&mut self) {
		unimplemented!()
	}
}

impl Clone for SocketDescriptorMock {
	fn clone(&self) -> Self {
		Self {
			unbounded: self.unbounded.clone(),
			send_recording: self.send_recording.clone(),
			free_space: self.free_space.clone()
		}
	}
}

impl PartialEq for SocketDescriptorMock {
	fn eq(&self, o: &Self) -> bool {
		Rc::ptr_eq(&self.send_recording, &o.send_recording)
	}
}
impl Hash for SocketDescriptorMock {
	fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
		self.send_recording.as_ptr().hash(state)
	}
}

/// Implement PayloadQueuer for Vec<Vec<u8>> so it can be used as a Spy in tests
impl PayloadQueuer for Vec<Vec<u8>> {
	fn push_back(&mut self, item: Vec<u8>) {
		self.push(item)
	}

	fn is_empty(&self) -> bool {
		self.is_empty()
	}

	fn queue_space(&self) -> usize {
		unimplemented!()
	}
}

