/// Test library for test doubles used in the various peers unit tests

use bitcoin::secp256k1;
use bitcoin::secp256k1::key::{PublicKey, SecretKey};

use ln::peers::conduit::Conduit;
use ln::peers::handler::{SocketDescriptor, ITransport, PeerHandleError, MessageQueuer};
use ln::peers::transport::{IPeerHandshake, PayloadQueuer};

use std::rc::Rc;
use std::cell::{RefCell};
use std::hash::Hash;
use std::cmp;
use ln::wire::{Message, Encode};
use bitcoin::hashes::core::ops::Deref;
use util::logger::Logger;
use util::ser::{Writeable, VecWriter};
use ln::wire;

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

	/// Record if disconnect() was called on the Mock
	disconnect_called: Rc<RefCell<bool>>,
}

impl SocketDescriptorMock {
	/// Basic unbounded implementation where send_data() will always succeed
	pub(super) fn new() -> Self {
		Self {
			unbounded: Rc::new(RefCell::new(true)),
			send_recording: Rc::new(RefCell::new(Vec::new())),
			free_space: Rc::new(RefCell::new(0)),
			disconnect_called: Rc::new(RefCell::new(false))
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

	/// Retrieve the underlying recording for use in pattern matching or more complex value validation
	pub(super) fn get_recording(&self) -> Vec<(Vec<u8>, bool)> {
		self.send_recording.borrow().clone()
	}

	pub(super) fn disconnect_called(&self) -> bool {
		*self.disconnect_called.borrow_mut()
	}

	/// Allow future send_data() calls to succeed for the next added_room bytes. Not valid for
	/// unbounded mock descriptors
	pub(super) fn make_room(&mut self, added_room: usize) {
		assert!(!*self.unbounded.borrow());
		let mut free_space = self.free_space.borrow_mut();

		*free_space += added_room;
	}

	/// Clear the saved recording. Useful for resetting state between test phases.
	pub(super) fn clear_recording(&mut self) {
		self.send_recording.borrow_mut().clear();
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
		let mut val = self.disconnect_called.borrow_mut();
		assert!(!*val, "disconnect_socket() was alraedy called");
		*val = true;
	}
}

impl Clone for SocketDescriptorMock {
	fn clone(&self) -> Self {
		Self {
			unbounded: self.unbounded.clone(),
			send_recording: self.send_recording.clone(),
			free_space: self.free_space.clone(),
			disconnect_called: self.disconnect_called.clone(),
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

// Builder for TransportTestStub that allows tests to easily construct the Transport layer they
// want to use for their test.
pub(super) struct TransportStubBuilder {
	stub: TransportStub,
}

impl TransportStubBuilder {
	pub(super) fn new() -> Self {
		Self {
			stub: TransportStub {
				is_connected: false,
				messages: vec![],
				process_returns_error: false,
				returned_newly_connected: false,
				their_node_id: None,
			}
		}
	}

	pub(super) fn set_connected(mut self, their_node_id: &PublicKey) -> Self {
		self.stub.is_connected = true;
		self.stub.their_node_id = Some(their_node_id.clone());
		self
	}

	pub(super) fn process_returns_error(mut self) -> Self {
		self.stub.process_returns_error();
		self
	}

	pub(super) fn finish(self) -> TransportStub {
		self.stub
	}
}

pub(super) struct TransportStub {
	is_connected: bool,
	messages: Vec<Message>,
	process_returns_error: bool,
	returned_newly_connected: bool,
	their_node_id: Option<PublicKey>,
}

// &RefCell passthrough to allow unit tests to pass in a Transport to the PeerManager, but later
// modify it to fail, return messages, etc.
impl<'a> ITransport for &'a RefCell<TransportStub> {
	fn new_outbound(_initiator_static_private_key: &SecretKey, _responder_static_public_key: &PublicKey, _initiator_ephemeral_private_key: &SecretKey) -> Self {
		unimplemented!()
	}

	fn set_up_outbound(&mut self) -> Vec<u8> {
		self.borrow_mut().set_up_outbound()
	}

	fn new_inbound(_responder_static_private_key: &SecretKey, _responder_ephemeral_private_key: &SecretKey) -> Self {
		unimplemented!()
	}

	fn process_input(&mut self, input: &[u8], output_buffer: &mut impl PayloadQueuer) -> Result<bool, String> {
		self.borrow_mut().process_input(input, output_buffer)
	}

	fn is_connected(&self) -> bool {
		self.borrow().is_connected()
	}

	fn get_their_node_id(&self) -> PublicKey {
		self.borrow().get_their_node_id()
	}

	fn drain_messages<L: Deref>(&mut self, logger: L) -> Result<Vec<Message>, PeerHandleError> where L::Target: Logger {
		self.borrow_mut().drain_messages(logger)
	}
}

impl<'a> MessageQueuer for &'a RefCell<TransportStub> {
	fn enqueue_message<M: Encode + Writeable, Q: PayloadQueuer, L: Deref>(&mut self, message: &M, output_buffer: &mut Q, logger: L) where L::Target: Logger {
		self.borrow_mut().enqueue_message(message, output_buffer, logger)
	}
}

impl TransportStub {
	pub(super) fn process_returns_error(&mut self) {
		self.process_returns_error = true;
	}

	pub(super) fn add_incoming_message(&mut self, message: Message) {
		assert!(self.is_connected, "Can't set messages on unconnected Transport");
		self.messages.push(message);
	}
}

// Stub implementation for ITransport with a fixed connection state. All enqueue_message() calls
// are placed directly into the PayloadQueuer unencrypted for easier test validation.
impl ITransport for TransportStub {
	fn new_outbound(_initiator_static_private_key: &SecretKey, _responder_static_public_key: &PublicKey, _initiator_ephemeral_private_key: &SecretKey) -> Self {
		unimplemented!()
	}

	fn set_up_outbound(&mut self) -> Vec<u8> {
		vec![]
	}

	fn new_inbound(_responder_static_private_key: &SecretKey, _responder_ephemeral_private_key: &SecretKey) -> Self {
		unimplemented!()
	}

	fn process_input(&mut self, _input: &[u8], _output_buffer: &mut impl PayloadQueuer) -> Result<bool, String> {
		if self.process_returns_error {
			Err("Oh no!".to_string())
		} else {
			if self.is_connected() {

				// Simulate the newly_connected behavior by returning Ok(true) on the first call
				if !self.returned_newly_connected {
					self.returned_newly_connected = true;
					return Ok(true)
				}
			}
			return Ok(false)
		}
	}

	fn is_connected(&self) -> bool {
		self.their_node_id.is_some()
	}

	fn get_their_node_id(&self) -> PublicKey {
		self.their_node_id.unwrap()
	}

	fn drain_messages<L: Deref>(&mut self, _logger: L) -> Result<Vec<Message>, PeerHandleError> where L::Target: Logger {
		Ok(self.messages.drain(..).collect())
	}
}

impl MessageQueuer for TransportStub {
	fn enqueue_message<M: Encode + Writeable, Q: PayloadQueuer, L: Deref>(&mut self, message: &M, output_buffer: &mut Q, _logger: L)
		where L::Target: Logger {
		let mut buffer = VecWriter(Vec::new());
		wire::write(message, &mut buffer).unwrap();
		output_buffer.push_back(buffer.0);
	}
}