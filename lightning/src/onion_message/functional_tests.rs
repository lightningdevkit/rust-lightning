// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Onion message testing and test utilities live here.

use crate::blinded_path::BlindedPath;
use crate::ln::features::InitFeatures;
use crate::ln::msgs::{self, DecodeError, OnionMessageHandler};
use crate::sign::{NodeSigner, Recipient};
use crate::util::ser::{FixedLengthReader, LengthReadable, Writeable, Writer};
use crate::util::test_utils;
use super::{CustomOnionMessageHandler, Destination, MessageRouter, OffersMessage, OffersMessageHandler, OnionMessageContents, OnionMessagePath, OnionMessenger, PendingOnionMessage, SendError};

use bitcoin::network::constants::Network;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

use crate::io;
use crate::io_extras::read_to_end;
use crate::sync::{Arc, Mutex};

use crate::prelude::*;

struct MessengerNode {
	keys_manager: Arc<test_utils::TestKeysInterface>,
	messenger: OnionMessenger<
		Arc<test_utils::TestKeysInterface>,
		Arc<test_utils::TestKeysInterface>,
		Arc<test_utils::TestLogger>,
		Arc<TestMessageRouter>,
		Arc<TestOffersMessageHandler>,
		Arc<TestCustomMessageHandler>
	>,
	custom_message_handler: Arc<TestCustomMessageHandler>,
}

impl MessengerNode {
	fn get_node_pk(&self) -> PublicKey {
		self.keys_manager.get_node_id(Recipient::Node).unwrap()
	}
}

struct TestMessageRouter {}

impl MessageRouter for TestMessageRouter {
	fn find_path(
		&self, _sender: PublicKey, _peers: Vec<PublicKey>, destination: Destination
	) -> Result<OnionMessagePath, ()> {
		Ok(OnionMessagePath {
			intermediate_nodes: vec![],
			destination,
		})
	}
}

struct TestOffersMessageHandler {}

impl OffersMessageHandler for TestOffersMessageHandler {
	fn handle_message(&self, _message: OffersMessage) -> Option<OffersMessage> {
		None
	}
}

#[derive(Clone, Debug, PartialEq)]
enum TestCustomMessage {
	Request,
	Response,
}

const CUSTOM_REQUEST_MESSAGE_TYPE: u64 = 4242;
const CUSTOM_RESPONSE_MESSAGE_TYPE: u64 = 4343;
const CUSTOM_REQUEST_MESSAGE_CONTENTS: [u8; 32] = [42; 32];
const CUSTOM_RESPONSE_MESSAGE_CONTENTS: [u8; 32] = [43; 32];

impl OnionMessageContents for TestCustomMessage {
	fn tlv_type(&self) -> u64 {
		match self {
			TestCustomMessage::Request => CUSTOM_REQUEST_MESSAGE_TYPE,
			TestCustomMessage::Response => CUSTOM_RESPONSE_MESSAGE_TYPE,
		}
	}
}

impl Writeable for TestCustomMessage {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		match self {
			TestCustomMessage::Request => Ok(CUSTOM_REQUEST_MESSAGE_CONTENTS.write(w)?),
			TestCustomMessage::Response => Ok(CUSTOM_RESPONSE_MESSAGE_CONTENTS.write(w)?),
		}
	}
}

struct TestCustomMessageHandler {
	expected_messages: Mutex<VecDeque<TestCustomMessage>>,
}

impl TestCustomMessageHandler {
	fn new() -> Self {
		Self { expected_messages: Mutex::new(VecDeque::new()) }
	}

	fn expect_message(&self, message: TestCustomMessage) {
		self.expected_messages.lock().unwrap().push_back(message);
	}
}

impl Drop for TestCustomMessageHandler {
	fn drop(&mut self) {
		#[cfg(feature = "std")] {
			if std::thread::panicking() {
				return;
			}
		}
		assert!(self.expected_messages.lock().unwrap().is_empty());
	}
}

impl CustomOnionMessageHandler for TestCustomMessageHandler {
	type CustomMessage = TestCustomMessage;
	fn handle_custom_message(&self, msg: Self::CustomMessage) -> Option<Self::CustomMessage> {
		match self.expected_messages.lock().unwrap().pop_front() {
			Some(expected_msg) => assert_eq!(expected_msg, msg),
			None => panic!("Unexpected message: {:?}", msg),
		}

		match msg {
			TestCustomMessage::Request => Some(TestCustomMessage::Response),
			TestCustomMessage::Response => None,
		}
	}
	fn read_custom_message<R: io::Read>(&self, message_type: u64, buffer: &mut R) -> Result<Option<Self::CustomMessage>, DecodeError> where Self: Sized {
		match message_type {
			CUSTOM_REQUEST_MESSAGE_TYPE => {
				let buf = read_to_end(buffer)?;
				assert_eq!(buf, CUSTOM_REQUEST_MESSAGE_CONTENTS);
				Ok(Some(TestCustomMessage::Request))
			},
			CUSTOM_RESPONSE_MESSAGE_TYPE => {
				let buf = read_to_end(buffer)?;
				assert_eq!(buf, CUSTOM_RESPONSE_MESSAGE_CONTENTS);
				Ok(Some(TestCustomMessage::Response))
			},
			_ => Ok(None),
		}
	}
	fn release_pending_custom_messages(&self) -> Vec<PendingOnionMessage<Self::CustomMessage>> {
		vec![]
	}
}

fn create_nodes(num_messengers: u8) -> Vec<MessengerNode> {
	let mut nodes = Vec::new();
	for i in 0..num_messengers {
		let logger = Arc::new(test_utils::TestLogger::with_id(format!("node {}", i)));
		let seed = [i as u8; 32];
		let keys_manager = Arc::new(test_utils::TestKeysInterface::new(&seed, Network::Testnet));
		let message_router = Arc::new(TestMessageRouter {});
		let offers_message_handler = Arc::new(TestOffersMessageHandler {});
		let custom_message_handler = Arc::new(TestCustomMessageHandler::new());
		nodes.push(MessengerNode {
			keys_manager: keys_manager.clone(),
			messenger: OnionMessenger::new(
				keys_manager.clone(), keys_manager, logger.clone(), message_router,
				offers_message_handler, custom_message_handler.clone()
			),
			custom_message_handler,
		});
	}
	for idx in 0..num_messengers - 1 {
		let i = idx as usize;
		let mut features = InitFeatures::empty();
		features.set_onion_messages_optional();
		let init_msg = msgs::Init { features, networks: None, remote_network_address: None };
		nodes[i].messenger.peer_connected(&nodes[i + 1].get_node_pk(), &init_msg.clone(), true).unwrap();
		nodes[i + 1].messenger.peer_connected(&nodes[i].get_node_pk(), &init_msg.clone(), false).unwrap();
	}
	nodes
}

fn pass_along_path(path: &Vec<MessengerNode>) {
	let mut prev_node = &path[0];
	for node in path.into_iter().skip(1) {
		let events = prev_node.messenger.release_pending_msgs();
		let onion_msg =  {
			let msgs = events.get(&node.get_node_pk()).unwrap();
			assert_eq!(msgs.len(), 1);
			msgs[0].clone()
		};
		node.messenger.handle_onion_message(&prev_node.get_node_pk(), &onion_msg);
		prev_node = node;
	}
}

#[test]
fn one_unblinded_hop() {
	let nodes = create_nodes(2);
	let test_msg = TestCustomMessage::Response;

	let path = OnionMessagePath {
		intermediate_nodes: vec![],
		destination: Destination::Node(nodes[1].get_node_pk()),
	};
	nodes[0].messenger.send_onion_message(path, test_msg, None).unwrap();
	nodes[1].custom_message_handler.expect_message(TestCustomMessage::Response);
	pass_along_path(&nodes);
}

#[test]
fn two_unblinded_hops() {
	let nodes = create_nodes(3);
	let test_msg = TestCustomMessage::Response;

	let path = OnionMessagePath {
		intermediate_nodes: vec![nodes[1].get_node_pk()],
		destination: Destination::Node(nodes[2].get_node_pk()),
	};
	nodes[0].messenger.send_onion_message(path, test_msg, None).unwrap();
	nodes[2].custom_message_handler.expect_message(TestCustomMessage::Response);
	pass_along_path(&nodes);
}

#[test]
fn one_blinded_hop() {
	let nodes = create_nodes(2);
	let test_msg = TestCustomMessage::Response;

	let secp_ctx = Secp256k1::new();
	let blinded_path = BlindedPath::new_for_message(&[nodes[1].get_node_pk()], &*nodes[1].keys_manager, &secp_ctx).unwrap();
	let path = OnionMessagePath {
		intermediate_nodes: vec![],
		destination: Destination::BlindedPath(blinded_path),
	};
	nodes[0].messenger.send_onion_message(path, test_msg, None).unwrap();
	nodes[1].custom_message_handler.expect_message(TestCustomMessage::Response);
	pass_along_path(&nodes);
}

#[test]
fn two_unblinded_two_blinded() {
	let nodes = create_nodes(5);
	let test_msg = TestCustomMessage::Response;

	let secp_ctx = Secp256k1::new();
	let blinded_path = BlindedPath::new_for_message(&[nodes[3].get_node_pk(), nodes[4].get_node_pk()], &*nodes[4].keys_manager, &secp_ctx).unwrap();
	let path = OnionMessagePath {
		intermediate_nodes: vec![nodes[1].get_node_pk(), nodes[2].get_node_pk()],
		destination: Destination::BlindedPath(blinded_path),
	};

	nodes[0].messenger.send_onion_message(path, test_msg, None).unwrap();
	nodes[4].custom_message_handler.expect_message(TestCustomMessage::Response);
	pass_along_path(&nodes);
}

#[test]
fn three_blinded_hops() {
	let nodes = create_nodes(4);
	let test_msg = TestCustomMessage::Response;

	let secp_ctx = Secp256k1::new();
	let blinded_path = BlindedPath::new_for_message(&[nodes[1].get_node_pk(), nodes[2].get_node_pk(), nodes[3].get_node_pk()], &*nodes[3].keys_manager, &secp_ctx).unwrap();
	let path = OnionMessagePath {
		intermediate_nodes: vec![],
		destination: Destination::BlindedPath(blinded_path),
	};

	nodes[0].messenger.send_onion_message(path, test_msg, None).unwrap();
	nodes[3].custom_message_handler.expect_message(TestCustomMessage::Response);
	pass_along_path(&nodes);
}

#[test]
fn too_big_packet_error() {
	// Make sure we error as expected if a packet is too big to send.
	let nodes = create_nodes(2);
	let test_msg = TestCustomMessage::Response;

	let hop_node_id = nodes[1].get_node_pk();
	let hops = vec![hop_node_id; 400];
	let path = OnionMessagePath {
		intermediate_nodes: hops,
		destination: Destination::Node(hop_node_id),
	};
	let err = nodes[0].messenger.send_onion_message(path, test_msg, None).unwrap_err();
	assert_eq!(err, SendError::TooBigPacket);
}

#[test]
fn we_are_intro_node() {
	// If we are sending straight to a blinded path and we are the introduction node, we need to
	// advance the blinded path by 1 hop so the second hop is the new introduction node.
	let mut nodes = create_nodes(3);
	let test_msg = TestCustomMessage::Response;

	let secp_ctx = Secp256k1::new();
	let blinded_path = BlindedPath::new_for_message(&[nodes[0].get_node_pk(), nodes[1].get_node_pk(), nodes[2].get_node_pk()], &*nodes[2].keys_manager, &secp_ctx).unwrap();
	let path = OnionMessagePath {
		intermediate_nodes: vec![],
		destination: Destination::BlindedPath(blinded_path),
	};

	nodes[0].messenger.send_onion_message(path, test_msg.clone(), None).unwrap();
	nodes[2].custom_message_handler.expect_message(TestCustomMessage::Response);
	pass_along_path(&nodes);

	// Try with a two-hop blinded path where we are the introduction node.
	let blinded_path = BlindedPath::new_for_message(&[nodes[0].get_node_pk(), nodes[1].get_node_pk()], &*nodes[1].keys_manager, &secp_ctx).unwrap();
	let path = OnionMessagePath {
		intermediate_nodes: vec![],
		destination: Destination::BlindedPath(blinded_path),
	};
	nodes[0].messenger.send_onion_message(path, test_msg, None).unwrap();
	nodes[1].custom_message_handler.expect_message(TestCustomMessage::Response);
	nodes.remove(2);
	pass_along_path(&nodes);
}

#[test]
fn invalid_blinded_path_error() {
	// Make sure we error as expected if a provided blinded path has 0 or 1 hops.
	let nodes = create_nodes(3);
	let test_msg = TestCustomMessage::Response;

	// 0 hops
	let secp_ctx = Secp256k1::new();
	let mut blinded_path = BlindedPath::new_for_message(&[nodes[1].get_node_pk(), nodes[2].get_node_pk()], &*nodes[2].keys_manager, &secp_ctx).unwrap();
	blinded_path.blinded_hops.clear();
	let path = OnionMessagePath {
		intermediate_nodes: vec![],
		destination: Destination::BlindedPath(blinded_path),
	};
	let err = nodes[0].messenger.send_onion_message(path, test_msg.clone(), None).unwrap_err();
	assert_eq!(err, SendError::TooFewBlindedHops);
}

#[test]
fn reply_path() {
	let mut nodes = create_nodes(4);
	let test_msg = TestCustomMessage::Request;
	let secp_ctx = Secp256k1::new();

	// Destination::Node
	let path = OnionMessagePath {
		intermediate_nodes: vec![nodes[1].get_node_pk(), nodes[2].get_node_pk()],
		destination: Destination::Node(nodes[3].get_node_pk()),
	};
	let reply_path = BlindedPath::new_for_message(&[nodes[2].get_node_pk(), nodes[1].get_node_pk(), nodes[0].get_node_pk()], &*nodes[0].keys_manager, &secp_ctx).unwrap();
	nodes[0].messenger.send_onion_message(path, test_msg.clone(), Some(reply_path)).unwrap();
	nodes[3].custom_message_handler.expect_message(TestCustomMessage::Request);
	pass_along_path(&nodes);
	// Make sure the last node successfully decoded the reply path.
	nodes[0].custom_message_handler.expect_message(TestCustomMessage::Response);
	nodes.reverse();
	pass_along_path(&nodes);

	// Destination::BlindedPath
	let blinded_path = BlindedPath::new_for_message(&[nodes[1].get_node_pk(), nodes[2].get_node_pk(), nodes[3].get_node_pk()], &*nodes[3].keys_manager, &secp_ctx).unwrap();
	let path = OnionMessagePath {
		intermediate_nodes: vec![],
		destination: Destination::BlindedPath(blinded_path),
	};
	let reply_path = BlindedPath::new_for_message(&[nodes[2].get_node_pk(), nodes[1].get_node_pk(), nodes[0].get_node_pk()], &*nodes[0].keys_manager, &secp_ctx).unwrap();

	nodes[0].messenger.send_onion_message(path, test_msg, Some(reply_path)).unwrap();
	nodes[3].custom_message_handler.expect_message(TestCustomMessage::Request);
	pass_along_path(&nodes);

	// Make sure the last node successfully decoded the reply path.
	nodes[0].custom_message_handler.expect_message(TestCustomMessage::Response);
	nodes.reverse();
	pass_along_path(&nodes);
}

#[test]
fn invalid_custom_message_type() {
	let nodes = create_nodes(2);

	struct InvalidCustomMessage{}
	impl OnionMessageContents for InvalidCustomMessage {
		fn tlv_type(&self) -> u64 {
			// Onion message contents must have a TLV >= 64.
			63
		}
	}

	impl Writeable for InvalidCustomMessage {
		fn write<W: Writer>(&self, _w: &mut W) -> Result<(), io::Error> { unreachable!() }
	}

	let test_msg = InvalidCustomMessage {};
	let path = OnionMessagePath {
		intermediate_nodes: vec![],
		destination: Destination::Node(nodes[1].get_node_pk()),
	};
	let err = nodes[0].messenger.send_onion_message(path, test_msg, None).unwrap_err();
	assert_eq!(err, SendError::InvalidMessage);
}

#[test]
fn peer_buffer_full() {
	let nodes = create_nodes(2);
	let test_msg = TestCustomMessage::Request;
	let path = OnionMessagePath {
		intermediate_nodes: vec![],
		destination: Destination::Node(nodes[1].get_node_pk()),
	};
	for _ in 0..188 { // Based on MAX_PER_PEER_BUFFER_SIZE in OnionMessenger
		nodes[0].messenger.send_onion_message(path.clone(), test_msg.clone(), None).unwrap();
	}
	let err = nodes[0].messenger.send_onion_message(path, test_msg, None).unwrap_err();
	assert_eq!(err, SendError::BufferFull);
}

#[test]
fn many_hops() {
	// Check we can send over a route with many hops. This will exercise our logic for onion messages
	// of size [`crate::onion_message::packet::BIG_PACKET_HOP_DATA_LEN`].
	let num_nodes: usize = 25;
	let nodes = create_nodes(num_nodes as u8);
	let test_msg = TestCustomMessage::Response;

	let mut intermediate_nodes = vec![];
	for i in 1..(num_nodes-1) {
		intermediate_nodes.push(nodes[i].get_node_pk());
	}

	let path = OnionMessagePath {
		intermediate_nodes,
		destination: Destination::Node(nodes[num_nodes-1].get_node_pk()),
	};
	nodes[0].messenger.send_onion_message(path, test_msg, None).unwrap();
	nodes[num_nodes-1].custom_message_handler.expect_message(TestCustomMessage::Response);
	pass_along_path(&nodes);
}

#[test]
fn spec_test_vector() {
	let keys_mgrs = vec![
		(Arc::new(test_utils::TestKeysInterface::new(&[0; 32], Network::Testnet)), // Alice
		 Arc::new(test_utils::TestNodeSigner::new(SecretKey::from_slice(&hex::decode("4141414141414141414141414141414141414141414141414141414141414141").unwrap()).unwrap()))),
		(Arc::new(test_utils::TestKeysInterface::new(&[1; 32], Network::Testnet)), // Bob
		 Arc::new(test_utils::TestNodeSigner::new(SecretKey::from_slice(&hex::decode("4242424242424242424242424242424242424242424242424242424242424242").unwrap()).unwrap()))),
		(Arc::new(test_utils::TestKeysInterface::new(&[2; 32], Network::Testnet)), // Carol
		 Arc::new(test_utils::TestNodeSigner::new(SecretKey::from_slice(&hex::decode("4343434343434343434343434343434343434343434343434343434343434343").unwrap()).unwrap()))),
		(Arc::new(test_utils::TestKeysInterface::new(&[3; 32], Network::Testnet)), // Dave
		 Arc::new(test_utils::TestNodeSigner::new(SecretKey::from_slice(&hex::decode("4444444444444444444444444444444444444444444444444444444444444444").unwrap()).unwrap()))),
	];
	let message_router = Arc::new(TestMessageRouter {});
	let offers_message_handler = Arc::new(TestOffersMessageHandler {});
	let custom_message_handler = Arc::new(TestCustomMessageHandler::new());
	let mut nodes = Vec::new();
	for (idx, (entropy_source, node_signer)) in keys_mgrs.iter().enumerate() {
		let logger = Arc::new(test_utils::TestLogger::with_id(format!("node {}", idx)));
		nodes.push(OnionMessenger::new(
			entropy_source.clone(), node_signer.clone(), logger.clone(), message_router.clone(),
			offers_message_handler.clone(), custom_message_handler.clone()
		));
	}
	for idx in 0..nodes.len() - 1 {
		let i = idx as usize;
		let mut features = InitFeatures::empty();
		features.set_onion_messages_optional();
		let init_msg = msgs::Init { features, networks: None, remote_network_address: None };
		nodes[i].peer_connected(
			&keys_mgrs[i + 1].1.get_node_id(Recipient::Node).unwrap(), &init_msg.clone(), true).unwrap();
		nodes[i + 1].peer_connected(
			&keys_mgrs[i].1.get_node_id(Recipient::Node).unwrap(), &init_msg.clone(), false).unwrap();
	}

	// Hardcode the sender->Alice onion message, because it includes an unknown TLV of type 1, which
	// LDK doesn't support constructing.
	let sender_to_alice_packet_bytes = hex::decode("0002531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe33793b828776d70aabbd8cef1a5b52d5a397ae1a20f20435ff6057cd8be339d5aee226660ef73b64afa45dbf2e6e8e26eb96a259b2db5aeecda1ce2e768bbc35d389d7f320ca3d2bd14e2689bef2f5ac0307eaaabc1924eb972c1563d4646ae131accd39da766257ed35ea36e4222527d1db4fa7b2000aab9eafcceed45e28b5560312d4e2299bd8d1e7fe27d10925966c28d497aec400b4630485e82efbabc00550996bdad5d6a9a8c75952f126d14ad2cff91e16198691a7ef2937de83209285f1fb90944b4e46bca7c856a9ce3da10cdf2a7d00dc2bf4f114bc4d3ed67b91cbde558ce9af86dc81fbdc37f8e301b29e23c1466659c62bdbf8cff5d4c20f0fb0851ec72f5e9385dd40fdd2e3ed67ca4517117825665e50a3e26f73c66998daf18e418e8aef9ce2d20da33c3629db2933640e03e7b44c2edf49e9b482db7b475cfd4c617ae1d46d5c24d697846f9f08561eac2b065f9b382501f6eabf07343ed6c602f61eab99cdb52adf63fd44a8db2d3016387ea708fc1c08591e19b4d9984ebe31edbd684c2ea86526dd8c7732b1d8d9117511dc1b643976d356258fce8313b1cb92682f41ab72dedd766f06de375f9edacbcd0ca8c99b865ea2b7952318ea1fd20775a28028b5cf59dece5de14f615b8df254eee63493a5111ea987224bea006d8f1b60d565eef06ac0da194dba2a6d02e79b2f2f34e9ca6e1984a507319d86e9d4fcaeea41b4b9144e0b1826304d4cc1da61cfc5f8b9850697df8adc5e9d6f3acb3219b02764b4909f2b2b22e799fd66c383414a84a7d791b899d4aa663770009eb122f90282c8cb9cda16aba6897edcf9b32951d0080c0f52be3ca011fbec3fb16423deb47744645c3b05fdbd932edf54ba6efd26e65340a8e9b1d1216582e1b30d64524f8ca2d6c5ba63a38f7120a3ed71bed8960bcac2feee2dd41c90be48e3c11ec518eb3d872779e4765a6cc28c6b0fa71ab57ced73ae963cc630edae4258cba2bf25821a6ae049fec2fca28b5dd1bb004d92924b65701b06dcf37f0ccd147a13a03f9bc0f98b7d78fe9058089756931e2cd0e0ed92ec6759d07b248069526c67e9e6ce095118fd3501ba0f858ef030b76c6f6beb11a09317b5ad25343f4b31aef02bc555951bc7791c2c289ecf94d5544dcd6ad3021ed8e8e3db34b2a73e1eedb57b578b068a5401836d6e382110b73690a94328c404af25e85a8d6b808893d1b71af6a31fadd8a8cc6e31ecc0d9ff7e6b91fd03c274a5c1f1ccd25b61150220a3fddb04c91012f5f7a83a5c90deb2470089d6e38cd5914b9c946eca6e9d31bbf8667d36cf87effc3f3ff283c21dd4137bd569fe7cf758feac94053e4baf7338bb592c8b7c291667fadf4a9bf9a2a154a18f612cbc7f851b3f8f2070e0a9d180622ee4f8e81b0ab250d504cef24116a3ff188cc829fcd8610b56343569e8dc997629410d1967ca9dd1d27eec5e01e4375aad16c46faba268524b154850d0d6fe3a76af2c6aa3e97647c51036049ac565370028d6a439a2672b6face56e1b171496c0722cfa22d9da631be359661617c5d5a2d286c5e19db9452c1e21a0107b6400debda2decb0c838f342dd017cdb2dccdf1fe97e3df3f881856b546997a3fed9e279c720145101567dd56be21688fed66bf9759e432a9aa89cbbd225d13cdea4ca05f7a45cfb6a682a3d5b1e18f7e6cf934fae5098108bae9058d05c3387a01d8d02a656d2bfff67e9f46b2d8a6aac28129e52efddf6e552214c3f8a45bc7a912cca9a7fec1d7d06412c6972cb9e3dc518983f56530b8bffe7f92c4b6eb47d4aef59fb513c4653a42de61bc17ad7728e7fc7590ff05a9e991de03f023d0aaf8688ed6170def5091c66576a424ac1cb").unwrap();
	let sender_to_alice_packet_bytes_len = sender_to_alice_packet_bytes.len() as u64;
	let mut reader = io::Cursor::new(sender_to_alice_packet_bytes);
	let mut packet_reader = FixedLengthReader::new(&mut reader, sender_to_alice_packet_bytes_len);
	let sender_to_alice_packet: super::Packet =
		<super::Packet as LengthReadable>::read(&mut packet_reader).unwrap();
	let secp_ctx = Secp256k1::new();
	let sender_to_alice_om = msgs::OnionMessage {
		blinding_point: PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&hex::decode("6363636363636363636363636363636363636363636363636363636363636363").unwrap()).unwrap()),
		onion_routing_packet: sender_to_alice_packet,
	};
	// The spec test vectors prepend the OM message type (513) to the encoded onion message strings,
	// which is why the asserted strings differ slightly from the spec.
	assert_eq!(sender_to_alice_om.encode(), hex::decode("031195a8046dcbb8e17034bca630065e7a0982e4e36f6f7e5a8d4554e4846fcd9905560002531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe33793b828776d70aabbd8cef1a5b52d5a397ae1a20f20435ff6057cd8be339d5aee226660ef73b64afa45dbf2e6e8e26eb96a259b2db5aeecda1ce2e768bbc35d389d7f320ca3d2bd14e2689bef2f5ac0307eaaabc1924eb972c1563d4646ae131accd39da766257ed35ea36e4222527d1db4fa7b2000aab9eafcceed45e28b5560312d4e2299bd8d1e7fe27d10925966c28d497aec400b4630485e82efbabc00550996bdad5d6a9a8c75952f126d14ad2cff91e16198691a7ef2937de83209285f1fb90944b4e46bca7c856a9ce3da10cdf2a7d00dc2bf4f114bc4d3ed67b91cbde558ce9af86dc81fbdc37f8e301b29e23c1466659c62bdbf8cff5d4c20f0fb0851ec72f5e9385dd40fdd2e3ed67ca4517117825665e50a3e26f73c66998daf18e418e8aef9ce2d20da33c3629db2933640e03e7b44c2edf49e9b482db7b475cfd4c617ae1d46d5c24d697846f9f08561eac2b065f9b382501f6eabf07343ed6c602f61eab99cdb52adf63fd44a8db2d3016387ea708fc1c08591e19b4d9984ebe31edbd684c2ea86526dd8c7732b1d8d9117511dc1b643976d356258fce8313b1cb92682f41ab72dedd766f06de375f9edacbcd0ca8c99b865ea2b7952318ea1fd20775a28028b5cf59dece5de14f615b8df254eee63493a5111ea987224bea006d8f1b60d565eef06ac0da194dba2a6d02e79b2f2f34e9ca6e1984a507319d86e9d4fcaeea41b4b9144e0b1826304d4cc1da61cfc5f8b9850697df8adc5e9d6f3acb3219b02764b4909f2b2b22e799fd66c383414a84a7d791b899d4aa663770009eb122f90282c8cb9cda16aba6897edcf9b32951d0080c0f52be3ca011fbec3fb16423deb47744645c3b05fdbd932edf54ba6efd26e65340a8e9b1d1216582e1b30d64524f8ca2d6c5ba63a38f7120a3ed71bed8960bcac2feee2dd41c90be48e3c11ec518eb3d872779e4765a6cc28c6b0fa71ab57ced73ae963cc630edae4258cba2bf25821a6ae049fec2fca28b5dd1bb004d92924b65701b06dcf37f0ccd147a13a03f9bc0f98b7d78fe9058089756931e2cd0e0ed92ec6759d07b248069526c67e9e6ce095118fd3501ba0f858ef030b76c6f6beb11a09317b5ad25343f4b31aef02bc555951bc7791c2c289ecf94d5544dcd6ad3021ed8e8e3db34b2a73e1eedb57b578b068a5401836d6e382110b73690a94328c404af25e85a8d6b808893d1b71af6a31fadd8a8cc6e31ecc0d9ff7e6b91fd03c274a5c1f1ccd25b61150220a3fddb04c91012f5f7a83a5c90deb2470089d6e38cd5914b9c946eca6e9d31bbf8667d36cf87effc3f3ff283c21dd4137bd569fe7cf758feac94053e4baf7338bb592c8b7c291667fadf4a9bf9a2a154a18f612cbc7f851b3f8f2070e0a9d180622ee4f8e81b0ab250d504cef24116a3ff188cc829fcd8610b56343569e8dc997629410d1967ca9dd1d27eec5e01e4375aad16c46faba268524b154850d0d6fe3a76af2c6aa3e97647c51036049ac565370028d6a439a2672b6face56e1b171496c0722cfa22d9da631be359661617c5d5a2d286c5e19db9452c1e21a0107b6400debda2decb0c838f342dd017cdb2dccdf1fe97e3df3f881856b546997a3fed9e279c720145101567dd56be21688fed66bf9759e432a9aa89cbbd225d13cdea4ca05f7a45cfb6a682a3d5b1e18f7e6cf934fae5098108bae9058d05c3387a01d8d02a656d2bfff67e9f46b2d8a6aac28129e52efddf6e552214c3f8a45bc7a912cca9a7fec1d7d06412c6972cb9e3dc518983f56530b8bffe7f92c4b6eb47d4aef59fb513c4653a42de61bc17ad7728e7fc7590ff05a9e991de03f023d0aaf8688ed6170def5091c66576a424ac1cb").unwrap());
	let sender_dummy_node_id = PublicKey::from_slice(&[2; 33]).unwrap();
	nodes[0].handle_onion_message(&sender_dummy_node_id, &sender_to_alice_om);
	let alice_to_bob_om = nodes[0].next_onion_message_for_peer(
		keys_mgrs[1].1.get_node_id(Recipient::Node).unwrap()).unwrap();
	assert_eq!(alice_to_bob_om.encode(), hex::decode("031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f05560002536d53f93796cad550b6c68662dca41f7e8c221c31022c64dd1a627b2df3982b25eac261e88369cfc66e1e3b6d9829cb3dcd707046e68a7796065202a7904811bf2608c5611cf74c9eb5371c7eb1a4428bb39a041493e2a568ddb0b2482a6cc6711bc6116cef144ebf988073cb18d9dd4ce2d3aa9de91a7dc6d7c6f11a852024626e66b41ba1158055505dff9cb15aa51099f315564d9ee3ed6349665dc3e209eedf9b5805ee4f69d315df44c80e63d0e2efbdab60ec96f44a3447c6a6ddb1efb6aa4e072bde1dab974081646bfddf3b02daa2b83847d74dd336465e76e9b8fecc2b0414045eeedfc39939088a76820177dd1103c99939e659beb07197bab9f714b30ba8dc83738e9a6553a57888aaeda156c68933a2f4ff35e3f81135076b944ed9856acbfee9c61299a5d1763eadd14bf5eaf71304c8e165e590d7ecbcd25f1650bf5b6c2ad1823b2dc9145e168974ecf6a2273c94decff76d94bc6708007a17f22262d63033c184d0166c14f41b225a956271947aae6ce65890ed8f0d09c6ffe05ec02ee8b9de69d7077a0c5adeb813aabcc1ba8975b73ab06ddea5f4db3c23a1de831602de2b83f990d4133871a1a81e53f86393e6a7c3a7b73f0c099fa72afe26c3027bb9412338a19303bd6e6591c04fb4cde9b832b5f41ae199301ea8c303b5cef3aca599454273565de40e1148156d1f97c1aa9e58459ab318304075e034f5b7899c12587b86776a18a1da96b7bcdc22864fccc4c41538ebce92a6f054d53bf46770273a70e75fe0155cd6d2f2e937465b0825ce3123b8c206fac4c30478fa0f08a97ade7216dce11626401374993213636e93545a31f500562130f2feb04089661ad8c34d5a4cbd2e4e426f37cb094c786198a220a2646ecadc38c04c29ee67b19d662c209a7b30bfecc7fe8bf7d274de0605ee5df4db490f6d32234f6af639d3fce38a2801bcf8d51e9c090a6c6932355a83848129a378095b34e71cb8f51152dc035a4fe8e802fec8de221a02ba5afd6765ce570bef912f87357936ea0b90cb2990f56035e89539ec66e8dbd6ed50835158614096990e019c3eba3d7dd6a77147641c6145e8b17552cd5cf7cd163dd40b9eaeba8c78e03a2cd8c0b7997d6f56d35f38983a202b4eb8a54e14945c4de1a6dde46167e11708b7a5ff5cb9c0f7fc12fae49a012aa90bb1995c038130b749c48e6f1ffb732e92086def42af10fbc460d94abeb7b2fa744a5e9a491d62a08452be8cf2fdef573deedc1fe97098bce889f98200b26f9bb99da9aceddda6d793d8e0e44a2601ef4590cfbb5c3d0197aac691e3d31c20fd8e38764962ca34dabeb85df28feabaf6255d4d0df3d814455186a84423182caa87f9673df770432ad8fdfe78d4888632d460d36d2719e8fa8e4b4ca10d817c5d6bc44a8b2affab8c2ba53b8bf4994d63286c2fad6be04c28661162fa1a67065ecda8ba8c13aee4a8039f4f0110e0c0da2366f178d8903e19136dad6df9d8693ce71f3a270f9941de2a93d9b67bc516207ac1687bf6e00b29723c42c7d9c90df9d5e599dbeb7b73add0a6a2b7aba82f98ac93cb6e60494040445229f983a81c34f7f686d166dfc98ec23a6318d4a02a311ac28d655ea4e0f9c3014984f31e621ef003e98c373561d9040893feece2e0fa6cd2dd565e6fbb2773a2407cb2c3273c306cf71f427f2e551c4092e067cf9869f31ac7c6c80dd52d4f85be57a891a41e34be0d564e39b4af6f46b85339254a58b205fb7e10e7d0470ee73622493f28c08962118c23a1198467e72c4ae1cd482144b419247a5895975ea90d135e2a46ef7e5794a1551a447ff0a0d299b66a7f565cd86531f5e7af5408d85d877ce95b1df12b88b7d5954903a5296325ba478ba1e1a9d1f30a2d5052b2e2889bbd64f72c72bc71d8817288a2").unwrap());
	nodes[1].handle_onion_message(
		&keys_mgrs[0].1.get_node_id(Recipient::Node).unwrap(), &alice_to_bob_om);
	let bob_to_carol_om = nodes[1].next_onion_message_for_peer(
		keys_mgrs[2].1.get_node_id(Recipient::Node).unwrap()).unwrap();
	assert_eq!(bob_to_carol_om.encode(), hex::decode("02b684babfd400c8dd48b367e9754b8021a3594a34dc94d7101776c7f6a86d0582055600029a77e8523162efa1f4208f4f2050cd5c386ddb6ce6d36235ea569d217ec52209fb85fdf7dbc4786c373eebdba0ddc184cfbe6da624f610e93f62c70f2c56be1090b926359969f040f932c03f53974db5656233bd60af375517d4323002937d784c2c88a564bcefe5c33d3fc21c26d94dfacab85e2e19685fd2ff4c543650958524439b6da68779459aee5ffc9dc543339acec73ff43be4c44ddcbe1c11d50e2411a67056ba9db7939d780f5a86123fdd3abd6f075f7a1d78ab7daf3a82798b7ec1e9f1345bc0d1e935098497067e2ae5a51ece396fcb3bb30871ad73aee51b2418b39f00c8e8e22be4a24f4b624e09cb0414dd46239de31c7be035f71e8da4f5a94d15b44061f46414d3f355069b5c5b874ba56704eb126148a22ec873407fe118972127e63ff80e682e410f297f23841777cec0517e933eaf49d7e34bd203266b42081b3a5193b51ccd34b41342bc67cf73523b741f5c012ba2572e9dda15fbe131a6ac2ff24dc2a7622d58b9f3553092cfae7fae3c8864d95f97aa49ec8edeff5d9f5782471160ee412d82ff6767030fc63eec6a93219a108cd41433834b26676a39846a944998796c79cd1cc460531b8ded659cedfd8aecefd91944f00476f1496daafb4ea6af3feacac1390ea510709783c2aa81a29de27f8959f6284f4684102b17815667cbb0645396ac7d542b878d90c42a1f7f00c4c4eedb2a22a219f38afadb4f1f562b6e000a94e75cc38f535b43a3c0384ccef127fde254a9033a317701c710b2b881065723486e3f4d3eea5e12f374a41565fe43fa137c1a252c2153dde055bb343344c65ad0529010ece29bbd405effbebfe3ba21382b94a60ac1a5ffa03f521792a67b30773cb42e862a8a02a8bbd41b842e115969c87d1ff1f8c7b5726b9f20772dd57fe6e4ea41f959a2a673ffad8e2f2a472c4c8564f3a5a47568dd75294b1c7180c500f7392a7da231b1fe9e525ea2d7251afe9ca52a17fe54a116cb57baca4f55b9b6de915924d644cba9dade4ccc01939d7935749c008bafc6d3ad01cd72341ce5ddf7a5d7d21cf0465ab7a3233433aef21f9acf2bfcdc5a8cc003adc4d82ac9d72b36eb74e05c9aa6ccf439ac92e6b84a3191f0764dd2a2e0b4cc3baa08782b232ad6ecd3ca6029bc08cc094aef3aebddcaddc30070cb6023a689641de86cfc6341c8817215a4650f844cd2ca60f2f10c6e44cfc5f23912684d4457bf4f599879d30b79bf12ef1ab8d34dddc15672b82e56169d4c770f0a2a7a960b1e8790773f5ff7fce92219808f16d061cc85e053971213676d28fb48925e9232b66533dbd938458eb2cc8358159df7a2a2e4cf87500ede2afb8ce963a845b98978edf26a6948d4932a6b95d022004556d25515fe158092ce9a913b4b4a493281393ca731e8d8e5a3449b9d888fc4e73ffcbb9c6d6d66e88e03cf6e81a0496ede6e4e4172b08c000601993af38f80c7f68c9d5fff9e0e215cff088285bf039ca731744efcb7825a272ca724517736b4890f47e306b200aa2543c363e2c9090bcf3cf56b5b86868a62471c7123a41740392fc1d5ab28da18dca66618e9af7b42b62b23aba907779e73ca03ec60e6ab9e0484b9cae6578e0fddb6386cb3468506bf6420298bf4a690947ab582255551d82487f271101c72e19e54872ab47eae144db66bc2f8194a666a5daec08d12822cb83a61946234f2dfdbd6ca7d8763e6818adee7b401fcdb1ac42f9df1ac5cc5ac131f2869013c8d6cd29d4c4e3d05bccd34ca83366d616296acf854fa05149bfd763a25b9938e96826a037fdcb85545439c76df6beed3bdbd01458f9cf984997cc4f0a7ac3cc3f5e1eeb59c09cadcf5a537f16e444149c8f17d4bdaef16c9fbabc5ef06eb0f0bf3a07a1beddfeacdaf1df5582d6dbd6bb808d6ab31bc22e5d7").unwrap());
	nodes[2].handle_onion_message(
		&keys_mgrs[1].1.get_node_id(Recipient::Node).unwrap(), &bob_to_carol_om);
	let carol_to_dave_om = nodes[2].next_onion_message_for_peer(
		keys_mgrs[3].1.get_node_id(Recipient::Node).unwrap()).unwrap();
	assert_eq!(carol_to_dave_om.encode(), hex::decode("025aaca62db7ce6b46386206ef9930daa32e979a35cb185a41cb951aa7d254b03c055600025550b2910294fa73bda99b9de9c851be9cbb481e23194a1743033630efba546b86e7d838d0f6e9cc0ed088dbf6889f0dceca3bfc745bd77d013a31311fa932a8bf1d28387d9ff521eabc651dee8f861fed609a68551145a451f017ec44978addeee97a423c08445531da488fd1ddc998e9cdbfcea59517b53fbf1833f0bbe6188dba6ca773a247220ec934010daca9cc185e1ceb136803469baac799e27a0d82abe53dc48a06a55d1f643885cc7894677dd20a4e4152577d1ba74b870b9279f065f9b340cedb3ca13b7df218e853e10ccd1b59c42a2acf93f489e170ee4373d30ab158b60fc20d3ba73a1f8c750951d69fb5b9321b968ddc8114936412346aff802df65516e1c09c51ef19849ff36c0199fd88c8bec301a30fef0c7cb497901c038611303f64e4174b5daf42832aa5586b84d2c9b95f382f4269a5d1bd4be898618dc78dfd451170f72ca16decac5b03e60702112e439cadd104fb3bbb3d5023c9b80823fdcd0a212a7e1aaa6eeb027adc7f8b3723031d135a09a979a4802788bb7861c6cc85501fb91137768b70aeab309b27b885686604ffc387004ac4f8c44b101c39bc0597ef7fd957f53fc5051f534b10eb3852100962b5e58254e5558689913c26ad6072ea41f5c5db10077cfc91101d4ae393be274c74297da5cc381cd88d54753aaa7df74b2f9da8d88a72bc9218fcd1f19e4ff4aace182312b9509c5175b6988f044c5756d232af02a451a02ca752f3c52747773acff6fd07d2032e6ce562a2c42105d106eba02d0b1904182cdc8c74875b082d4989d3a7e9f0e73de7c75d357f4af976c28c0b206c5e8123fc2391d078592d0d5ff686fd245c0a2de2e535b7cca99c0a37d432a8657393a9e3ca53eec1692159046ba52cb9bc97107349d8673f74cbc97e231f1108005c8d03e24ca813cea2294b39a7a493bcc062708f1f6cf0074e387e7d50e0666ce784ef4d31cb860f6cad767438d9ea5156ff0ae86e029e0247bf94df75ee0cda4f2006061455cb2eaff513d558863ae334cef7a3d45f55e7cc13153c6719e9901c1d4db6c03f643b69ea4860690305651794284d9e61eb848ccdf5a77794d376f0af62e46d4835acce6fd9eef5df73ebb8ea3bb48629766967f446e744ecc57ff3642c4aa1ccee9a2f72d5caa75fa05787d08b79408fce792485fdecdc25df34820fb061275d70b84ece540b0fc47b2453612be34f2b78133a64e812598fbe225fd85415f8ffe5340ce955b5fd9d67dd88c1c531dde298ed25f96df271558c812c26fa386966c76f03a6ebccbca49ac955916929bd42e134f982dde03f924c464be5fd1ba44f8dc4c3cbc8162755fd1d8f7dc044b15b1a796c53df7d8769bb167b2045b49cc71e08908796c92c16a235717cabc4bb9f60f8f66ff4fff1f9836388a99583acebdff4a7fb20f48eedcd1f4bdcc06ec8b48e35307df51d9bc81d38a94992dd135b30079e1f592da6e98dff496cb1a7776460a26b06395b176f585636ebdf7eab692b227a31d6979f5a6141292698e91346b6c806b90c7c6971e481559cae92ee8f4136f2226861f5c39ddd29bbdb118a35dece03f49a96804caea79a3dacfbf09d65f2611b5622de51d98e18151acb3bb84c09caaa0cc80edfa743a4679f37d6167618ce99e73362fa6f213409931762618a61f1738c071bba5afc1db24fe94afb70c40d731908ab9a505f76f57a7d40e708fd3df0efc5b7cbb2a7b75cd23449e09684a2f0e2bfa0d6176c35f96fe94d92fc9fa4103972781f81cb6e8df7dbeb0fc529c600d768bed3f08828b773d284f69e9a203459d88c12d6df7a75be2455fec128f07a497a2b2bf626cc6272d0419ca663e9dc66b8224227eb796f0246dcae9c5b0b6cfdbbd40c3245a610481c92047c968c9fc92c04b89cc41a0c15355a8f").unwrap());
	// Dave handles the onion message but he'll log that he errored while decoding the hop data
	// because he sees it as an empty onion message (the only contents of the sender's OM is "hello"
	// with TLV type 1, which Dave ignores because (1) it's odd and he can't understand it and (2) LDK
	// only attempts to parse custom OM TLVs with type > 64).
	nodes[3].handle_onion_message(
		&keys_mgrs[2].1.get_node_id(Recipient::Node).unwrap(), &carol_to_dave_om);
}
