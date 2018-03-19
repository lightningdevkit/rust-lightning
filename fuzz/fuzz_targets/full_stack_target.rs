extern crate bitcoin;
extern crate lightning;
extern crate secp256k1;

use bitcoin::network::constants::Network;
use bitcoin::util::hash::Sha256dHash;

use lightning::chain::chaininterface::{ConfirmationTarget,FeeEstimator,ChainWatchInterfaceUtil};
use lightning::ln::{channelmonitor,msgs};
use lightning::ln::channelmanager::ChannelManager;
use lightning::ln::peer_handler::{MessageHandler,PeerManager,SocketDescriptor};
use lightning::ln::router::Router;

use secp256k1::key::{PublicKey,SecretKey};
use secp256k1::Secp256k1;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize,Ordering};

#[inline]
pub fn slice_to_be16(v: &[u8]) -> u16 {
	((v[0] as u16) << 8*1) |
	((v[1] as u16) << 8*0)
}

#[inline]
pub fn slice_to_be32(v: &[u8]) -> u32 {
	((v[0] as u32) << 8*3) |
	((v[1] as u32) << 8*2) |
	((v[2] as u32) << 8*1) |
	((v[3] as u32) << 8*0)
}

struct InputData {
	data: Vec<u8>,
	read_pos: AtomicUsize,
}
impl InputData {
	fn get_slice(&self, len: usize) -> Option<&[u8]> {
		let old_pos = self.read_pos.fetch_add(len, Ordering::AcqRel);
		if self.data.len() < old_pos + len {
			return None;
		}
		Some(&self.data[old_pos..old_pos + len])
	}
	fn get_slice_nonadvancing(&self, len: usize) -> Option<&[u8]> {
		let old_pos = self.read_pos.load(Ordering::Acquire);
		if self.data.len() < old_pos + len {
			return None;
		}
		Some(&self.data[old_pos..old_pos + len])
	}
}

struct FuzzEstimator {
	input: Arc<InputData>,
}
impl FeeEstimator for FuzzEstimator {
	fn get_est_sat_per_vbyte(&self, _: ConfirmationTarget) -> u64 {
		//TODO: We should actually be testing at least much more than 64k...
		match self.input.get_slice(2) {
			Some(slice) => slice_to_be16(slice) as u64,
			None => 0
		}
	}
}

struct TestChannelMonitor {}
impl channelmonitor::ManyChannelMonitor for TestChannelMonitor {
	fn add_update_monitor(&self, _funding_txo: (Sha256dHash, u16), _monitor: channelmonitor::ChannelMonitor) -> Result<(), msgs::HandleError> {
		//TODO!
		Ok(())
	}
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct Peer {
	id: u8,
}
impl SocketDescriptor for Peer {
	fn send_data(&mut self, data: &Vec<u8>, write_offset: usize, _resume_read: bool) -> usize {
		assert!(write_offset < data.len());
		data.len() - write_offset
	}
}

#[inline]
pub fn do_test(data: &[u8]) {
	let input = Arc::new(InputData {
		data: data.to_vec(),
		read_pos: AtomicUsize::new(0),
	});
	let fee_est = Arc::new(FuzzEstimator {
		input: input.clone(),
	});

	macro_rules! get_slice {
		($len: expr) => {
			match input.get_slice($len as usize) {
				Some(slice) => slice,
				None => return,
			}
		}
	}

	let secp_ctx = Secp256k1::new();
	macro_rules! get_pubkey {
		() => {
			match PublicKey::from_slice(&secp_ctx, get_slice!(33)) {
				Ok(key) => key,
				Err(_) => return,
			}
		}
	}

	let our_network_key = match SecretKey::from_slice(&secp_ctx, get_slice!(32)) {
		Ok(key) => key,
		Err(_) => return,
	};

	let monitor = Arc::new(TestChannelMonitor{});
	let watch = Arc::new(ChainWatchInterfaceUtil::new());

	let channelmanager = ChannelManager::new(our_network_key, slice_to_be32(get_slice!(4)), get_slice!(1)[0] != 0, Network::Bitcoin, fee_est.clone(), monitor.clone(), watch.clone()).unwrap();
	let router = Arc::new(Router::new(PublicKey::from_secret_key(&secp_ctx, &our_network_key).unwrap()));

	let handler = PeerManager::new(MessageHandler {
		chan_handler: channelmanager.clone(),
		route_handler: router.clone(),
	}, our_network_key);

	let mut peers = [false; 256];

	loop {
		match get_slice!(1)[0] {
			0 => {
				let mut new_id = 0;
				for i in 1..256 {
					if !peers[i-1] {
						new_id = i;
						break;
					}
				}
				if new_id == 0 { return; }
				peers[new_id - 1] = true;
				handler.new_outbound_connection(get_pubkey!(), Peer{id: (new_id - 1) as u8}).unwrap();
			},
			1 => {
				let mut new_id = 0;
				for i in 1..256 {
					if !peers[i-1] {
						new_id = i;
						break;
					}
				}
				if new_id == 0 { return; }
				peers[new_id - 1] = true;
				handler.new_inbound_connection(Peer{id: (new_id - 1) as u8}).unwrap();
			},
			2 => {
				let peer_id = get_slice!(1)[0];
				if !peers[peer_id as usize] { return; }
				peers[peer_id as usize] = false;
				handler.disconnect_event(&Peer{id: peer_id});
			},
			3 => {
				let peer_id = get_slice!(1)[0];
				if !peers[peer_id as usize] { return; }
				match handler.read_event(&mut Peer{id: peer_id}, get_slice!(get_slice!(1)[0]).to_vec()) {
					Ok(res) => assert!(!res),
					Err(_) => { peers[peer_id as usize] = false; }
				}
			},
			_ => return,
		}
	}
}

#[cfg(feature = "afl")]
extern crate afl;
#[cfg(feature = "afl")]
fn main() {
	afl::read_stdio_bytes(|data| {
		do_test(&data);
	});
}

#[cfg(feature = "honggfuzz")]
#[macro_use] extern crate honggfuzz;
#[cfg(feature = "honggfuzz")]
fn main() {
	loop {
		fuzz!(|data| {
			do_test(data);
		});
	}
}

#[cfg(test)]
mod tests {
	fn extend_vec_from_hex(hex: &str, out: &mut Vec<u8>) {
		let mut b = 0;
		for (idx, c) in hex.as_bytes().iter().enumerate() {
			b <<= 4;
			match *c {
				b'A'...b'F' => b |= c - b'A' + 10,
				b'a'...b'f' => b |= c - b'a' + 10,
				b'0'...b'9' => b |= c - b'0',
				_ => panic!("Bad hex"),
			}
			if (idx & 1) == 1 {
				out.push(b);
				b = 0;
			}
		}
	}

	#[test]
	fn duplicate_crash() {
		let mut a = Vec::new();
		extend_vec_from_hex("00", &mut a);
		super::do_test(&a);
	}
}
