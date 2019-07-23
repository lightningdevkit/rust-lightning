extern crate bitcoin;
extern crate bitcoin_hashes;
extern crate lightning;
extern crate secp256k1;

use bitcoin_hashes::sha256d::Hash as Sha256dHash;
use bitcoin::blockdata::script::{Script, Builder};

use lightning::chain::chaininterface::{ChainError,ChainWatchInterface, ChainListener};
use lightning::ln::channelmanager::ChannelDetails;
use lightning::ln::msgs;
use lightning::ln::msgs::{RoutingMessageHandler};
use lightning::ln::router::{Router, RouteHint};
use lightning::util::logger::Logger;
use lightning::util::ser::Readable;

use secp256k1::key::PublicKey;

mod utils;

use utils::test_logger;

use std::sync::{Weak, Arc};
use std::sync::atomic::{AtomicUsize, Ordering};

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

#[inline]
pub fn slice_to_be64(v: &[u8]) -> u64 {
	((v[0] as u64) << 8*7) |
	((v[1] as u64) << 8*6) |
	((v[2] as u64) << 8*5) |
	((v[3] as u64) << 8*4) |
	((v[4] as u64) << 8*3) |
	((v[5] as u64) << 8*2) |
	((v[6] as u64) << 8*1) |
	((v[7] as u64) << 8*0)
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

struct DummyChainWatcher {
	input: Arc<InputData>,
}

impl ChainWatchInterface for DummyChainWatcher {
	fn install_watch_tx(&self, _txid: &Sha256dHash, _script_pub_key: &Script) { }
	fn install_watch_outpoint(&self, _outpoint: (Sha256dHash, u32), _out_script: &Script) { }
	fn watch_all_txn(&self) { }
	fn register_listener(&self, _listener: Weak<ChainListener>) { }

	fn get_chain_utxo(&self, _genesis_hash: Sha256dHash, _unspent_tx_output_identifier: u64) -> Result<(Script, u64), ChainError> {
		match self.input.get_slice(2) {
			Some(&[0, _]) => Err(ChainError::NotSupported),
			Some(&[1, _]) => Err(ChainError::NotWatched),
			Some(&[2, _]) => Err(ChainError::UnknownTx),
			Some(&[_, x]) => Ok((Builder::new().push_int(x as i64).into_script().to_v0_p2wsh(), 0)),
			None => Err(ChainError::UnknownTx),
			_ => unreachable!(),
		}
	}
}

#[inline]
pub fn do_test(data: &[u8]) {
	let input = Arc::new(InputData {
		data: data.to_vec(),
		read_pos: AtomicUsize::new(0),
	});
	macro_rules! get_slice_nonadvancing {
		($len: expr) => {
			match input.get_slice_nonadvancing($len as usize) {
				Some(slice) => slice,
				None => return,
			}
		}
	}
	macro_rules! get_slice {
		($len: expr) => {
			match input.get_slice($len as usize) {
				Some(slice) => slice,
				None => return,
			}
		}
	}

	macro_rules! decode_msg {
		($MsgType: path, $len: expr) => {{
			let mut reader = ::std::io::Cursor::new(get_slice!($len));
			match <($MsgType)>::read(&mut reader) {
				Ok(msg) => msg,
				Err(e) => match e {
					msgs::DecodeError::UnknownVersion => return,
					msgs::DecodeError::UnknownRequiredFeature => return,
					msgs::DecodeError::InvalidValue => return,
					msgs::DecodeError::ExtraAddressesPerType => return,
					msgs::DecodeError::BadLengthDescriptor => return,
					msgs::DecodeError::ShortRead => panic!("We picked the length..."),
					msgs::DecodeError::Io(e) => panic!(format!("{}", e)),
				}
			}
		}}
	}

	macro_rules! decode_msg_with_len16 {
		($MsgType: path, $begin_len: expr, $excess: expr) => {
			{
				let extra_len = slice_to_be16(&get_slice_nonadvancing!($begin_len as usize + 2)[$begin_len..$begin_len + 2]);
				decode_msg!($MsgType, $begin_len as usize + 2 + (extra_len as usize) + $excess)
			}
		}
	}

	macro_rules! get_pubkey {
		() => {
			match PublicKey::from_slice(get_slice!(33)) {
				Ok(key) => key,
				Err(_) => return,
			}
		}
	}

	let logger: Arc<Logger> = Arc::new(test_logger::TestLogger::new("".to_owned()));
	let chain_monitor = Arc::new(DummyChainWatcher {
		input: Arc::clone(&input),
	});

	let our_pubkey = get_pubkey!();
	let router = Router::new(our_pubkey.clone(), chain_monitor, Arc::clone(&logger));

	loop {
		match get_slice!(1)[0] {
			0 => {
				let start_len = slice_to_be16(&get_slice_nonadvancing!(64 + 2)[64..64 + 2]) as usize;
				let addr_len = slice_to_be16(&get_slice_nonadvancing!(64+start_len+2 + 74)[64+start_len+2 + 72..64+start_len+2 + 74]);
				if addr_len > (37+1)*4 {
					return;
				}
				let _ = router.handle_node_announcement(&decode_msg_with_len16!(msgs::NodeAnnouncement, 64, 288));
			},
			1 => {
				let _ = router.handle_channel_announcement(&decode_msg_with_len16!(msgs::ChannelAnnouncement, 64*4, 32+8+33*4));
			},
			2 => {
				let _ = router.handle_channel_update(&decode_msg!(msgs::ChannelUpdate, 128));
			},
			3 => {
				match get_slice!(1)[0] {
					0 => {
						router.handle_htlc_fail_channel_update(&msgs::HTLCFailChannelUpdate::ChannelUpdateMessage {msg: decode_msg!(msgs::ChannelUpdate, 128)});
					},
					1 => {
						let short_channel_id = slice_to_be64(get_slice!(8));
						router.handle_htlc_fail_channel_update(&msgs::HTLCFailChannelUpdate::ChannelClosed {short_channel_id, is_permanent: false});
					},
					_ => return,
				}
			},
			4 => {
				let target = get_pubkey!();
				let mut first_hops_vec = Vec::new();
				let first_hops = match get_slice!(1)[0] {
					0 => None,
					1 => {
						let count = slice_to_be16(get_slice!(2));
						for _ in 0..count {
							first_hops_vec.push(ChannelDetails {
								channel_id: [0; 32],
								short_channel_id: Some(slice_to_be64(get_slice!(8))),
								remote_network_id: get_pubkey!(),
								channel_value_satoshis: slice_to_be64(get_slice!(8)),
								user_id: 0,
								inbound_capacity_msat: 0,
								is_live: true,
								outbound_capacity_msat: 0,
							});
						}
						Some(&first_hops_vec[..])
					},
					_ => return,
				};
				let mut last_hops_vec = Vec::new();
				let last_hops = {
					let count = slice_to_be16(get_slice!(2));
					for _ in 0..count {
						last_hops_vec.push(RouteHint {
							src_node_id: get_pubkey!(),
							short_channel_id: slice_to_be64(get_slice!(8)),
							fee_base_msat: slice_to_be32(get_slice!(4)),
							fee_proportional_millionths: slice_to_be32(get_slice!(4)),
							cltv_expiry_delta: slice_to_be16(get_slice!(2)),
							htlc_minimum_msat: slice_to_be64(get_slice!(8)),
						});
					}
					&last_hops_vec[..]
				};
				let _ = router.get_route(&target, first_hops, last_hops, slice_to_be64(get_slice!(8)), slice_to_be32(get_slice!(4)));
			},
			_ => return,
		}
	}
}

#[cfg(feature = "afl")]
#[macro_use] extern crate afl;
#[cfg(feature = "afl")]
fn main() {
	fuzz!(|data| {
		do_test(data);
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

extern crate hex;
#[cfg(test)]
mod tests {

	#[test]
	fn duplicate_crash() {
		super::do_test(&::hex::decode("00").unwrap());
	}
}
