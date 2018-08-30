extern crate bitcoin;
extern crate lightning;
extern crate secp256k1;

use bitcoin::network::constants::Network;

use lightning::chain::chaininterface;
use lightning::ln::channelmanager::ChannelDetails;
use lightning::ln::msgs;
use lightning::ln::msgs::{MsgDecodable, RoutingMessageHandler};
use lightning::ln::router::{Router, RouteHint};
use lightning::util::reset_rng_state;
use lightning::util::logger::Logger;

use secp256k1::key::PublicKey;
use secp256k1::Secp256k1;

mod utils;

use utils::test_logger;

use std::sync::Arc;

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

#[inline]
pub fn do_test(data: &[u8]) {
	reset_rng_state();

	let mut read_pos = 0;
	macro_rules! get_slice_nonadvancing {
		($len: expr) => {
			{
				if data.len() < read_pos + $len as usize {
					return;
				}
				&data[read_pos..read_pos + $len as usize]
			}
		}
	}
	macro_rules! get_slice {
		($len: expr) => {
			{
				let res = get_slice_nonadvancing!($len);
				read_pos += $len;
				res
			}
		}
	}

	macro_rules! decode_msg {
		($MsgType: path, $len: expr) => {
			match <($MsgType)>::decode(get_slice!($len)) {
				Ok(msg) => msg,
				Err(e) => match e {
					msgs::DecodeError::UnknownRealmByte => return,
					msgs::DecodeError::UnknownRequiredFeature => return,
					msgs::DecodeError::BadPublicKey => return,
					msgs::DecodeError::BadSignature => return,
					msgs::DecodeError::BadText => return,
					msgs::DecodeError::ExtraAddressesPerType => return,
					msgs::DecodeError::BadLengthDescriptor => return,
					msgs::DecodeError::ShortRead => panic!("We picked the length..."),
				}
			}
		}
	}

	macro_rules! decode_msg_with_len16 {
		($MsgType: path, $begin_len: expr, $excess: expr) => {
			{
				let extra_len = slice_to_be16(&get_slice_nonadvancing!($begin_len as usize + 2)[$begin_len..$begin_len + 2]);
				decode_msg!($MsgType, $begin_len as usize + 2 + (extra_len as usize) + $excess)
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

	let logger: Arc<Logger> = Arc::new(test_logger::TestLogger{});
	let chain_monitor = Arc::new(chaininterface::ChainWatchInterfaceUtil::new(Network::Bitcoin, Arc::clone(&logger)));

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
						router.handle_htlc_fail_channel_update(&msgs::HTLCFailChannelUpdate::ChannelClosed {short_channel_id});
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
