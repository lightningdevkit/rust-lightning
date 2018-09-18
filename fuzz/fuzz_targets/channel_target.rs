extern crate bitcoin;
extern crate lightning;
extern crate secp256k1;

use bitcoin::blockdata::block::BlockHeader;
use bitcoin::blockdata::transaction::{Transaction, TxOut};
use bitcoin::util::hash::Sha256dHash;
use bitcoin::network::serialize::{serialize, BitcoinHash};

use lightning::ln::channel::{Channel, ChannelKeys};
use lightning::ln::channelmanager::{HTLCFailReason, HTLCSource, PendingHTLCStatus};
use lightning::ln::msgs;
use lightning::ln::msgs::{ErrorAction};
use lightning::chain::chaininterface::{FeeEstimator, ConfirmationTarget};
use lightning::chain::transaction::OutPoint;
use lightning::util::reset_rng_state;
use lightning::util::logger::Logger;
use lightning::util::ser::Readable;

mod utils;

use utils::test_logger;

use secp256k1::key::{PublicKey, SecretKey};
use secp256k1::Secp256k1;

use std::sync::atomic::{AtomicUsize,Ordering};
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
fn slice_to_be24(v: &[u8]) -> u64 {
	//TODO: We should probably be returning a Result for channel creation, not panic!()ing on
	//>2**24 values...
	((v[0] as u64) << 8*2) |
	((v[1] as u64) << 8*1) |
	((v[2] as u64) << 8*0)
}

struct InputData<'a> {
	data: &'a [u8],
	read_pos: AtomicUsize,
}
impl<'a> InputData<'a> {
	fn get_slice(&self, len: usize) -> Option<&'a [u8]> {
		let old_pos = self.read_pos.fetch_add(len, Ordering::AcqRel);
		if self.data.len() < old_pos + len {
			return None;
		}
		Some(&self.data[old_pos..old_pos + len])
	}
	fn get_slice_nonadvancing(&self, len: usize) -> Option<&'a [u8]> {
		let old_pos = self.read_pos.load(Ordering::Acquire);
		if self.data.len() < old_pos + len {
			return None;
		}
		Some(&self.data[old_pos..old_pos + len])
	}
}

struct FuzzEstimator<'a> {
	input: &'a InputData<'a>,
}
impl<'a> FeeEstimator for FuzzEstimator<'a> {
	fn get_est_sat_per_1000_weight(&self, _: ConfirmationTarget) -> u64 {
		//TODO: We should actually be testing at least much more than 64k...
		match self.input.get_slice(2) {
			Some(slice) => slice_to_be16(slice) as u64 * 250,
			None => 0
		}
	}
}

#[inline]
pub fn do_test(data: &[u8]) {
	reset_rng_state();

	let input = InputData {
		data,
		read_pos: AtomicUsize::new(0),
	};
	let fee_est = FuzzEstimator {
		input: &input,
	};

	let logger: Arc<Logger> = Arc::new(test_logger::TestLogger{});

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
					msgs::DecodeError::UnknownRealmByte => return,
					msgs::DecodeError::UnknownRequiredFeature => return,
					msgs::DecodeError::BadPublicKey => return,
					msgs::DecodeError::BadSignature => return,
					msgs::DecodeError::BadText => return,
					msgs::DecodeError::ExtraAddressesPerType => return,
					msgs::DecodeError::BadLengthDescriptor => return,
					msgs::DecodeError::ShortRead => panic!("We picked the length..."),
					msgs::DecodeError::InvalidValue => panic!("Should not happen with p2p message decoding"),
					msgs::DecodeError::Io(e) => panic!(format!("{}", e)),
				}
			}
		}}
	}

	macro_rules! decode_msg_with_len16 {
		($MsgType: path, $begin_len: expr, $factor: expr) => {
			{
				let extra_len = slice_to_be16(&match input.get_slice_nonadvancing($begin_len as usize + 2) {
					Some(slice) => slice,
					None => return,
				}[$begin_len..$begin_len + 2]);
				decode_msg!($MsgType, $begin_len as usize + 2 + (extra_len as usize)*$factor)
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

	macro_rules! return_err {
		($expr: expr) => {
			match $expr {
				Ok(r) => r,
				Err(_) => return,
			}
		}
	}

	macro_rules! chan_keys {
		() => {
			ChannelKeys {
				funding_key:               SecretKey::from_slice(&secp_ctx, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
				revocation_base_key:       SecretKey::from_slice(&secp_ctx, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
				payment_base_key:          SecretKey::from_slice(&secp_ctx, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
				delayed_payment_base_key:  SecretKey::from_slice(&secp_ctx, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
				htlc_base_key:             SecretKey::from_slice(&secp_ctx, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
				channel_close_key:         SecretKey::from_slice(&secp_ctx, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
				channel_monitor_claim_key: SecretKey::from_slice(&secp_ctx, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
				commitment_seed: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
			}
		}
	}

	let their_pubkey = get_pubkey!();

	let mut tx = Transaction { version: 0, lock_time: 0, input: Vec::new(), output: Vec::new() };

	let mut channel = if get_slice!(1)[0] != 0 {
		let chan_value = slice_to_be24(get_slice!(3));

		let mut chan = match Channel::new_outbound(&fee_est, chan_keys!(), their_pubkey, chan_value, slice_to_be24(get_slice!(3)), get_slice!(1)[0] == 0, slice_to_be64(get_slice!(8)), Arc::clone(&logger)) {
			Ok(chan) => chan,
			Err(_) => return,
		};
		chan.get_open_channel(Sha256dHash::from(get_slice!(32)), &fee_est);
		let accept_chan = if get_slice!(1)[0] == 0 {
			decode_msg_with_len16!(msgs::AcceptChannel, 270, 1)
		} else {
			decode_msg!(msgs::AcceptChannel, 270)
		};
		return_err!(chan.accept_channel(&accept_chan));

		tx.output.push(TxOut{ value: chan_value, script_pubkey: chan.get_funding_redeemscript().to_v0_p2wsh() });
		let funding_output = OutPoint::new(Sha256dHash::from_data(&serialize(&tx).unwrap()[..]), 0);

		chan.get_outbound_funding_created(funding_output).unwrap();
		let funding_signed = decode_msg!(msgs::FundingSigned, 32+64);
		return_err!(chan.funding_signed(&funding_signed));
		chan
	} else {
		let open_chan = if get_slice!(1)[0] == 0 {
			decode_msg_with_len16!(msgs::OpenChannel, 2*32+6*8+4+2*2+6*33+1, 1)
		} else {
			decode_msg!(msgs::OpenChannel, 2*32+6*8+4+2*2+6*33+1)
		};
		let mut chan = match Channel::new_from_req(&fee_est, chan_keys!(), their_pubkey, &open_chan, slice_to_be64(get_slice!(8)), false, get_slice!(1)[0] == 0, Arc::clone(&logger)) {
			Ok(chan) => chan,
			Err(_) => return,
		};
		chan.get_accept_channel();

		tx.output.push(TxOut{ value: open_chan.funding_satoshis, script_pubkey: chan.get_funding_redeemscript().to_v0_p2wsh() });
		let funding_output = OutPoint::new(Sha256dHash::from_data(&serialize(&tx).unwrap()[..]), 0);

		let mut funding_created = decode_msg!(msgs::FundingCreated, 32+32+2+64);
		funding_created.funding_txid = funding_output.txid.clone();
		funding_created.funding_output_index = funding_output.index;
		return_err!(chan.funding_created(&funding_created));
		chan
	};

	let mut header = BlockHeader { version: 0x20000000, prev_blockhash: Default::default(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
	channel.block_connected(&header, 1, &[&tx; 1], &[42; 1]);
	for i in 2..100 {
		header = BlockHeader { version: 0x20000000, prev_blockhash: header.bitcoin_hash(), merkle_root: Default::default(), time: 42, bits: 42, nonce: 42 };
		channel.block_connected(&header, i, &[&tx; 0], &[0; 0]);
	}

	let funding_locked = decode_msg!(msgs::FundingLocked, 32+33);
	return_err!(channel.funding_locked(&funding_locked));

	macro_rules! test_err {
		($expr: expr) => {
			match $expr {
				Ok(r) => Some(r),
				Err(e) => match e.action {
					None => return,
					Some(ErrorAction::DisconnectPeer {..}) => return,
					Some(ErrorAction::IgnoreError) => None,
					Some(ErrorAction::SendErrorMessage {..}) => None,
				},
			}
		}
	}

	loop {
		match get_slice!(1)[0] {
			0 => {
				test_err!(channel.send_htlc(slice_to_be64(get_slice!(8)), [42; 32], slice_to_be32(get_slice!(4)), HTLCSource::dummy(), msgs::OnionPacket {
					version: get_slice!(1)[0],
					public_key: PublicKey::from_slice(&secp_ctx, get_slice!(33)),
					hop_data: [0; 20*65],
					hmac: [0; 32],
				}));
			},
			1 => {
				test_err!(channel.send_commitment());
			},
			2 => {
				let update_add_htlc = decode_msg!(msgs::UpdateAddHTLC, 32+8+8+32+4+4+33+20*65+32);
				test_err!(channel.update_add_htlc(&update_add_htlc, PendingHTLCStatus::dummy()));
			},
			3 => {
				let update_fulfill_htlc = decode_msg!(msgs::UpdateFulfillHTLC, 32 + 8 + 32);
				test_err!(channel.update_fulfill_htlc(&update_fulfill_htlc));
			},
			4 => {
				let update_fail_htlc = decode_msg_with_len16!(msgs::UpdateFailHTLC, 32 + 8, 1);
				test_err!(channel.update_fail_htlc(&update_fail_htlc, HTLCFailReason::dummy()));
			},
			5 => {
				let update_fail_malformed_htlc = decode_msg!(msgs::UpdateFailMalformedHTLC, 32+8+32+2);
				test_err!(channel.update_fail_malformed_htlc(&update_fail_malformed_htlc, HTLCFailReason::dummy()));
			},
			6 => {
				let commitment_signed = decode_msg_with_len16!(msgs::CommitmentSigned, 32+64, 64);
				test_err!(channel.commitment_signed(&commitment_signed));
			},
			7 => {
				let revoke_and_ack = decode_msg!(msgs::RevokeAndACK, 32+32+33);
				test_err!(channel.revoke_and_ack(&revoke_and_ack));
			},
			8 => {
				let update_fee = decode_msg!(msgs::UpdateFee, 32+4);
				test_err!(channel.update_fee(&fee_est, &update_fee));
			},
			9 => {
				let shutdown = decode_msg_with_len16!(msgs::Shutdown, 32, 1);
				test_err!(channel.shutdown(&fee_est, &shutdown));
				if channel.is_shutdown() { return; }
			},
			10 => {
				let closing_signed = decode_msg!(msgs::ClosingSigned, 32+8+64);
				let sign_res = test_err!(channel.closing_signed(&fee_est, &closing_signed));
				if sign_res.is_some() && sign_res.unwrap().1.is_some() {
					assert!(channel.is_shutdown());
					return;
				}
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
