use crate::chain::BestBlock;
use crate::ln::types::ChannelId;
use bitcoin::hash_types::Txid;
use bitcoin::secp256k1::PublicKey;
use bitcoin::block::Header;

use crate::chain::channelmonitor::{
	ChannelMonitorUpdate, ChannelMonitorUpdateStep,
};
use crate::crypto::chacha20poly1305rfc::ChaCha20Poly1305RFC;

use crate::util::ser::{ Writeable, VecWriter };

use crate::prelude::*;
use crate::chain::transaction::OutPoint;
use crate::ln::chan_utils::CounterpartyCommitmentSecrets;
use crate::ln::channel_keys::{DelayedPaymentBasepoint, HtlcBasepoint};
use crate::ln::features::{ChannelTypeFeatures};


/// [StubChannelMonitor] is the smallest unit of [OurPeerStorage], it contains
/// information about a single channel using which we can recover on-chain funds.
#[derive(Clone, PartialEq, Eq)]
pub struct StubChannelMonitor {
	pub(crate) channel_id: ChannelId,
	pub(crate) funding_outpoint: OutPoint,
	pub(crate) channel_value_stoshis: u64,
	pub(crate) channel_keys_id: [u8;32],
	pub(crate) commitment_secrets: CounterpartyCommitmentSecrets,
	pub(crate) counterparty_node_id: PublicKey,
	pub(crate) counterparty_delayed_payment_base_key: DelayedPaymentBasepoint,
	pub(crate) counterparty_htlc_base_key: HtlcBasepoint,
	pub(crate) on_counterparty_tx_csv: u16,
	pub(crate) obscure_factor: u64,
	pub(crate) latest_state: Option<Txid>,
	pub(crate) their_cur_per_commitment_points: Option<(u64, PublicKey, Option<PublicKey>)>,
	pub(crate) features: ChannelTypeFeatures,
	pub(crate) best_block: BestBlock,
}

impl StubChannelMonitor {
    pub(crate) fn new(channel_id: ChannelId, funding_outpoint: OutPoint, channel_value_stoshis: u64, channel_keys_id: [u8; 32],
		       commitment_secrets: CounterpartyCommitmentSecrets, counterparty_node_id: PublicKey, counterparty_delayed_payment_base_key: DelayedPaymentBasepoint, counterparty_htlc_base_key: HtlcBasepoint, on_counterparty_tx_csv: u16,
			   obscure_factor: u64, latest_state: Option<Txid>, their_cur_per_commitment_points: Option<(u64, PublicKey, Option<PublicKey>)>,
			   features: ChannelTypeFeatures, best_block: BestBlock) -> Self {
        StubChannelMonitor {
            channel_id,
			funding_outpoint,
			channel_value_stoshis,
            channel_keys_id,
            commitment_secrets,
			counterparty_node_id,
			counterparty_delayed_payment_base_key,
			counterparty_htlc_base_key,
			on_counterparty_tx_csv,
			obscure_factor,
			latest_state,
			their_cur_per_commitment_points,
			features,
			best_block,
        }
    }

	/// Get the min seen secret from the commitment secrets.
	pub fn get_min_seen_secret(&self) -> u64 {
		return self.commitment_secrets.get_min_seen_secret();
	}
}

impl_writeable_tlv_based!(StubChannelMonitor, {
	(0, channel_id, required),
	(2, channel_keys_id, required),
	(4, channel_value_stoshis, required),
	(6, funding_outpoint, required),
	(8, commitment_secrets, required),
	(10, counterparty_node_id, required),
	(12, counterparty_delayed_payment_base_key, required),
	(14, counterparty_htlc_base_key, required),
	(16, on_counterparty_tx_csv, required),
	(18, obscure_factor, required),
	(20, latest_state, required),
	(22, their_cur_per_commitment_points, option),
	(24, features, required),
	(26, best_block, required),
});


/// [`OurPeerStorage`] is used to store our channels using which we
/// can create our PeerStorage Backup.
/// This includes timestamp to compare between two given 
/// [`OurPeerStorage`] and version defines the structure.
#[derive(Clone, PartialEq, Eq)]
pub struct OurPeerStorage {
    version: u32,
    timestamp: u32,
    channels: Vec<StubChannelMonitor>,
}

impl OurPeerStorage {
	/// Returns a [`OurPeerStorage`] with version 1 and current timestamp.
    pub fn new() -> Self {
        let duration_since_epoch = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("Time must be > 1970");

        Self {
            version: 1,
            timestamp: duration_since_epoch.as_secs() as u32,
            channels: Vec::new(),
        }
    }

	/// Stubs a channel inside [`OurPeerStorage`]
    pub fn stub_channel(&mut self, chan: StubChannelMonitor) {
        self.channels.push(chan);
    }

	/// Get a reference of `channels` array from [`StubChannelMonitor::channels`]
	pub fn get_channels(&self) -> &Vec<StubChannelMonitor> {
		self.channels.as_ref()
	}

	pub(crate) fn update_latest_state(&mut self, cid: ChannelId, txid: Txid, their_cur_per_commitment_points: Option<(u64, PublicKey, Option<PublicKey>)>) {
        for stub_channel in &mut self.channels {
            if stub_channel.channel_id == cid {
                stub_channel.latest_state = Some(txid);
				stub_channel.their_cur_per_commitment_points = their_cur_per_commitment_points;
                return;
            }
        }
	}

	pub(crate) fn provide_secret(&mut self, cid: ChannelId, idx:u64, secret: [u8; 32]) -> Result<(), ()> {
		for stub_channel in &mut self.channels {
            if stub_channel.channel_id == cid {
                return stub_channel.commitment_secrets.provide_secret(idx, secret);
            }
        }
		return Err(());
	}

	/// This is called to update the data of the latest state inside [`OurPeerStorage`] using
	/// [`ChannelMonitorUpdateStep::LatestCounterpartyCommitmentTXInfo`]
	pub(crate) fn update_state_from_monitor_update(&mut self, cid: ChannelId, monitor_update: ChannelMonitorUpdate) -> Result<(),()> {
		for update in monitor_update.updates.iter() {
			match update {
				ChannelMonitorUpdateStep::LatestCounterpartyCommitmentTXInfo { commitment_txid, htlc_outputs, commitment_number, 
					their_per_commitment_point, .. } => {
						let stub_channels = &self.channels;
						let mut cur_per_commitment_points = None;
						for stub_channel in stub_channels {
							if stub_channel.channel_id == cid {
								match stub_channel.their_cur_per_commitment_points {
									Some(old_points) => {
										if old_points.0 == commitment_number + 1 {
											cur_per_commitment_points = Some((old_points.0, old_points.1, Some(*their_per_commitment_point)));
										} else if old_points.0 == commitment_number + 2 {
											if let Some(old_second_point) = old_points.2 {
												cur_per_commitment_points = Some((old_points.0 - 1, old_second_point, Some(*their_per_commitment_point)));
											} else {
												cur_per_commitment_points = Some((*commitment_number, *their_per_commitment_point, None));
											}
										} else {
											cur_per_commitment_points = Some((*commitment_number, *their_per_commitment_point, None));
										}
									},
									None => {
										cur_per_commitment_points = Some((*commitment_number, *their_per_commitment_point, None));
									}
								}
							}
						}
						self.update_latest_state(cid, *commitment_txid, cur_per_commitment_points);
						return Ok(());
					}
				ChannelMonitorUpdateStep::CommitmentSecret { idx, secret } => {
					let _ = self.provide_secret(cid, *idx, *secret);
					return Ok(());
				}
				_ => {}
			}
		}
		Err(())
	}

	pub fn update_best_block(&mut self, header: &Header, height: u32) {
		for channel in &mut self.channels {
			channel.best_block = BestBlock::new(header.block_hash(), height);
		}
	}

	/// Encrypt [`OurPeerStorage`] using the `key` and return a Vec<u8> containing the result.
    pub fn encrypt_our_peer_storage(&self, key: [u8; 32]) -> Vec<u8> {
        let n = 0u64;
        let mut peer_storage = VecWriter(Vec::new());
        self.write(&mut peer_storage).unwrap();
        let mut res = vec![0;peer_storage.0.len() + 16];

        let plaintext = &peer_storage.0[..];
		let mut nonce = [0; 12];
		nonce[4..].copy_from_slice(&n.to_le_bytes()[..]);

		let mut chacha = ChaCha20Poly1305RFC::new(&key, &nonce, b"");
		let mut tag = [0; 16];
		chacha.encrypt(plaintext, &mut res[0..plaintext.len()], &mut tag);
		res[plaintext.len()..].copy_from_slice(&tag);
        res
	}

	/// Decrypt `OurPeerStorage` using the `key`, result is stored inside the `res`.
	/// Returns an error if the the `cyphertext` is not correct.
    pub fn decrypt_our_peer_storage(&self, res: &mut[u8], cyphertext: &[u8], key: [u8; 32]) -> Result<(), ()> {
		let n = 0u64;
        let mut nonce = [0; 12];
		nonce[4..].copy_from_slice(&n.to_le_bytes()[..]);

		let mut chacha = ChaCha20Poly1305RFC::new(&key, &nonce, b"");
		if chacha.variable_time_decrypt(&cyphertext[0..cyphertext.len() - 16], res, &cyphertext[cyphertext.len() - 16..]).is_err() {
			return Err(());
		}
		Ok(())
	}
}

impl_writeable_tlv_based!(OurPeerStorage, {
	(0, version, (default_value, 1)),
	(2, timestamp, required),
	(4, channels, optional_vec),
});
