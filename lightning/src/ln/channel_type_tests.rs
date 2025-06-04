#![cfg_attr(rustfmt, rustfmt_skip)]

use bitcoin::constants::ChainHash;
use bitcoin::network::Network;
use lightning_types::features::{ChannelTypeFeatures, InitFeatures};
use crate::ln::channel::{OutboundV1Channel, InboundV1Channel};
use crate::chain::chaininterface::LowerBoundedFeeEstimator;
use bitcoin::secp256k1::{SecretKey, PublicKey};
use crate::ln::channelmanager;
use crate::util::config::UserConfig;
use crate::util::test_utils::{TestFeeEstimator, TestKeysInterface, TestLogger};
use bitcoin::secp256k1::Secp256k1;
use crate::prelude::*;

#[test]
fn test_zero_conf_channel_type_support() {
	let test_est = TestFeeEstimator::new(15000);
	let feeest = LowerBoundedFeeEstimator::new(&test_est);
	let secp_ctx = Secp256k1::new();
	let seed = [42; 32];
	let network = Network::Testnet;
	let keys_provider = TestKeysInterface::new(&seed, network);
	let logger = TestLogger::new();

	let node_b_node_id = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
	let config = UserConfig::default();
	let mut node_a_chan = OutboundV1Channel::<&TestKeysInterface>::new(&feeest, &&keys_provider, &&keys_provider,
		node_b_node_id, &channelmanager::provided_init_features(&config), 10000000, 100000, 42, &config, 0, 42, None, &logger).unwrap();

	let mut channel_type_features = ChannelTypeFeatures::only_static_remote_key();
	channel_type_features.set_zero_conf_required();

	let mut open_channel_msg = node_a_chan.get_open_channel(ChainHash::using_genesis_block(network), &&logger).unwrap();
	open_channel_msg.common_fields.channel_type = Some(channel_type_features);
	let node_b_node_id = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[7; 32]).unwrap());
	let res = InboundV1Channel::<&TestKeysInterface>::new(&feeest, &&keys_provider, &&keys_provider,
		node_b_node_id, &channelmanager::provided_channel_type_features(&config),
		&channelmanager::provided_init_features(&config), &open_channel_msg, 7, &config, 0, &&logger, /*is_0conf=*/false);
	assert!(res.is_ok());
}

#[test]
fn test_supports_anchors_zero_htlc_tx_fee() {
	// Tests that if both sides support and negotiate `anchors_zero_fee_htlc_tx`, it is the
	// resulting `channel_type`.
	let mut config = UserConfig::default();
	config.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = true;

	let mut expected_channel_type = ChannelTypeFeatures::empty();
	expected_channel_type.set_static_remote_key_required();
	expected_channel_type.set_anchors_zero_fee_htlc_tx_required();

	do_test_supports_channel_type(config, expected_channel_type)
}

#[test]
fn test_supports_zero_fee_commitments() {
	// Tests that if both sides support and negotiate `anchors_zero_fee_commitments`, it is
	// the resulting `channel_type`.
	let mut config = UserConfig::default();
	config.channel_handshake_config.negotiate_anchor_zero_fee_commitments = true;

	let mut expected_channel_type = ChannelTypeFeatures::empty();
	expected_channel_type.set_anchor_zero_fee_commitments_required();

	do_test_supports_channel_type(config, expected_channel_type)
}

#[test]
fn test_supports_zero_fee_commitments_and_htlc_tx_fee() {
	// Tests that if both sides support and negotiate `anchors_zero_fee_commitments` and
	// `anchors_zero_fee_htlc_tx`, the resulting `channel_type` is
	// `anchors_zero_fee_commitments`.
	let mut config = UserConfig::default();
	config.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = true;
	config.channel_handshake_config.negotiate_anchor_zero_fee_commitments = true;

	let mut expected_channel_type = ChannelTypeFeatures::empty();
	expected_channel_type.set_anchor_zero_fee_commitments_required();

	do_test_supports_channel_type(config, expected_channel_type)
}

fn do_test_supports_channel_type(config: UserConfig, expected_channel_type: ChannelTypeFeatures) {
	let secp_ctx = Secp256k1::new();
	let test_est = TestFeeEstimator::new(15000);
	let fee_estimator = LowerBoundedFeeEstimator::new(&test_est);
	let network = Network::Testnet;
	let keys_provider = TestKeysInterface::new(&[42; 32], network);
	let logger = TestLogger::new();

	let node_id_a = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[1; 32]).unwrap());
	let node_id_b = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[2; 32]).unwrap());

	// Assert that we get `static_remotekey` when no custom config is negotiated.
	let channel_a = OutboundV1Channel::<&TestKeysInterface>::new(
		&fee_estimator, &&keys_provider, &&keys_provider, node_id_b,
		&channelmanager::provided_init_features(&UserConfig::default()), 10000000, 100000, 42,
		&config, 0, 42, None, &logger
	).unwrap();
	assert_eq!(channel_a.funding.get_channel_type(), &ChannelTypeFeatures::only_static_remote_key());

	let mut channel_a = OutboundV1Channel::<&TestKeysInterface>::new(
		&fee_estimator, &&keys_provider, &&keys_provider, node_id_b,
		&channelmanager::provided_init_features(&config), 10000000, 100000, 42, &config, 0, 42,
		None, &logger
	).unwrap();

	let open_channel_msg = channel_a.get_open_channel(ChainHash::using_genesis_block(network), &&logger).unwrap();
	let channel_b = InboundV1Channel::<&TestKeysInterface>::new(
		&fee_estimator, &&keys_provider, &&keys_provider, node_id_a,
		&channelmanager::provided_channel_type_features(&config), &channelmanager::provided_init_features(&config),
		&open_channel_msg, 7, &config, 0, &&logger, /*is_0conf=*/false
	).unwrap();

	assert_eq!(channel_a.funding.get_channel_type(), &expected_channel_type);
	assert_eq!(channel_b.funding.get_channel_type(), &expected_channel_type);

	if expected_channel_type.supports_anchor_zero_fee_commitments() {
		assert_eq!(channel_a.context.feerate_per_kw, 0);
		assert_eq!(channel_b.context.feerate_per_kw, 0);
	} else {
		assert_ne!(channel_a.context.feerate_per_kw, 0);
		assert_ne!(channel_b.context.feerate_per_kw, 0);
	}
}

#[test]
fn test_rejects_implicit_simple_anchors() {
	// Tests that if `option_anchors` is being negotiated implicitly through the intersection of
	// each side's `InitFeatures`, it is rejected.
	let secp_ctx = Secp256k1::new();
	let test_est = TestFeeEstimator::new(15000);
	let fee_estimator = LowerBoundedFeeEstimator::new(&test_est);
	let network = Network::Testnet;
	let keys_provider = TestKeysInterface::new(&[42; 32], network);
	let logger = TestLogger::new();

	let node_id_a = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[1; 32]).unwrap());
	let node_id_b = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[2; 32]).unwrap());

	let config = UserConfig::default();

	// See feature bit assignments: https://github.com/lightning/bolts/blob/master/09-features.md
	let static_remote_key_required: u64 = 1 << 12;
	let simple_anchors_required: u64 = 1 << 20;
	let raw_init_features = static_remote_key_required | simple_anchors_required;
	let init_features_with_simple_anchors = InitFeatures::from_le_bytes(raw_init_features.to_le_bytes().to_vec());

	let mut channel_a = OutboundV1Channel::<&TestKeysInterface>::new(
		&fee_estimator, &&keys_provider, &&keys_provider, node_id_b,
		&channelmanager::provided_init_features(&config), 10000000, 100000, 42, &config, 0, 42,
		None, &logger
	).unwrap();

	// Set `channel_type` to `None` to force the implicit feature negotiation.
	let mut open_channel_msg = channel_a.get_open_channel(ChainHash::using_genesis_block(network), &&logger).unwrap();
	open_channel_msg.common_fields.channel_type = None;

	// Since A supports both `static_remote_key` and `option_anchors`, but B only accepts
	// `static_remote_key`, it will fail the channel.
	let channel_b = InboundV1Channel::<&TestKeysInterface>::new(
		&fee_estimator, &&keys_provider, &&keys_provider, node_id_a,
		&channelmanager::provided_channel_type_features(&config), &init_features_with_simple_anchors,
		&open_channel_msg, 7, &config, 0, &&logger, /*is_0conf=*/false
	);
	assert!(channel_b.is_err());
}

#[test]
fn test_rejects_simple_anchors_channel_type() {
	// Tests that if `option_anchors` is being negotiated through the `channel_type` feature,
	// it is rejected.
	let secp_ctx = Secp256k1::new();
	let test_est = TestFeeEstimator::new(15000);
	let fee_estimator = LowerBoundedFeeEstimator::new(&test_est);
	let network = Network::Testnet;
	let keys_provider = TestKeysInterface::new(&[42; 32], network);
	let logger = TestLogger::new();

	let node_id_a = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[1; 32]).unwrap());
	let node_id_b = PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[2; 32]).unwrap());

	let config = UserConfig::default();

	// See feature bit assignments: https://github.com/lightning/bolts/blob/master/09-features.md
	let static_remote_key_required: u64 = 1 << 12;
	let simple_anchors_required: u64 = 1 << 20;
	let simple_anchors_raw_features = static_remote_key_required | simple_anchors_required;
	let simple_anchors_init = InitFeatures::from_le_bytes(simple_anchors_raw_features.to_le_bytes().to_vec());
	let simple_anchors_channel_type = ChannelTypeFeatures::from_le_bytes(simple_anchors_raw_features.to_le_bytes().to_vec());
	assert!(!simple_anchors_init.requires_unknown_bits());
	assert!(!simple_anchors_channel_type.requires_unknown_bits());

	// First, we'll try to open a channel between A and B where A requests a channel type for
	// the original `option_anchors` feature (non zero fee htlc tx). This should be rejected by
	// B as it's not supported by LDK.
	let mut channel_a = OutboundV1Channel::<&TestKeysInterface>::new(
		&fee_estimator, &&keys_provider, &&keys_provider, node_id_b,
		&channelmanager::provided_init_features(&config), 10000000, 100000, 42, &config, 0, 42,
		None, &logger
	).unwrap();

	let mut open_channel_msg = channel_a.get_open_channel(ChainHash::using_genesis_block(network), &&logger).unwrap();
	open_channel_msg.common_fields.channel_type = Some(simple_anchors_channel_type.clone());

	let res = InboundV1Channel::<&TestKeysInterface>::new(
		&fee_estimator, &&keys_provider, &&keys_provider, node_id_a,
		&channelmanager::provided_channel_type_features(&config), &simple_anchors_init,
		&open_channel_msg, 7, &config, 0, &&logger, /*is_0conf=*/false
	);
	assert!(res.is_err());

	// Then, we'll try to open another channel where A requests a channel type for
	// `anchors_zero_fee_htlc_tx`. B is malicious and tries to downgrade the channel type to the
	// original `option_anchors` feature, which should be rejected by A as it's not supported by
	// LDK.
	let mut channel_a = OutboundV1Channel::<&TestKeysInterface>::new(
		&fee_estimator, &&keys_provider, &&keys_provider, node_id_b, &simple_anchors_init,
		10000000, 100000, 42, &config, 0, 42, None, &logger
	).unwrap();

	let open_channel_msg = channel_a.get_open_channel(ChainHash::using_genesis_block(network), &&logger).unwrap();

	let mut channel_b = InboundV1Channel::<&TestKeysInterface>::new(
		&fee_estimator, &&keys_provider, &&keys_provider, node_id_a,
		&channelmanager::provided_channel_type_features(&config), &channelmanager::provided_init_features(&config),
		&open_channel_msg, 7, &config, 0, &&logger, /*is_0conf=*/false
	).unwrap();

	let mut accept_channel_msg = channel_b.get_accept_channel_message(&&logger).unwrap();
	accept_channel_msg.common_fields.channel_type = Some(simple_anchors_channel_type.clone());

	let res = channel_a.accept_channel(
		&accept_channel_msg, &config.channel_handshake_limits, &simple_anchors_init
	);
	assert!(res.is_err());
}
