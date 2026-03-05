use crate::chain::chaininterface::LowerBoundedFeeEstimator;
use crate::ln::channel::{get_initial_channel_type, InboundV1Channel, OutboundV1Channel};
use crate::ln::channelmanager;
use crate::prelude::*;
use crate::util::config::UserConfig;
use crate::util::test_utils::{TestFeeEstimator, TestKeysInterface, TestLogger};
use bitcoin::constants::ChainHash;
use bitcoin::network::Network;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use lightning_types::features::{ChannelTypeFeatures, InitFeatures};

#[test]
fn test_option_scid_privacy_initial() {
	let mut expected_type = ChannelTypeFeatures::only_static_remote_key();
	expected_type.set_scid_privacy_required();

	do_test_get_initial_channel_type(
		UserConfig::default(),
		InitFeatures::empty(),
		ChannelTypeFeatures::only_static_remote_key(),
		|cfg: &mut UserConfig| {
			// announce_for_forwarding = false is required, but set by UserConfig::default().
			cfg.channel_handshake_config.negotiate_scid_privacy = true;
		},
		|their_features: &mut InitFeatures| {
			their_features.set_scid_privacy_optional();
		},
		expected_type,
	)
}

#[test]
fn test_option_anchors_zero_fee_initial() {
	let mut expected_type = ChannelTypeFeatures::only_static_remote_key();
	expected_type.set_anchors_zero_fee_htlc_tx_required();

	let mut start_cfg = UserConfig::default();
	start_cfg.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = false;
	do_test_get_initial_channel_type(
		start_cfg,
		InitFeatures::empty(),
		ChannelTypeFeatures::only_static_remote_key(),
		|cfg: &mut UserConfig| {
			cfg.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = true;
		},
		|their_features: &mut InitFeatures| {
			their_features.set_anchors_zero_fee_htlc_tx_optional();
		},
		expected_type,
	)
}

#[test]
fn test_option_zero_fee_commitments_initial() {
	let mut expected_type = ChannelTypeFeatures::empty();
	expected_type.set_anchor_zero_fee_commitments_required();

	do_test_get_initial_channel_type(
		UserConfig::default(),
		InitFeatures::empty(),
		ChannelTypeFeatures::only_static_remote_key(),
		|cfg: &mut UserConfig| {
			cfg.channel_handshake_config.negotiate_anchor_zero_fee_commitments = true;
		},
		|their_features: &mut InitFeatures| {
			their_features.set_anchor_zero_fee_commitments_optional();
		},
		expected_type,
	)
}

#[test]
fn test_option_zero_fee_commitments_from_zero_htlc_anchors_initial() {
	let mut start_cfg = UserConfig::default();
	start_cfg.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = true;

	let mut start_features = InitFeatures::empty();
	start_features.set_anchors_zero_fee_htlc_tx_optional();

	let mut start_type = ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies();

	let mut expected_type = ChannelTypeFeatures::empty();
	expected_type.set_anchor_zero_fee_commitments_required();

	do_test_get_initial_channel_type(
		start_cfg,
		start_features,
		start_type,
		|cfg: &mut UserConfig| {
			cfg.channel_handshake_config.negotiate_anchor_zero_fee_commitments = true;
		},
		|their_features: &mut InitFeatures| {
			their_features.set_anchor_zero_fee_commitments_optional();
		},
		expected_type,
	)
}

fn do_test_get_initial_channel_type<F1, F2>(
	start_cfg: UserConfig, start_features: InitFeatures, start_type: ChannelTypeFeatures,
	mut local_cfg_mod: F1, mut remote_features_mod: F2, channel_type: ChannelTypeFeatures,
) where
	F1: FnOnce(&mut UserConfig),
	F2: FnOnce(&mut InitFeatures),
{
	// Local node supports feature, remote does not.
	let mut config = start_cfg.clone();
	local_cfg_mod(&mut config);
	assert_eq!(get_initial_channel_type(&config, &start_features), start_type);

	// Remote node supports feature, local does not.
	let mut their_features = start_features.clone();
	remote_features_mod(&mut their_features);
	assert_eq!(get_initial_channel_type(&start_cfg, &their_features), start_type);

	// Both support feature.
	assert_eq!(get_initial_channel_type(&config, &their_features), channel_type)
}

#[test]
fn test_zero_conf_channel_type_support() {
	let test_est = TestFeeEstimator::new(15000);
	let feeest = LowerBoundedFeeEstimator::new(&test_est);
	let secp_ctx = Secp256k1::new();
	let seed = [42; 32];
	let network = Network::Testnet;
	let keys_provider = TestKeysInterface::new(&seed, network);
	let logger = TestLogger::new();

	let node_b_node_id =
		PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
	let config = UserConfig::default();
	let mut node_a_chan = OutboundV1Channel::<&TestKeysInterface>::new(
		&feeest,
		&&keys_provider,
		&&keys_provider,
		node_b_node_id,
		&channelmanager::provided_init_features(&config),
		10000000,
		100000,
		42,
		&config,
		0,
		42,
		None,
		&logger,
	)
	.unwrap();

	let mut channel_type_features = ChannelTypeFeatures::only_static_remote_key();
	channel_type_features.set_zero_conf_required();

	let mut open_channel_msg =
		node_a_chan.get_open_channel(ChainHash::using_genesis_block(network), &&logger).unwrap();
	open_channel_msg.common_fields.channel_type = Some(channel_type_features);
	let node_b_node_id =
		PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[7; 32]).unwrap());
	let res = InboundV1Channel::<&TestKeysInterface>::new(
		&feeest,
		&&keys_provider,
		&&keys_provider,
		node_b_node_id,
		&channelmanager::provided_channel_type_features(&config),
		&channelmanager::provided_init_features(&config),
		&open_channel_msg,
		7,
		&config,
		0,
		&&logger,
		/*is_0conf=*/ false,
	);
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

	let node_id_a =
		PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[1; 32]).unwrap());
	let node_id_b =
		PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[2; 32]).unwrap());

	let mut non_anchors_config = UserConfig::default();
	non_anchors_config.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = false;
	// Assert that we get `static_remotekey` when no custom config is negotiated.
	let channel_a = OutboundV1Channel::<&TestKeysInterface>::new(
		&fee_estimator,
		&&keys_provider,
		&&keys_provider,
		node_id_b,
		&channelmanager::provided_init_features(&non_anchors_config),
		10000000,
		100000,
		42,
		&config,
		0,
		42,
		None,
		&logger,
	)
	.unwrap();
	assert_eq!(
		channel_a.funding.get_channel_type(),
		&ChannelTypeFeatures::only_static_remote_key()
	);

	let mut channel_a = OutboundV1Channel::<&TestKeysInterface>::new(
		&fee_estimator,
		&&keys_provider,
		&&keys_provider,
		node_id_b,
		&channelmanager::provided_init_features(&config),
		10000000,
		100000,
		42,
		&config,
		0,
		42,
		None,
		&logger,
	)
	.unwrap();

	let open_channel_msg =
		channel_a.get_open_channel(ChainHash::using_genesis_block(network), &&logger).unwrap();
	let channel_b = InboundV1Channel::<&TestKeysInterface>::new(
		&fee_estimator,
		&&keys_provider,
		&&keys_provider,
		node_id_a,
		&channelmanager::provided_channel_type_features(&config),
		&channelmanager::provided_init_features(&config),
		&open_channel_msg,
		7,
		&config,
		0,
		&&logger,
		/*is_0conf=*/ false,
	)
	.unwrap();

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
fn test_rejects_if_channel_type_not_set() {
	// Tests that if `channel_type` is not set in `open_channel` and `accept_channel`, it is
	// rejected.
	let secp_ctx = Secp256k1::new();
	let test_est = TestFeeEstimator::new(15000);
	let fee_estimator = LowerBoundedFeeEstimator::new(&test_est);
	let network = Network::Testnet;
	let keys_provider = TestKeysInterface::new(&[42; 32], network);
	let logger = TestLogger::new();

	let node_id_a =
		PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[1; 32]).unwrap());
	let node_id_b =
		PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[2; 32]).unwrap());

	let config = UserConfig::default();

	let mut channel_a = OutboundV1Channel::<&TestKeysInterface>::new(
		&fee_estimator,
		&&keys_provider,
		&&keys_provider,
		node_id_b,
		&channelmanager::provided_init_features(&config),
		10000000,
		100000,
		42,
		&config,
		0,
		42,
		None,
		&logger,
	)
	.unwrap();

	// Set `channel_type` to `None` to cause failure.
	let mut open_channel_msg =
		channel_a.get_open_channel(ChainHash::using_genesis_block(network), &&logger).unwrap();
	open_channel_msg.common_fields.channel_type = None;

	let channel_b = InboundV1Channel::<&TestKeysInterface>::new(
		&fee_estimator,
		&&keys_provider,
		&&keys_provider,
		node_id_a,
		&channelmanager::provided_channel_type_features(&config),
		&channelmanager::provided_init_features(&config),
		&open_channel_msg,
		7,
		&config,
		0,
		&&logger,
		/*is_0conf=*/ false,
	);
	assert!(channel_b.is_err());

	open_channel_msg.common_fields.channel_type =
		Some(channel_a.funding.get_channel_type().clone());
	let mut channel_b = InboundV1Channel::<&TestKeysInterface>::new(
		&fee_estimator,
		&&keys_provider,
		&&keys_provider,
		node_id_a,
		&channelmanager::provided_channel_type_features(&config),
		&channelmanager::provided_init_features(&config),
		&open_channel_msg,
		7,
		&config,
		0,
		&&logger,
		/*is_0conf=*/ false,
	)
	.unwrap();

	// Set `channel_type` to `None` in `accept_channel` to cause failure.
	let mut accept_channel_msg = channel_b.get_accept_channel_message(&&logger).unwrap();
	accept_channel_msg.common_fields.channel_type = None;

	let res = channel_a.accept_channel(
		&accept_channel_msg,
		&config.channel_handshake_limits,
		&channelmanager::provided_init_features(&config),
	);
	assert!(res.is_err());
}

#[test]
fn test_rejects_if_channel_type_differ() {
	// Tests that if the `channel_type` in `accept_channel` does not match the one set in
	// `open_channel` it rejects the channel.
	let secp_ctx = Secp256k1::new();
	let test_est = TestFeeEstimator::new(15000);
	let fee_estimator = LowerBoundedFeeEstimator::new(&test_est);
	let network = Network::Testnet;
	let keys_provider = TestKeysInterface::new(&[42; 32], network);
	let logger = TestLogger::new();

	let node_id_a =
		PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[1; 32]).unwrap());
	let node_id_b =
		PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[2; 32]).unwrap());

	let config = UserConfig::default();

	let mut channel_a = OutboundV1Channel::<&TestKeysInterface>::new(
		&fee_estimator,
		&&keys_provider,
		&&keys_provider,
		node_id_b,
		&channelmanager::provided_init_features(&config),
		10000000,
		100000,
		42,
		&config,
		0,
		42,
		None,
		&logger,
	)
	.unwrap();

	let open_channel_msg =
		channel_a.get_open_channel(ChainHash::using_genesis_block(network), &&logger).unwrap();

	let mut channel_b = InboundV1Channel::<&TestKeysInterface>::new(
		&fee_estimator,
		&&keys_provider,
		&&keys_provider,
		node_id_a,
		&channelmanager::provided_channel_type_features(&config),
		&channelmanager::provided_init_features(&config),
		&open_channel_msg,
		7,
		&config,
		0,
		&&logger,
		/*is_0conf=*/ false,
	)
	.unwrap();

	// Change the `channel_type` in `accept_channel` msg to make it different from the one set in
	// `open_channel` to cause failure.
	let mut accept_channel_msg = channel_b.get_accept_channel_message(&&logger).unwrap();
	let mut channel_type = channelmanager::provided_channel_type_features(&config);
	channel_type.set_zero_conf_required();
	accept_channel_msg.common_fields.channel_type = Some(channel_type.clone());

	let res = channel_a.accept_channel(
		&accept_channel_msg,
		&config.channel_handshake_limits,
		&channelmanager::provided_init_features(&config),
	);
	assert!(res.is_err());
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

	let node_id_a =
		PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[1; 32]).unwrap());
	let node_id_b =
		PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[2; 32]).unwrap());

	let config = UserConfig::default();

	// See feature bit assignments: https://github.com/lightning/bolts/blob/master/09-features.md
	let static_remote_key_required: u64 = 1 << 12;
	let simple_anchors_required: u64 = 1 << 20;
	let simple_anchors_raw_features = static_remote_key_required | simple_anchors_required;
	let simple_anchors_init =
		InitFeatures::from_le_bytes(simple_anchors_raw_features.to_le_bytes().to_vec());
	let simple_anchors_channel_type =
		ChannelTypeFeatures::from_le_bytes(simple_anchors_raw_features.to_le_bytes().to_vec());
	assert!(!simple_anchors_init.requires_unknown_bits());
	assert!(!simple_anchors_channel_type.requires_unknown_bits());

	// First, we'll try to open a channel between A and B where A requests a channel type for
	// the original `option_anchors` feature (non zero fee htlc tx). This should be rejected by
	// B as it's not supported by LDK.
	let mut channel_a = OutboundV1Channel::<&TestKeysInterface>::new(
		&fee_estimator,
		&&keys_provider,
		&&keys_provider,
		node_id_b,
		&channelmanager::provided_init_features(&config),
		10000000,
		100000,
		42,
		&config,
		0,
		42,
		None,
		&logger,
	)
	.unwrap();

	let mut open_channel_msg =
		channel_a.get_open_channel(ChainHash::using_genesis_block(network), &&logger).unwrap();
	open_channel_msg.common_fields.channel_type = Some(simple_anchors_channel_type.clone());

	let res = InboundV1Channel::<&TestKeysInterface>::new(
		&fee_estimator,
		&&keys_provider,
		&&keys_provider,
		node_id_a,
		&channelmanager::provided_channel_type_features(&config),
		&simple_anchors_init,
		&open_channel_msg,
		7,
		&config,
		0,
		&&logger,
		/*is_0conf=*/ false,
	);
	assert!(res.is_err());

	// Then, we'll try to open another channel where A requests a channel type for
	// `anchors_zero_fee_htlc_tx`. B is malicious and tries to downgrade the channel type to the
	// original `option_anchors` feature, which should be rejected by A as it's not supported by
	// LDK.
	let mut channel_a = OutboundV1Channel::<&TestKeysInterface>::new(
		&fee_estimator,
		&&keys_provider,
		&&keys_provider,
		node_id_b,
		&simple_anchors_init,
		10000000,
		100000,
		42,
		&config,
		0,
		42,
		None,
		&logger,
	)
	.unwrap();

	let open_channel_msg =
		channel_a.get_open_channel(ChainHash::using_genesis_block(network), &&logger).unwrap();

	let mut channel_b = InboundV1Channel::<&TestKeysInterface>::new(
		&fee_estimator,
		&&keys_provider,
		&&keys_provider,
		node_id_a,
		&channelmanager::provided_channel_type_features(&config),
		&channelmanager::provided_init_features(&config),
		&open_channel_msg,
		7,
		&config,
		0,
		&&logger,
		/*is_0conf=*/ false,
	)
	.unwrap();

	let mut accept_channel_msg = channel_b.get_accept_channel_message(&&logger).unwrap();
	accept_channel_msg.common_fields.channel_type = Some(simple_anchors_channel_type.clone());

	let res = channel_a.accept_channel(
		&accept_channel_msg,
		&config.channel_handshake_limits,
		&simple_anchors_init,
	);
	assert!(res.is_err());
}
