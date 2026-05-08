#!/bin/sh

echo "#include <stdint.h>" > ../../targets.h
GEN_TEST() {
	dest_dir=$1
	target_name=$2
	target_mod=$3
	hashes_flag=$4

	mkdir -p "$dest_dir"
	sed "s/TARGET_NAME/$target_name/g; s|TARGET_MOD|$target_mod$target_name|g; s/HASHES_FLAG/$hashes_flag/g" \
		target_template.txt > "$dest_dir/${target_name}_target.rs"
	echo "void ${target_name}_run(const unsigned char* data, size_t data_len);" >> ../../targets.h
}

GEN_FAKE_HASHES_TEST() {
	GEN_TEST ../../fuzz-fake-hashes/src/bin "$1" "$2" "not(hashes_fuzz)"
}

GEN_REAL_HASHES_TEST() {
	GEN_TEST ../../fuzz-real-hashes/src/bin "$1" "$2" "hashes_fuzz"
}

GEN_FAKE_HASHES_TEST bech32_parse
GEN_FAKE_HASHES_TEST chanmon_deser
GEN_REAL_HASHES_TEST chanmon_consistency
GEN_FAKE_HASHES_TEST full_stack
GEN_FAKE_HASHES_TEST invoice_deser
GEN_FAKE_HASHES_TEST invoice_request_deser
GEN_FAKE_HASHES_TEST offer_deser
GEN_FAKE_HASHES_TEST bolt11_deser
GEN_FAKE_HASHES_TEST static_invoice_deser
GEN_FAKE_HASHES_TEST onion_message
GEN_FAKE_HASHES_TEST peer_crypt
GEN_FAKE_HASHES_TEST process_network_graph
GEN_FAKE_HASHES_TEST process_onion_failure
GEN_FAKE_HASHES_TEST refund_deser
GEN_FAKE_HASHES_TEST router
GEN_FAKE_HASHES_TEST zbase32
GEN_FAKE_HASHES_TEST indexedmap
GEN_FAKE_HASHES_TEST onion_hop_data
GEN_FAKE_HASHES_TEST base32
GEN_FAKE_HASHES_TEST fromstr_to_netaddress
GEN_FAKE_HASHES_TEST feature_flags
GEN_FAKE_HASHES_TEST lsps_message
GEN_FAKE_HASHES_TEST fs_store
GEN_FAKE_HASHES_TEST gossip_discovery

GEN_FAKE_HASHES_TEST msg_accept_channel msg_targets::
GEN_FAKE_HASHES_TEST msg_announcement_signatures msg_targets::
GEN_FAKE_HASHES_TEST msg_channel_reestablish msg_targets::
GEN_FAKE_HASHES_TEST msg_closing_signed msg_targets::
GEN_FAKE_HASHES_TEST msg_closing_complete msg_targets::
GEN_FAKE_HASHES_TEST msg_closing_sig msg_targets::
GEN_FAKE_HASHES_TEST msg_commitment_signed msg_targets::
GEN_FAKE_HASHES_TEST msg_decoded_onion_error_packet msg_targets::
GEN_FAKE_HASHES_TEST msg_funding_created msg_targets::
GEN_FAKE_HASHES_TEST msg_channel_ready msg_targets::
GEN_FAKE_HASHES_TEST msg_funding_signed msg_targets::
GEN_FAKE_HASHES_TEST msg_init msg_targets::
GEN_FAKE_HASHES_TEST msg_open_channel msg_targets::
GEN_FAKE_HASHES_TEST msg_revoke_and_ack msg_targets::
GEN_FAKE_HASHES_TEST msg_shutdown msg_targets::
GEN_FAKE_HASHES_TEST msg_update_fail_htlc msg_targets::
GEN_FAKE_HASHES_TEST msg_update_fail_malformed_htlc msg_targets::
GEN_FAKE_HASHES_TEST msg_update_fee msg_targets::
GEN_FAKE_HASHES_TEST msg_update_fulfill_htlc msg_targets::

GEN_FAKE_HASHES_TEST msg_channel_announcement msg_targets::
GEN_FAKE_HASHES_TEST msg_node_announcement msg_targets::
GEN_FAKE_HASHES_TEST msg_query_short_channel_ids msg_targets::
GEN_FAKE_HASHES_TEST msg_reply_short_channel_ids_end msg_targets::
GEN_FAKE_HASHES_TEST msg_query_channel_range msg_targets::
GEN_FAKE_HASHES_TEST msg_reply_channel_range msg_targets::
GEN_FAKE_HASHES_TEST msg_gossip_timestamp_filter msg_targets::

GEN_FAKE_HASHES_TEST msg_update_add_htlc msg_targets::
GEN_FAKE_HASHES_TEST msg_error_message msg_targets::
GEN_FAKE_HASHES_TEST msg_channel_update msg_targets::

GEN_FAKE_HASHES_TEST msg_ping msg_targets::
GEN_FAKE_HASHES_TEST msg_pong msg_targets::

GEN_FAKE_HASHES_TEST msg_channel_details msg_targets::

GEN_FAKE_HASHES_TEST msg_open_channel_v2 msg_targets::
GEN_FAKE_HASHES_TEST msg_accept_channel_v2 msg_targets::
GEN_FAKE_HASHES_TEST msg_tx_add_input msg_targets::
GEN_FAKE_HASHES_TEST msg_tx_add_output msg_targets::
GEN_FAKE_HASHES_TEST msg_tx_remove_input msg_targets::
GEN_FAKE_HASHES_TEST msg_tx_remove_output msg_targets::
GEN_FAKE_HASHES_TEST msg_tx_complete msg_targets::
GEN_FAKE_HASHES_TEST msg_tx_signatures msg_targets::
GEN_FAKE_HASHES_TEST msg_tx_init_rbf msg_targets::
GEN_FAKE_HASHES_TEST msg_tx_ack_rbf msg_targets::
GEN_FAKE_HASHES_TEST msg_tx_abort msg_targets::

GEN_FAKE_HASHES_TEST msg_stfu msg_targets::

GEN_FAKE_HASHES_TEST msg_splice_init msg_targets::
GEN_FAKE_HASHES_TEST msg_splice_ack msg_targets::
GEN_FAKE_HASHES_TEST msg_splice_locked msg_targets::

GEN_FAKE_HASHES_TEST msg_blinded_message_path msg_targets::
