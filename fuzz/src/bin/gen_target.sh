#!/bin/sh

echo "#include <stdint.h>" > ../../targets.h
GEN_TEST() {
	cat target_template.txt | sed s/TARGET_NAME/$1/ | sed s/TARGET_MOD/$2$1/ > $1_target.rs
	echo "void $1_run(const unsigned char* data, size_t data_len);" >> ../../targets.h
}

GEN_TEST bech32_parse
GEN_TEST chanmon_deser
GEN_TEST chanmon_consistency
GEN_TEST full_stack
GEN_TEST invoice_deser
GEN_TEST invoice_request_deser
GEN_TEST offer_deser
GEN_TEST onion_message
GEN_TEST peer_crypt
GEN_TEST process_network_graph
GEN_TEST refund_deser
GEN_TEST router
GEN_TEST zbase32
GEN_TEST indexedmap

GEN_TEST msg_accept_channel msg_targets::
GEN_TEST msg_announcement_signatures msg_targets::
GEN_TEST msg_channel_reestablish msg_targets::
GEN_TEST msg_closing_signed msg_targets::
GEN_TEST msg_commitment_signed msg_targets::
GEN_TEST msg_decoded_onion_error_packet msg_targets::
GEN_TEST msg_funding_created msg_targets::
GEN_TEST msg_channel_ready msg_targets::
GEN_TEST msg_funding_signed msg_targets::
GEN_TEST msg_init msg_targets::
GEN_TEST msg_open_channel msg_targets::
GEN_TEST msg_revoke_and_ack msg_targets::
GEN_TEST msg_shutdown msg_targets::
GEN_TEST msg_update_fail_htlc msg_targets::
GEN_TEST msg_update_fail_malformed_htlc msg_targets::
GEN_TEST msg_update_fee msg_targets::
GEN_TEST msg_update_fulfill_htlc msg_targets::

GEN_TEST msg_channel_announcement msg_targets::
GEN_TEST msg_node_announcement msg_targets::
GEN_TEST msg_query_short_channel_ids msg_targets::
GEN_TEST msg_reply_short_channel_ids_end msg_targets::
GEN_TEST msg_query_channel_range msg_targets::
GEN_TEST msg_reply_channel_range msg_targets::
GEN_TEST msg_gossip_timestamp_filter msg_targets::

GEN_TEST msg_update_add_htlc msg_targets::
GEN_TEST msg_error_message msg_targets::
GEN_TEST msg_channel_update msg_targets::

GEN_TEST msg_onion_hop_data msg_targets::
GEN_TEST msg_ping msg_targets::
GEN_TEST msg_pong msg_targets::

GEN_TEST msg_channel_details msg_targets::
