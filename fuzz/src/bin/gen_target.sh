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
GEN_FAKE_HASHES_TEST payer_proof_deser
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

# The message targets are listed in ../msg_targets/gen_target.sh, which writes a
# module for each of them to ../msg_targets/mod.rs. Generate a binary for every
# such module rather than repeating the list here.
for msg_target in $(sed -n 's/^pub mod \(msg_[a-z0-9_]*\);$/\1/p' ../msg_targets/mod.rs); do
	GEN_FAKE_HASHES_TEST "$msg_target" msg_targets::
done
