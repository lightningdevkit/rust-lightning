#include "include/rust_types.h"
#include "include/lightning.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

void print_log(const void *this_arg, const char *record) {
	printf("%s", record);
}

uint32_t get_fee(const void *this_arg, LDKConfirmationTarget target) {
	if (target == LDKConfirmationTarget_Background) {
		return 253;
	} else {
		return 507;
	}
}

void broadcast_tx(const void *this_arg, LDKTransaction tx) {
	//TODO
	Transaction_free(tx);
}

LDKCResult_NoneChannelMonitorUpdateErrZ add_channel_monitor(const void *this_arg, LDKOutPoint funding_txo, LDKChannelMonitor monitor) {
	return CResult_NoneChannelMonitorUpdateErrZ_ok();
}
LDKCResult_NoneChannelMonitorUpdateErrZ update_channel_monitor(const void *this_arg, LDKOutPoint funding_txo, LDKChannelMonitorUpdate monitor) {
	return CResult_NoneChannelMonitorUpdateErrZ_ok();
}
LDKCVec_MonitorEventZ monitors_pending_monitor_events(const void *this_arg) {
	LDKCVec_MonitorEventZ empty_htlc_vec = {
		.data = NULL,
		.datalen = 0,
	};
	return empty_htlc_vec;
}

int main() {
	uint8_t node_seed[32];
	memset(node_seed, 0, 32);

	LDKNetwork net = LDKNetwork_Bitcoin;

	LDKLogger logger = {
		.this_arg = NULL,
		.log = print_log,
		.free = NULL,
	};

	LDKFeeEstimator fee_est = {
		.this_arg = NULL,
		.get_est_sat_per_1000_weight = get_fee,
		.free = NULL
	};

	LDKWatch mon = {
		.this_arg = NULL,
		.watch_channel = add_channel_monitor,
		.update_channel = update_channel_monitor,
		.release_pending_monitor_events = monitors_pending_monitor_events,
		.free = NULL,
	};

	LDKBroadcasterInterface broadcast = {
		broadcast.this_arg = NULL,
		broadcast.broadcast_transaction = broadcast_tx,
		.free = NULL,
	};

	LDKKeysManager keys = KeysManager_new(&node_seed, 0, 0);
	LDKKeysInterface keys_source = KeysManager_as_KeysInterface(&keys);

	LDKUserConfig config = UserConfig_default();
	LDKThirtyTwoBytes chain_tip;
	memset(&chain_tip, 0, 32);
	LDKChainParameters chain = ChainParameters_new(net, chain_tip, 0);
	LDKChannelManager cm = ChannelManager_new(fee_est, mon, broadcast, logger, keys_source, config, chain);

	LDKCVec_ChannelDetailsZ channels = ChannelManager_list_channels(&cm);
	assert((unsigned long)channels.data < 4096); // There's an offset, but it should still be an offset against null in the 0 page
	assert(channels.datalen == 0);
	CVec_ChannelDetailsZ_free(channels);

	LDKEventsProvider prov = ChannelManager_as_EventsProvider(&cm);
	LDKCVec_EventZ events = (prov.get_and_clear_pending_events)(prov.this_arg);
	assert((unsigned long)events.data < 4096); // There's an offset, but it should still be an offset against null in the 0 page
	assert(events.datalen == 0);

	ChannelManager_free(cm);
	KeysManager_free(keys);

	// Check that passing empty vecs to rust doesn't blow it up:
	LDKCVec_MonitorEventZ empty_htlc_vec = {
		.data = NULL,
		.datalen = 0,
	};
	CVec_MonitorEventZ_free(empty_htlc_vec);
}
