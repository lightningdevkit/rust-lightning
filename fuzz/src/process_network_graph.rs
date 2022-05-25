// Import that needs to be added manually
use utils::test_logger;

/// Actual fuzz test, method signature and name are fixed
fn do_test(data: &[u8]) {
	let block_hash = bitcoin::BlockHash::default();
	let network_graph = lightning::routing::network_graph::NetworkGraph::new(block_hash);
	lightning_rapid_gossip_sync::processing::update_network_graph(&network_graph, data);
}

/// Method that needs to be added manually, {name}_test
pub fn process_network_graph_test<Out: test_logger::Output>(data: &[u8], _out: Out) {
	do_test(data);
}

/// Method that needs to be added manually, {name}_run
#[no_mangle]
pub extern "C" fn process_network_graph_run(data: *const u8, datalen: usize) {
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) });
}
