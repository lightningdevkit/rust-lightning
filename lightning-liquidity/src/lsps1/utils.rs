use super::msgs::{LSPS1Options, OrderParameters};

pub fn check_range(min: u64, max: u64, value: u64) -> bool {
	(value >= min) && (value <= max)
}

pub fn is_valid(order: &OrderParameters, options: &LSPS1Options) -> bool {
	let bool = check_range(
		options.min_initial_client_balance_sat,
		options.max_initial_client_balance_sat,
		order.client_balance_sat,
	) && check_range(
		options.min_initial_lsp_balance_sat,
		options.max_initial_lsp_balance_sat,
		order.lsp_balance_sat,
	) && check_range(
		1,
		options.max_channel_expiry_blocks.into(),
		order.channel_expiry_blocks.into(),
	);

	bool
}
