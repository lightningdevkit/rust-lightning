//! This is the config struct used by the channel and channel_manager for channel specific settings and channel handshake limits
//! ChannelHandshakeLimits sets the limits of certain variables that if they are exceeded the channel will be denied.
//! ChannelConfig is used by the channel to control its own properties, it contains defaults for a new channel but these can by changed by update messages or channel creation.
//! Changing the ChannelConfig of channel_manager after a channel was created will not change the settings in already created channels

/// This is the main user config
/// It wraps the ChannelHandshakeLimits struct and ChannelConfig struct into a single one for channel manager.
#[derive(Clone, Debug)]
pub struct UserConfig{
	/// optional user specified channel limits, this hold information regarding handshakes of channels.
	pub channel_limits : ChannelHandshakeLimits,
	/// channel specific options and settings egis channel announced or not
	pub channel_options : ChannelConfig,
}

impl UserConfig {
	///default constructor, calls default ChannelOptions and default ChannelLimits constructors
    pub fn new() -> Self{
        UserConfig {
            channel_limits : ChannelHandshakeLimits::new(),
			channel_options : ChannelConfig::new(),
        }
    }
}

/// This struct contains all the optional channel limits. If these limits are breached the new channel will be denied
/// If the user wants to check a value, the value needs to be filled in, as by default most are not checked
#[derive(Copy, Clone, Debug)]
pub struct ChannelHandshakeLimits{
	/// minimum allowed satoshis when a channel is funded, this is supplied by the sender.
	pub min_funding_satoshis :u64,
	/// maximum allowed smallest HTLC that will be accepted by us.
	pub max_htlc_minimum_msat : u64,
	/// min allowed cap on outstanding HTLC. This is used to limit exposure to HTLCs.
	pub min_max_htlc_value_in_flight_msat : u64,
	/// max allowed satoshis that may be used as a direct payment by the peer.
	pub max_channel_reserve_satoshis : u64,
	/// min allowed max outstanding HTLC that can be offered.
	pub min_max_accepted_htlcs : u16,
	/// min allowed threshold below which outputs should not be generated.
	/// These outputs are either commitment or HTLC transactions.
	/// HTLCs below this amount plus HTLC transaction fees are not enforceable on-chain.
	/// This reflects the reality that tiny outputs are not considered standard transactions and will not propagate through the Bitcoin network
	pub min_dust_limit_satoshis : u64,
	/// max allowed threshold above which outputs should not be generated. Bolt 2 mentions channel_reserve_satoshis as upper limit, but this can be a lower limit
	pub max_dust_limit_satoshis : u64,
	/// minimum depth to a number of blocks that is considered reasonable to avoid double-spending of the funding transaction
	pub minimum_depth : u32,
	/// do we force the incoming channel to match our announced channel preference
	pub force_announced_channel_preference : bool,
}

impl ChannelHandshakeLimits {
//creating max and min possible values because if they are not set, means we should not check them.
///default constructor creates limits so that they are not tested for
///min_dust_limit_satoshis is set to the network default of 546
	pub fn new() -> Self{
		ChannelHandshakeLimits {
			min_funding_satoshis : 0,
			max_htlc_minimum_msat : <u64>::max_value(),
			min_max_htlc_value_in_flight_msat : 0,
			max_channel_reserve_satoshis : <u64>::max_value(),
			min_max_accepted_htlcs : 0,
			min_dust_limit_satoshis : 546,
			max_dust_limit_satoshis : <u64>::max_value(),
			minimum_depth : <u32>::max_value(),
			force_announced_channel_preference : false,
		}
	}
}

/// This struct contains all the custom channel options.
#[derive(Copy, Clone, Debug)]
pub struct ChannelConfig{
	/// Amount (in millionths of a satoshi) the channel will charge per transferred satoshi.
	/// This must be updated as the channel updates and can change in runtime.
	pub fee_proportional_millionths : u32,
	//TODO enforce non-mutability when config can change at runtime
	///Is this channel publicly announced channel or not.
	///This cannot change after channel creation.
	pub announced_channel : bool,
}
impl ChannelConfig {
	/// creating a struct with default values.
	/// fee_proportional_millionths should be changed and updated afterwords
	pub fn new() -> Self{
		ChannelConfig {
			fee_proportional_millionths : 0,
			announced_channel : true,
		}
	}
}

//Add write and readable traits to channelconfig
impl_writeable!(ChannelConfig, 8+1, {
	fee_proportional_millionths,
	announced_channel
});
