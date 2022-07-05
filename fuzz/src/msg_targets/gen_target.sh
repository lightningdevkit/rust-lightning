#!/bin/sh

GEN_TEST() {
	tn=msg_$(echo $1 | sed s'/.*:://g' | sed 's/\([a-z0-9]\)\([A-Z]\)/\1_\2/g' | tr '[:upper:]' '[:lower:]')
	fn=${tn}.rs
	cat msg_target_template.txt | sed s/MSG_TARGET/$1/ | sed "s/TARGET_NAME/$tn/" | sed "s/TEST_MSG/$2/" | sed "s/EXTRA_ARGS/$3/" > $fn
	echo "pub mod $tn;" >> mod.rs
}

echo "mod utils;" > mod.rs

# Note when adding new targets here you should add a similar line in src/bin/gen_target.sh

GEN_TEST lightning::ln::msgs::AcceptChannel test_msg_simple ""
GEN_TEST lightning::ln::msgs::AnnouncementSignatures test_msg_simple ""
GEN_TEST lightning::ln::msgs::ClosingSigned test_msg_simple ""
GEN_TEST lightning::ln::msgs::CommitmentSigned test_msg_simple ""
GEN_TEST lightning::ln::msgs::FundingCreated test_msg_simple ""
GEN_TEST lightning::ln::msgs::ChannelReady test_msg_simple ""
GEN_TEST lightning::ln::msgs::FundingSigned test_msg_simple ""
GEN_TEST lightning::ln::msgs::GossipTimestampFilter test_msg_simple ""
GEN_TEST lightning::ln::msgs::Init test_msg_simple ""
GEN_TEST lightning::ln::msgs::OnionHopData test_msg_simple ""
GEN_TEST lightning::ln::msgs::OpenChannel test_msg_simple ""
GEN_TEST lightning::ln::msgs::Ping test_msg_simple ""
GEN_TEST lightning::ln::msgs::Pong test_msg_simple ""
GEN_TEST lightning::ln::msgs::QueryChannelRange test_msg_simple ""
GEN_TEST lightning::ln::msgs::ReplyShortChannelIdsEnd test_msg_simple ""
GEN_TEST lightning::ln::msgs::RevokeAndACK test_msg_simple ""
GEN_TEST lightning::ln::msgs::Shutdown test_msg_simple ""
GEN_TEST lightning::ln::msgs::UpdateAddHTLC test_msg_simple ""
GEN_TEST lightning::ln::msgs::UpdateFailHTLC test_msg_simple ""
GEN_TEST lightning::ln::msgs::UpdateFailMalformedHTLC test_msg_simple ""
GEN_TEST lightning::ln::msgs::UpdateFee test_msg_simple ""
GEN_TEST lightning::ln::msgs::UpdateFulfillHTLC test_msg_simple ""

GEN_TEST lightning::ln::msgs::ChannelReestablish test_msg ""
GEN_TEST lightning::ln::msgs::DecodedOnionErrorPacket test_msg ""

GEN_TEST lightning::ln::msgs::ChannelAnnouncement test_msg_exact ""
GEN_TEST lightning::ln::msgs::NodeAnnouncement test_msg_exact ""
GEN_TEST lightning::ln::msgs::QueryShortChannelIds test_msg ""
GEN_TEST lightning::ln::msgs::ReplyChannelRange test_msg ""

GEN_TEST lightning::ln::msgs::ErrorMessage test_msg_hole ", 32, 2"
GEN_TEST lightning::ln::msgs::WarningMessage test_msg_hole ", 32, 2"
GEN_TEST lightning::ln::msgs::ChannelUpdate test_msg_hole ", 108, 1"

GEN_TEST lightning::ln::channelmanager::ChannelDetails test_msg_simple ""
