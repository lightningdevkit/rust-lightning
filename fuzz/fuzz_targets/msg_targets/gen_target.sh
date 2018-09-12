#!/bin/sh

GEN_TEST() {
	tn=$(echo $1 | sed 's/\([a-z0-9]\)\([A-Z]\)/\1_\2/g')
	fn=msg_$(echo $tn | tr '[:upper:]' '[:lower:]')_target.rs
	cat msg_target_template.txt | sed s/MSG_TARGET/$1/ | sed "s/TEST_MSG/$2/" | sed "s/EXTRA_ARGS/$3/" > $fn
}

GEN_TEST AcceptChannel test_msg ""
GEN_TEST AnnouncementSignatures test_msg ""
GEN_TEST ChannelReestablish test_msg ""
GEN_TEST ClosingSigned test_msg ""
GEN_TEST CommitmentSigned test_msg ""
GEN_TEST DecodedOnionErrorPacket test_msg ""
GEN_TEST FundingCreated test_msg ""
GEN_TEST FundingLocked test_msg ""
GEN_TEST FundingSigned test_msg ""
GEN_TEST Init test_msg ""
GEN_TEST OpenChannel test_msg ""
GEN_TEST RevokeAndACK test_msg ""
GEN_TEST Shutdown test_msg ""
GEN_TEST UpdateFailHTLC test_msg ""
GEN_TEST UpdateFailMalformedHTLC test_msg ""
GEN_TEST UpdateFee test_msg ""
GEN_TEST UpdateFulfillHTLC test_msg ""

GEN_TEST ChannelAnnouncement test_msg_exact ""
GEN_TEST ChannelUpdate test_msg_exact ""
GEN_TEST NodeAnnouncement test_msg_exact ""

GEN_TEST UpdateAddHTLC test_msg_hole ", 85, 33"
GEN_TEST ErrorMessage test_msg_hole ", 32, 2"
GEN_TEST OnionHopData test_msg_hole ", 1+8+8+4, 12"

GEN_TEST Ping test_msg_simple ""
GEN_TEST Pong test_msg_simple ""
