for target in CommitmentSigned FundingCreated FundingLocked FundingSigned OpenChannel RevokeAndACK Shutdown UpdateAddHTLC UpdateFailHTLC UpdateFailMalformedHTLC UpdateFee UpdateFulfillHTLC AcceptChannel ClosingSigned ChannelReestablish; do
	tn=$(echo $target | sed 's/\([a-z0-9]\)\([A-Z]\)/\1_\2/g')
	fn=msg_$(echo $tn | tr '[:upper:]' '[:lower:]')_target.rs
	cat msg_target_template.txt | sed s/MSG_TARGET/$target/ > $fn
done
