pub type CVec_SpendableOutputDescriptorZ = crate::c_types::CVecTempl<crate::chain::keysinterface::SpendableOutputDescriptor>;
#[no_mangle]
pub static CVec_SpendableOutputDescriptorZ_free: extern "C" fn(CVec_SpendableOutputDescriptorZ) = crate::c_types::CVecTempl_free::<crate::chain::keysinterface::SpendableOutputDescriptor>;

pub type CVec_MessageSendEventZ = crate::c_types::CVecTempl<crate::util::events::MessageSendEvent>;
#[no_mangle]
pub static CVec_MessageSendEventZ_free: extern "C" fn(CVec_MessageSendEventZ) = crate::c_types::CVecTempl_free::<crate::util::events::MessageSendEvent>;

pub type CVec_EventZ = crate::c_types::CVecTempl<crate::util::events::Event>;
#[no_mangle]
pub static CVec_EventZ_free: extern "C" fn(CVec_EventZ) = crate::c_types::CVecTempl_free::<crate::util::events::Event>;

pub type C2Tuple_usizeTransactionZ = crate::c_types::C2TupleTempl<usize, crate::c_types::Transaction>;
#[no_mangle]
pub static C2Tuple_usizeTransactionZ_free: extern "C" fn(C2Tuple_usizeTransactionZ) = crate::c_types::C2TupleTempl_free::<usize, crate::c_types::Transaction>;
#[no_mangle]
pub extern "C" fn C2Tuple_usizeTransactionZ_new(a: usize, b: crate::c_types::Transaction) -> C2Tuple_usizeTransactionZ {
	C2Tuple_usizeTransactionZ { a, b, }
}

pub type CVec_C2Tuple_usizeTransactionZZ = crate::c_types::CVecTempl<crate::c_types::C2TupleTempl<usize, crate::c_types::Transaction>>;
#[no_mangle]
pub static CVec_C2Tuple_usizeTransactionZZ_free: extern "C" fn(CVec_C2Tuple_usizeTransactionZZ) = crate::c_types::CVecTempl_free::<crate::c_types::C2TupleTempl<usize, crate::c_types::Transaction>>;

pub type CResult_NoneChannelMonitorUpdateErrZ = crate::c_types::CResultTempl<u8, crate::chain::channelmonitor::ChannelMonitorUpdateErr>;
#[no_mangle]
pub static CResult_NoneChannelMonitorUpdateErrZ_free: extern "C" fn(CResult_NoneChannelMonitorUpdateErrZ) = crate::c_types::CResultTempl_free::<u8, crate::chain::channelmonitor::ChannelMonitorUpdateErr>;
#[no_mangle]
pub extern "C" fn CResult_NoneChannelMonitorUpdateErrZ_ok() -> CResult_NoneChannelMonitorUpdateErrZ {
	crate::c_types::CResultTempl::ok(0)
}

#[no_mangle]
pub static CResult_NoneChannelMonitorUpdateErrZ_err: extern "C" fn (crate::chain::channelmonitor::ChannelMonitorUpdateErr) -> CResult_NoneChannelMonitorUpdateErrZ =
	crate::c_types::CResultTempl::<u8, crate::chain::channelmonitor::ChannelMonitorUpdateErr>::err;

pub type CVec_MonitorEventZ = crate::c_types::CVecTempl<crate::chain::channelmonitor::MonitorEvent>;
#[no_mangle]
pub static CVec_MonitorEventZ_free: extern "C" fn(CVec_MonitorEventZ) = crate::c_types::CVecTempl_free::<crate::chain::channelmonitor::MonitorEvent>;

pub type CResult_NoneMonitorUpdateErrorZ = crate::c_types::CResultTempl<u8, crate::chain::channelmonitor::MonitorUpdateError>;
#[no_mangle]
pub static CResult_NoneMonitorUpdateErrorZ_free: extern "C" fn(CResult_NoneMonitorUpdateErrorZ) = crate::c_types::CResultTempl_free::<u8, crate::chain::channelmonitor::MonitorUpdateError>;
#[no_mangle]
pub extern "C" fn CResult_NoneMonitorUpdateErrorZ_ok() -> CResult_NoneMonitorUpdateErrorZ {
	crate::c_types::CResultTempl::ok(0)
}

#[no_mangle]
pub static CResult_NoneMonitorUpdateErrorZ_err: extern "C" fn (crate::chain::channelmonitor::MonitorUpdateError) -> CResult_NoneMonitorUpdateErrorZ =
	crate::c_types::CResultTempl::<u8, crate::chain::channelmonitor::MonitorUpdateError>::err;

pub type C2Tuple_OutPointScriptZ = crate::c_types::C2TupleTempl<crate::chain::transaction::OutPoint, crate::c_types::derived::CVec_u8Z>;
#[no_mangle]
pub static C2Tuple_OutPointScriptZ_free: extern "C" fn(C2Tuple_OutPointScriptZ) = crate::c_types::C2TupleTempl_free::<crate::chain::transaction::OutPoint, crate::c_types::derived::CVec_u8Z>;
#[no_mangle]
pub extern "C" fn C2Tuple_OutPointScriptZ_new(a: crate::chain::transaction::OutPoint, b: crate::c_types::derived::CVec_u8Z) -> C2Tuple_OutPointScriptZ {
	C2Tuple_OutPointScriptZ { a, b, }
}

pub type CVec_TransactionZ = crate::c_types::CVecTempl<crate::c_types::Transaction>;
#[no_mangle]
pub static CVec_TransactionZ_free: extern "C" fn(CVec_TransactionZ) = crate::c_types::CVecTempl_free::<crate::c_types::Transaction>;

pub type C2Tuple_u32TxOutZ = crate::c_types::C2TupleTempl<u32, crate::c_types::TxOut>;
#[no_mangle]
pub static C2Tuple_u32TxOutZ_free: extern "C" fn(C2Tuple_u32TxOutZ) = crate::c_types::C2TupleTempl_free::<u32, crate::c_types::TxOut>;
#[no_mangle]
pub extern "C" fn C2Tuple_u32TxOutZ_new(a: u32, b: crate::c_types::TxOut) -> C2Tuple_u32TxOutZ {
	C2Tuple_u32TxOutZ { a, b, }
}

pub type CVec_C2Tuple_u32TxOutZZ = crate::c_types::CVecTempl<crate::c_types::C2TupleTempl<u32, crate::c_types::TxOut>>;
#[no_mangle]
pub static CVec_C2Tuple_u32TxOutZZ_free: extern "C" fn(CVec_C2Tuple_u32TxOutZZ) = crate::c_types::CVecTempl_free::<crate::c_types::C2TupleTempl<u32, crate::c_types::TxOut>>;

pub type C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ = crate::c_types::C2TupleTempl<crate::c_types::ThirtyTwoBytes, crate::c_types::CVecTempl<crate::c_types::C2TupleTempl<u32, crate::c_types::TxOut>>>;
#[no_mangle]
pub static C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ_free: extern "C" fn(C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ) = crate::c_types::C2TupleTempl_free::<crate::c_types::ThirtyTwoBytes, crate::c_types::CVecTempl<crate::c_types::C2TupleTempl<u32, crate::c_types::TxOut>>>;
#[no_mangle]
pub extern "C" fn C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ_new(a: crate::c_types::ThirtyTwoBytes, b: crate::c_types::derived::CVec_C2Tuple_u32TxOutZZ) -> C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ {
	C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ { a, b, }
}

pub type CVec_C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZZ = crate::c_types::CVecTempl<crate::c_types::C2TupleTempl<crate::c_types::ThirtyTwoBytes, crate::c_types::CVecTempl<crate::c_types::C2TupleTempl<u32, crate::c_types::TxOut>>>>;
#[no_mangle]
pub static CVec_C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZZ_free: extern "C" fn(CVec_C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZZ) = crate::c_types::CVecTempl_free::<crate::c_types::C2TupleTempl<crate::c_types::ThirtyTwoBytes, crate::c_types::CVecTempl<crate::c_types::C2TupleTempl<u32, crate::c_types::TxOut>>>>;

pub type C2Tuple_u64u64Z = crate::c_types::C2TupleTempl<u64, u64>;
#[no_mangle]
pub static C2Tuple_u64u64Z_free: extern "C" fn(C2Tuple_u64u64Z) = crate::c_types::C2TupleTempl_free::<u64, u64>;
#[no_mangle]
pub extern "C" fn C2Tuple_u64u64Z_new(a: u64, b: u64) -> C2Tuple_u64u64Z {
	C2Tuple_u64u64Z { a, b, }
}

pub type CVec_SignatureZ = crate::c_types::CVecTempl<crate::c_types::Signature>;
#[no_mangle]
pub static CVec_SignatureZ_free: extern "C" fn(CVec_SignatureZ) = crate::c_types::CVecTempl_free::<crate::c_types::Signature>;

pub type C2Tuple_SignatureCVec_SignatureZZ = crate::c_types::C2TupleTempl<crate::c_types::Signature, crate::c_types::CVecTempl<crate::c_types::Signature>>;
#[no_mangle]
pub static C2Tuple_SignatureCVec_SignatureZZ_free: extern "C" fn(C2Tuple_SignatureCVec_SignatureZZ) = crate::c_types::C2TupleTempl_free::<crate::c_types::Signature, crate::c_types::CVecTempl<crate::c_types::Signature>>;
#[no_mangle]
pub extern "C" fn C2Tuple_SignatureCVec_SignatureZZ_new(a: crate::c_types::Signature, b: crate::c_types::derived::CVec_SignatureZ) -> C2Tuple_SignatureCVec_SignatureZZ {
	C2Tuple_SignatureCVec_SignatureZZ { a, b, }
}

pub type CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ = crate::c_types::CResultTempl<crate::c_types::C2TupleTempl<crate::c_types::Signature, crate::c_types::CVecTempl<crate::c_types::Signature>>, u8>;
#[no_mangle]
pub static CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ_free: extern "C" fn(CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ) = crate::c_types::CResultTempl_free::<crate::c_types::C2TupleTempl<crate::c_types::Signature, crate::c_types::CVecTempl<crate::c_types::Signature>>, u8>;
#[no_mangle]
pub static CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ_ok: extern "C" fn (C2Tuple_SignatureCVec_SignatureZZ) -> CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ =
	crate::c_types::CResultTempl::<crate::c_types::C2TupleTempl<crate::c_types::Signature, crate::c_types::CVecTempl<crate::c_types::Signature>>, u8>::ok;

#[no_mangle]
pub extern "C" fn CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ_err() -> CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ {
	crate::c_types::CResultTempl::err(0)
}

pub type CResult_SignatureNoneZ = crate::c_types::CResultTempl<crate::c_types::Signature, u8>;
#[no_mangle]
pub static CResult_SignatureNoneZ_free: extern "C" fn(CResult_SignatureNoneZ) = crate::c_types::CResultTempl_free::<crate::c_types::Signature, u8>;
#[no_mangle]
pub static CResult_SignatureNoneZ_ok: extern "C" fn (crate::c_types::Signature) -> CResult_SignatureNoneZ =
	crate::c_types::CResultTempl::<crate::c_types::Signature, u8>::ok;

#[no_mangle]
pub extern "C" fn CResult_SignatureNoneZ_err() -> CResult_SignatureNoneZ {
	crate::c_types::CResultTempl::err(0)
}

pub type CResult_ChanKeySignerDecodeErrorZ = crate::c_types::CResultTempl<crate::chain::keysinterface::ChannelKeys, crate::ln::msgs::DecodeError>;
#[no_mangle]
pub static CResult_ChanKeySignerDecodeErrorZ_free: extern "C" fn(CResult_ChanKeySignerDecodeErrorZ) = crate::c_types::CResultTempl_free::<crate::chain::keysinterface::ChannelKeys, crate::ln::msgs::DecodeError>;
#[no_mangle]
pub static CResult_ChanKeySignerDecodeErrorZ_ok: extern "C" fn (crate::chain::keysinterface::ChannelKeys) -> CResult_ChanKeySignerDecodeErrorZ =
	crate::c_types::CResultTempl::<crate::chain::keysinterface::ChannelKeys, crate::ln::msgs::DecodeError>::ok;

#[no_mangle]
pub static CResult_ChanKeySignerDecodeErrorZ_err: extern "C" fn (crate::ln::msgs::DecodeError) -> CResult_ChanKeySignerDecodeErrorZ =
	crate::c_types::CResultTempl::<crate::chain::keysinterface::ChannelKeys, crate::ln::msgs::DecodeError>::err;

pub type CResult_TxOutAccessErrorZ = crate::c_types::CResultTempl<crate::c_types::TxOut, crate::chain::AccessError>;
#[no_mangle]
pub static CResult_TxOutAccessErrorZ_free: extern "C" fn(CResult_TxOutAccessErrorZ) = crate::c_types::CResultTempl_free::<crate::c_types::TxOut, crate::chain::AccessError>;
#[no_mangle]
pub static CResult_TxOutAccessErrorZ_ok: extern "C" fn (crate::c_types::TxOut) -> CResult_TxOutAccessErrorZ =
	crate::c_types::CResultTempl::<crate::c_types::TxOut, crate::chain::AccessError>::ok;

#[no_mangle]
pub static CResult_TxOutAccessErrorZ_err: extern "C" fn (crate::chain::AccessError) -> CResult_TxOutAccessErrorZ =
	crate::c_types::CResultTempl::<crate::c_types::TxOut, crate::chain::AccessError>::err;

pub type CResult_NoneAPIErrorZ = crate::c_types::CResultTempl<u8, crate::util::errors::APIError>;
#[no_mangle]
pub static CResult_NoneAPIErrorZ_free: extern "C" fn(CResult_NoneAPIErrorZ) = crate::c_types::CResultTempl_free::<u8, crate::util::errors::APIError>;
#[no_mangle]
pub extern "C" fn CResult_NoneAPIErrorZ_ok() -> CResult_NoneAPIErrorZ {
	crate::c_types::CResultTempl::ok(0)
}

#[no_mangle]
pub static CResult_NoneAPIErrorZ_err: extern "C" fn (crate::util::errors::APIError) -> CResult_NoneAPIErrorZ =
	crate::c_types::CResultTempl::<u8, crate::util::errors::APIError>::err;

pub type CVec_ChannelDetailsZ = crate::c_types::CVecTempl<crate::ln::channelmanager::ChannelDetails>;
#[no_mangle]
pub static CVec_ChannelDetailsZ_free: extern "C" fn(CVec_ChannelDetailsZ) = crate::c_types::CVecTempl_free::<crate::ln::channelmanager::ChannelDetails>;

pub type CResult_NonePaymentSendFailureZ = crate::c_types::CResultTempl<u8, crate::ln::channelmanager::PaymentSendFailure>;
#[no_mangle]
pub static CResult_NonePaymentSendFailureZ_free: extern "C" fn(CResult_NonePaymentSendFailureZ) = crate::c_types::CResultTempl_free::<u8, crate::ln::channelmanager::PaymentSendFailure>;
#[no_mangle]
pub extern "C" fn CResult_NonePaymentSendFailureZ_ok() -> CResult_NonePaymentSendFailureZ {
	crate::c_types::CResultTempl::ok(0)
}

#[no_mangle]
pub static CResult_NonePaymentSendFailureZ_err: extern "C" fn (crate::ln::channelmanager::PaymentSendFailure) -> CResult_NonePaymentSendFailureZ =
	crate::c_types::CResultTempl::<u8, crate::ln::channelmanager::PaymentSendFailure>::err;

pub type CVec_NetAddressZ = crate::c_types::CVecTempl<crate::ln::msgs::NetAddress>;
#[no_mangle]
pub static CVec_NetAddressZ_free: extern "C" fn(CVec_NetAddressZ) = crate::c_types::CVecTempl_free::<crate::ln::msgs::NetAddress>;

pub type CVec_ChannelMonitorZ = crate::c_types::CVecTempl<crate::chain::channelmonitor::ChannelMonitor>;
#[no_mangle]
pub static CVec_ChannelMonitorZ_free: extern "C" fn(CVec_ChannelMonitorZ) = crate::c_types::CVecTempl_free::<crate::chain::channelmonitor::ChannelMonitor>;

pub type CVec_u64Z = crate::c_types::CVecTempl<u64>;
#[no_mangle]
pub static CVec_u64Z_free: extern "C" fn(CVec_u64Z) = crate::c_types::CVecTempl_free::<u64>;

pub type CVec_UpdateAddHTLCZ = crate::c_types::CVecTempl<crate::ln::msgs::UpdateAddHTLC>;
#[no_mangle]
pub static CVec_UpdateAddHTLCZ_free: extern "C" fn(CVec_UpdateAddHTLCZ) = crate::c_types::CVecTempl_free::<crate::ln::msgs::UpdateAddHTLC>;

pub type CVec_UpdateFulfillHTLCZ = crate::c_types::CVecTempl<crate::ln::msgs::UpdateFulfillHTLC>;
#[no_mangle]
pub static CVec_UpdateFulfillHTLCZ_free: extern "C" fn(CVec_UpdateFulfillHTLCZ) = crate::c_types::CVecTempl_free::<crate::ln::msgs::UpdateFulfillHTLC>;

pub type CVec_UpdateFailHTLCZ = crate::c_types::CVecTempl<crate::ln::msgs::UpdateFailHTLC>;
#[no_mangle]
pub static CVec_UpdateFailHTLCZ_free: extern "C" fn(CVec_UpdateFailHTLCZ) = crate::c_types::CVecTempl_free::<crate::ln::msgs::UpdateFailHTLC>;

pub type CVec_UpdateFailMalformedHTLCZ = crate::c_types::CVecTempl<crate::ln::msgs::UpdateFailMalformedHTLC>;
#[no_mangle]
pub static CVec_UpdateFailMalformedHTLCZ_free: extern "C" fn(CVec_UpdateFailMalformedHTLCZ) = crate::c_types::CVecTempl_free::<crate::ln::msgs::UpdateFailMalformedHTLC>;

pub type CResult_boolLightningErrorZ = crate::c_types::CResultTempl<bool, crate::ln::msgs::LightningError>;
#[no_mangle]
pub static CResult_boolLightningErrorZ_free: extern "C" fn(CResult_boolLightningErrorZ) = crate::c_types::CResultTempl_free::<bool, crate::ln::msgs::LightningError>;
#[no_mangle]
pub static CResult_boolLightningErrorZ_ok: extern "C" fn (bool) -> CResult_boolLightningErrorZ =
	crate::c_types::CResultTempl::<bool, crate::ln::msgs::LightningError>::ok;

#[no_mangle]
pub static CResult_boolLightningErrorZ_err: extern "C" fn (crate::ln::msgs::LightningError) -> CResult_boolLightningErrorZ =
	crate::c_types::CResultTempl::<bool, crate::ln::msgs::LightningError>::err;

pub type C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ = crate::c_types::C3TupleTempl<crate::ln::msgs::ChannelAnnouncement, crate::ln::msgs::ChannelUpdate, crate::ln::msgs::ChannelUpdate>;
#[no_mangle]
pub static C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ_free: extern "C" fn(C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ) = crate::c_types::C3TupleTempl_free::<crate::ln::msgs::ChannelAnnouncement, crate::ln::msgs::ChannelUpdate, crate::ln::msgs::ChannelUpdate>;
#[no_mangle]
pub extern "C" fn C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ_new(a: crate::ln::msgs::ChannelAnnouncement, b: crate::ln::msgs::ChannelUpdate, c: crate::ln::msgs::ChannelUpdate) -> C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ {
	C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ { a, b, c, }
}

pub type CVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ = crate::c_types::CVecTempl<crate::c_types::C3TupleTempl<crate::ln::msgs::ChannelAnnouncement, crate::ln::msgs::ChannelUpdate, crate::ln::msgs::ChannelUpdate>>;
#[no_mangle]
pub static CVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ_free: extern "C" fn(CVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ) = crate::c_types::CVecTempl_free::<crate::c_types::C3TupleTempl<crate::ln::msgs::ChannelAnnouncement, crate::ln::msgs::ChannelUpdate, crate::ln::msgs::ChannelUpdate>>;

pub type CVec_NodeAnnouncementZ = crate::c_types::CVecTempl<crate::ln::msgs::NodeAnnouncement>;
#[no_mangle]
pub static CVec_NodeAnnouncementZ_free: extern "C" fn(CVec_NodeAnnouncementZ) = crate::c_types::CVecTempl_free::<crate::ln::msgs::NodeAnnouncement>;

pub type CResult_NoneLightningErrorZ = crate::c_types::CResultTempl<u8, crate::ln::msgs::LightningError>;
#[no_mangle]
pub static CResult_NoneLightningErrorZ_free: extern "C" fn(CResult_NoneLightningErrorZ) = crate::c_types::CResultTempl_free::<u8, crate::ln::msgs::LightningError>;
#[no_mangle]
pub extern "C" fn CResult_NoneLightningErrorZ_ok() -> CResult_NoneLightningErrorZ {
	crate::c_types::CResultTempl::ok(0)
}

#[no_mangle]
pub static CResult_NoneLightningErrorZ_err: extern "C" fn (crate::ln::msgs::LightningError) -> CResult_NoneLightningErrorZ =
	crate::c_types::CResultTempl::<u8, crate::ln::msgs::LightningError>::err;

pub type CVec_PublicKeyZ = crate::c_types::CVecTempl<crate::c_types::PublicKey>;
#[no_mangle]
pub static CVec_PublicKeyZ_free: extern "C" fn(CVec_PublicKeyZ) = crate::c_types::CVecTempl_free::<crate::c_types::PublicKey>;

pub type CVec_u8Z = crate::c_types::CVecTempl<u8>;
#[no_mangle]
pub static CVec_u8Z_free: extern "C" fn(CVec_u8Z) = crate::c_types::CVecTempl_free::<u8>;

pub type CResult_CVec_u8ZPeerHandleErrorZ = crate::c_types::CResultTempl<crate::c_types::CVecTempl<u8>, crate::ln::peer_handler::PeerHandleError>;
#[no_mangle]
pub static CResult_CVec_u8ZPeerHandleErrorZ_free: extern "C" fn(CResult_CVec_u8ZPeerHandleErrorZ) = crate::c_types::CResultTempl_free::<crate::c_types::CVecTempl<u8>, crate::ln::peer_handler::PeerHandleError>;
#[no_mangle]
pub static CResult_CVec_u8ZPeerHandleErrorZ_ok: extern "C" fn (CVec_u8Z) -> CResult_CVec_u8ZPeerHandleErrorZ =
	crate::c_types::CResultTempl::<crate::c_types::CVecTempl<u8>, crate::ln::peer_handler::PeerHandleError>::ok;

#[no_mangle]
pub static CResult_CVec_u8ZPeerHandleErrorZ_err: extern "C" fn (crate::ln::peer_handler::PeerHandleError) -> CResult_CVec_u8ZPeerHandleErrorZ =
	crate::c_types::CResultTempl::<crate::c_types::CVecTempl<u8>, crate::ln::peer_handler::PeerHandleError>::err;

pub type CResult_NonePeerHandleErrorZ = crate::c_types::CResultTempl<u8, crate::ln::peer_handler::PeerHandleError>;
#[no_mangle]
pub static CResult_NonePeerHandleErrorZ_free: extern "C" fn(CResult_NonePeerHandleErrorZ) = crate::c_types::CResultTempl_free::<u8, crate::ln::peer_handler::PeerHandleError>;
#[no_mangle]
pub extern "C" fn CResult_NonePeerHandleErrorZ_ok() -> CResult_NonePeerHandleErrorZ {
	crate::c_types::CResultTempl::ok(0)
}

#[no_mangle]
pub static CResult_NonePeerHandleErrorZ_err: extern "C" fn (crate::ln::peer_handler::PeerHandleError) -> CResult_NonePeerHandleErrorZ =
	crate::c_types::CResultTempl::<u8, crate::ln::peer_handler::PeerHandleError>::err;

pub type CResult_boolPeerHandleErrorZ = crate::c_types::CResultTempl<bool, crate::ln::peer_handler::PeerHandleError>;
#[no_mangle]
pub static CResult_boolPeerHandleErrorZ_free: extern "C" fn(CResult_boolPeerHandleErrorZ) = crate::c_types::CResultTempl_free::<bool, crate::ln::peer_handler::PeerHandleError>;
#[no_mangle]
pub static CResult_boolPeerHandleErrorZ_ok: extern "C" fn (bool) -> CResult_boolPeerHandleErrorZ =
	crate::c_types::CResultTempl::<bool, crate::ln::peer_handler::PeerHandleError>::ok;

#[no_mangle]
pub static CResult_boolPeerHandleErrorZ_err: extern "C" fn (crate::ln::peer_handler::PeerHandleError) -> CResult_boolPeerHandleErrorZ =
	crate::c_types::CResultTempl::<bool, crate::ln::peer_handler::PeerHandleError>::err;

pub type CResult_SecretKeySecpErrorZ = crate::c_types::CResultTempl<crate::c_types::SecretKey, crate::c_types::Secp256k1Error>;
#[no_mangle]
pub static CResult_SecretKeySecpErrorZ_free: extern "C" fn(CResult_SecretKeySecpErrorZ) = crate::c_types::CResultTempl_free::<crate::c_types::SecretKey, crate::c_types::Secp256k1Error>;
#[no_mangle]
pub static CResult_SecretKeySecpErrorZ_ok: extern "C" fn (crate::c_types::SecretKey) -> CResult_SecretKeySecpErrorZ =
	crate::c_types::CResultTempl::<crate::c_types::SecretKey, crate::c_types::Secp256k1Error>::ok;

#[no_mangle]
pub static CResult_SecretKeySecpErrorZ_err: extern "C" fn (crate::c_types::Secp256k1Error) -> CResult_SecretKeySecpErrorZ =
	crate::c_types::CResultTempl::<crate::c_types::SecretKey, crate::c_types::Secp256k1Error>::err;

pub type CResult_PublicKeySecpErrorZ = crate::c_types::CResultTempl<crate::c_types::PublicKey, crate::c_types::Secp256k1Error>;
#[no_mangle]
pub static CResult_PublicKeySecpErrorZ_free: extern "C" fn(CResult_PublicKeySecpErrorZ) = crate::c_types::CResultTempl_free::<crate::c_types::PublicKey, crate::c_types::Secp256k1Error>;
#[no_mangle]
pub static CResult_PublicKeySecpErrorZ_ok: extern "C" fn (crate::c_types::PublicKey) -> CResult_PublicKeySecpErrorZ =
	crate::c_types::CResultTempl::<crate::c_types::PublicKey, crate::c_types::Secp256k1Error>::ok;

#[no_mangle]
pub static CResult_PublicKeySecpErrorZ_err: extern "C" fn (crate::c_types::Secp256k1Error) -> CResult_PublicKeySecpErrorZ =
	crate::c_types::CResultTempl::<crate::c_types::PublicKey, crate::c_types::Secp256k1Error>::err;

pub type CResult_TxCreationKeysSecpErrorZ = crate::c_types::CResultTempl<crate::ln::chan_utils::TxCreationKeys, crate::c_types::Secp256k1Error>;
#[no_mangle]
pub static CResult_TxCreationKeysSecpErrorZ_free: extern "C" fn(CResult_TxCreationKeysSecpErrorZ) = crate::c_types::CResultTempl_free::<crate::ln::chan_utils::TxCreationKeys, crate::c_types::Secp256k1Error>;
#[no_mangle]
pub static CResult_TxCreationKeysSecpErrorZ_ok: extern "C" fn (crate::ln::chan_utils::TxCreationKeys) -> CResult_TxCreationKeysSecpErrorZ =
	crate::c_types::CResultTempl::<crate::ln::chan_utils::TxCreationKeys, crate::c_types::Secp256k1Error>::ok;

#[no_mangle]
pub static CResult_TxCreationKeysSecpErrorZ_err: extern "C" fn (crate::c_types::Secp256k1Error) -> CResult_TxCreationKeysSecpErrorZ =
	crate::c_types::CResultTempl::<crate::ln::chan_utils::TxCreationKeys, crate::c_types::Secp256k1Error>::err;

pub type CResult_TrustedCommitmentTransactionNoneZ = crate::c_types::CResultTempl<crate::ln::chan_utils::TrustedCommitmentTransaction, u8>;
#[no_mangle]
pub static CResult_TrustedCommitmentTransactionNoneZ_free: extern "C" fn(CResult_TrustedCommitmentTransactionNoneZ) = crate::c_types::CResultTempl_free::<crate::ln::chan_utils::TrustedCommitmentTransaction, u8>;
#[no_mangle]
pub static CResult_TrustedCommitmentTransactionNoneZ_ok: extern "C" fn (crate::ln::chan_utils::TrustedCommitmentTransaction) -> CResult_TrustedCommitmentTransactionNoneZ =
	crate::c_types::CResultTempl::<crate::ln::chan_utils::TrustedCommitmentTransaction, u8>::ok;

#[no_mangle]
pub extern "C" fn CResult_TrustedCommitmentTransactionNoneZ_err() -> CResult_TrustedCommitmentTransactionNoneZ {
	crate::c_types::CResultTempl::err(0)
}

pub type CResult_CVec_SignatureZNoneZ = crate::c_types::CResultTempl<crate::c_types::CVecTempl<crate::c_types::Signature>, u8>;
#[no_mangle]
pub static CResult_CVec_SignatureZNoneZ_free: extern "C" fn(CResult_CVec_SignatureZNoneZ) = crate::c_types::CResultTempl_free::<crate::c_types::CVecTempl<crate::c_types::Signature>, u8>;
#[no_mangle]
pub static CResult_CVec_SignatureZNoneZ_ok: extern "C" fn (CVec_SignatureZ) -> CResult_CVec_SignatureZNoneZ =
	crate::c_types::CResultTempl::<crate::c_types::CVecTempl<crate::c_types::Signature>, u8>::ok;

#[no_mangle]
pub extern "C" fn CResult_CVec_SignatureZNoneZ_err() -> CResult_CVec_SignatureZNoneZ {
	crate::c_types::CResultTempl::err(0)
}

pub type CVec_RouteHopZ = crate::c_types::CVecTempl<crate::routing::router::RouteHop>;
#[no_mangle]
pub static CVec_RouteHopZ_free: extern "C" fn(CVec_RouteHopZ) = crate::c_types::CVecTempl_free::<crate::routing::router::RouteHop>;

pub type CVec_CVec_RouteHopZZ = crate::c_types::CVecTempl<crate::c_types::CVecTempl<crate::routing::router::RouteHop>>;
#[no_mangle]
pub static CVec_CVec_RouteHopZZ_free: extern "C" fn(CVec_CVec_RouteHopZZ) = crate::c_types::CVecTempl_free::<crate::c_types::CVecTempl<crate::routing::router::RouteHop>>;

pub type CVec_RouteHintZ = crate::c_types::CVecTempl<crate::routing::router::RouteHint>;
#[no_mangle]
pub static CVec_RouteHintZ_free: extern "C" fn(CVec_RouteHintZ) = crate::c_types::CVecTempl_free::<crate::routing::router::RouteHint>;

pub type CResult_RouteLightningErrorZ = crate::c_types::CResultTempl<crate::routing::router::Route, crate::ln::msgs::LightningError>;
#[no_mangle]
pub static CResult_RouteLightningErrorZ_free: extern "C" fn(CResult_RouteLightningErrorZ) = crate::c_types::CResultTempl_free::<crate::routing::router::Route, crate::ln::msgs::LightningError>;
#[no_mangle]
pub static CResult_RouteLightningErrorZ_ok: extern "C" fn (crate::routing::router::Route) -> CResult_RouteLightningErrorZ =
	crate::c_types::CResultTempl::<crate::routing::router::Route, crate::ln::msgs::LightningError>::ok;

#[no_mangle]
pub static CResult_RouteLightningErrorZ_err: extern "C" fn (crate::ln::msgs::LightningError) -> CResult_RouteLightningErrorZ =
	crate::c_types::CResultTempl::<crate::routing::router::Route, crate::ln::msgs::LightningError>::err;

