//! functions for managing broadcaster.
//! Usually, you don't have to have a handler to the broadcaster in a wrapper side. Just create
//! ChannelMonitor or ChannelManager and hold a reference to it.
//! However, sometimes it is useful for testing.

use std::sync::Arc;

use bitcoin::blockdata::transaction::Transaction;
use lightning::chain::chaininterface::BroadcasterInterface;
use crate::adaptors::*;
use crate::handle::{Ref, Out, HandleShared};
use crate::error::FFIResult;

pub type FFIBroadCasterHandle<'a> = HandleShared<'a, FFIBroadCaster>;

#[cfg(debug_assertions)]
#[repr(C)]
pub struct BroadcasterWrapper {
    broadcaster: Arc<FFIBroadCaster>,
}

#[cfg(debug_assertions)]
impl BroadcasterWrapper {
    pub fn broadcast(&self, tx: &Transaction) {
        self.broadcaster.as_ref().broadcast_transaction(&tx)
    }
}

#[cfg(debug_assertions)]
type BroadcasterWrapperHandle<'a> = HandleShared<'a, BroadcasterWrapper>;


ffi! {
    fn create_broadcaster(broadcast_transaction_ptr: Ref<broadcaster_fn::BroadcastTransactionPtr>, out: Out<FFIBroadCasterHandle>) -> FFIResult {
        let broadcast_transaction = unsafe_block!("" => broadcast_transaction_ptr.as_ref());
        let broadcaster = FFIBroadCaster{ broadcast_transaction_ptr: *broadcast_transaction };
        unsafe_block!("" => out.init(FFIBroadCasterHandle::alloc(broadcaster)));
        FFIResult::ok()
    }

    fn release_broadcaster(handle: FFIBroadCasterHandle) -> FFIResult {
        unsafe_block!("The upstream caller guarantees the handle will not be accessed after being freed" => FFIBroadCasterHandle::dealloc(handle, |mut handle| {
            FFIResult::ok()
        }))
    }
}

/// Useful for testing low-level interoperability.
#[cfg(debug_assertions)]
ffi! {
    fn ffi_test_broadcaster(broadcaster_ptr: FFIBroadCasterHandle) -> FFIResult {
        let broadcaster = unsafe_block!("" => broadcaster_ptr.as_ref());
        let tx: Transaction = bitcoin::consensus::deserialize(&hex::decode("020000000001031cfbc8f54fbfa4a33a30068841371f80dbfe166211242213188428f437445c91000000006a47304402206fbcec8d2d2e740d824d3d36cc345b37d9f65d665a99f5bd5c9e8d42270a03a8022013959632492332200c2908459547bf8dbf97c65ab1a28dec377d6f1d41d3d63e012103d7279dfb90ce17fe139ba60a7c41ddf605b25e1c07a4ddcb9dfef4e7d6710f48feffffff476222484f5e35b3f0e43f65fc76e21d8be7818dd6a989c160b1e5039b7835fc00000000171600140914414d3c94af70ac7e25407b0689e0baa10c77feffffffa83d954a62568bbc99cc644c62eb7383d7c2a2563041a0aeb891a6a4055895570000000017160014795d04cc2d4f31480d9a3710993fbd80d04301dffeffffff06fef72f000000000017a91476fd7035cd26f1a32a5ab979e056713aac25796887a5000f00000000001976a914b8332d502a529571c6af4be66399cd33379071c588ac3fda0500000000001976a914fc1d692f8de10ae33295f090bea5fe49527d975c88ac522e1b00000000001976a914808406b54d1044c429ac54c0e189b0d8061667e088ac6eb68501000000001976a914dfab6085f3a8fb3e6710206a5a959313c5618f4d88acbba20000000000001976a914eb3026552d7e3f3073457d0bee5d4757de48160d88ac0002483045022100bee24b63212939d33d513e767bc79300051f7a0d433c3fcf1e0e3bf03b9eb1d70220588dc45a9ce3a939103b4459ce47500b64e23ab118dfc03c9caa7d6bfc32b9c601210354fd80328da0f9ae6eef2b3a81f74f9a6f66761fadf96f1d1d22b1fd6845876402483045022100e29c7e3a5efc10da6269e5fc20b6a1cb8beb92130cc52c67e46ef40aaa5cac5f0220644dd1b049727d991aece98a105563416e10a5ac4221abac7d16931842d5c322012103960b87412d6e169f30e12106bdf70122aabb9eb61f455518322a18b920a4dfa887d30700")?)?;
        broadcaster.broadcast_transaction(&tx);
        FFIResult::ok()
    }

    fn create_broadcaster_wrapper(fn_ptr: Ref<broadcaster_fn::BroadcastTransactionPtr>, out: Out<BroadcasterWrapperHandle>) -> FFIResult {
        // Test if passing dependent object by handle will be safe.
        let broadcaster_fn = unsafe_block!("" => fn_ptr.as_ref());
        let broadcaster = Arc::new(FFIBroadCaster { broadcast_transaction_ptr: *broadcaster_fn });
        let wrapper_raw = BroadcasterWrapper{ broadcaster: broadcaster };
        unsafe_block!("" => out.init(BroadcasterWrapperHandle::alloc(wrapper_raw)));
        FFIResult::ok()
    }

    fn test_broadcaster_wrapper(wrapper_handle: BroadcasterWrapperHandle) -> FFIResult {
        let wrapper = unsafe_block!("" => wrapper_handle.as_ref());
        let tx: Transaction = bitcoin::consensus::deserialize(&hex::decode("020000000001031cfbc8f54fbfa4a33a30068841371f80dbfe166211242213188428f437445c91000000006a47304402206fbcec8d2d2e740d824d3d36cc345b37d9f65d665a99f5bd5c9e8d42270a03a8022013959632492332200c2908459547bf8dbf97c65ab1a28dec377d6f1d41d3d63e012103d7279dfb90ce17fe139ba60a7c41ddf605b25e1c07a4ddcb9dfef4e7d6710f48feffffff476222484f5e35b3f0e43f65fc76e21d8be7818dd6a989c160b1e5039b7835fc00000000171600140914414d3c94af70ac7e25407b0689e0baa10c77feffffffa83d954a62568bbc99cc644c62eb7383d7c2a2563041a0aeb891a6a4055895570000000017160014795d04cc2d4f31480d9a3710993fbd80d04301dffeffffff06fef72f000000000017a91476fd7035cd26f1a32a5ab979e056713aac25796887a5000f00000000001976a914b8332d502a529571c6af4be66399cd33379071c588ac3fda0500000000001976a914fc1d692f8de10ae33295f090bea5fe49527d975c88ac522e1b00000000001976a914808406b54d1044c429ac54c0e189b0d8061667e088ac6eb68501000000001976a914dfab6085f3a8fb3e6710206a5a959313c5618f4d88acbba20000000000001976a914eb3026552d7e3f3073457d0bee5d4757de48160d88ac0002483045022100bee24b63212939d33d513e767bc79300051f7a0d433c3fcf1e0e3bf03b9eb1d70220588dc45a9ce3a939103b4459ce47500b64e23ab118dfc03c9caa7d6bfc32b9c601210354fd80328da0f9ae6eef2b3a81f74f9a6f66761fadf96f1d1d22b1fd6845876402483045022100e29c7e3a5efc10da6269e5fc20b6a1cb8beb92130cc52c67e46ef40aaa5cac5f0220644dd1b049727d991aece98a105563416e10a5ac4221abac7d16931842d5c322012103960b87412d6e169f30e12106bdf70122aabb9eb61f455518322a18b920a4dfa887d30700")?)?;
        wrapper.broadcast(&tx);
        FFIResult::ok()
    }

    fn release_broadcaster_wrapper(handle: BroadcasterWrapperHandle) -> FFIResult {
        unsafe_block!("The upstream caller guarantees the handle will not be accessed after being freed" => BroadcasterWrapperHandle::dealloc(handle, |mut handle| {
            FFIResult::ok()
        }))
    }

}
