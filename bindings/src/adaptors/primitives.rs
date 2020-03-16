use std::{
    convert::{TryFrom, TryInto},
    fmt::{Formatter, Error}
};

use bitcoin::{
    hash_types::{Txid, BlockHash},
    blockdata::script::Script,
    hashes::Hash,
    Transaction,
    secp256k1
};
use lightning::{
    chain::chaininterface::ChainError,
    ln::channelmanager::{PaymentHash, PaymentSecret},
    routing::router::{Route},
    util::ser::{Readable, Writeable},
    util::events::Event,
    chain::transaction::OutPoint
};
use crate::{
    FFIResult,
    is_null::IsNull
};

macro_rules! array_struct{
    (
        $(#[$meta:meta])*
        $name:ident) => {
        $(#[$meta])*
        #[derive(Clone)]
        #[repr(C)]
        pub struct $name {
            ptr: *const u8,
            len: usize,
        }
        unsafe_impl!("Simulate `Unique<T>`" => impl<'a> Send for $name {});
        unsafe_impl!("Simulate `Unique<T>`" => impl<'a> Sync for $name {});
        impl $name {
            fn new(ptr: *const u8, len: usize) -> Self { $name{ ptr: ptr, len: len } }
        }
        impl From<&[u8]> for $name {
            fn from(slice: &[u8]) -> Self {
                $name::new(
                    slice.as_ptr(),
                    slice.len(),
                )
            }
        }

        impl From<Box<[u8]>> for $name {
            fn from(slice: Box<[u8]>) -> Self {
                $name::new(
                    slice.as_ptr(),
                    slice.len(),
                )
            }
        }


        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                hex::encode(self).fmt(f)
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                unsafe_block!("" => std::slice::from_raw_parts(self.ptr, self.len))
            }
        }

        impl IsNull for $name {
            fn is_null(&self) -> bool {
                self.ptr.is_null()
            }
        }
    }
}

#[doc="The length must be [the same as a byte number of secp256k1 secret key](secp256k1::constants::SECRET_KEY_SIZE)"]
array_struct!(SecretKey);

impl TryFrom<SecretKey> for secp256k1::SecretKey {
    type Error = FFIResult;

    fn try_from(value: SecretKey) -> Result<Self, Self::Error> {
        let s = value.as_ref();
        secp256k1::SecretKey::from_slice(s).map_err(|e| FFIResult::internal_error().context(e))
    }
}


#[doc="The length must be [the same as a byte number of secp256k1 public key] `secp256k1::constants::PUBLIC_KEY_SIZE`"]
array_struct!(PublicKey);

impl TryFrom<PublicKey> for secp256k1::PublicKey {
    type Error = FFIResult;

    fn try_from(value: PublicKey) -> Result<Self, Self::Error> {
        let s = value.as_ref();
        secp256k1::PublicKey::from_slice(s).map_err(|e| FFIResult::internal_error().context(e))
    }
}

#[doc="256 bit seed to initialize [ChannelManager](lightning::ln::channelmanager::ChannelManager)"]
array_struct!(Seed);

array_struct!(FFISha256dHash);

impl TryFrom<FFISha256dHash> for PaymentHash {
    type Error = FFIResult;

    fn try_from(ffi_hash: FFISha256dHash) -> Result<PaymentHash, Self::Error> {
        let s = unsafe_block!("" => std::slice::from_raw_parts(ffi_hash.ptr, ffi_hash.len));
        let s:[u8; 32] = s.try_into().map_err(|_| FFIResult::invalid_data_length())?;
        Ok(PaymentHash(s))
    }
}

impl From<&Txid> for FFISha256dHash {
    fn from(hash: &Txid) -> Self {
        let v = hash.encode();
        FFISha256dHash::from(v.into_boxed_slice())
    }
}

impl From<Txid> for FFISha256dHash {
    fn from(hash: Txid) -> Self {
        let v = hash.encode();
        FFISha256dHash::from(v.into_boxed_slice())
    }
}

impl TryFrom<FFISha256dHash> for Txid {
    type Error = bitcoin::hashes::Error;
    fn try_from(hash: FFISha256dHash) -> Result<Self, Self::Error> {
        let slice = unsafe_block!("We know it points to valid buffer" => std::slice::from_raw_parts(hash.ptr, hash.len));
        let v = bitcoin::hashes::sha256d::Hash::from_slice(slice)?;
        Ok(v.into())
    }
}

impl From<&BlockHash> for FFISha256dHash {
    fn from(hash: &BlockHash) -> Self {
        let v = hash.encode();
        FFISha256dHash::from(v.into_boxed_slice())
    }
}

impl From<BlockHash> for FFISha256dHash {
    fn from(hash: BlockHash) -> Self {
        let v = hash.encode();
        FFISha256dHash::from(v.into_boxed_slice())
    }
}

array_struct!(FFISecret);

impl TryFrom<FFISecret> for PaymentSecret {
    type Error = FFIResult;

    fn try_from(ffi_secret: FFISecret) -> Result<PaymentSecret, Self::Error> {
        let s = unsafe_block!("" => std::slice::from_raw_parts(ffi_secret.ptr, ffi_secret.len));
        let s:[u8; 32] = s.try_into().map_err(|_| FFIResult::invalid_data_length())?;
        Ok(PaymentSecret(s))
    }
}

array_struct!(FFIScript);
impl FFIScript {
    pub fn to_script(&self) -> Script {
        unimplemented!()
    }
}

#[derive(Clone)]
#[repr(C)]
pub struct FFIOutPoint {
	pub txid: FFISha256dHash,
	pub index: u16,
}

impl TryFrom<FFIOutPoint> for OutPoint {
    type Error = bitcoin::hashes::Error;
    fn try_from(value: FFIOutPoint) -> Result<Self, Self::Error> {
        let txid = value.txid.try_into()?;
        Ok(OutPoint{ txid, index: value.index })
    }
}

impl From<OutPoint> for FFIOutPoint {
    fn from(value: OutPoint) -> Self {
        FFIOutPoint { txid: value.txid.into(), index: value.index }
    }
}

impl IsNull for FFIOutPoint {
    fn is_null(&self) -> bool {
        false
    }
}

#[derive(Clone)]
#[repr(C)]
pub struct FFITxOut {
    pub value: u64,
    pub script_pubkey: FFIScript,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub enum FFIChainError {
    /// Client doesn't support UTXO lookup (but the chain hash matches our genesis block hash)
    NotSupported,
    /// Chain isn't the one watched
    NotWatched,
    /// Tx doesn't exist or is unconfirmed
    UnknownTx,
}

impl From<FFIChainError> for ChainError {
    fn from(e: FFIChainError) -> Self {
        match e {
            FFIChainError::NotSupported => ChainError::NotSupported,
            FFIChainError::NotWatched => ChainError::NotWatched,
            FFIChainError::UnknownTx => ChainError::UnknownTx,
        }
    }
}

array_struct!(FFIRoute);

impl TryFrom<FFIRoute> for Route {
    type Error = FFIResult;

    fn try_from(value: FFIRoute) -> Result<Self, Self::Error> {
        let mut slice = value.as_ref();
        <Route as Readable>::read(&mut slice).map_err(|_| FFIResult::deserialization_failure())
    }
}

array_struct!(FFITransaction);
array_struct!(FFIBlock);
array_struct!(FFIEvents);

/// General purpose byte array which has to cross ffi-boundary
array_struct!(FFIBytes);

/// For `ChainWatchInterface::filter_block`
impl TryFrom<FFIBytes> for (Vec<&Transaction>, Vec<u32>) {
    type Error = FFIResult;

    fn try_from(bytes: FFIBytes) -> Result<Self, Self::Error> {
        unimplemented!()
    }
}

impl From<Vec<Event>> for FFIEvents {

    fn from(value: Vec<Event>) -> Self {
        let len = value.len();
        let mut result_vec: Vec<u8> = Vec::with_capacity(len * std::mem::size_of::<Event>());
        for e in value {
            result_vec.extend(e.encode());
        }
        let r = result_vec.into_boxed_slice();
        r.into()
    }
}
