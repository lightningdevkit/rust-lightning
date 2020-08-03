use std::{
    convert::{TryFrom},
    fmt::{Formatter},
    io::{Error}
};

use bitcoin::{
    hash_types::{Txid, BlockHash},
    blockdata::script::Script,
    hashes::Hash,
    secp256k1
};
use lightning::{
    chain::chaininterface::ChainError,
    ln::channelmanager::{PaymentHash, PaymentSecret},
    routing::router::{Route},
    util::ser::{Readable, Writeable},
    util::events::Event,
    chain::transaction::OutPoint,
    ln::channelmanager::PaymentPreimage,
    util::ser::Writer
};
use crate::{
    FFIResult,
    is_null::IsNull
};

#[derive(Debug, Clone)]
#[repr(C)]
pub struct Bytes32 {
    pub bytes: [u8; 32],
}

impl IsNull for Bytes32 {
    fn is_null(&self) -> bool {
        false
    }
}

impl From<Bytes32> for secp256k1::SecretKey {
    fn from(value: Bytes32) -> Self {
        secp256k1::SecretKey::from_slice(&value.bytes).unwrap()
    }
}

impl From<secp256k1::SecretKey> for Bytes32 {
    fn from(value: secp256k1::SecretKey) -> Self {
        let mut bytes =  [0;32];
        bytes.copy_from_slice(&value[..]);
        Self {
            bytes
        }
    }
}

impl From<Bytes32> for PaymentHash {
    fn from(ffi_hash: Bytes32) -> PaymentHash {
        PaymentHash(ffi_hash.bytes)
    }
}

impl From<Txid> for Bytes32 {
    fn from(hash: Txid) -> Self {
        let bytes = hash.as_hash().into_inner();
        Bytes32{ bytes }
    }
}

impl From<Bytes32> for Txid {
    fn from(hash: Bytes32) -> Self {
        Txid::from_slice(&hash.bytes).unwrap()
    }
}

impl From<BlockHash> for Bytes32 {
    fn from(hash: BlockHash) -> Self {
        let bytes = hash.as_hash().into_inner();
        Bytes32{ bytes }
    }
}

impl From<Bytes32> for BlockHash {
    fn from(this: Bytes32) -> Self {
        BlockHash::from_slice(&this.bytes).unwrap()
    }
}

impl From<Bytes32> for PaymentSecret {
    fn from(ffi_secret: Bytes32) -> PaymentSecret {
        PaymentSecret(ffi_secret.bytes)
    }
}

impl From<PaymentSecret> for Bytes32 {
    fn from(x: PaymentSecret) -> Self {
        Self {bytes: x.0}
    }
}

impl From<PaymentPreimage> for Bytes32 {
    fn from(x: PaymentPreimage) -> Self {
        Self { bytes: x.0 }
    }
}

impl From<Bytes32> for PaymentPreimage {
    fn from(x: Bytes32) -> Self {
        PaymentPreimage(x.bytes)
    }
}

#[derive(Clone)]
#[repr(C)]
pub struct Bytes33 {
    pub bytes: [u8; 33]
}

impl IsNull for Bytes33 {
    fn is_null(&self) -> bool {
        false
    }
}

impl From<Bytes33> for secp256k1::PublicKey {
    fn from(value: Bytes33) -> Self {
        secp256k1::PublicKey::from_slice(&value.bytes).unwrap()
    }
}

impl From<secp256k1::PublicKey> for Bytes33 {
    fn from(value: secp256k1::PublicKey) -> Self {
        Self {
            bytes: value.serialize()
        }
    }
}


#[derive(Clone)]
#[repr(C)]
pub struct FFIOutPoint {
    pub txid: Bytes32,
    pub index: u16,
}

impl From<FFIOutPoint> for OutPoint {
    fn from(value: FFIOutPoint) -> Self {
        let txid = value.txid.into();
        OutPoint{ txid, index: value.index }
    }
}

impl From<OutPoint> for FFIOutPoint {
    fn from(value: OutPoint) -> Self {
        let txid: Bytes32 =  value.txid.into();
        FFIOutPoint { txid, index: value.index }
    }
}

impl IsNull for FFIOutPoint {
    fn is_null(&self) -> bool {
        false
    }
}

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

// Length-prefixed script.
array_struct!(FFIScript);
impl FFIScript {
    pub fn to_script(&self) -> Script {
        unimplemented!()
    }
}

#[derive(Clone)]
#[repr(C)]
pub struct FFITxOut {
    pub value: u64,
    pub script_pubkey: FFIScript,
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u32)]
pub enum FFIChainError {
    /// Client doesn't support UTXO lookup (but the chain hash matches our genesis block hash)
    NotSupported,
    /// Chain isn't the one watched
    NotWatched,
    /// Tx doesn't exist or is unconfirmed
    UnknownTx,
    UnInitialized,
}

impl From<FFIChainError> for ChainError {
    fn from(e: FFIChainError) -> Self {
        match e {
            FFIChainError::NotSupported => ChainError::NotSupported,
            FFIChainError::NotWatched => ChainError::NotWatched,
            FFIChainError::UnknownTx => ChainError::UnknownTx,
            FFIChainError::UnInitialized => panic!("We should never try to convert uninitialized FFIChainError into ChainError")
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

// General purpose byte array which has to cross ffi-boundary
array_struct!(FFIBytes);

pub struct FFIEvents {
    pub events: Vec<Event>,
}

impl Writeable for FFIEvents {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
        (self.events.len() as u16).write(writer)?;
        for e in &self.events {
            match e {
                Event::FundingGenerationReady {ref temporary_channel_id, ref channel_value_satoshis, ref output_script, ref user_channel_id} => {
                    0u8.write(writer)?;
                    temporary_channel_id.write(writer)?;
                    channel_value_satoshis.write(writer)?;
                    output_script.write(writer)?;
                    user_channel_id.write(writer)?
                }
                Event::PendingHTLCsForwardable { ref time_forwardable } => {
                    5u8.write(writer)?;
                    let milli = time_forwardable.as_millis() as u64;
                    milli.write(writer)?;
                },
                x => x.write(writer)?,
            }
        }
        Ok(())
    }
}

