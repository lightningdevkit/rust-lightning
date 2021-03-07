#[repr(C)]
pub union CResult_SecretKeyErrorZPtr {
	pub result: *mut crate::c_types::SecretKey,
	pub err: *mut crate::c_types::Secp256k1Error,
}
#[repr(C)]
pub struct CResult_SecretKeyErrorZ {
	pub contents: CResult_SecretKeyErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_SecretKeyErrorZ_ok(o: crate::c_types::SecretKey) -> CResult_SecretKeyErrorZ {
	CResult_SecretKeyErrorZ {
		contents: CResult_SecretKeyErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_SecretKeyErrorZ_err(e: crate::c_types::Secp256k1Error) -> CResult_SecretKeyErrorZ {
	CResult_SecretKeyErrorZ {
		contents: CResult_SecretKeyErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_SecretKeyErrorZ_free(_res: CResult_SecretKeyErrorZ) { }
impl Drop for CResult_SecretKeyErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::c_types::SecretKey, crate::c_types::Secp256k1Error>> for CResult_SecretKeyErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::c_types::SecretKey, crate::c_types::Secp256k1Error>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_SecretKeyErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_SecretKeyErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
#[repr(C)]
pub union CResult_PublicKeyErrorZPtr {
	pub result: *mut crate::c_types::PublicKey,
	pub err: *mut crate::c_types::Secp256k1Error,
}
#[repr(C)]
pub struct CResult_PublicKeyErrorZ {
	pub contents: CResult_PublicKeyErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_PublicKeyErrorZ_ok(o: crate::c_types::PublicKey) -> CResult_PublicKeyErrorZ {
	CResult_PublicKeyErrorZ {
		contents: CResult_PublicKeyErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_PublicKeyErrorZ_err(e: crate::c_types::Secp256k1Error) -> CResult_PublicKeyErrorZ {
	CResult_PublicKeyErrorZ {
		contents: CResult_PublicKeyErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_PublicKeyErrorZ_free(_res: CResult_PublicKeyErrorZ) { }
impl Drop for CResult_PublicKeyErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::c_types::PublicKey, crate::c_types::Secp256k1Error>> for CResult_PublicKeyErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::c_types::PublicKey, crate::c_types::Secp256k1Error>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_PublicKeyErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_PublicKeyErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
#[repr(C)]
pub union CResult_TxCreationKeysDecodeErrorZPtr {
	pub result: *mut crate::ln::chan_utils::TxCreationKeys,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_TxCreationKeysDecodeErrorZ {
	pub contents: CResult_TxCreationKeysDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_TxCreationKeysDecodeErrorZ_ok(o: crate::ln::chan_utils::TxCreationKeys) -> CResult_TxCreationKeysDecodeErrorZ {
	CResult_TxCreationKeysDecodeErrorZ {
		contents: CResult_TxCreationKeysDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_TxCreationKeysDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_TxCreationKeysDecodeErrorZ {
	CResult_TxCreationKeysDecodeErrorZ {
		contents: CResult_TxCreationKeysDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_TxCreationKeysDecodeErrorZ_free(_res: CResult_TxCreationKeysDecodeErrorZ) { }
impl Drop for CResult_TxCreationKeysDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::chan_utils::TxCreationKeys, crate::ln::msgs::DecodeError>> for CResult_TxCreationKeysDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::chan_utils::TxCreationKeys, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_TxCreationKeysDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_TxCreationKeysDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_TxCreationKeysDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_TxCreationKeysDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::ln::chan_utils::TxCreationKeys>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_TxCreationKeysDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_TxCreationKeysDecodeErrorZ_clone(orig: &CResult_TxCreationKeysDecodeErrorZ) -> CResult_TxCreationKeysDecodeErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_ChannelPublicKeysDecodeErrorZPtr {
	pub result: *mut crate::ln::chan_utils::ChannelPublicKeys,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_ChannelPublicKeysDecodeErrorZ {
	pub contents: CResult_ChannelPublicKeysDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_ChannelPublicKeysDecodeErrorZ_ok(o: crate::ln::chan_utils::ChannelPublicKeys) -> CResult_ChannelPublicKeysDecodeErrorZ {
	CResult_ChannelPublicKeysDecodeErrorZ {
		contents: CResult_ChannelPublicKeysDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_ChannelPublicKeysDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_ChannelPublicKeysDecodeErrorZ {
	CResult_ChannelPublicKeysDecodeErrorZ {
		contents: CResult_ChannelPublicKeysDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_ChannelPublicKeysDecodeErrorZ_free(_res: CResult_ChannelPublicKeysDecodeErrorZ) { }
impl Drop for CResult_ChannelPublicKeysDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::chan_utils::ChannelPublicKeys, crate::ln::msgs::DecodeError>> for CResult_ChannelPublicKeysDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::chan_utils::ChannelPublicKeys, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_ChannelPublicKeysDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_ChannelPublicKeysDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_ChannelPublicKeysDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_ChannelPublicKeysDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::ln::chan_utils::ChannelPublicKeys>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_ChannelPublicKeysDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_ChannelPublicKeysDecodeErrorZ_clone(orig: &CResult_ChannelPublicKeysDecodeErrorZ) -> CResult_ChannelPublicKeysDecodeErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_TxCreationKeysErrorZPtr {
	pub result: *mut crate::ln::chan_utils::TxCreationKeys,
	pub err: *mut crate::c_types::Secp256k1Error,
}
#[repr(C)]
pub struct CResult_TxCreationKeysErrorZ {
	pub contents: CResult_TxCreationKeysErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_TxCreationKeysErrorZ_ok(o: crate::ln::chan_utils::TxCreationKeys) -> CResult_TxCreationKeysErrorZ {
	CResult_TxCreationKeysErrorZ {
		contents: CResult_TxCreationKeysErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_TxCreationKeysErrorZ_err(e: crate::c_types::Secp256k1Error) -> CResult_TxCreationKeysErrorZ {
	CResult_TxCreationKeysErrorZ {
		contents: CResult_TxCreationKeysErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_TxCreationKeysErrorZ_free(_res: CResult_TxCreationKeysErrorZ) { }
impl Drop for CResult_TxCreationKeysErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::chan_utils::TxCreationKeys, crate::c_types::Secp256k1Error>> for CResult_TxCreationKeysErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::chan_utils::TxCreationKeys, crate::c_types::Secp256k1Error>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_TxCreationKeysErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_TxCreationKeysErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
#[repr(C)]
pub union CResult_HTLCOutputInCommitmentDecodeErrorZPtr {
	pub result: *mut crate::ln::chan_utils::HTLCOutputInCommitment,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_HTLCOutputInCommitmentDecodeErrorZ {
	pub contents: CResult_HTLCOutputInCommitmentDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_HTLCOutputInCommitmentDecodeErrorZ_ok(o: crate::ln::chan_utils::HTLCOutputInCommitment) -> CResult_HTLCOutputInCommitmentDecodeErrorZ {
	CResult_HTLCOutputInCommitmentDecodeErrorZ {
		contents: CResult_HTLCOutputInCommitmentDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_HTLCOutputInCommitmentDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_HTLCOutputInCommitmentDecodeErrorZ {
	CResult_HTLCOutputInCommitmentDecodeErrorZ {
		contents: CResult_HTLCOutputInCommitmentDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_HTLCOutputInCommitmentDecodeErrorZ_free(_res: CResult_HTLCOutputInCommitmentDecodeErrorZ) { }
impl Drop for CResult_HTLCOutputInCommitmentDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::chan_utils::HTLCOutputInCommitment, crate::ln::msgs::DecodeError>> for CResult_HTLCOutputInCommitmentDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::chan_utils::HTLCOutputInCommitment, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_HTLCOutputInCommitmentDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_HTLCOutputInCommitmentDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_HTLCOutputInCommitmentDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_HTLCOutputInCommitmentDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::ln::chan_utils::HTLCOutputInCommitment>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_HTLCOutputInCommitmentDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_HTLCOutputInCommitmentDecodeErrorZ_clone(orig: &CResult_HTLCOutputInCommitmentDecodeErrorZ) -> CResult_HTLCOutputInCommitmentDecodeErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_CounterpartyChannelTransactionParametersDecodeErrorZPtr {
	pub result: *mut crate::ln::chan_utils::CounterpartyChannelTransactionParameters,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_CounterpartyChannelTransactionParametersDecodeErrorZ {
	pub contents: CResult_CounterpartyChannelTransactionParametersDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_CounterpartyChannelTransactionParametersDecodeErrorZ_ok(o: crate::ln::chan_utils::CounterpartyChannelTransactionParameters) -> CResult_CounterpartyChannelTransactionParametersDecodeErrorZ {
	CResult_CounterpartyChannelTransactionParametersDecodeErrorZ {
		contents: CResult_CounterpartyChannelTransactionParametersDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_CounterpartyChannelTransactionParametersDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_CounterpartyChannelTransactionParametersDecodeErrorZ {
	CResult_CounterpartyChannelTransactionParametersDecodeErrorZ {
		contents: CResult_CounterpartyChannelTransactionParametersDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_CounterpartyChannelTransactionParametersDecodeErrorZ_free(_res: CResult_CounterpartyChannelTransactionParametersDecodeErrorZ) { }
impl Drop for CResult_CounterpartyChannelTransactionParametersDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::chan_utils::CounterpartyChannelTransactionParameters, crate::ln::msgs::DecodeError>> for CResult_CounterpartyChannelTransactionParametersDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::chan_utils::CounterpartyChannelTransactionParameters, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_CounterpartyChannelTransactionParametersDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_CounterpartyChannelTransactionParametersDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_CounterpartyChannelTransactionParametersDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_CounterpartyChannelTransactionParametersDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::ln::chan_utils::CounterpartyChannelTransactionParameters>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_CounterpartyChannelTransactionParametersDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_CounterpartyChannelTransactionParametersDecodeErrorZ_clone(orig: &CResult_CounterpartyChannelTransactionParametersDecodeErrorZ) -> CResult_CounterpartyChannelTransactionParametersDecodeErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_ChannelTransactionParametersDecodeErrorZPtr {
	pub result: *mut crate::ln::chan_utils::ChannelTransactionParameters,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_ChannelTransactionParametersDecodeErrorZ {
	pub contents: CResult_ChannelTransactionParametersDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_ChannelTransactionParametersDecodeErrorZ_ok(o: crate::ln::chan_utils::ChannelTransactionParameters) -> CResult_ChannelTransactionParametersDecodeErrorZ {
	CResult_ChannelTransactionParametersDecodeErrorZ {
		contents: CResult_ChannelTransactionParametersDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_ChannelTransactionParametersDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_ChannelTransactionParametersDecodeErrorZ {
	CResult_ChannelTransactionParametersDecodeErrorZ {
		contents: CResult_ChannelTransactionParametersDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_ChannelTransactionParametersDecodeErrorZ_free(_res: CResult_ChannelTransactionParametersDecodeErrorZ) { }
impl Drop for CResult_ChannelTransactionParametersDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::chan_utils::ChannelTransactionParameters, crate::ln::msgs::DecodeError>> for CResult_ChannelTransactionParametersDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::chan_utils::ChannelTransactionParameters, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_ChannelTransactionParametersDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_ChannelTransactionParametersDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_ChannelTransactionParametersDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_ChannelTransactionParametersDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::ln::chan_utils::ChannelTransactionParameters>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_ChannelTransactionParametersDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_ChannelTransactionParametersDecodeErrorZ_clone(orig: &CResult_ChannelTransactionParametersDecodeErrorZ) -> CResult_ChannelTransactionParametersDecodeErrorZ { orig.clone() }
#[repr(C)]
pub struct CVec_SignatureZ {
	pub data: *mut crate::c_types::Signature,
	pub datalen: usize
}
impl CVec_SignatureZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::c_types::Signature> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::c_types::Signature] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::c_types::Signature>> for CVec_SignatureZ {
	fn from(v: Vec<crate::c_types::Signature>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
pub extern "C" fn CVec_SignatureZ_free(_res: CVec_SignatureZ) { }
impl Drop for CVec_SignatureZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_SignatureZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
pub union CResult_HolderCommitmentTransactionDecodeErrorZPtr {
	pub result: *mut crate::ln::chan_utils::HolderCommitmentTransaction,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_HolderCommitmentTransactionDecodeErrorZ {
	pub contents: CResult_HolderCommitmentTransactionDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_HolderCommitmentTransactionDecodeErrorZ_ok(o: crate::ln::chan_utils::HolderCommitmentTransaction) -> CResult_HolderCommitmentTransactionDecodeErrorZ {
	CResult_HolderCommitmentTransactionDecodeErrorZ {
		contents: CResult_HolderCommitmentTransactionDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_HolderCommitmentTransactionDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_HolderCommitmentTransactionDecodeErrorZ {
	CResult_HolderCommitmentTransactionDecodeErrorZ {
		contents: CResult_HolderCommitmentTransactionDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_HolderCommitmentTransactionDecodeErrorZ_free(_res: CResult_HolderCommitmentTransactionDecodeErrorZ) { }
impl Drop for CResult_HolderCommitmentTransactionDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::chan_utils::HolderCommitmentTransaction, crate::ln::msgs::DecodeError>> for CResult_HolderCommitmentTransactionDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::chan_utils::HolderCommitmentTransaction, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_HolderCommitmentTransactionDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_HolderCommitmentTransactionDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_HolderCommitmentTransactionDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_HolderCommitmentTransactionDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::ln::chan_utils::HolderCommitmentTransaction>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_HolderCommitmentTransactionDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_HolderCommitmentTransactionDecodeErrorZ_clone(orig: &CResult_HolderCommitmentTransactionDecodeErrorZ) -> CResult_HolderCommitmentTransactionDecodeErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_BuiltCommitmentTransactionDecodeErrorZPtr {
	pub result: *mut crate::ln::chan_utils::BuiltCommitmentTransaction,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_BuiltCommitmentTransactionDecodeErrorZ {
	pub contents: CResult_BuiltCommitmentTransactionDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_BuiltCommitmentTransactionDecodeErrorZ_ok(o: crate::ln::chan_utils::BuiltCommitmentTransaction) -> CResult_BuiltCommitmentTransactionDecodeErrorZ {
	CResult_BuiltCommitmentTransactionDecodeErrorZ {
		contents: CResult_BuiltCommitmentTransactionDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_BuiltCommitmentTransactionDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_BuiltCommitmentTransactionDecodeErrorZ {
	CResult_BuiltCommitmentTransactionDecodeErrorZ {
		contents: CResult_BuiltCommitmentTransactionDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_BuiltCommitmentTransactionDecodeErrorZ_free(_res: CResult_BuiltCommitmentTransactionDecodeErrorZ) { }
impl Drop for CResult_BuiltCommitmentTransactionDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::chan_utils::BuiltCommitmentTransaction, crate::ln::msgs::DecodeError>> for CResult_BuiltCommitmentTransactionDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::chan_utils::BuiltCommitmentTransaction, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_BuiltCommitmentTransactionDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_BuiltCommitmentTransactionDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_BuiltCommitmentTransactionDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_BuiltCommitmentTransactionDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::ln::chan_utils::BuiltCommitmentTransaction>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_BuiltCommitmentTransactionDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_BuiltCommitmentTransactionDecodeErrorZ_clone(orig: &CResult_BuiltCommitmentTransactionDecodeErrorZ) -> CResult_BuiltCommitmentTransactionDecodeErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_CommitmentTransactionDecodeErrorZPtr {
	pub result: *mut crate::ln::chan_utils::CommitmentTransaction,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_CommitmentTransactionDecodeErrorZ {
	pub contents: CResult_CommitmentTransactionDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_CommitmentTransactionDecodeErrorZ_ok(o: crate::ln::chan_utils::CommitmentTransaction) -> CResult_CommitmentTransactionDecodeErrorZ {
	CResult_CommitmentTransactionDecodeErrorZ {
		contents: CResult_CommitmentTransactionDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_CommitmentTransactionDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_CommitmentTransactionDecodeErrorZ {
	CResult_CommitmentTransactionDecodeErrorZ {
		contents: CResult_CommitmentTransactionDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_CommitmentTransactionDecodeErrorZ_free(_res: CResult_CommitmentTransactionDecodeErrorZ) { }
impl Drop for CResult_CommitmentTransactionDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::chan_utils::CommitmentTransaction, crate::ln::msgs::DecodeError>> for CResult_CommitmentTransactionDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::chan_utils::CommitmentTransaction, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_CommitmentTransactionDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_CommitmentTransactionDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_CommitmentTransactionDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_CommitmentTransactionDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::ln::chan_utils::CommitmentTransaction>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_CommitmentTransactionDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_CommitmentTransactionDecodeErrorZ_clone(orig: &CResult_CommitmentTransactionDecodeErrorZ) -> CResult_CommitmentTransactionDecodeErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_TrustedCommitmentTransactionNoneZPtr {
	pub result: *mut crate::ln::chan_utils::TrustedCommitmentTransaction,
	/// Note that this value is always NULL, as there are no contents in the Err variant
	pub err: *mut std::ffi::c_void,
}
#[repr(C)]
pub struct CResult_TrustedCommitmentTransactionNoneZ {
	pub contents: CResult_TrustedCommitmentTransactionNoneZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_TrustedCommitmentTransactionNoneZ_ok(o: crate::ln::chan_utils::TrustedCommitmentTransaction) -> CResult_TrustedCommitmentTransactionNoneZ {
	CResult_TrustedCommitmentTransactionNoneZ {
		contents: CResult_TrustedCommitmentTransactionNoneZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_TrustedCommitmentTransactionNoneZ_err() -> CResult_TrustedCommitmentTransactionNoneZ {
	CResult_TrustedCommitmentTransactionNoneZ {
		contents: CResult_TrustedCommitmentTransactionNoneZPtr {
			err: std::ptr::null_mut(),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_TrustedCommitmentTransactionNoneZ_free(_res: CResult_TrustedCommitmentTransactionNoneZ) { }
impl Drop for CResult_TrustedCommitmentTransactionNoneZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::chan_utils::TrustedCommitmentTransaction, u8>> for CResult_TrustedCommitmentTransactionNoneZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::chan_utils::TrustedCommitmentTransaction, u8>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_TrustedCommitmentTransactionNoneZPtr { result }
		} else {
			let _ = unsafe { Box::from_raw(o.contents.err) };
			o.contents.err = std::ptr::null_mut();
			CResult_TrustedCommitmentTransactionNoneZPtr { err: std::ptr::null_mut() }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
#[repr(C)]
pub union CResult_CVec_SignatureZNoneZPtr {
	pub result: *mut crate::c_types::derived::CVec_SignatureZ,
	/// Note that this value is always NULL, as there are no contents in the Err variant
	pub err: *mut std::ffi::c_void,
}
#[repr(C)]
pub struct CResult_CVec_SignatureZNoneZ {
	pub contents: CResult_CVec_SignatureZNoneZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_CVec_SignatureZNoneZ_ok(o: crate::c_types::derived::CVec_SignatureZ) -> CResult_CVec_SignatureZNoneZ {
	CResult_CVec_SignatureZNoneZ {
		contents: CResult_CVec_SignatureZNoneZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_CVec_SignatureZNoneZ_err() -> CResult_CVec_SignatureZNoneZ {
	CResult_CVec_SignatureZNoneZ {
		contents: CResult_CVec_SignatureZNoneZPtr {
			err: std::ptr::null_mut(),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_CVec_SignatureZNoneZ_free(_res: CResult_CVec_SignatureZNoneZ) { }
impl Drop for CResult_CVec_SignatureZNoneZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::c_types::derived::CVec_SignatureZ, u8>> for CResult_CVec_SignatureZNoneZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::c_types::derived::CVec_SignatureZ, u8>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_CVec_SignatureZNoneZPtr { result }
		} else {
			let _ = unsafe { Box::from_raw(o.contents.err) };
			o.contents.err = std::ptr::null_mut();
			CResult_CVec_SignatureZNoneZPtr { err: std::ptr::null_mut() }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_CVec_SignatureZNoneZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_CVec_SignatureZNoneZPtr {
				result: Box::into_raw(Box::new(<crate::c_types::derived::CVec_SignatureZ>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_CVec_SignatureZNoneZPtr {
				err: std::ptr::null_mut()
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_CVec_SignatureZNoneZ_clone(orig: &CResult_CVec_SignatureZNoneZ) -> CResult_CVec_SignatureZNoneZ { orig.clone() }
#[repr(C)]
pub struct CVec_MessageSendEventZ {
	pub data: *mut crate::util::events::MessageSendEvent,
	pub datalen: usize
}
impl CVec_MessageSendEventZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::util::events::MessageSendEvent> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::util::events::MessageSendEvent] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::util::events::MessageSendEvent>> for CVec_MessageSendEventZ {
	fn from(v: Vec<crate::util::events::MessageSendEvent>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
pub extern "C" fn CVec_MessageSendEventZ_free(_res: CVec_MessageSendEventZ) { }
impl Drop for CVec_MessageSendEventZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_MessageSendEventZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
pub union CResult_boolLightningErrorZPtr {
	pub result: *mut bool,
	pub err: *mut crate::ln::msgs::LightningError,
}
#[repr(C)]
pub struct CResult_boolLightningErrorZ {
	pub contents: CResult_boolLightningErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_boolLightningErrorZ_ok(o: bool) -> CResult_boolLightningErrorZ {
	CResult_boolLightningErrorZ {
		contents: CResult_boolLightningErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_boolLightningErrorZ_err(e: crate::ln::msgs::LightningError) -> CResult_boolLightningErrorZ {
	CResult_boolLightningErrorZ {
		contents: CResult_boolLightningErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_boolLightningErrorZ_free(_res: CResult_boolLightningErrorZ) { }
impl Drop for CResult_boolLightningErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<bool, crate::ln::msgs::LightningError>> for CResult_boolLightningErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<bool, crate::ln::msgs::LightningError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_boolLightningErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_boolLightningErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_boolLightningErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_boolLightningErrorZPtr {
				result: Box::into_raw(Box::new(<bool>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_boolLightningErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::LightningError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_boolLightningErrorZ_clone(orig: &CResult_boolLightningErrorZ) -> CResult_boolLightningErrorZ { orig.clone() }
#[repr(C)]
pub struct C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ {
	pub a: crate::ln::msgs::ChannelAnnouncement,
	pub b: crate::ln::msgs::ChannelUpdate,
	pub c: crate::ln::msgs::ChannelUpdate,
}
impl From<(crate::ln::msgs::ChannelAnnouncement, crate::ln::msgs::ChannelUpdate, crate::ln::msgs::ChannelUpdate)> for C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ {
	fn from (tup: (crate::ln::msgs::ChannelAnnouncement, crate::ln::msgs::ChannelUpdate, crate::ln::msgs::ChannelUpdate)) -> Self {
		Self {
			a: tup.0,
			b: tup.1,
			c: tup.2,
		}
	}
}
impl C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ {
	#[allow(unused)] pub(crate) fn to_rust(mut self) -> (crate::ln::msgs::ChannelAnnouncement, crate::ln::msgs::ChannelUpdate, crate::ln::msgs::ChannelUpdate) {
		(self.a, self.b, self.c)
	}
}
impl Clone for C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ {
	fn clone(&self) -> Self {
		Self {
			a: self.a.clone(),
			b: self.b.clone(),
			c: self.c.clone(),
		}
	}
}
#[no_mangle]
pub extern "C" fn C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ_clone(orig: &C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ) -> C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ { orig.clone() }
#[no_mangle]
pub extern "C" fn C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ_new(a: crate::ln::msgs::ChannelAnnouncement, b: crate::ln::msgs::ChannelUpdate, c: crate::ln::msgs::ChannelUpdate) -> C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ {
	C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ { a, b, c, }
}

#[no_mangle]
pub extern "C" fn C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ_free(_res: C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ) { }
#[repr(C)]
pub struct CVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ {
	pub data: *mut crate::c_types::derived::C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ,
	pub datalen: usize
}
impl CVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::c_types::derived::C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::c_types::derived::C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::c_types::derived::C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ>> for CVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ {
	fn from(v: Vec<crate::c_types::derived::C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
pub extern "C" fn CVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ_free(_res: CVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ) { }
impl Drop for CVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
pub struct CVec_NodeAnnouncementZ {
	pub data: *mut crate::ln::msgs::NodeAnnouncement,
	pub datalen: usize
}
impl CVec_NodeAnnouncementZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::ln::msgs::NodeAnnouncement> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::ln::msgs::NodeAnnouncement] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::ln::msgs::NodeAnnouncement>> for CVec_NodeAnnouncementZ {
	fn from(v: Vec<crate::ln::msgs::NodeAnnouncement>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
pub extern "C" fn CVec_NodeAnnouncementZ_free(_res: CVec_NodeAnnouncementZ) { }
impl Drop for CVec_NodeAnnouncementZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_NodeAnnouncementZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
pub union CResult_NoneLightningErrorZPtr {
	/// Note that this value is always NULL, as there are no contents in the OK variant
	pub result: *mut std::ffi::c_void,
	pub err: *mut crate::ln::msgs::LightningError,
}
#[repr(C)]
pub struct CResult_NoneLightningErrorZ {
	pub contents: CResult_NoneLightningErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_NoneLightningErrorZ_ok() -> CResult_NoneLightningErrorZ {
	CResult_NoneLightningErrorZ {
		contents: CResult_NoneLightningErrorZPtr {
			result: std::ptr::null_mut(),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_NoneLightningErrorZ_err(e: crate::ln::msgs::LightningError) -> CResult_NoneLightningErrorZ {
	CResult_NoneLightningErrorZ {
		contents: CResult_NoneLightningErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_NoneLightningErrorZ_free(_res: CResult_NoneLightningErrorZ) { }
impl Drop for CResult_NoneLightningErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<u8, crate::ln::msgs::LightningError>> for CResult_NoneLightningErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<u8, crate::ln::msgs::LightningError>) -> Self {
		let contents = if o.result_ok {
			let _ = unsafe { Box::from_raw(o.contents.result) };
			o.contents.result = std::ptr::null_mut();
			CResult_NoneLightningErrorZPtr { result: std::ptr::null_mut() }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_NoneLightningErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_NoneLightningErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_NoneLightningErrorZPtr {
				result: std::ptr::null_mut()
			} }
		} else {
			Self { result_ok: false, contents: CResult_NoneLightningErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::LightningError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_NoneLightningErrorZ_clone(orig: &CResult_NoneLightningErrorZ) -> CResult_NoneLightningErrorZ { orig.clone() }
#[repr(C)]
pub struct CVec_PublicKeyZ {
	pub data: *mut crate::c_types::PublicKey,
	pub datalen: usize
}
impl CVec_PublicKeyZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::c_types::PublicKey> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::c_types::PublicKey] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::c_types::PublicKey>> for CVec_PublicKeyZ {
	fn from(v: Vec<crate::c_types::PublicKey>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
pub extern "C" fn CVec_PublicKeyZ_free(_res: CVec_PublicKeyZ) { }
impl Drop for CVec_PublicKeyZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
#[repr(C)]
pub struct CVec_u8Z {
	pub data: *mut u8,
	pub datalen: usize
}
impl CVec_u8Z {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<u8> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[u8] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<u8>> for CVec_u8Z {
	fn from(v: Vec<u8>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
pub extern "C" fn CVec_u8Z_free(_res: CVec_u8Z) { }
impl Drop for CVec_u8Z {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_u8Z {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
pub union CResult_CVec_u8ZPeerHandleErrorZPtr {
	pub result: *mut crate::c_types::derived::CVec_u8Z,
	pub err: *mut crate::ln::peer_handler::PeerHandleError,
}
#[repr(C)]
pub struct CResult_CVec_u8ZPeerHandleErrorZ {
	pub contents: CResult_CVec_u8ZPeerHandleErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_CVec_u8ZPeerHandleErrorZ_ok(o: crate::c_types::derived::CVec_u8Z) -> CResult_CVec_u8ZPeerHandleErrorZ {
	CResult_CVec_u8ZPeerHandleErrorZ {
		contents: CResult_CVec_u8ZPeerHandleErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_CVec_u8ZPeerHandleErrorZ_err(e: crate::ln::peer_handler::PeerHandleError) -> CResult_CVec_u8ZPeerHandleErrorZ {
	CResult_CVec_u8ZPeerHandleErrorZ {
		contents: CResult_CVec_u8ZPeerHandleErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_CVec_u8ZPeerHandleErrorZ_free(_res: CResult_CVec_u8ZPeerHandleErrorZ) { }
impl Drop for CResult_CVec_u8ZPeerHandleErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::c_types::derived::CVec_u8Z, crate::ln::peer_handler::PeerHandleError>> for CResult_CVec_u8ZPeerHandleErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::c_types::derived::CVec_u8Z, crate::ln::peer_handler::PeerHandleError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_CVec_u8ZPeerHandleErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_CVec_u8ZPeerHandleErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_CVec_u8ZPeerHandleErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_CVec_u8ZPeerHandleErrorZPtr {
				result: Box::into_raw(Box::new(<crate::c_types::derived::CVec_u8Z>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_CVec_u8ZPeerHandleErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::peer_handler::PeerHandleError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_CVec_u8ZPeerHandleErrorZ_clone(orig: &CResult_CVec_u8ZPeerHandleErrorZ) -> CResult_CVec_u8ZPeerHandleErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_NonePeerHandleErrorZPtr {
	/// Note that this value is always NULL, as there are no contents in the OK variant
	pub result: *mut std::ffi::c_void,
	pub err: *mut crate::ln::peer_handler::PeerHandleError,
}
#[repr(C)]
pub struct CResult_NonePeerHandleErrorZ {
	pub contents: CResult_NonePeerHandleErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_NonePeerHandleErrorZ_ok() -> CResult_NonePeerHandleErrorZ {
	CResult_NonePeerHandleErrorZ {
		contents: CResult_NonePeerHandleErrorZPtr {
			result: std::ptr::null_mut(),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_NonePeerHandleErrorZ_err(e: crate::ln::peer_handler::PeerHandleError) -> CResult_NonePeerHandleErrorZ {
	CResult_NonePeerHandleErrorZ {
		contents: CResult_NonePeerHandleErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_NonePeerHandleErrorZ_free(_res: CResult_NonePeerHandleErrorZ) { }
impl Drop for CResult_NonePeerHandleErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<u8, crate::ln::peer_handler::PeerHandleError>> for CResult_NonePeerHandleErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<u8, crate::ln::peer_handler::PeerHandleError>) -> Self {
		let contents = if o.result_ok {
			let _ = unsafe { Box::from_raw(o.contents.result) };
			o.contents.result = std::ptr::null_mut();
			CResult_NonePeerHandleErrorZPtr { result: std::ptr::null_mut() }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_NonePeerHandleErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_NonePeerHandleErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_NonePeerHandleErrorZPtr {
				result: std::ptr::null_mut()
			} }
		} else {
			Self { result_ok: false, contents: CResult_NonePeerHandleErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::peer_handler::PeerHandleError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_NonePeerHandleErrorZ_clone(orig: &CResult_NonePeerHandleErrorZ) -> CResult_NonePeerHandleErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_boolPeerHandleErrorZPtr {
	pub result: *mut bool,
	pub err: *mut crate::ln::peer_handler::PeerHandleError,
}
#[repr(C)]
pub struct CResult_boolPeerHandleErrorZ {
	pub contents: CResult_boolPeerHandleErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_boolPeerHandleErrorZ_ok(o: bool) -> CResult_boolPeerHandleErrorZ {
	CResult_boolPeerHandleErrorZ {
		contents: CResult_boolPeerHandleErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_boolPeerHandleErrorZ_err(e: crate::ln::peer_handler::PeerHandleError) -> CResult_boolPeerHandleErrorZ {
	CResult_boolPeerHandleErrorZ {
		contents: CResult_boolPeerHandleErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_boolPeerHandleErrorZ_free(_res: CResult_boolPeerHandleErrorZ) { }
impl Drop for CResult_boolPeerHandleErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<bool, crate::ln::peer_handler::PeerHandleError>> for CResult_boolPeerHandleErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<bool, crate::ln::peer_handler::PeerHandleError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_boolPeerHandleErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_boolPeerHandleErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_boolPeerHandleErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_boolPeerHandleErrorZPtr {
				result: Box::into_raw(Box::new(<bool>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_boolPeerHandleErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::peer_handler::PeerHandleError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_boolPeerHandleErrorZ_clone(orig: &CResult_boolPeerHandleErrorZ) -> CResult_boolPeerHandleErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_InitFeaturesDecodeErrorZPtr {
	pub result: *mut crate::ln::features::InitFeatures,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_InitFeaturesDecodeErrorZ {
	pub contents: CResult_InitFeaturesDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_InitFeaturesDecodeErrorZ_ok(o: crate::ln::features::InitFeatures) -> CResult_InitFeaturesDecodeErrorZ {
	CResult_InitFeaturesDecodeErrorZ {
		contents: CResult_InitFeaturesDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_InitFeaturesDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_InitFeaturesDecodeErrorZ {
	CResult_InitFeaturesDecodeErrorZ {
		contents: CResult_InitFeaturesDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_InitFeaturesDecodeErrorZ_free(_res: CResult_InitFeaturesDecodeErrorZ) { }
impl Drop for CResult_InitFeaturesDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::features::InitFeatures, crate::ln::msgs::DecodeError>> for CResult_InitFeaturesDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::features::InitFeatures, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_InitFeaturesDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_InitFeaturesDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
#[repr(C)]
pub union CResult_NodeFeaturesDecodeErrorZPtr {
	pub result: *mut crate::ln::features::NodeFeatures,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_NodeFeaturesDecodeErrorZ {
	pub contents: CResult_NodeFeaturesDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_NodeFeaturesDecodeErrorZ_ok(o: crate::ln::features::NodeFeatures) -> CResult_NodeFeaturesDecodeErrorZ {
	CResult_NodeFeaturesDecodeErrorZ {
		contents: CResult_NodeFeaturesDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_NodeFeaturesDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_NodeFeaturesDecodeErrorZ {
	CResult_NodeFeaturesDecodeErrorZ {
		contents: CResult_NodeFeaturesDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_NodeFeaturesDecodeErrorZ_free(_res: CResult_NodeFeaturesDecodeErrorZ) { }
impl Drop for CResult_NodeFeaturesDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::features::NodeFeatures, crate::ln::msgs::DecodeError>> for CResult_NodeFeaturesDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::features::NodeFeatures, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_NodeFeaturesDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_NodeFeaturesDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
#[repr(C)]
pub union CResult_ChannelFeaturesDecodeErrorZPtr {
	pub result: *mut crate::ln::features::ChannelFeatures,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_ChannelFeaturesDecodeErrorZ {
	pub contents: CResult_ChannelFeaturesDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_ChannelFeaturesDecodeErrorZ_ok(o: crate::ln::features::ChannelFeatures) -> CResult_ChannelFeaturesDecodeErrorZ {
	CResult_ChannelFeaturesDecodeErrorZ {
		contents: CResult_ChannelFeaturesDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_ChannelFeaturesDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_ChannelFeaturesDecodeErrorZ {
	CResult_ChannelFeaturesDecodeErrorZ {
		contents: CResult_ChannelFeaturesDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_ChannelFeaturesDecodeErrorZ_free(_res: CResult_ChannelFeaturesDecodeErrorZ) { }
impl Drop for CResult_ChannelFeaturesDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::features::ChannelFeatures, crate::ln::msgs::DecodeError>> for CResult_ChannelFeaturesDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::features::ChannelFeatures, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_ChannelFeaturesDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_ChannelFeaturesDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
#[repr(C)]
pub union CResult_ChannelConfigDecodeErrorZPtr {
	pub result: *mut crate::util::config::ChannelConfig,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_ChannelConfigDecodeErrorZ {
	pub contents: CResult_ChannelConfigDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_ChannelConfigDecodeErrorZ_ok(o: crate::util::config::ChannelConfig) -> CResult_ChannelConfigDecodeErrorZ {
	CResult_ChannelConfigDecodeErrorZ {
		contents: CResult_ChannelConfigDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_ChannelConfigDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_ChannelConfigDecodeErrorZ {
	CResult_ChannelConfigDecodeErrorZ {
		contents: CResult_ChannelConfigDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_ChannelConfigDecodeErrorZ_free(_res: CResult_ChannelConfigDecodeErrorZ) { }
impl Drop for CResult_ChannelConfigDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::util::config::ChannelConfig, crate::ln::msgs::DecodeError>> for CResult_ChannelConfigDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::util::config::ChannelConfig, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_ChannelConfigDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_ChannelConfigDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_ChannelConfigDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_ChannelConfigDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::util::config::ChannelConfig>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_ChannelConfigDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_ChannelConfigDecodeErrorZ_clone(orig: &CResult_ChannelConfigDecodeErrorZ) -> CResult_ChannelConfigDecodeErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_DirectionalChannelInfoDecodeErrorZPtr {
	pub result: *mut crate::routing::network_graph::DirectionalChannelInfo,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_DirectionalChannelInfoDecodeErrorZ {
	pub contents: CResult_DirectionalChannelInfoDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_DirectionalChannelInfoDecodeErrorZ_ok(o: crate::routing::network_graph::DirectionalChannelInfo) -> CResult_DirectionalChannelInfoDecodeErrorZ {
	CResult_DirectionalChannelInfoDecodeErrorZ {
		contents: CResult_DirectionalChannelInfoDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_DirectionalChannelInfoDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_DirectionalChannelInfoDecodeErrorZ {
	CResult_DirectionalChannelInfoDecodeErrorZ {
		contents: CResult_DirectionalChannelInfoDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_DirectionalChannelInfoDecodeErrorZ_free(_res: CResult_DirectionalChannelInfoDecodeErrorZ) { }
impl Drop for CResult_DirectionalChannelInfoDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::routing::network_graph::DirectionalChannelInfo, crate::ln::msgs::DecodeError>> for CResult_DirectionalChannelInfoDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::routing::network_graph::DirectionalChannelInfo, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_DirectionalChannelInfoDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_DirectionalChannelInfoDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_DirectionalChannelInfoDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_DirectionalChannelInfoDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::routing::network_graph::DirectionalChannelInfo>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_DirectionalChannelInfoDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_DirectionalChannelInfoDecodeErrorZ_clone(orig: &CResult_DirectionalChannelInfoDecodeErrorZ) -> CResult_DirectionalChannelInfoDecodeErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_ChannelInfoDecodeErrorZPtr {
	pub result: *mut crate::routing::network_graph::ChannelInfo,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_ChannelInfoDecodeErrorZ {
	pub contents: CResult_ChannelInfoDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_ChannelInfoDecodeErrorZ_ok(o: crate::routing::network_graph::ChannelInfo) -> CResult_ChannelInfoDecodeErrorZ {
	CResult_ChannelInfoDecodeErrorZ {
		contents: CResult_ChannelInfoDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_ChannelInfoDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_ChannelInfoDecodeErrorZ {
	CResult_ChannelInfoDecodeErrorZ {
		contents: CResult_ChannelInfoDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_ChannelInfoDecodeErrorZ_free(_res: CResult_ChannelInfoDecodeErrorZ) { }
impl Drop for CResult_ChannelInfoDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::routing::network_graph::ChannelInfo, crate::ln::msgs::DecodeError>> for CResult_ChannelInfoDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::routing::network_graph::ChannelInfo, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_ChannelInfoDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_ChannelInfoDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_ChannelInfoDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_ChannelInfoDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::routing::network_graph::ChannelInfo>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_ChannelInfoDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_ChannelInfoDecodeErrorZ_clone(orig: &CResult_ChannelInfoDecodeErrorZ) -> CResult_ChannelInfoDecodeErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_RoutingFeesDecodeErrorZPtr {
	pub result: *mut crate::routing::network_graph::RoutingFees,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_RoutingFeesDecodeErrorZ {
	pub contents: CResult_RoutingFeesDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_RoutingFeesDecodeErrorZ_ok(o: crate::routing::network_graph::RoutingFees) -> CResult_RoutingFeesDecodeErrorZ {
	CResult_RoutingFeesDecodeErrorZ {
		contents: CResult_RoutingFeesDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_RoutingFeesDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_RoutingFeesDecodeErrorZ {
	CResult_RoutingFeesDecodeErrorZ {
		contents: CResult_RoutingFeesDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_RoutingFeesDecodeErrorZ_free(_res: CResult_RoutingFeesDecodeErrorZ) { }
impl Drop for CResult_RoutingFeesDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::routing::network_graph::RoutingFees, crate::ln::msgs::DecodeError>> for CResult_RoutingFeesDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::routing::network_graph::RoutingFees, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_RoutingFeesDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_RoutingFeesDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_RoutingFeesDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_RoutingFeesDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::routing::network_graph::RoutingFees>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_RoutingFeesDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_RoutingFeesDecodeErrorZ_clone(orig: &CResult_RoutingFeesDecodeErrorZ) -> CResult_RoutingFeesDecodeErrorZ { orig.clone() }
#[repr(C)]
pub struct CVec_NetAddressZ {
	pub data: *mut crate::ln::msgs::NetAddress,
	pub datalen: usize
}
impl CVec_NetAddressZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::ln::msgs::NetAddress> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::ln::msgs::NetAddress] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::ln::msgs::NetAddress>> for CVec_NetAddressZ {
	fn from(v: Vec<crate::ln::msgs::NetAddress>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
pub extern "C" fn CVec_NetAddressZ_free(_res: CVec_NetAddressZ) { }
impl Drop for CVec_NetAddressZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_NetAddressZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
pub union CResult_NodeAnnouncementInfoDecodeErrorZPtr {
	pub result: *mut crate::routing::network_graph::NodeAnnouncementInfo,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_NodeAnnouncementInfoDecodeErrorZ {
	pub contents: CResult_NodeAnnouncementInfoDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_NodeAnnouncementInfoDecodeErrorZ_ok(o: crate::routing::network_graph::NodeAnnouncementInfo) -> CResult_NodeAnnouncementInfoDecodeErrorZ {
	CResult_NodeAnnouncementInfoDecodeErrorZ {
		contents: CResult_NodeAnnouncementInfoDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_NodeAnnouncementInfoDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_NodeAnnouncementInfoDecodeErrorZ {
	CResult_NodeAnnouncementInfoDecodeErrorZ {
		contents: CResult_NodeAnnouncementInfoDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_NodeAnnouncementInfoDecodeErrorZ_free(_res: CResult_NodeAnnouncementInfoDecodeErrorZ) { }
impl Drop for CResult_NodeAnnouncementInfoDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::routing::network_graph::NodeAnnouncementInfo, crate::ln::msgs::DecodeError>> for CResult_NodeAnnouncementInfoDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::routing::network_graph::NodeAnnouncementInfo, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_NodeAnnouncementInfoDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_NodeAnnouncementInfoDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_NodeAnnouncementInfoDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_NodeAnnouncementInfoDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::routing::network_graph::NodeAnnouncementInfo>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_NodeAnnouncementInfoDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_NodeAnnouncementInfoDecodeErrorZ_clone(orig: &CResult_NodeAnnouncementInfoDecodeErrorZ) -> CResult_NodeAnnouncementInfoDecodeErrorZ { orig.clone() }
#[repr(C)]
pub struct CVec_u64Z {
	pub data: *mut u64,
	pub datalen: usize
}
impl CVec_u64Z {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<u64> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[u64] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<u64>> for CVec_u64Z {
	fn from(v: Vec<u64>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
pub extern "C" fn CVec_u64Z_free(_res: CVec_u64Z) { }
impl Drop for CVec_u64Z {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_u64Z {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
pub union CResult_NodeInfoDecodeErrorZPtr {
	pub result: *mut crate::routing::network_graph::NodeInfo,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_NodeInfoDecodeErrorZ {
	pub contents: CResult_NodeInfoDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_NodeInfoDecodeErrorZ_ok(o: crate::routing::network_graph::NodeInfo) -> CResult_NodeInfoDecodeErrorZ {
	CResult_NodeInfoDecodeErrorZ {
		contents: CResult_NodeInfoDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_NodeInfoDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_NodeInfoDecodeErrorZ {
	CResult_NodeInfoDecodeErrorZ {
		contents: CResult_NodeInfoDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_NodeInfoDecodeErrorZ_free(_res: CResult_NodeInfoDecodeErrorZ) { }
impl Drop for CResult_NodeInfoDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::routing::network_graph::NodeInfo, crate::ln::msgs::DecodeError>> for CResult_NodeInfoDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::routing::network_graph::NodeInfo, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_NodeInfoDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_NodeInfoDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_NodeInfoDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_NodeInfoDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::routing::network_graph::NodeInfo>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_NodeInfoDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_NodeInfoDecodeErrorZ_clone(orig: &CResult_NodeInfoDecodeErrorZ) -> CResult_NodeInfoDecodeErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_NetworkGraphDecodeErrorZPtr {
	pub result: *mut crate::routing::network_graph::NetworkGraph,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_NetworkGraphDecodeErrorZ {
	pub contents: CResult_NetworkGraphDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_NetworkGraphDecodeErrorZ_ok(o: crate::routing::network_graph::NetworkGraph) -> CResult_NetworkGraphDecodeErrorZ {
	CResult_NetworkGraphDecodeErrorZ {
		contents: CResult_NetworkGraphDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_NetworkGraphDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_NetworkGraphDecodeErrorZ {
	CResult_NetworkGraphDecodeErrorZ {
		contents: CResult_NetworkGraphDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_NetworkGraphDecodeErrorZ_free(_res: CResult_NetworkGraphDecodeErrorZ) { }
impl Drop for CResult_NetworkGraphDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::routing::network_graph::NetworkGraph, crate::ln::msgs::DecodeError>> for CResult_NetworkGraphDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::routing::network_graph::NetworkGraph, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_NetworkGraphDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_NetworkGraphDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_NetworkGraphDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_NetworkGraphDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::routing::network_graph::NetworkGraph>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_NetworkGraphDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_NetworkGraphDecodeErrorZ_clone(orig: &CResult_NetworkGraphDecodeErrorZ) -> CResult_NetworkGraphDecodeErrorZ { orig.clone() }
#[repr(C)]
pub struct C2Tuple_usizeTransactionZ {
	pub a: usize,
	pub b: crate::c_types::Transaction,
}
impl From<(usize, crate::c_types::Transaction)> for C2Tuple_usizeTransactionZ {
	fn from (tup: (usize, crate::c_types::Transaction)) -> Self {
		Self {
			a: tup.0,
			b: tup.1,
		}
	}
}
impl C2Tuple_usizeTransactionZ {
	#[allow(unused)] pub(crate) fn to_rust(mut self) -> (usize, crate::c_types::Transaction) {
		(self.a, self.b)
	}
}
#[no_mangle]
pub extern "C" fn C2Tuple_usizeTransactionZ_new(a: usize, b: crate::c_types::Transaction) -> C2Tuple_usizeTransactionZ {
	C2Tuple_usizeTransactionZ { a, b, }
}

#[no_mangle]
pub extern "C" fn C2Tuple_usizeTransactionZ_free(_res: C2Tuple_usizeTransactionZ) { }
#[repr(C)]
pub struct CVec_C2Tuple_usizeTransactionZZ {
	pub data: *mut crate::c_types::derived::C2Tuple_usizeTransactionZ,
	pub datalen: usize
}
impl CVec_C2Tuple_usizeTransactionZZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::c_types::derived::C2Tuple_usizeTransactionZ> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::c_types::derived::C2Tuple_usizeTransactionZ] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::c_types::derived::C2Tuple_usizeTransactionZ>> for CVec_C2Tuple_usizeTransactionZZ {
	fn from(v: Vec<crate::c_types::derived::C2Tuple_usizeTransactionZ>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
pub extern "C" fn CVec_C2Tuple_usizeTransactionZZ_free(_res: CVec_C2Tuple_usizeTransactionZZ) { }
impl Drop for CVec_C2Tuple_usizeTransactionZZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
#[repr(C)]
pub union CResult_NoneChannelMonitorUpdateErrZPtr {
	/// Note that this value is always NULL, as there are no contents in the OK variant
	pub result: *mut std::ffi::c_void,
	pub err: *mut crate::chain::channelmonitor::ChannelMonitorUpdateErr,
}
#[repr(C)]
pub struct CResult_NoneChannelMonitorUpdateErrZ {
	pub contents: CResult_NoneChannelMonitorUpdateErrZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_NoneChannelMonitorUpdateErrZ_ok() -> CResult_NoneChannelMonitorUpdateErrZ {
	CResult_NoneChannelMonitorUpdateErrZ {
		contents: CResult_NoneChannelMonitorUpdateErrZPtr {
			result: std::ptr::null_mut(),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_NoneChannelMonitorUpdateErrZ_err(e: crate::chain::channelmonitor::ChannelMonitorUpdateErr) -> CResult_NoneChannelMonitorUpdateErrZ {
	CResult_NoneChannelMonitorUpdateErrZ {
		contents: CResult_NoneChannelMonitorUpdateErrZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_NoneChannelMonitorUpdateErrZ_free(_res: CResult_NoneChannelMonitorUpdateErrZ) { }
impl Drop for CResult_NoneChannelMonitorUpdateErrZ {
	fn drop(&mut self) {
		if self.result_ok {
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<u8, crate::chain::channelmonitor::ChannelMonitorUpdateErr>> for CResult_NoneChannelMonitorUpdateErrZ {
	fn from(mut o: crate::c_types::CResultTempl<u8, crate::chain::channelmonitor::ChannelMonitorUpdateErr>) -> Self {
		let contents = if o.result_ok {
			let _ = unsafe { Box::from_raw(o.contents.result) };
			o.contents.result = std::ptr::null_mut();
			CResult_NoneChannelMonitorUpdateErrZPtr { result: std::ptr::null_mut() }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_NoneChannelMonitorUpdateErrZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_NoneChannelMonitorUpdateErrZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_NoneChannelMonitorUpdateErrZPtr {
				result: std::ptr::null_mut()
			} }
		} else {
			Self { result_ok: false, contents: CResult_NoneChannelMonitorUpdateErrZPtr {
				err: Box::into_raw(Box::new(<crate::chain::channelmonitor::ChannelMonitorUpdateErr>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_NoneChannelMonitorUpdateErrZ_clone(orig: &CResult_NoneChannelMonitorUpdateErrZ) -> CResult_NoneChannelMonitorUpdateErrZ { orig.clone() }
#[repr(C)]
pub struct CVec_MonitorEventZ {
	pub data: *mut crate::chain::channelmonitor::MonitorEvent,
	pub datalen: usize
}
impl CVec_MonitorEventZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::chain::channelmonitor::MonitorEvent> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::chain::channelmonitor::MonitorEvent] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::chain::channelmonitor::MonitorEvent>> for CVec_MonitorEventZ {
	fn from(v: Vec<crate::chain::channelmonitor::MonitorEvent>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
pub extern "C" fn CVec_MonitorEventZ_free(_res: CVec_MonitorEventZ) { }
impl Drop for CVec_MonitorEventZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_MonitorEventZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
pub struct CVec_EventZ {
	pub data: *mut crate::util::events::Event,
	pub datalen: usize
}
impl CVec_EventZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::util::events::Event> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::util::events::Event] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::util::events::Event>> for CVec_EventZ {
	fn from(v: Vec<crate::util::events::Event>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
pub extern "C" fn CVec_EventZ_free(_res: CVec_EventZ) { }
impl Drop for CVec_EventZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_EventZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
pub union CResult_OutPointDecodeErrorZPtr {
	pub result: *mut crate::chain::transaction::OutPoint,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_OutPointDecodeErrorZ {
	pub contents: CResult_OutPointDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_OutPointDecodeErrorZ_ok(o: crate::chain::transaction::OutPoint) -> CResult_OutPointDecodeErrorZ {
	CResult_OutPointDecodeErrorZ {
		contents: CResult_OutPointDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_OutPointDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_OutPointDecodeErrorZ {
	CResult_OutPointDecodeErrorZ {
		contents: CResult_OutPointDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_OutPointDecodeErrorZ_free(_res: CResult_OutPointDecodeErrorZ) { }
impl Drop for CResult_OutPointDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::chain::transaction::OutPoint, crate::ln::msgs::DecodeError>> for CResult_OutPointDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::chain::transaction::OutPoint, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_OutPointDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_OutPointDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_OutPointDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_OutPointDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::chain::transaction::OutPoint>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_OutPointDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_OutPointDecodeErrorZ_clone(orig: &CResult_OutPointDecodeErrorZ) -> CResult_OutPointDecodeErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_ChannelMonitorUpdateDecodeErrorZPtr {
	pub result: *mut crate::chain::channelmonitor::ChannelMonitorUpdate,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_ChannelMonitorUpdateDecodeErrorZ {
	pub contents: CResult_ChannelMonitorUpdateDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_ChannelMonitorUpdateDecodeErrorZ_ok(o: crate::chain::channelmonitor::ChannelMonitorUpdate) -> CResult_ChannelMonitorUpdateDecodeErrorZ {
	CResult_ChannelMonitorUpdateDecodeErrorZ {
		contents: CResult_ChannelMonitorUpdateDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_ChannelMonitorUpdateDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_ChannelMonitorUpdateDecodeErrorZ {
	CResult_ChannelMonitorUpdateDecodeErrorZ {
		contents: CResult_ChannelMonitorUpdateDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_ChannelMonitorUpdateDecodeErrorZ_free(_res: CResult_ChannelMonitorUpdateDecodeErrorZ) { }
impl Drop for CResult_ChannelMonitorUpdateDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::chain::channelmonitor::ChannelMonitorUpdate, crate::ln::msgs::DecodeError>> for CResult_ChannelMonitorUpdateDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::chain::channelmonitor::ChannelMonitorUpdate, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_ChannelMonitorUpdateDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_ChannelMonitorUpdateDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_ChannelMonitorUpdateDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_ChannelMonitorUpdateDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::chain::channelmonitor::ChannelMonitorUpdate>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_ChannelMonitorUpdateDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_ChannelMonitorUpdateDecodeErrorZ_clone(orig: &CResult_ChannelMonitorUpdateDecodeErrorZ) -> CResult_ChannelMonitorUpdateDecodeErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_HTLCUpdateDecodeErrorZPtr {
	pub result: *mut crate::chain::channelmonitor::HTLCUpdate,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_HTLCUpdateDecodeErrorZ {
	pub contents: CResult_HTLCUpdateDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_HTLCUpdateDecodeErrorZ_ok(o: crate::chain::channelmonitor::HTLCUpdate) -> CResult_HTLCUpdateDecodeErrorZ {
	CResult_HTLCUpdateDecodeErrorZ {
		contents: CResult_HTLCUpdateDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_HTLCUpdateDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_HTLCUpdateDecodeErrorZ {
	CResult_HTLCUpdateDecodeErrorZ {
		contents: CResult_HTLCUpdateDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_HTLCUpdateDecodeErrorZ_free(_res: CResult_HTLCUpdateDecodeErrorZ) { }
impl Drop for CResult_HTLCUpdateDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::chain::channelmonitor::HTLCUpdate, crate::ln::msgs::DecodeError>> for CResult_HTLCUpdateDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::chain::channelmonitor::HTLCUpdate, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_HTLCUpdateDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_HTLCUpdateDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_HTLCUpdateDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_HTLCUpdateDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::chain::channelmonitor::HTLCUpdate>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_HTLCUpdateDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_HTLCUpdateDecodeErrorZ_clone(orig: &CResult_HTLCUpdateDecodeErrorZ) -> CResult_HTLCUpdateDecodeErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_NoneMonitorUpdateErrorZPtr {
	/// Note that this value is always NULL, as there are no contents in the OK variant
	pub result: *mut std::ffi::c_void,
	pub err: *mut crate::chain::channelmonitor::MonitorUpdateError,
}
#[repr(C)]
pub struct CResult_NoneMonitorUpdateErrorZ {
	pub contents: CResult_NoneMonitorUpdateErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_NoneMonitorUpdateErrorZ_ok() -> CResult_NoneMonitorUpdateErrorZ {
	CResult_NoneMonitorUpdateErrorZ {
		contents: CResult_NoneMonitorUpdateErrorZPtr {
			result: std::ptr::null_mut(),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_NoneMonitorUpdateErrorZ_err(e: crate::chain::channelmonitor::MonitorUpdateError) -> CResult_NoneMonitorUpdateErrorZ {
	CResult_NoneMonitorUpdateErrorZ {
		contents: CResult_NoneMonitorUpdateErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_NoneMonitorUpdateErrorZ_free(_res: CResult_NoneMonitorUpdateErrorZ) { }
impl Drop for CResult_NoneMonitorUpdateErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<u8, crate::chain::channelmonitor::MonitorUpdateError>> for CResult_NoneMonitorUpdateErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<u8, crate::chain::channelmonitor::MonitorUpdateError>) -> Self {
		let contents = if o.result_ok {
			let _ = unsafe { Box::from_raw(o.contents.result) };
			o.contents.result = std::ptr::null_mut();
			CResult_NoneMonitorUpdateErrorZPtr { result: std::ptr::null_mut() }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_NoneMonitorUpdateErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_NoneMonitorUpdateErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_NoneMonitorUpdateErrorZPtr {
				result: std::ptr::null_mut()
			} }
		} else {
			Self { result_ok: false, contents: CResult_NoneMonitorUpdateErrorZPtr {
				err: Box::into_raw(Box::new(<crate::chain::channelmonitor::MonitorUpdateError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_NoneMonitorUpdateErrorZ_clone(orig: &CResult_NoneMonitorUpdateErrorZ) -> CResult_NoneMonitorUpdateErrorZ { orig.clone() }
#[repr(C)]
pub struct C2Tuple_OutPointScriptZ {
	pub a: crate::chain::transaction::OutPoint,
	pub b: crate::c_types::derived::CVec_u8Z,
}
impl From<(crate::chain::transaction::OutPoint, crate::c_types::derived::CVec_u8Z)> for C2Tuple_OutPointScriptZ {
	fn from (tup: (crate::chain::transaction::OutPoint, crate::c_types::derived::CVec_u8Z)) -> Self {
		Self {
			a: tup.0,
			b: tup.1,
		}
	}
}
impl C2Tuple_OutPointScriptZ {
	#[allow(unused)] pub(crate) fn to_rust(mut self) -> (crate::chain::transaction::OutPoint, crate::c_types::derived::CVec_u8Z) {
		(self.a, self.b)
	}
}
impl Clone for C2Tuple_OutPointScriptZ {
	fn clone(&self) -> Self {
		Self {
			a: self.a.clone(),
			b: self.b.clone(),
		}
	}
}
#[no_mangle]
pub extern "C" fn C2Tuple_OutPointScriptZ_clone(orig: &C2Tuple_OutPointScriptZ) -> C2Tuple_OutPointScriptZ { orig.clone() }
#[no_mangle]
pub extern "C" fn C2Tuple_OutPointScriptZ_new(a: crate::chain::transaction::OutPoint, b: crate::c_types::derived::CVec_u8Z) -> C2Tuple_OutPointScriptZ {
	C2Tuple_OutPointScriptZ { a, b, }
}

#[no_mangle]
pub extern "C" fn C2Tuple_OutPointScriptZ_free(_res: C2Tuple_OutPointScriptZ) { }
#[repr(C)]
pub struct CVec_TransactionZ {
	pub data: *mut crate::c_types::Transaction,
	pub datalen: usize
}
impl CVec_TransactionZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::c_types::Transaction> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::c_types::Transaction] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::c_types::Transaction>> for CVec_TransactionZ {
	fn from(v: Vec<crate::c_types::Transaction>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
pub extern "C" fn CVec_TransactionZ_free(_res: CVec_TransactionZ) { }
impl Drop for CVec_TransactionZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
#[repr(C)]
pub struct C2Tuple_u32TxOutZ {
	pub a: u32,
	pub b: crate::c_types::TxOut,
}
impl From<(u32, crate::c_types::TxOut)> for C2Tuple_u32TxOutZ {
	fn from (tup: (u32, crate::c_types::TxOut)) -> Self {
		Self {
			a: tup.0,
			b: tup.1,
		}
	}
}
impl C2Tuple_u32TxOutZ {
	#[allow(unused)] pub(crate) fn to_rust(mut self) -> (u32, crate::c_types::TxOut) {
		(self.a, self.b)
	}
}
impl Clone for C2Tuple_u32TxOutZ {
	fn clone(&self) -> Self {
		Self {
			a: self.a.clone(),
			b: self.b.clone(),
		}
	}
}
#[no_mangle]
pub extern "C" fn C2Tuple_u32TxOutZ_clone(orig: &C2Tuple_u32TxOutZ) -> C2Tuple_u32TxOutZ { orig.clone() }
#[no_mangle]
pub extern "C" fn C2Tuple_u32TxOutZ_new(a: u32, b: crate::c_types::TxOut) -> C2Tuple_u32TxOutZ {
	C2Tuple_u32TxOutZ { a, b, }
}

#[no_mangle]
pub extern "C" fn C2Tuple_u32TxOutZ_free(_res: C2Tuple_u32TxOutZ) { }
#[repr(C)]
pub struct CVec_C2Tuple_u32TxOutZZ {
	pub data: *mut crate::c_types::derived::C2Tuple_u32TxOutZ,
	pub datalen: usize
}
impl CVec_C2Tuple_u32TxOutZZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::c_types::derived::C2Tuple_u32TxOutZ> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::c_types::derived::C2Tuple_u32TxOutZ] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::c_types::derived::C2Tuple_u32TxOutZ>> for CVec_C2Tuple_u32TxOutZZ {
	fn from(v: Vec<crate::c_types::derived::C2Tuple_u32TxOutZ>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
pub extern "C" fn CVec_C2Tuple_u32TxOutZZ_free(_res: CVec_C2Tuple_u32TxOutZZ) { }
impl Drop for CVec_C2Tuple_u32TxOutZZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_C2Tuple_u32TxOutZZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
pub struct C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ {
	pub a: crate::c_types::ThirtyTwoBytes,
	pub b: crate::c_types::derived::CVec_C2Tuple_u32TxOutZZ,
}
impl From<(crate::c_types::ThirtyTwoBytes, crate::c_types::derived::CVec_C2Tuple_u32TxOutZZ)> for C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ {
	fn from (tup: (crate::c_types::ThirtyTwoBytes, crate::c_types::derived::CVec_C2Tuple_u32TxOutZZ)) -> Self {
		Self {
			a: tup.0,
			b: tup.1,
		}
	}
}
impl C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ {
	#[allow(unused)] pub(crate) fn to_rust(mut self) -> (crate::c_types::ThirtyTwoBytes, crate::c_types::derived::CVec_C2Tuple_u32TxOutZZ) {
		(self.a, self.b)
	}
}
#[no_mangle]
pub extern "C" fn C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ_new(a: crate::c_types::ThirtyTwoBytes, b: crate::c_types::derived::CVec_C2Tuple_u32TxOutZZ) -> C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ {
	C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ { a, b, }
}

#[no_mangle]
pub extern "C" fn C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ_free(_res: C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ) { }
#[repr(C)]
pub struct CVec_C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZZ {
	pub data: *mut crate::c_types::derived::C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ,
	pub datalen: usize
}
impl CVec_C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::c_types::derived::C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::c_types::derived::C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::c_types::derived::C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ>> for CVec_C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZZ {
	fn from(v: Vec<crate::c_types::derived::C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
pub extern "C" fn CVec_C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZZ_free(_res: CVec_C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZZ) { }
impl Drop for CVec_C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
#[repr(C)]
pub struct C2Tuple_BlockHashChannelMonitorZ {
	pub a: crate::c_types::ThirtyTwoBytes,
	pub b: crate::chain::channelmonitor::ChannelMonitor,
}
impl From<(crate::c_types::ThirtyTwoBytes, crate::chain::channelmonitor::ChannelMonitor)> for C2Tuple_BlockHashChannelMonitorZ {
	fn from (tup: (crate::c_types::ThirtyTwoBytes, crate::chain::channelmonitor::ChannelMonitor)) -> Self {
		Self {
			a: tup.0,
			b: tup.1,
		}
	}
}
impl C2Tuple_BlockHashChannelMonitorZ {
	#[allow(unused)] pub(crate) fn to_rust(mut self) -> (crate::c_types::ThirtyTwoBytes, crate::chain::channelmonitor::ChannelMonitor) {
		(self.a, self.b)
	}
}
#[no_mangle]
pub extern "C" fn C2Tuple_BlockHashChannelMonitorZ_new(a: crate::c_types::ThirtyTwoBytes, b: crate::chain::channelmonitor::ChannelMonitor) -> C2Tuple_BlockHashChannelMonitorZ {
	C2Tuple_BlockHashChannelMonitorZ { a, b, }
}

#[no_mangle]
pub extern "C" fn C2Tuple_BlockHashChannelMonitorZ_free(_res: C2Tuple_BlockHashChannelMonitorZ) { }
#[repr(C)]
pub union CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZPtr {
	pub result: *mut crate::c_types::derived::C2Tuple_BlockHashChannelMonitorZ,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ {
	pub contents: CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ_ok(o: crate::c_types::derived::C2Tuple_BlockHashChannelMonitorZ) -> CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ {
	CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ {
		contents: CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ {
	CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ {
		contents: CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ_free(_res: CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ) { }
impl Drop for CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::c_types::derived::C2Tuple_BlockHashChannelMonitorZ, crate::ln::msgs::DecodeError>> for CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::c_types::derived::C2Tuple_BlockHashChannelMonitorZ, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
#[repr(C)]
pub struct CVec_SpendableOutputDescriptorZ {
	pub data: *mut crate::chain::keysinterface::SpendableOutputDescriptor,
	pub datalen: usize
}
impl CVec_SpendableOutputDescriptorZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::chain::keysinterface::SpendableOutputDescriptor> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::chain::keysinterface::SpendableOutputDescriptor] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::chain::keysinterface::SpendableOutputDescriptor>> for CVec_SpendableOutputDescriptorZ {
	fn from(v: Vec<crate::chain::keysinterface::SpendableOutputDescriptor>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
pub extern "C" fn CVec_SpendableOutputDescriptorZ_free(_res: CVec_SpendableOutputDescriptorZ) { }
impl Drop for CVec_SpendableOutputDescriptorZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_SpendableOutputDescriptorZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
pub union CResult_TxOutAccessErrorZPtr {
	pub result: *mut crate::c_types::TxOut,
	pub err: *mut crate::chain::AccessError,
}
#[repr(C)]
pub struct CResult_TxOutAccessErrorZ {
	pub contents: CResult_TxOutAccessErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_TxOutAccessErrorZ_ok(o: crate::c_types::TxOut) -> CResult_TxOutAccessErrorZ {
	CResult_TxOutAccessErrorZ {
		contents: CResult_TxOutAccessErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_TxOutAccessErrorZ_err(e: crate::chain::AccessError) -> CResult_TxOutAccessErrorZ {
	CResult_TxOutAccessErrorZ {
		contents: CResult_TxOutAccessErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_TxOutAccessErrorZ_free(_res: CResult_TxOutAccessErrorZ) { }
impl Drop for CResult_TxOutAccessErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::c_types::TxOut, crate::chain::AccessError>> for CResult_TxOutAccessErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::c_types::TxOut, crate::chain::AccessError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_TxOutAccessErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_TxOutAccessErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_TxOutAccessErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_TxOutAccessErrorZPtr {
				result: Box::into_raw(Box::new(<crate::c_types::TxOut>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_TxOutAccessErrorZPtr {
				err: Box::into_raw(Box::new(<crate::chain::AccessError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_TxOutAccessErrorZ_clone(orig: &CResult_TxOutAccessErrorZ) -> CResult_TxOutAccessErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_NoneAPIErrorZPtr {
	/// Note that this value is always NULL, as there are no contents in the OK variant
	pub result: *mut std::ffi::c_void,
	pub err: *mut crate::util::errors::APIError,
}
#[repr(C)]
pub struct CResult_NoneAPIErrorZ {
	pub contents: CResult_NoneAPIErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_NoneAPIErrorZ_ok() -> CResult_NoneAPIErrorZ {
	CResult_NoneAPIErrorZ {
		contents: CResult_NoneAPIErrorZPtr {
			result: std::ptr::null_mut(),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_NoneAPIErrorZ_err(e: crate::util::errors::APIError) -> CResult_NoneAPIErrorZ {
	CResult_NoneAPIErrorZ {
		contents: CResult_NoneAPIErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_NoneAPIErrorZ_free(_res: CResult_NoneAPIErrorZ) { }
impl Drop for CResult_NoneAPIErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<u8, crate::util::errors::APIError>> for CResult_NoneAPIErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<u8, crate::util::errors::APIError>) -> Self {
		let contents = if o.result_ok {
			let _ = unsafe { Box::from_raw(o.contents.result) };
			o.contents.result = std::ptr::null_mut();
			CResult_NoneAPIErrorZPtr { result: std::ptr::null_mut() }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_NoneAPIErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_NoneAPIErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_NoneAPIErrorZPtr {
				result: std::ptr::null_mut()
			} }
		} else {
			Self { result_ok: false, contents: CResult_NoneAPIErrorZPtr {
				err: Box::into_raw(Box::new(<crate::util::errors::APIError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_NoneAPIErrorZ_clone(orig: &CResult_NoneAPIErrorZ) -> CResult_NoneAPIErrorZ { orig.clone() }
#[repr(C)]
pub struct CVec_CResult_NoneAPIErrorZZ {
	pub data: *mut crate::c_types::derived::CResult_NoneAPIErrorZ,
	pub datalen: usize
}
impl CVec_CResult_NoneAPIErrorZZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::c_types::derived::CResult_NoneAPIErrorZ> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::c_types::derived::CResult_NoneAPIErrorZ] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::c_types::derived::CResult_NoneAPIErrorZ>> for CVec_CResult_NoneAPIErrorZZ {
	fn from(v: Vec<crate::c_types::derived::CResult_NoneAPIErrorZ>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
pub extern "C" fn CVec_CResult_NoneAPIErrorZZ_free(_res: CVec_CResult_NoneAPIErrorZZ) { }
impl Drop for CVec_CResult_NoneAPIErrorZZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_CResult_NoneAPIErrorZZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
pub struct CVec_APIErrorZ {
	pub data: *mut crate::util::errors::APIError,
	pub datalen: usize
}
impl CVec_APIErrorZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::util::errors::APIError> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::util::errors::APIError] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::util::errors::APIError>> for CVec_APIErrorZ {
	fn from(v: Vec<crate::util::errors::APIError>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
pub extern "C" fn CVec_APIErrorZ_free(_res: CVec_APIErrorZ) { }
impl Drop for CVec_APIErrorZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_APIErrorZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
pub struct CVec_ChannelDetailsZ {
	pub data: *mut crate::ln::channelmanager::ChannelDetails,
	pub datalen: usize
}
impl CVec_ChannelDetailsZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::ln::channelmanager::ChannelDetails> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::ln::channelmanager::ChannelDetails] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::ln::channelmanager::ChannelDetails>> for CVec_ChannelDetailsZ {
	fn from(v: Vec<crate::ln::channelmanager::ChannelDetails>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
pub extern "C" fn CVec_ChannelDetailsZ_free(_res: CVec_ChannelDetailsZ) { }
impl Drop for CVec_ChannelDetailsZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_ChannelDetailsZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
pub union CResult_NonePaymentSendFailureZPtr {
	/// Note that this value is always NULL, as there are no contents in the OK variant
	pub result: *mut std::ffi::c_void,
	pub err: *mut crate::ln::channelmanager::PaymentSendFailure,
}
#[repr(C)]
pub struct CResult_NonePaymentSendFailureZ {
	pub contents: CResult_NonePaymentSendFailureZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_NonePaymentSendFailureZ_ok() -> CResult_NonePaymentSendFailureZ {
	CResult_NonePaymentSendFailureZ {
		contents: CResult_NonePaymentSendFailureZPtr {
			result: std::ptr::null_mut(),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_NonePaymentSendFailureZ_err(e: crate::ln::channelmanager::PaymentSendFailure) -> CResult_NonePaymentSendFailureZ {
	CResult_NonePaymentSendFailureZ {
		contents: CResult_NonePaymentSendFailureZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_NonePaymentSendFailureZ_free(_res: CResult_NonePaymentSendFailureZ) { }
impl Drop for CResult_NonePaymentSendFailureZ {
	fn drop(&mut self) {
		if self.result_ok {
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<u8, crate::ln::channelmanager::PaymentSendFailure>> for CResult_NonePaymentSendFailureZ {
	fn from(mut o: crate::c_types::CResultTempl<u8, crate::ln::channelmanager::PaymentSendFailure>) -> Self {
		let contents = if o.result_ok {
			let _ = unsafe { Box::from_raw(o.contents.result) };
			o.contents.result = std::ptr::null_mut();
			CResult_NonePaymentSendFailureZPtr { result: std::ptr::null_mut() }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_NonePaymentSendFailureZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_NonePaymentSendFailureZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_NonePaymentSendFailureZPtr {
				result: std::ptr::null_mut()
			} }
		} else {
			Self { result_ok: false, contents: CResult_NonePaymentSendFailureZPtr {
				err: Box::into_raw(Box::new(<crate::ln::channelmanager::PaymentSendFailure>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_NonePaymentSendFailureZ_clone(orig: &CResult_NonePaymentSendFailureZ) -> CResult_NonePaymentSendFailureZ { orig.clone() }
#[repr(C)]
pub struct CVec_ChannelMonitorZ {
	pub data: *mut crate::chain::channelmonitor::ChannelMonitor,
	pub datalen: usize
}
impl CVec_ChannelMonitorZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::chain::channelmonitor::ChannelMonitor> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::chain::channelmonitor::ChannelMonitor] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::chain::channelmonitor::ChannelMonitor>> for CVec_ChannelMonitorZ {
	fn from(v: Vec<crate::chain::channelmonitor::ChannelMonitor>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
pub extern "C" fn CVec_ChannelMonitorZ_free(_res: CVec_ChannelMonitorZ) { }
impl Drop for CVec_ChannelMonitorZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
#[repr(C)]
pub struct C2Tuple_BlockHashChannelManagerZ {
	pub a: crate::c_types::ThirtyTwoBytes,
	pub b: crate::ln::channelmanager::ChannelManager,
}
impl From<(crate::c_types::ThirtyTwoBytes, crate::ln::channelmanager::ChannelManager)> for C2Tuple_BlockHashChannelManagerZ {
	fn from (tup: (crate::c_types::ThirtyTwoBytes, crate::ln::channelmanager::ChannelManager)) -> Self {
		Self {
			a: tup.0,
			b: tup.1,
		}
	}
}
impl C2Tuple_BlockHashChannelManagerZ {
	#[allow(unused)] pub(crate) fn to_rust(mut self) -> (crate::c_types::ThirtyTwoBytes, crate::ln::channelmanager::ChannelManager) {
		(self.a, self.b)
	}
}
#[no_mangle]
pub extern "C" fn C2Tuple_BlockHashChannelManagerZ_new(a: crate::c_types::ThirtyTwoBytes, b: crate::ln::channelmanager::ChannelManager) -> C2Tuple_BlockHashChannelManagerZ {
	C2Tuple_BlockHashChannelManagerZ { a, b, }
}

#[no_mangle]
pub extern "C" fn C2Tuple_BlockHashChannelManagerZ_free(_res: C2Tuple_BlockHashChannelManagerZ) { }
#[repr(C)]
pub union CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZPtr {
	pub result: *mut crate::c_types::derived::C2Tuple_BlockHashChannelManagerZ,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ {
	pub contents: CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ_ok(o: crate::c_types::derived::C2Tuple_BlockHashChannelManagerZ) -> CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ {
	CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ {
		contents: CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ {
	CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ {
		contents: CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ_free(_res: CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ) { }
impl Drop for CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::c_types::derived::C2Tuple_BlockHashChannelManagerZ, crate::ln::msgs::DecodeError>> for CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::c_types::derived::C2Tuple_BlockHashChannelManagerZ, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
#[repr(C)]
pub union CResult_SpendableOutputDescriptorDecodeErrorZPtr {
	pub result: *mut crate::chain::keysinterface::SpendableOutputDescriptor,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_SpendableOutputDescriptorDecodeErrorZ {
	pub contents: CResult_SpendableOutputDescriptorDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_SpendableOutputDescriptorDecodeErrorZ_ok(o: crate::chain::keysinterface::SpendableOutputDescriptor) -> CResult_SpendableOutputDescriptorDecodeErrorZ {
	CResult_SpendableOutputDescriptorDecodeErrorZ {
		contents: CResult_SpendableOutputDescriptorDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_SpendableOutputDescriptorDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_SpendableOutputDescriptorDecodeErrorZ {
	CResult_SpendableOutputDescriptorDecodeErrorZ {
		contents: CResult_SpendableOutputDescriptorDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_SpendableOutputDescriptorDecodeErrorZ_free(_res: CResult_SpendableOutputDescriptorDecodeErrorZ) { }
impl Drop for CResult_SpendableOutputDescriptorDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::chain::keysinterface::SpendableOutputDescriptor, crate::ln::msgs::DecodeError>> for CResult_SpendableOutputDescriptorDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::chain::keysinterface::SpendableOutputDescriptor, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_SpendableOutputDescriptorDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_SpendableOutputDescriptorDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_SpendableOutputDescriptorDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_SpendableOutputDescriptorDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::chain::keysinterface::SpendableOutputDescriptor>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_SpendableOutputDescriptorDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_SpendableOutputDescriptorDecodeErrorZ_clone(orig: &CResult_SpendableOutputDescriptorDecodeErrorZ) -> CResult_SpendableOutputDescriptorDecodeErrorZ { orig.clone() }
#[repr(C)]
pub struct C2Tuple_SignatureCVec_SignatureZZ {
	pub a: crate::c_types::Signature,
	pub b: crate::c_types::derived::CVec_SignatureZ,
}
impl From<(crate::c_types::Signature, crate::c_types::derived::CVec_SignatureZ)> for C2Tuple_SignatureCVec_SignatureZZ {
	fn from (tup: (crate::c_types::Signature, crate::c_types::derived::CVec_SignatureZ)) -> Self {
		Self {
			a: tup.0,
			b: tup.1,
		}
	}
}
impl C2Tuple_SignatureCVec_SignatureZZ {
	#[allow(unused)] pub(crate) fn to_rust(mut self) -> (crate::c_types::Signature, crate::c_types::derived::CVec_SignatureZ) {
		(self.a, self.b)
	}
}
impl Clone for C2Tuple_SignatureCVec_SignatureZZ {
	fn clone(&self) -> Self {
		Self {
			a: self.a.clone(),
			b: self.b.clone(),
		}
	}
}
#[no_mangle]
pub extern "C" fn C2Tuple_SignatureCVec_SignatureZZ_clone(orig: &C2Tuple_SignatureCVec_SignatureZZ) -> C2Tuple_SignatureCVec_SignatureZZ { orig.clone() }
#[no_mangle]
pub extern "C" fn C2Tuple_SignatureCVec_SignatureZZ_new(a: crate::c_types::Signature, b: crate::c_types::derived::CVec_SignatureZ) -> C2Tuple_SignatureCVec_SignatureZZ {
	C2Tuple_SignatureCVec_SignatureZZ { a, b, }
}

#[no_mangle]
pub extern "C" fn C2Tuple_SignatureCVec_SignatureZZ_free(_res: C2Tuple_SignatureCVec_SignatureZZ) { }
#[repr(C)]
pub union CResult_C2Tuple_SignatureCVec_SignatureZZNoneZPtr {
	pub result: *mut crate::c_types::derived::C2Tuple_SignatureCVec_SignatureZZ,
	/// Note that this value is always NULL, as there are no contents in the Err variant
	pub err: *mut std::ffi::c_void,
}
#[repr(C)]
pub struct CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ {
	pub contents: CResult_C2Tuple_SignatureCVec_SignatureZZNoneZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ_ok(o: crate::c_types::derived::C2Tuple_SignatureCVec_SignatureZZ) -> CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ {
	CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ {
		contents: CResult_C2Tuple_SignatureCVec_SignatureZZNoneZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ_err() -> CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ {
	CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ {
		contents: CResult_C2Tuple_SignatureCVec_SignatureZZNoneZPtr {
			err: std::ptr::null_mut(),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ_free(_res: CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ) { }
impl Drop for CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::c_types::derived::C2Tuple_SignatureCVec_SignatureZZ, u8>> for CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::c_types::derived::C2Tuple_SignatureCVec_SignatureZZ, u8>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_C2Tuple_SignatureCVec_SignatureZZNoneZPtr { result }
		} else {
			let _ = unsafe { Box::from_raw(o.contents.err) };
			o.contents.err = std::ptr::null_mut();
			CResult_C2Tuple_SignatureCVec_SignatureZZNoneZPtr { err: std::ptr::null_mut() }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_C2Tuple_SignatureCVec_SignatureZZNoneZPtr {
				result: Box::into_raw(Box::new(<crate::c_types::derived::C2Tuple_SignatureCVec_SignatureZZ>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_C2Tuple_SignatureCVec_SignatureZZNoneZPtr {
				err: std::ptr::null_mut()
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ_clone(orig: &CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ) -> CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ { orig.clone() }
#[repr(C)]
pub union CResult_SignatureNoneZPtr {
	pub result: *mut crate::c_types::Signature,
	/// Note that this value is always NULL, as there are no contents in the Err variant
	pub err: *mut std::ffi::c_void,
}
#[repr(C)]
pub struct CResult_SignatureNoneZ {
	pub contents: CResult_SignatureNoneZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_SignatureNoneZ_ok(o: crate::c_types::Signature) -> CResult_SignatureNoneZ {
	CResult_SignatureNoneZ {
		contents: CResult_SignatureNoneZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_SignatureNoneZ_err() -> CResult_SignatureNoneZ {
	CResult_SignatureNoneZ {
		contents: CResult_SignatureNoneZPtr {
			err: std::ptr::null_mut(),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_SignatureNoneZ_free(_res: CResult_SignatureNoneZ) { }
impl Drop for CResult_SignatureNoneZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::c_types::Signature, u8>> for CResult_SignatureNoneZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::c_types::Signature, u8>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_SignatureNoneZPtr { result }
		} else {
			let _ = unsafe { Box::from_raw(o.contents.err) };
			o.contents.err = std::ptr::null_mut();
			CResult_SignatureNoneZPtr { err: std::ptr::null_mut() }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_SignatureNoneZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_SignatureNoneZPtr {
				result: Box::into_raw(Box::new(<crate::c_types::Signature>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_SignatureNoneZPtr {
				err: std::ptr::null_mut()
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_SignatureNoneZ_clone(orig: &CResult_SignatureNoneZ) -> CResult_SignatureNoneZ { orig.clone() }
#[repr(C)]
pub union CResult_SignDecodeErrorZPtr {
	pub result: *mut crate::chain::keysinterface::Sign,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_SignDecodeErrorZ {
	pub contents: CResult_SignDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_SignDecodeErrorZ_ok(o: crate::chain::keysinterface::Sign) -> CResult_SignDecodeErrorZ {
	CResult_SignDecodeErrorZ {
		contents: CResult_SignDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_SignDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_SignDecodeErrorZ {
	CResult_SignDecodeErrorZ {
		contents: CResult_SignDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_SignDecodeErrorZ_free(_res: CResult_SignDecodeErrorZ) { }
impl Drop for CResult_SignDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::chain::keysinterface::Sign, crate::ln::msgs::DecodeError>> for CResult_SignDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::chain::keysinterface::Sign, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_SignDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_SignDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_SignDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_SignDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::chain::keysinterface::Sign>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_SignDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_SignDecodeErrorZ_clone(orig: &CResult_SignDecodeErrorZ) -> CResult_SignDecodeErrorZ { orig.clone() }
#[repr(C)]
pub struct CVec_CVec_u8ZZ {
	pub data: *mut crate::c_types::derived::CVec_u8Z,
	pub datalen: usize
}
impl CVec_CVec_u8ZZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::c_types::derived::CVec_u8Z> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::c_types::derived::CVec_u8Z] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::c_types::derived::CVec_u8Z>> for CVec_CVec_u8ZZ {
	fn from(v: Vec<crate::c_types::derived::CVec_u8Z>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
pub extern "C" fn CVec_CVec_u8ZZ_free(_res: CVec_CVec_u8ZZ) { }
impl Drop for CVec_CVec_u8ZZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_CVec_u8ZZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
pub union CResult_CVec_CVec_u8ZZNoneZPtr {
	pub result: *mut crate::c_types::derived::CVec_CVec_u8ZZ,
	/// Note that this value is always NULL, as there are no contents in the Err variant
	pub err: *mut std::ffi::c_void,
}
#[repr(C)]
pub struct CResult_CVec_CVec_u8ZZNoneZ {
	pub contents: CResult_CVec_CVec_u8ZZNoneZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_CVec_CVec_u8ZZNoneZ_ok(o: crate::c_types::derived::CVec_CVec_u8ZZ) -> CResult_CVec_CVec_u8ZZNoneZ {
	CResult_CVec_CVec_u8ZZNoneZ {
		contents: CResult_CVec_CVec_u8ZZNoneZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_CVec_CVec_u8ZZNoneZ_err() -> CResult_CVec_CVec_u8ZZNoneZ {
	CResult_CVec_CVec_u8ZZNoneZ {
		contents: CResult_CVec_CVec_u8ZZNoneZPtr {
			err: std::ptr::null_mut(),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_CVec_CVec_u8ZZNoneZ_free(_res: CResult_CVec_CVec_u8ZZNoneZ) { }
impl Drop for CResult_CVec_CVec_u8ZZNoneZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::c_types::derived::CVec_CVec_u8ZZ, u8>> for CResult_CVec_CVec_u8ZZNoneZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::c_types::derived::CVec_CVec_u8ZZ, u8>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_CVec_CVec_u8ZZNoneZPtr { result }
		} else {
			let _ = unsafe { Box::from_raw(o.contents.err) };
			o.contents.err = std::ptr::null_mut();
			CResult_CVec_CVec_u8ZZNoneZPtr { err: std::ptr::null_mut() }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_CVec_CVec_u8ZZNoneZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_CVec_CVec_u8ZZNoneZPtr {
				result: Box::into_raw(Box::new(<crate::c_types::derived::CVec_CVec_u8ZZ>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_CVec_CVec_u8ZZNoneZPtr {
				err: std::ptr::null_mut()
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_CVec_CVec_u8ZZNoneZ_clone(orig: &CResult_CVec_CVec_u8ZZNoneZ) -> CResult_CVec_CVec_u8ZZNoneZ { orig.clone() }
#[repr(C)]
pub union CResult_InMemorySignerDecodeErrorZPtr {
	pub result: *mut crate::chain::keysinterface::InMemorySigner,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_InMemorySignerDecodeErrorZ {
	pub contents: CResult_InMemorySignerDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_InMemorySignerDecodeErrorZ_ok(o: crate::chain::keysinterface::InMemorySigner) -> CResult_InMemorySignerDecodeErrorZ {
	CResult_InMemorySignerDecodeErrorZ {
		contents: CResult_InMemorySignerDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_InMemorySignerDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_InMemorySignerDecodeErrorZ {
	CResult_InMemorySignerDecodeErrorZ {
		contents: CResult_InMemorySignerDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_InMemorySignerDecodeErrorZ_free(_res: CResult_InMemorySignerDecodeErrorZ) { }
impl Drop for CResult_InMemorySignerDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::chain::keysinterface::InMemorySigner, crate::ln::msgs::DecodeError>> for CResult_InMemorySignerDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::chain::keysinterface::InMemorySigner, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_InMemorySignerDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_InMemorySignerDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_InMemorySignerDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_InMemorySignerDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::chain::keysinterface::InMemorySigner>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_InMemorySignerDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_InMemorySignerDecodeErrorZ_clone(orig: &CResult_InMemorySignerDecodeErrorZ) -> CResult_InMemorySignerDecodeErrorZ { orig.clone() }
#[repr(C)]
pub struct CVec_TxOutZ {
	pub data: *mut crate::c_types::TxOut,
	pub datalen: usize
}
impl CVec_TxOutZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::c_types::TxOut> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::c_types::TxOut] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::c_types::TxOut>> for CVec_TxOutZ {
	fn from(v: Vec<crate::c_types::TxOut>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
pub extern "C" fn CVec_TxOutZ_free(_res: CVec_TxOutZ) { }
impl Drop for CVec_TxOutZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_TxOutZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
pub union CResult_TransactionNoneZPtr {
	pub result: *mut crate::c_types::Transaction,
	/// Note that this value is always NULL, as there are no contents in the Err variant
	pub err: *mut std::ffi::c_void,
}
#[repr(C)]
pub struct CResult_TransactionNoneZ {
	pub contents: CResult_TransactionNoneZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_TransactionNoneZ_ok(o: crate::c_types::Transaction) -> CResult_TransactionNoneZ {
	CResult_TransactionNoneZ {
		contents: CResult_TransactionNoneZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_TransactionNoneZ_err() -> CResult_TransactionNoneZ {
	CResult_TransactionNoneZ {
		contents: CResult_TransactionNoneZPtr {
			err: std::ptr::null_mut(),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_TransactionNoneZ_free(_res: CResult_TransactionNoneZ) { }
impl Drop for CResult_TransactionNoneZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::c_types::Transaction, u8>> for CResult_TransactionNoneZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::c_types::Transaction, u8>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_TransactionNoneZPtr { result }
		} else {
			let _ = unsafe { Box::from_raw(o.contents.err) };
			o.contents.err = std::ptr::null_mut();
			CResult_TransactionNoneZPtr { err: std::ptr::null_mut() }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
#[repr(C)]
pub struct CVec_RouteHopZ {
	pub data: *mut crate::routing::router::RouteHop,
	pub datalen: usize
}
impl CVec_RouteHopZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::routing::router::RouteHop> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::routing::router::RouteHop] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::routing::router::RouteHop>> for CVec_RouteHopZ {
	fn from(v: Vec<crate::routing::router::RouteHop>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
pub extern "C" fn CVec_RouteHopZ_free(_res: CVec_RouteHopZ) { }
impl Drop for CVec_RouteHopZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_RouteHopZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
pub struct CVec_CVec_RouteHopZZ {
	pub data: *mut crate::c_types::derived::CVec_RouteHopZ,
	pub datalen: usize
}
impl CVec_CVec_RouteHopZZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::c_types::derived::CVec_RouteHopZ> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::c_types::derived::CVec_RouteHopZ] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::c_types::derived::CVec_RouteHopZ>> for CVec_CVec_RouteHopZZ {
	fn from(v: Vec<crate::c_types::derived::CVec_RouteHopZ>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
pub extern "C" fn CVec_CVec_RouteHopZZ_free(_res: CVec_CVec_RouteHopZZ) { }
impl Drop for CVec_CVec_RouteHopZZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_CVec_RouteHopZZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
pub union CResult_RouteDecodeErrorZPtr {
	pub result: *mut crate::routing::router::Route,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_RouteDecodeErrorZ {
	pub contents: CResult_RouteDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_RouteDecodeErrorZ_ok(o: crate::routing::router::Route) -> CResult_RouteDecodeErrorZ {
	CResult_RouteDecodeErrorZ {
		contents: CResult_RouteDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_RouteDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_RouteDecodeErrorZ {
	CResult_RouteDecodeErrorZ {
		contents: CResult_RouteDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_RouteDecodeErrorZ_free(_res: CResult_RouteDecodeErrorZ) { }
impl Drop for CResult_RouteDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::routing::router::Route, crate::ln::msgs::DecodeError>> for CResult_RouteDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::routing::router::Route, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_RouteDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_RouteDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_RouteDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_RouteDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::routing::router::Route>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_RouteDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_RouteDecodeErrorZ_clone(orig: &CResult_RouteDecodeErrorZ) -> CResult_RouteDecodeErrorZ { orig.clone() }
#[repr(C)]
pub struct CVec_RouteHintZ {
	pub data: *mut crate::routing::router::RouteHint,
	pub datalen: usize
}
impl CVec_RouteHintZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::routing::router::RouteHint> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::routing::router::RouteHint] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::routing::router::RouteHint>> for CVec_RouteHintZ {
	fn from(v: Vec<crate::routing::router::RouteHint>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
pub extern "C" fn CVec_RouteHintZ_free(_res: CVec_RouteHintZ) { }
impl Drop for CVec_RouteHintZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_RouteHintZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
pub union CResult_RouteLightningErrorZPtr {
	pub result: *mut crate::routing::router::Route,
	pub err: *mut crate::ln::msgs::LightningError,
}
#[repr(C)]
pub struct CResult_RouteLightningErrorZ {
	pub contents: CResult_RouteLightningErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_RouteLightningErrorZ_ok(o: crate::routing::router::Route) -> CResult_RouteLightningErrorZ {
	CResult_RouteLightningErrorZ {
		contents: CResult_RouteLightningErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_RouteLightningErrorZ_err(e: crate::ln::msgs::LightningError) -> CResult_RouteLightningErrorZ {
	CResult_RouteLightningErrorZ {
		contents: CResult_RouteLightningErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_RouteLightningErrorZ_free(_res: CResult_RouteLightningErrorZ) { }
impl Drop for CResult_RouteLightningErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::routing::router::Route, crate::ln::msgs::LightningError>> for CResult_RouteLightningErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::routing::router::Route, crate::ln::msgs::LightningError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_RouteLightningErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_RouteLightningErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_RouteLightningErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_RouteLightningErrorZPtr {
				result: Box::into_raw(Box::new(<crate::routing::router::Route>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_RouteLightningErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::LightningError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_RouteLightningErrorZ_clone(orig: &CResult_RouteLightningErrorZ) -> CResult_RouteLightningErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_NetAddressu8ZPtr {
	pub result: *mut crate::ln::msgs::NetAddress,
	pub err: *mut u8,
}
#[repr(C)]
pub struct CResult_NetAddressu8Z {
	pub contents: CResult_NetAddressu8ZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_NetAddressu8Z_ok(o: crate::ln::msgs::NetAddress) -> CResult_NetAddressu8Z {
	CResult_NetAddressu8Z {
		contents: CResult_NetAddressu8ZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_NetAddressu8Z_err(e: u8) -> CResult_NetAddressu8Z {
	CResult_NetAddressu8Z {
		contents: CResult_NetAddressu8ZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_NetAddressu8Z_free(_res: CResult_NetAddressu8Z) { }
impl Drop for CResult_NetAddressu8Z {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::msgs::NetAddress, u8>> for CResult_NetAddressu8Z {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::msgs::NetAddress, u8>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_NetAddressu8ZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_NetAddressu8ZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_NetAddressu8Z {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_NetAddressu8ZPtr {
				result: Box::into_raw(Box::new(<crate::ln::msgs::NetAddress>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_NetAddressu8ZPtr {
				err: Box::into_raw(Box::new(<u8>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_NetAddressu8Z_clone(orig: &CResult_NetAddressu8Z) -> CResult_NetAddressu8Z { orig.clone() }
#[repr(C)]
pub union CResult_CResult_NetAddressu8ZDecodeErrorZPtr {
	pub result: *mut crate::c_types::derived::CResult_NetAddressu8Z,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_CResult_NetAddressu8ZDecodeErrorZ {
	pub contents: CResult_CResult_NetAddressu8ZDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_CResult_NetAddressu8ZDecodeErrorZ_ok(o: crate::c_types::derived::CResult_NetAddressu8Z) -> CResult_CResult_NetAddressu8ZDecodeErrorZ {
	CResult_CResult_NetAddressu8ZDecodeErrorZ {
		contents: CResult_CResult_NetAddressu8ZDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_CResult_NetAddressu8ZDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_CResult_NetAddressu8ZDecodeErrorZ {
	CResult_CResult_NetAddressu8ZDecodeErrorZ {
		contents: CResult_CResult_NetAddressu8ZDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_CResult_NetAddressu8ZDecodeErrorZ_free(_res: CResult_CResult_NetAddressu8ZDecodeErrorZ) { }
impl Drop for CResult_CResult_NetAddressu8ZDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::c_types::derived::CResult_NetAddressu8Z, crate::ln::msgs::DecodeError>> for CResult_CResult_NetAddressu8ZDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::c_types::derived::CResult_NetAddressu8Z, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_CResult_NetAddressu8ZDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_CResult_NetAddressu8ZDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_CResult_NetAddressu8ZDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_CResult_NetAddressu8ZDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::c_types::derived::CResult_NetAddressu8Z>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_CResult_NetAddressu8ZDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_CResult_NetAddressu8ZDecodeErrorZ_clone(orig: &CResult_CResult_NetAddressu8ZDecodeErrorZ) -> CResult_CResult_NetAddressu8ZDecodeErrorZ { orig.clone() }
#[repr(C)]
pub struct CVec_UpdateAddHTLCZ {
	pub data: *mut crate::ln::msgs::UpdateAddHTLC,
	pub datalen: usize
}
impl CVec_UpdateAddHTLCZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::ln::msgs::UpdateAddHTLC> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::ln::msgs::UpdateAddHTLC] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::ln::msgs::UpdateAddHTLC>> for CVec_UpdateAddHTLCZ {
	fn from(v: Vec<crate::ln::msgs::UpdateAddHTLC>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
pub extern "C" fn CVec_UpdateAddHTLCZ_free(_res: CVec_UpdateAddHTLCZ) { }
impl Drop for CVec_UpdateAddHTLCZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_UpdateAddHTLCZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
pub struct CVec_UpdateFulfillHTLCZ {
	pub data: *mut crate::ln::msgs::UpdateFulfillHTLC,
	pub datalen: usize
}
impl CVec_UpdateFulfillHTLCZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::ln::msgs::UpdateFulfillHTLC> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::ln::msgs::UpdateFulfillHTLC] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::ln::msgs::UpdateFulfillHTLC>> for CVec_UpdateFulfillHTLCZ {
	fn from(v: Vec<crate::ln::msgs::UpdateFulfillHTLC>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
pub extern "C" fn CVec_UpdateFulfillHTLCZ_free(_res: CVec_UpdateFulfillHTLCZ) { }
impl Drop for CVec_UpdateFulfillHTLCZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_UpdateFulfillHTLCZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
pub struct CVec_UpdateFailHTLCZ {
	pub data: *mut crate::ln::msgs::UpdateFailHTLC,
	pub datalen: usize
}
impl CVec_UpdateFailHTLCZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::ln::msgs::UpdateFailHTLC> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::ln::msgs::UpdateFailHTLC] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::ln::msgs::UpdateFailHTLC>> for CVec_UpdateFailHTLCZ {
	fn from(v: Vec<crate::ln::msgs::UpdateFailHTLC>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
pub extern "C" fn CVec_UpdateFailHTLCZ_free(_res: CVec_UpdateFailHTLCZ) { }
impl Drop for CVec_UpdateFailHTLCZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_UpdateFailHTLCZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
pub struct CVec_UpdateFailMalformedHTLCZ {
	pub data: *mut crate::ln::msgs::UpdateFailMalformedHTLC,
	pub datalen: usize
}
impl CVec_UpdateFailMalformedHTLCZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::ln::msgs::UpdateFailMalformedHTLC> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::ln::msgs::UpdateFailMalformedHTLC] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::ln::msgs::UpdateFailMalformedHTLC>> for CVec_UpdateFailMalformedHTLCZ {
	fn from(v: Vec<crate::ln::msgs::UpdateFailMalformedHTLC>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
pub extern "C" fn CVec_UpdateFailMalformedHTLCZ_free(_res: CVec_UpdateFailMalformedHTLCZ) { }
impl Drop for CVec_UpdateFailMalformedHTLCZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_UpdateFailMalformedHTLCZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
pub union CResult_AcceptChannelDecodeErrorZPtr {
	pub result: *mut crate::ln::msgs::AcceptChannel,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_AcceptChannelDecodeErrorZ {
	pub contents: CResult_AcceptChannelDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_AcceptChannelDecodeErrorZ_ok(o: crate::ln::msgs::AcceptChannel) -> CResult_AcceptChannelDecodeErrorZ {
	CResult_AcceptChannelDecodeErrorZ {
		contents: CResult_AcceptChannelDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_AcceptChannelDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_AcceptChannelDecodeErrorZ {
	CResult_AcceptChannelDecodeErrorZ {
		contents: CResult_AcceptChannelDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_AcceptChannelDecodeErrorZ_free(_res: CResult_AcceptChannelDecodeErrorZ) { }
impl Drop for CResult_AcceptChannelDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::msgs::AcceptChannel, crate::ln::msgs::DecodeError>> for CResult_AcceptChannelDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::msgs::AcceptChannel, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_AcceptChannelDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_AcceptChannelDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_AcceptChannelDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_AcceptChannelDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::ln::msgs::AcceptChannel>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_AcceptChannelDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_AcceptChannelDecodeErrorZ_clone(orig: &CResult_AcceptChannelDecodeErrorZ) -> CResult_AcceptChannelDecodeErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_AnnouncementSignaturesDecodeErrorZPtr {
	pub result: *mut crate::ln::msgs::AnnouncementSignatures,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_AnnouncementSignaturesDecodeErrorZ {
	pub contents: CResult_AnnouncementSignaturesDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_AnnouncementSignaturesDecodeErrorZ_ok(o: crate::ln::msgs::AnnouncementSignatures) -> CResult_AnnouncementSignaturesDecodeErrorZ {
	CResult_AnnouncementSignaturesDecodeErrorZ {
		contents: CResult_AnnouncementSignaturesDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_AnnouncementSignaturesDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_AnnouncementSignaturesDecodeErrorZ {
	CResult_AnnouncementSignaturesDecodeErrorZ {
		contents: CResult_AnnouncementSignaturesDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_AnnouncementSignaturesDecodeErrorZ_free(_res: CResult_AnnouncementSignaturesDecodeErrorZ) { }
impl Drop for CResult_AnnouncementSignaturesDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::msgs::AnnouncementSignatures, crate::ln::msgs::DecodeError>> for CResult_AnnouncementSignaturesDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::msgs::AnnouncementSignatures, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_AnnouncementSignaturesDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_AnnouncementSignaturesDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_AnnouncementSignaturesDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_AnnouncementSignaturesDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::ln::msgs::AnnouncementSignatures>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_AnnouncementSignaturesDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_AnnouncementSignaturesDecodeErrorZ_clone(orig: &CResult_AnnouncementSignaturesDecodeErrorZ) -> CResult_AnnouncementSignaturesDecodeErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_ChannelReestablishDecodeErrorZPtr {
	pub result: *mut crate::ln::msgs::ChannelReestablish,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_ChannelReestablishDecodeErrorZ {
	pub contents: CResult_ChannelReestablishDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_ChannelReestablishDecodeErrorZ_ok(o: crate::ln::msgs::ChannelReestablish) -> CResult_ChannelReestablishDecodeErrorZ {
	CResult_ChannelReestablishDecodeErrorZ {
		contents: CResult_ChannelReestablishDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_ChannelReestablishDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_ChannelReestablishDecodeErrorZ {
	CResult_ChannelReestablishDecodeErrorZ {
		contents: CResult_ChannelReestablishDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_ChannelReestablishDecodeErrorZ_free(_res: CResult_ChannelReestablishDecodeErrorZ) { }
impl Drop for CResult_ChannelReestablishDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::msgs::ChannelReestablish, crate::ln::msgs::DecodeError>> for CResult_ChannelReestablishDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::msgs::ChannelReestablish, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_ChannelReestablishDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_ChannelReestablishDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_ChannelReestablishDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_ChannelReestablishDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::ln::msgs::ChannelReestablish>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_ChannelReestablishDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_ChannelReestablishDecodeErrorZ_clone(orig: &CResult_ChannelReestablishDecodeErrorZ) -> CResult_ChannelReestablishDecodeErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_ClosingSignedDecodeErrorZPtr {
	pub result: *mut crate::ln::msgs::ClosingSigned,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_ClosingSignedDecodeErrorZ {
	pub contents: CResult_ClosingSignedDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_ClosingSignedDecodeErrorZ_ok(o: crate::ln::msgs::ClosingSigned) -> CResult_ClosingSignedDecodeErrorZ {
	CResult_ClosingSignedDecodeErrorZ {
		contents: CResult_ClosingSignedDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_ClosingSignedDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_ClosingSignedDecodeErrorZ {
	CResult_ClosingSignedDecodeErrorZ {
		contents: CResult_ClosingSignedDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_ClosingSignedDecodeErrorZ_free(_res: CResult_ClosingSignedDecodeErrorZ) { }
impl Drop for CResult_ClosingSignedDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::msgs::ClosingSigned, crate::ln::msgs::DecodeError>> for CResult_ClosingSignedDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::msgs::ClosingSigned, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_ClosingSignedDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_ClosingSignedDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_ClosingSignedDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_ClosingSignedDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::ln::msgs::ClosingSigned>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_ClosingSignedDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_ClosingSignedDecodeErrorZ_clone(orig: &CResult_ClosingSignedDecodeErrorZ) -> CResult_ClosingSignedDecodeErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_CommitmentSignedDecodeErrorZPtr {
	pub result: *mut crate::ln::msgs::CommitmentSigned,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_CommitmentSignedDecodeErrorZ {
	pub contents: CResult_CommitmentSignedDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_CommitmentSignedDecodeErrorZ_ok(o: crate::ln::msgs::CommitmentSigned) -> CResult_CommitmentSignedDecodeErrorZ {
	CResult_CommitmentSignedDecodeErrorZ {
		contents: CResult_CommitmentSignedDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_CommitmentSignedDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_CommitmentSignedDecodeErrorZ {
	CResult_CommitmentSignedDecodeErrorZ {
		contents: CResult_CommitmentSignedDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_CommitmentSignedDecodeErrorZ_free(_res: CResult_CommitmentSignedDecodeErrorZ) { }
impl Drop for CResult_CommitmentSignedDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::msgs::CommitmentSigned, crate::ln::msgs::DecodeError>> for CResult_CommitmentSignedDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::msgs::CommitmentSigned, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_CommitmentSignedDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_CommitmentSignedDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_CommitmentSignedDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_CommitmentSignedDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::ln::msgs::CommitmentSigned>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_CommitmentSignedDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_CommitmentSignedDecodeErrorZ_clone(orig: &CResult_CommitmentSignedDecodeErrorZ) -> CResult_CommitmentSignedDecodeErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_FundingCreatedDecodeErrorZPtr {
	pub result: *mut crate::ln::msgs::FundingCreated,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_FundingCreatedDecodeErrorZ {
	pub contents: CResult_FundingCreatedDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_FundingCreatedDecodeErrorZ_ok(o: crate::ln::msgs::FundingCreated) -> CResult_FundingCreatedDecodeErrorZ {
	CResult_FundingCreatedDecodeErrorZ {
		contents: CResult_FundingCreatedDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_FundingCreatedDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_FundingCreatedDecodeErrorZ {
	CResult_FundingCreatedDecodeErrorZ {
		contents: CResult_FundingCreatedDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_FundingCreatedDecodeErrorZ_free(_res: CResult_FundingCreatedDecodeErrorZ) { }
impl Drop for CResult_FundingCreatedDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::msgs::FundingCreated, crate::ln::msgs::DecodeError>> for CResult_FundingCreatedDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::msgs::FundingCreated, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_FundingCreatedDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_FundingCreatedDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_FundingCreatedDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_FundingCreatedDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::ln::msgs::FundingCreated>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_FundingCreatedDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_FundingCreatedDecodeErrorZ_clone(orig: &CResult_FundingCreatedDecodeErrorZ) -> CResult_FundingCreatedDecodeErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_FundingSignedDecodeErrorZPtr {
	pub result: *mut crate::ln::msgs::FundingSigned,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_FundingSignedDecodeErrorZ {
	pub contents: CResult_FundingSignedDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_FundingSignedDecodeErrorZ_ok(o: crate::ln::msgs::FundingSigned) -> CResult_FundingSignedDecodeErrorZ {
	CResult_FundingSignedDecodeErrorZ {
		contents: CResult_FundingSignedDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_FundingSignedDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_FundingSignedDecodeErrorZ {
	CResult_FundingSignedDecodeErrorZ {
		contents: CResult_FundingSignedDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_FundingSignedDecodeErrorZ_free(_res: CResult_FundingSignedDecodeErrorZ) { }
impl Drop for CResult_FundingSignedDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::msgs::FundingSigned, crate::ln::msgs::DecodeError>> for CResult_FundingSignedDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::msgs::FundingSigned, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_FundingSignedDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_FundingSignedDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_FundingSignedDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_FundingSignedDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::ln::msgs::FundingSigned>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_FundingSignedDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_FundingSignedDecodeErrorZ_clone(orig: &CResult_FundingSignedDecodeErrorZ) -> CResult_FundingSignedDecodeErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_FundingLockedDecodeErrorZPtr {
	pub result: *mut crate::ln::msgs::FundingLocked,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_FundingLockedDecodeErrorZ {
	pub contents: CResult_FundingLockedDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_FundingLockedDecodeErrorZ_ok(o: crate::ln::msgs::FundingLocked) -> CResult_FundingLockedDecodeErrorZ {
	CResult_FundingLockedDecodeErrorZ {
		contents: CResult_FundingLockedDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_FundingLockedDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_FundingLockedDecodeErrorZ {
	CResult_FundingLockedDecodeErrorZ {
		contents: CResult_FundingLockedDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_FundingLockedDecodeErrorZ_free(_res: CResult_FundingLockedDecodeErrorZ) { }
impl Drop for CResult_FundingLockedDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::msgs::FundingLocked, crate::ln::msgs::DecodeError>> for CResult_FundingLockedDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::msgs::FundingLocked, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_FundingLockedDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_FundingLockedDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_FundingLockedDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_FundingLockedDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::ln::msgs::FundingLocked>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_FundingLockedDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_FundingLockedDecodeErrorZ_clone(orig: &CResult_FundingLockedDecodeErrorZ) -> CResult_FundingLockedDecodeErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_InitDecodeErrorZPtr {
	pub result: *mut crate::ln::msgs::Init,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_InitDecodeErrorZ {
	pub contents: CResult_InitDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_InitDecodeErrorZ_ok(o: crate::ln::msgs::Init) -> CResult_InitDecodeErrorZ {
	CResult_InitDecodeErrorZ {
		contents: CResult_InitDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_InitDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_InitDecodeErrorZ {
	CResult_InitDecodeErrorZ {
		contents: CResult_InitDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_InitDecodeErrorZ_free(_res: CResult_InitDecodeErrorZ) { }
impl Drop for CResult_InitDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::msgs::Init, crate::ln::msgs::DecodeError>> for CResult_InitDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::msgs::Init, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_InitDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_InitDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_InitDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_InitDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::ln::msgs::Init>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_InitDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_InitDecodeErrorZ_clone(orig: &CResult_InitDecodeErrorZ) -> CResult_InitDecodeErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_OpenChannelDecodeErrorZPtr {
	pub result: *mut crate::ln::msgs::OpenChannel,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_OpenChannelDecodeErrorZ {
	pub contents: CResult_OpenChannelDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_OpenChannelDecodeErrorZ_ok(o: crate::ln::msgs::OpenChannel) -> CResult_OpenChannelDecodeErrorZ {
	CResult_OpenChannelDecodeErrorZ {
		contents: CResult_OpenChannelDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_OpenChannelDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_OpenChannelDecodeErrorZ {
	CResult_OpenChannelDecodeErrorZ {
		contents: CResult_OpenChannelDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_OpenChannelDecodeErrorZ_free(_res: CResult_OpenChannelDecodeErrorZ) { }
impl Drop for CResult_OpenChannelDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::msgs::OpenChannel, crate::ln::msgs::DecodeError>> for CResult_OpenChannelDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::msgs::OpenChannel, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_OpenChannelDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_OpenChannelDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_OpenChannelDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_OpenChannelDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::ln::msgs::OpenChannel>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_OpenChannelDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_OpenChannelDecodeErrorZ_clone(orig: &CResult_OpenChannelDecodeErrorZ) -> CResult_OpenChannelDecodeErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_RevokeAndACKDecodeErrorZPtr {
	pub result: *mut crate::ln::msgs::RevokeAndACK,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_RevokeAndACKDecodeErrorZ {
	pub contents: CResult_RevokeAndACKDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_RevokeAndACKDecodeErrorZ_ok(o: crate::ln::msgs::RevokeAndACK) -> CResult_RevokeAndACKDecodeErrorZ {
	CResult_RevokeAndACKDecodeErrorZ {
		contents: CResult_RevokeAndACKDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_RevokeAndACKDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_RevokeAndACKDecodeErrorZ {
	CResult_RevokeAndACKDecodeErrorZ {
		contents: CResult_RevokeAndACKDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_RevokeAndACKDecodeErrorZ_free(_res: CResult_RevokeAndACKDecodeErrorZ) { }
impl Drop for CResult_RevokeAndACKDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::msgs::RevokeAndACK, crate::ln::msgs::DecodeError>> for CResult_RevokeAndACKDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::msgs::RevokeAndACK, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_RevokeAndACKDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_RevokeAndACKDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_RevokeAndACKDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_RevokeAndACKDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::ln::msgs::RevokeAndACK>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_RevokeAndACKDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_RevokeAndACKDecodeErrorZ_clone(orig: &CResult_RevokeAndACKDecodeErrorZ) -> CResult_RevokeAndACKDecodeErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_ShutdownDecodeErrorZPtr {
	pub result: *mut crate::ln::msgs::Shutdown,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_ShutdownDecodeErrorZ {
	pub contents: CResult_ShutdownDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_ShutdownDecodeErrorZ_ok(o: crate::ln::msgs::Shutdown) -> CResult_ShutdownDecodeErrorZ {
	CResult_ShutdownDecodeErrorZ {
		contents: CResult_ShutdownDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_ShutdownDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_ShutdownDecodeErrorZ {
	CResult_ShutdownDecodeErrorZ {
		contents: CResult_ShutdownDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_ShutdownDecodeErrorZ_free(_res: CResult_ShutdownDecodeErrorZ) { }
impl Drop for CResult_ShutdownDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::msgs::Shutdown, crate::ln::msgs::DecodeError>> for CResult_ShutdownDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::msgs::Shutdown, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_ShutdownDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_ShutdownDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_ShutdownDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_ShutdownDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::ln::msgs::Shutdown>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_ShutdownDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_ShutdownDecodeErrorZ_clone(orig: &CResult_ShutdownDecodeErrorZ) -> CResult_ShutdownDecodeErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_UpdateFailHTLCDecodeErrorZPtr {
	pub result: *mut crate::ln::msgs::UpdateFailHTLC,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_UpdateFailHTLCDecodeErrorZ {
	pub contents: CResult_UpdateFailHTLCDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_UpdateFailHTLCDecodeErrorZ_ok(o: crate::ln::msgs::UpdateFailHTLC) -> CResult_UpdateFailHTLCDecodeErrorZ {
	CResult_UpdateFailHTLCDecodeErrorZ {
		contents: CResult_UpdateFailHTLCDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_UpdateFailHTLCDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_UpdateFailHTLCDecodeErrorZ {
	CResult_UpdateFailHTLCDecodeErrorZ {
		contents: CResult_UpdateFailHTLCDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_UpdateFailHTLCDecodeErrorZ_free(_res: CResult_UpdateFailHTLCDecodeErrorZ) { }
impl Drop for CResult_UpdateFailHTLCDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::msgs::UpdateFailHTLC, crate::ln::msgs::DecodeError>> for CResult_UpdateFailHTLCDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::msgs::UpdateFailHTLC, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_UpdateFailHTLCDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_UpdateFailHTLCDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_UpdateFailHTLCDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_UpdateFailHTLCDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::ln::msgs::UpdateFailHTLC>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_UpdateFailHTLCDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_UpdateFailHTLCDecodeErrorZ_clone(orig: &CResult_UpdateFailHTLCDecodeErrorZ) -> CResult_UpdateFailHTLCDecodeErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_UpdateFailMalformedHTLCDecodeErrorZPtr {
	pub result: *mut crate::ln::msgs::UpdateFailMalformedHTLC,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_UpdateFailMalformedHTLCDecodeErrorZ {
	pub contents: CResult_UpdateFailMalformedHTLCDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_UpdateFailMalformedHTLCDecodeErrorZ_ok(o: crate::ln::msgs::UpdateFailMalformedHTLC) -> CResult_UpdateFailMalformedHTLCDecodeErrorZ {
	CResult_UpdateFailMalformedHTLCDecodeErrorZ {
		contents: CResult_UpdateFailMalformedHTLCDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_UpdateFailMalformedHTLCDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_UpdateFailMalformedHTLCDecodeErrorZ {
	CResult_UpdateFailMalformedHTLCDecodeErrorZ {
		contents: CResult_UpdateFailMalformedHTLCDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_UpdateFailMalformedHTLCDecodeErrorZ_free(_res: CResult_UpdateFailMalformedHTLCDecodeErrorZ) { }
impl Drop for CResult_UpdateFailMalformedHTLCDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::msgs::UpdateFailMalformedHTLC, crate::ln::msgs::DecodeError>> for CResult_UpdateFailMalformedHTLCDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::msgs::UpdateFailMalformedHTLC, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_UpdateFailMalformedHTLCDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_UpdateFailMalformedHTLCDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_UpdateFailMalformedHTLCDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_UpdateFailMalformedHTLCDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::ln::msgs::UpdateFailMalformedHTLC>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_UpdateFailMalformedHTLCDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_UpdateFailMalformedHTLCDecodeErrorZ_clone(orig: &CResult_UpdateFailMalformedHTLCDecodeErrorZ) -> CResult_UpdateFailMalformedHTLCDecodeErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_UpdateFeeDecodeErrorZPtr {
	pub result: *mut crate::ln::msgs::UpdateFee,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_UpdateFeeDecodeErrorZ {
	pub contents: CResult_UpdateFeeDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_UpdateFeeDecodeErrorZ_ok(o: crate::ln::msgs::UpdateFee) -> CResult_UpdateFeeDecodeErrorZ {
	CResult_UpdateFeeDecodeErrorZ {
		contents: CResult_UpdateFeeDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_UpdateFeeDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_UpdateFeeDecodeErrorZ {
	CResult_UpdateFeeDecodeErrorZ {
		contents: CResult_UpdateFeeDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_UpdateFeeDecodeErrorZ_free(_res: CResult_UpdateFeeDecodeErrorZ) { }
impl Drop for CResult_UpdateFeeDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::msgs::UpdateFee, crate::ln::msgs::DecodeError>> for CResult_UpdateFeeDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::msgs::UpdateFee, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_UpdateFeeDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_UpdateFeeDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_UpdateFeeDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_UpdateFeeDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::ln::msgs::UpdateFee>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_UpdateFeeDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_UpdateFeeDecodeErrorZ_clone(orig: &CResult_UpdateFeeDecodeErrorZ) -> CResult_UpdateFeeDecodeErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_UpdateFulfillHTLCDecodeErrorZPtr {
	pub result: *mut crate::ln::msgs::UpdateFulfillHTLC,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_UpdateFulfillHTLCDecodeErrorZ {
	pub contents: CResult_UpdateFulfillHTLCDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_UpdateFulfillHTLCDecodeErrorZ_ok(o: crate::ln::msgs::UpdateFulfillHTLC) -> CResult_UpdateFulfillHTLCDecodeErrorZ {
	CResult_UpdateFulfillHTLCDecodeErrorZ {
		contents: CResult_UpdateFulfillHTLCDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_UpdateFulfillHTLCDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_UpdateFulfillHTLCDecodeErrorZ {
	CResult_UpdateFulfillHTLCDecodeErrorZ {
		contents: CResult_UpdateFulfillHTLCDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_UpdateFulfillHTLCDecodeErrorZ_free(_res: CResult_UpdateFulfillHTLCDecodeErrorZ) { }
impl Drop for CResult_UpdateFulfillHTLCDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::msgs::UpdateFulfillHTLC, crate::ln::msgs::DecodeError>> for CResult_UpdateFulfillHTLCDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::msgs::UpdateFulfillHTLC, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_UpdateFulfillHTLCDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_UpdateFulfillHTLCDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_UpdateFulfillHTLCDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_UpdateFulfillHTLCDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::ln::msgs::UpdateFulfillHTLC>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_UpdateFulfillHTLCDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_UpdateFulfillHTLCDecodeErrorZ_clone(orig: &CResult_UpdateFulfillHTLCDecodeErrorZ) -> CResult_UpdateFulfillHTLCDecodeErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_UpdateAddHTLCDecodeErrorZPtr {
	pub result: *mut crate::ln::msgs::UpdateAddHTLC,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_UpdateAddHTLCDecodeErrorZ {
	pub contents: CResult_UpdateAddHTLCDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_UpdateAddHTLCDecodeErrorZ_ok(o: crate::ln::msgs::UpdateAddHTLC) -> CResult_UpdateAddHTLCDecodeErrorZ {
	CResult_UpdateAddHTLCDecodeErrorZ {
		contents: CResult_UpdateAddHTLCDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_UpdateAddHTLCDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_UpdateAddHTLCDecodeErrorZ {
	CResult_UpdateAddHTLCDecodeErrorZ {
		contents: CResult_UpdateAddHTLCDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_UpdateAddHTLCDecodeErrorZ_free(_res: CResult_UpdateAddHTLCDecodeErrorZ) { }
impl Drop for CResult_UpdateAddHTLCDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::msgs::UpdateAddHTLC, crate::ln::msgs::DecodeError>> for CResult_UpdateAddHTLCDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::msgs::UpdateAddHTLC, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_UpdateAddHTLCDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_UpdateAddHTLCDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_UpdateAddHTLCDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_UpdateAddHTLCDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::ln::msgs::UpdateAddHTLC>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_UpdateAddHTLCDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_UpdateAddHTLCDecodeErrorZ_clone(orig: &CResult_UpdateAddHTLCDecodeErrorZ) -> CResult_UpdateAddHTLCDecodeErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_PingDecodeErrorZPtr {
	pub result: *mut crate::ln::msgs::Ping,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_PingDecodeErrorZ {
	pub contents: CResult_PingDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_PingDecodeErrorZ_ok(o: crate::ln::msgs::Ping) -> CResult_PingDecodeErrorZ {
	CResult_PingDecodeErrorZ {
		contents: CResult_PingDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_PingDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_PingDecodeErrorZ {
	CResult_PingDecodeErrorZ {
		contents: CResult_PingDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_PingDecodeErrorZ_free(_res: CResult_PingDecodeErrorZ) { }
impl Drop for CResult_PingDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::msgs::Ping, crate::ln::msgs::DecodeError>> for CResult_PingDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::msgs::Ping, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_PingDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_PingDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_PingDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_PingDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::ln::msgs::Ping>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_PingDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_PingDecodeErrorZ_clone(orig: &CResult_PingDecodeErrorZ) -> CResult_PingDecodeErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_PongDecodeErrorZPtr {
	pub result: *mut crate::ln::msgs::Pong,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_PongDecodeErrorZ {
	pub contents: CResult_PongDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_PongDecodeErrorZ_ok(o: crate::ln::msgs::Pong) -> CResult_PongDecodeErrorZ {
	CResult_PongDecodeErrorZ {
		contents: CResult_PongDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_PongDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_PongDecodeErrorZ {
	CResult_PongDecodeErrorZ {
		contents: CResult_PongDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_PongDecodeErrorZ_free(_res: CResult_PongDecodeErrorZ) { }
impl Drop for CResult_PongDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::msgs::Pong, crate::ln::msgs::DecodeError>> for CResult_PongDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::msgs::Pong, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_PongDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_PongDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_PongDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_PongDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::ln::msgs::Pong>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_PongDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_PongDecodeErrorZ_clone(orig: &CResult_PongDecodeErrorZ) -> CResult_PongDecodeErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_UnsignedChannelAnnouncementDecodeErrorZPtr {
	pub result: *mut crate::ln::msgs::UnsignedChannelAnnouncement,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_UnsignedChannelAnnouncementDecodeErrorZ {
	pub contents: CResult_UnsignedChannelAnnouncementDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_UnsignedChannelAnnouncementDecodeErrorZ_ok(o: crate::ln::msgs::UnsignedChannelAnnouncement) -> CResult_UnsignedChannelAnnouncementDecodeErrorZ {
	CResult_UnsignedChannelAnnouncementDecodeErrorZ {
		contents: CResult_UnsignedChannelAnnouncementDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_UnsignedChannelAnnouncementDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_UnsignedChannelAnnouncementDecodeErrorZ {
	CResult_UnsignedChannelAnnouncementDecodeErrorZ {
		contents: CResult_UnsignedChannelAnnouncementDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_UnsignedChannelAnnouncementDecodeErrorZ_free(_res: CResult_UnsignedChannelAnnouncementDecodeErrorZ) { }
impl Drop for CResult_UnsignedChannelAnnouncementDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::msgs::UnsignedChannelAnnouncement, crate::ln::msgs::DecodeError>> for CResult_UnsignedChannelAnnouncementDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::msgs::UnsignedChannelAnnouncement, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_UnsignedChannelAnnouncementDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_UnsignedChannelAnnouncementDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_UnsignedChannelAnnouncementDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_UnsignedChannelAnnouncementDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::ln::msgs::UnsignedChannelAnnouncement>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_UnsignedChannelAnnouncementDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_UnsignedChannelAnnouncementDecodeErrorZ_clone(orig: &CResult_UnsignedChannelAnnouncementDecodeErrorZ) -> CResult_UnsignedChannelAnnouncementDecodeErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_ChannelAnnouncementDecodeErrorZPtr {
	pub result: *mut crate::ln::msgs::ChannelAnnouncement,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_ChannelAnnouncementDecodeErrorZ {
	pub contents: CResult_ChannelAnnouncementDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_ChannelAnnouncementDecodeErrorZ_ok(o: crate::ln::msgs::ChannelAnnouncement) -> CResult_ChannelAnnouncementDecodeErrorZ {
	CResult_ChannelAnnouncementDecodeErrorZ {
		contents: CResult_ChannelAnnouncementDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_ChannelAnnouncementDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_ChannelAnnouncementDecodeErrorZ {
	CResult_ChannelAnnouncementDecodeErrorZ {
		contents: CResult_ChannelAnnouncementDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_ChannelAnnouncementDecodeErrorZ_free(_res: CResult_ChannelAnnouncementDecodeErrorZ) { }
impl Drop for CResult_ChannelAnnouncementDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::msgs::ChannelAnnouncement, crate::ln::msgs::DecodeError>> for CResult_ChannelAnnouncementDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::msgs::ChannelAnnouncement, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_ChannelAnnouncementDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_ChannelAnnouncementDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_ChannelAnnouncementDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_ChannelAnnouncementDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::ln::msgs::ChannelAnnouncement>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_ChannelAnnouncementDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_ChannelAnnouncementDecodeErrorZ_clone(orig: &CResult_ChannelAnnouncementDecodeErrorZ) -> CResult_ChannelAnnouncementDecodeErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_UnsignedChannelUpdateDecodeErrorZPtr {
	pub result: *mut crate::ln::msgs::UnsignedChannelUpdate,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_UnsignedChannelUpdateDecodeErrorZ {
	pub contents: CResult_UnsignedChannelUpdateDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_UnsignedChannelUpdateDecodeErrorZ_ok(o: crate::ln::msgs::UnsignedChannelUpdate) -> CResult_UnsignedChannelUpdateDecodeErrorZ {
	CResult_UnsignedChannelUpdateDecodeErrorZ {
		contents: CResult_UnsignedChannelUpdateDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_UnsignedChannelUpdateDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_UnsignedChannelUpdateDecodeErrorZ {
	CResult_UnsignedChannelUpdateDecodeErrorZ {
		contents: CResult_UnsignedChannelUpdateDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_UnsignedChannelUpdateDecodeErrorZ_free(_res: CResult_UnsignedChannelUpdateDecodeErrorZ) { }
impl Drop for CResult_UnsignedChannelUpdateDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::msgs::UnsignedChannelUpdate, crate::ln::msgs::DecodeError>> for CResult_UnsignedChannelUpdateDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::msgs::UnsignedChannelUpdate, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_UnsignedChannelUpdateDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_UnsignedChannelUpdateDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_UnsignedChannelUpdateDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_UnsignedChannelUpdateDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::ln::msgs::UnsignedChannelUpdate>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_UnsignedChannelUpdateDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_UnsignedChannelUpdateDecodeErrorZ_clone(orig: &CResult_UnsignedChannelUpdateDecodeErrorZ) -> CResult_UnsignedChannelUpdateDecodeErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_ChannelUpdateDecodeErrorZPtr {
	pub result: *mut crate::ln::msgs::ChannelUpdate,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_ChannelUpdateDecodeErrorZ {
	pub contents: CResult_ChannelUpdateDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_ChannelUpdateDecodeErrorZ_ok(o: crate::ln::msgs::ChannelUpdate) -> CResult_ChannelUpdateDecodeErrorZ {
	CResult_ChannelUpdateDecodeErrorZ {
		contents: CResult_ChannelUpdateDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_ChannelUpdateDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_ChannelUpdateDecodeErrorZ {
	CResult_ChannelUpdateDecodeErrorZ {
		contents: CResult_ChannelUpdateDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_ChannelUpdateDecodeErrorZ_free(_res: CResult_ChannelUpdateDecodeErrorZ) { }
impl Drop for CResult_ChannelUpdateDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::msgs::ChannelUpdate, crate::ln::msgs::DecodeError>> for CResult_ChannelUpdateDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::msgs::ChannelUpdate, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_ChannelUpdateDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_ChannelUpdateDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_ChannelUpdateDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_ChannelUpdateDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::ln::msgs::ChannelUpdate>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_ChannelUpdateDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_ChannelUpdateDecodeErrorZ_clone(orig: &CResult_ChannelUpdateDecodeErrorZ) -> CResult_ChannelUpdateDecodeErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_ErrorMessageDecodeErrorZPtr {
	pub result: *mut crate::ln::msgs::ErrorMessage,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_ErrorMessageDecodeErrorZ {
	pub contents: CResult_ErrorMessageDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_ErrorMessageDecodeErrorZ_ok(o: crate::ln::msgs::ErrorMessage) -> CResult_ErrorMessageDecodeErrorZ {
	CResult_ErrorMessageDecodeErrorZ {
		contents: CResult_ErrorMessageDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_ErrorMessageDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_ErrorMessageDecodeErrorZ {
	CResult_ErrorMessageDecodeErrorZ {
		contents: CResult_ErrorMessageDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_ErrorMessageDecodeErrorZ_free(_res: CResult_ErrorMessageDecodeErrorZ) { }
impl Drop for CResult_ErrorMessageDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::msgs::ErrorMessage, crate::ln::msgs::DecodeError>> for CResult_ErrorMessageDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::msgs::ErrorMessage, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_ErrorMessageDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_ErrorMessageDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_ErrorMessageDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_ErrorMessageDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::ln::msgs::ErrorMessage>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_ErrorMessageDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_ErrorMessageDecodeErrorZ_clone(orig: &CResult_ErrorMessageDecodeErrorZ) -> CResult_ErrorMessageDecodeErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_UnsignedNodeAnnouncementDecodeErrorZPtr {
	pub result: *mut crate::ln::msgs::UnsignedNodeAnnouncement,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_UnsignedNodeAnnouncementDecodeErrorZ {
	pub contents: CResult_UnsignedNodeAnnouncementDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_UnsignedNodeAnnouncementDecodeErrorZ_ok(o: crate::ln::msgs::UnsignedNodeAnnouncement) -> CResult_UnsignedNodeAnnouncementDecodeErrorZ {
	CResult_UnsignedNodeAnnouncementDecodeErrorZ {
		contents: CResult_UnsignedNodeAnnouncementDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_UnsignedNodeAnnouncementDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_UnsignedNodeAnnouncementDecodeErrorZ {
	CResult_UnsignedNodeAnnouncementDecodeErrorZ {
		contents: CResult_UnsignedNodeAnnouncementDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_UnsignedNodeAnnouncementDecodeErrorZ_free(_res: CResult_UnsignedNodeAnnouncementDecodeErrorZ) { }
impl Drop for CResult_UnsignedNodeAnnouncementDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::msgs::UnsignedNodeAnnouncement, crate::ln::msgs::DecodeError>> for CResult_UnsignedNodeAnnouncementDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::msgs::UnsignedNodeAnnouncement, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_UnsignedNodeAnnouncementDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_UnsignedNodeAnnouncementDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_UnsignedNodeAnnouncementDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_UnsignedNodeAnnouncementDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::ln::msgs::UnsignedNodeAnnouncement>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_UnsignedNodeAnnouncementDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_UnsignedNodeAnnouncementDecodeErrorZ_clone(orig: &CResult_UnsignedNodeAnnouncementDecodeErrorZ) -> CResult_UnsignedNodeAnnouncementDecodeErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_NodeAnnouncementDecodeErrorZPtr {
	pub result: *mut crate::ln::msgs::NodeAnnouncement,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_NodeAnnouncementDecodeErrorZ {
	pub contents: CResult_NodeAnnouncementDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_NodeAnnouncementDecodeErrorZ_ok(o: crate::ln::msgs::NodeAnnouncement) -> CResult_NodeAnnouncementDecodeErrorZ {
	CResult_NodeAnnouncementDecodeErrorZ {
		contents: CResult_NodeAnnouncementDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_NodeAnnouncementDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_NodeAnnouncementDecodeErrorZ {
	CResult_NodeAnnouncementDecodeErrorZ {
		contents: CResult_NodeAnnouncementDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_NodeAnnouncementDecodeErrorZ_free(_res: CResult_NodeAnnouncementDecodeErrorZ) { }
impl Drop for CResult_NodeAnnouncementDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::msgs::NodeAnnouncement, crate::ln::msgs::DecodeError>> for CResult_NodeAnnouncementDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::msgs::NodeAnnouncement, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_NodeAnnouncementDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_NodeAnnouncementDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_NodeAnnouncementDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_NodeAnnouncementDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::ln::msgs::NodeAnnouncement>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_NodeAnnouncementDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_NodeAnnouncementDecodeErrorZ_clone(orig: &CResult_NodeAnnouncementDecodeErrorZ) -> CResult_NodeAnnouncementDecodeErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_QueryShortChannelIdsDecodeErrorZPtr {
	pub result: *mut crate::ln::msgs::QueryShortChannelIds,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_QueryShortChannelIdsDecodeErrorZ {
	pub contents: CResult_QueryShortChannelIdsDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_QueryShortChannelIdsDecodeErrorZ_ok(o: crate::ln::msgs::QueryShortChannelIds) -> CResult_QueryShortChannelIdsDecodeErrorZ {
	CResult_QueryShortChannelIdsDecodeErrorZ {
		contents: CResult_QueryShortChannelIdsDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_QueryShortChannelIdsDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_QueryShortChannelIdsDecodeErrorZ {
	CResult_QueryShortChannelIdsDecodeErrorZ {
		contents: CResult_QueryShortChannelIdsDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_QueryShortChannelIdsDecodeErrorZ_free(_res: CResult_QueryShortChannelIdsDecodeErrorZ) { }
impl Drop for CResult_QueryShortChannelIdsDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::msgs::QueryShortChannelIds, crate::ln::msgs::DecodeError>> for CResult_QueryShortChannelIdsDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::msgs::QueryShortChannelIds, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_QueryShortChannelIdsDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_QueryShortChannelIdsDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_QueryShortChannelIdsDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_QueryShortChannelIdsDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::ln::msgs::QueryShortChannelIds>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_QueryShortChannelIdsDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_QueryShortChannelIdsDecodeErrorZ_clone(orig: &CResult_QueryShortChannelIdsDecodeErrorZ) -> CResult_QueryShortChannelIdsDecodeErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_ReplyShortChannelIdsEndDecodeErrorZPtr {
	pub result: *mut crate::ln::msgs::ReplyShortChannelIdsEnd,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_ReplyShortChannelIdsEndDecodeErrorZ {
	pub contents: CResult_ReplyShortChannelIdsEndDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_ReplyShortChannelIdsEndDecodeErrorZ_ok(o: crate::ln::msgs::ReplyShortChannelIdsEnd) -> CResult_ReplyShortChannelIdsEndDecodeErrorZ {
	CResult_ReplyShortChannelIdsEndDecodeErrorZ {
		contents: CResult_ReplyShortChannelIdsEndDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_ReplyShortChannelIdsEndDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_ReplyShortChannelIdsEndDecodeErrorZ {
	CResult_ReplyShortChannelIdsEndDecodeErrorZ {
		contents: CResult_ReplyShortChannelIdsEndDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_ReplyShortChannelIdsEndDecodeErrorZ_free(_res: CResult_ReplyShortChannelIdsEndDecodeErrorZ) { }
impl Drop for CResult_ReplyShortChannelIdsEndDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::msgs::ReplyShortChannelIdsEnd, crate::ln::msgs::DecodeError>> for CResult_ReplyShortChannelIdsEndDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::msgs::ReplyShortChannelIdsEnd, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_ReplyShortChannelIdsEndDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_ReplyShortChannelIdsEndDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_ReplyShortChannelIdsEndDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_ReplyShortChannelIdsEndDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::ln::msgs::ReplyShortChannelIdsEnd>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_ReplyShortChannelIdsEndDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_ReplyShortChannelIdsEndDecodeErrorZ_clone(orig: &CResult_ReplyShortChannelIdsEndDecodeErrorZ) -> CResult_ReplyShortChannelIdsEndDecodeErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_QueryChannelRangeDecodeErrorZPtr {
	pub result: *mut crate::ln::msgs::QueryChannelRange,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_QueryChannelRangeDecodeErrorZ {
	pub contents: CResult_QueryChannelRangeDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_QueryChannelRangeDecodeErrorZ_ok(o: crate::ln::msgs::QueryChannelRange) -> CResult_QueryChannelRangeDecodeErrorZ {
	CResult_QueryChannelRangeDecodeErrorZ {
		contents: CResult_QueryChannelRangeDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_QueryChannelRangeDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_QueryChannelRangeDecodeErrorZ {
	CResult_QueryChannelRangeDecodeErrorZ {
		contents: CResult_QueryChannelRangeDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_QueryChannelRangeDecodeErrorZ_free(_res: CResult_QueryChannelRangeDecodeErrorZ) { }
impl Drop for CResult_QueryChannelRangeDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::msgs::QueryChannelRange, crate::ln::msgs::DecodeError>> for CResult_QueryChannelRangeDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::msgs::QueryChannelRange, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_QueryChannelRangeDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_QueryChannelRangeDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_QueryChannelRangeDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_QueryChannelRangeDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::ln::msgs::QueryChannelRange>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_QueryChannelRangeDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_QueryChannelRangeDecodeErrorZ_clone(orig: &CResult_QueryChannelRangeDecodeErrorZ) -> CResult_QueryChannelRangeDecodeErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_ReplyChannelRangeDecodeErrorZPtr {
	pub result: *mut crate::ln::msgs::ReplyChannelRange,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_ReplyChannelRangeDecodeErrorZ {
	pub contents: CResult_ReplyChannelRangeDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_ReplyChannelRangeDecodeErrorZ_ok(o: crate::ln::msgs::ReplyChannelRange) -> CResult_ReplyChannelRangeDecodeErrorZ {
	CResult_ReplyChannelRangeDecodeErrorZ {
		contents: CResult_ReplyChannelRangeDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_ReplyChannelRangeDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_ReplyChannelRangeDecodeErrorZ {
	CResult_ReplyChannelRangeDecodeErrorZ {
		contents: CResult_ReplyChannelRangeDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_ReplyChannelRangeDecodeErrorZ_free(_res: CResult_ReplyChannelRangeDecodeErrorZ) { }
impl Drop for CResult_ReplyChannelRangeDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::msgs::ReplyChannelRange, crate::ln::msgs::DecodeError>> for CResult_ReplyChannelRangeDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::msgs::ReplyChannelRange, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_ReplyChannelRangeDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_ReplyChannelRangeDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_ReplyChannelRangeDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_ReplyChannelRangeDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::ln::msgs::ReplyChannelRange>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_ReplyChannelRangeDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_ReplyChannelRangeDecodeErrorZ_clone(orig: &CResult_ReplyChannelRangeDecodeErrorZ) -> CResult_ReplyChannelRangeDecodeErrorZ { orig.clone() }
#[repr(C)]
pub union CResult_GossipTimestampFilterDecodeErrorZPtr {
	pub result: *mut crate::ln::msgs::GossipTimestampFilter,
	pub err: *mut crate::ln::msgs::DecodeError,
}
#[repr(C)]
pub struct CResult_GossipTimestampFilterDecodeErrorZ {
	pub contents: CResult_GossipTimestampFilterDecodeErrorZPtr,
	pub result_ok: bool,
}
#[no_mangle]
pub extern "C" fn CResult_GossipTimestampFilterDecodeErrorZ_ok(o: crate::ln::msgs::GossipTimestampFilter) -> CResult_GossipTimestampFilterDecodeErrorZ {
	CResult_GossipTimestampFilterDecodeErrorZ {
		contents: CResult_GossipTimestampFilterDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
pub extern "C" fn CResult_GossipTimestampFilterDecodeErrorZ_err(e: crate::ln::msgs::DecodeError) -> CResult_GossipTimestampFilterDecodeErrorZ {
	CResult_GossipTimestampFilterDecodeErrorZ {
		contents: CResult_GossipTimestampFilterDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
#[no_mangle]
pub extern "C" fn CResult_GossipTimestampFilterDecodeErrorZ_free(_res: CResult_GossipTimestampFilterDecodeErrorZ) { }
impl Drop for CResult_GossipTimestampFilterDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::ln::msgs::GossipTimestampFilter, crate::ln::msgs::DecodeError>> for CResult_GossipTimestampFilterDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::ln::msgs::GossipTimestampFilter, crate::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_GossipTimestampFilterDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_GossipTimestampFilterDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_GossipTimestampFilterDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_GossipTimestampFilterDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::ln::msgs::GossipTimestampFilter>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_GossipTimestampFilterDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
pub extern "C" fn CResult_GossipTimestampFilterDecodeErrorZ_clone(orig: &CResult_GossipTimestampFilterDecodeErrorZ) -> CResult_GossipTimestampFilterDecodeErrorZ { orig.clone() }
