use crate::adaptors::*;
use crate::handle::{Ref, Out, HandleShared};
use crate::error::FFIResult;

pub type FeeEstimatorHandle<'a> = HandleShared<'a, FFIFeeEstimator>;

ffi! {
    fn create_fee_estimator(fn_ref: Ref<fee_estimator_fn::GetEstSatPer1000WeightPtr>, out: Out<FeeEstimatorHandle>) -> FFIResult {
        let func = unsafe_block!("" => *fn_ref.as_ref());
        let fee_estimator = FFIFeeEstimator {get_est_sat_per_1000_weight_ptr: func};
        unsafe_block!("We know fee_estimator handle is not null by wrapper macro. And we know `Out` is writable" =>
            out.init(FeeEstimatorHandle::alloc(fee_estimator))
        );
        FFIResult::ok()
    }

    fn release_fee_estimator(handle: FeeEstimatorHandle) -> FFIResult {
        unsafe_block!("The upstream caller guarantees the handle will not be accessed after being freed" => FeeEstimatorHandle::dealloc(handle, |mut handle| {
            FFIResult::ok()
        }))
    }
}