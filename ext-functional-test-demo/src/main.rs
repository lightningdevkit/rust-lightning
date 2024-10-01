fn main() {
	println!("{} tests were exported", lightning::get_xtests().len());
}

#[cfg(test)]
mod tests {
	use lightning::util::dyn_signer::{DynKeysInterfaceTrait, DynSigner};
	use lightning::util::test_utils::{TestSignerFactory, SIGNER_FACTORY};
	use std::panic::catch_unwind;
	use std::sync::Arc;
	use std::time::Duration;

	struct BrokenSignerFactory();

	impl TestSignerFactory for BrokenSignerFactory {
		fn make_signer(
			&self, _seed: &[u8; 32], _now: Duration,
		) -> Box<dyn DynKeysInterfaceTrait<EcdsaSigner = DynSigner>> {
			panic!()
		}
	}

	#[test]
	fn test_functional() {
		lightning::ln::functional_tests::test_insane_channel_opens();
		lightning::ln::functional_tests::fake_network_test();

		SIGNER_FACTORY.set(Arc::new(BrokenSignerFactory()));
		catch_unwind(|| lightning::ln::functional_tests::fake_network_test()).unwrap_err();
	}
}
