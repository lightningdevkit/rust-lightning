fn main() {
	println!("{} tests were exported", lightning::get_xtests().len());
}

#[cfg(test)]
#[allow(unused)]
mod tests {
	use lightning::ln::functional_tests::*;
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

	#[cfg(feature = "test-broken")]
	#[test]
	fn test_broken() {
		SIGNER_FACTORY.set(Arc::new(BrokenSignerFactory()));
		catch_unwind(|| fake_network_test()).unwrap_err();
	}

	#[cfg(not(feature = "test-broken"))]
	#[test]
	fn test_default_one() {
		test_htlc_on_chain_success();
	}

	#[cfg(not(feature = "test-broken"))]
	#[test]
	fn test_default_all() {
		let mut failed_tests = Vec::new();
		for test in lightning::get_xtests() {
			print!("Running test: {}", test.test_name);
			let mut pass = catch_unwind(|| (test.test_fn)()).is_ok();
			if test.should_panic {
				pass = !pass;
			}
			if !pass {
				failed_tests.push(test.test_name);
			}
		}
		if !failed_tests.is_empty() {
			println!("Failed tests:");
			for test in failed_tests.iter() {
				println!("- {}", test);
			}
		}
		println!("Done with {} failures", failed_tests.len());
		assert!(failed_tests.is_empty());
	}
}
