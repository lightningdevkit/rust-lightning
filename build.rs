extern crate cc;

fn main() {
	#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "arm")))]
	{
		let mut cfg = cc::Build::new();
		cfg.file("src/util/rust_crypto_nonstd_arch.c");
		cfg.compile("lib_rust_crypto_nonstd_arch.a");
	}
}
