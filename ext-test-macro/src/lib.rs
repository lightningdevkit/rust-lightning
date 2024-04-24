use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{parse2, ItemFn, ItemMod};

/// An exposed test.  This is a test that will run locally and also be
/// made available to other crates that want to run it in their own context.
///
/// For example:
/// ```rust
/// use ext_test_macro::xtest;
///
/// fn f1() {}
///
/// #[xtest(feature = "_test_utils")]
/// pub fn test_f1() {
///     f1();
/// }
/// ```
///
/// May also be applied to modules, like so:
///
/// ```rust
/// use ext_test_macro::xtest;
///
/// #[xtest(feature = "_test_utils")]
/// pub mod tests {
/// 	use super::*;
///
///     fn f1() {}
///
/// 	#[xtest]
/// 	pub fn test_f1() {
/// 	    f1();
/// 	}
/// }
/// ```
///
/// Which will include the module if we are testing or the `externalize-the-tests` feature
/// is on.
#[proc_macro_attribute]
pub fn xtest(attrs: TokenStream, item: TokenStream) -> TokenStream {
	let input = syn::parse_macro_input!(item as TokenStream2);
	let attrs = syn::parse_macro_input!(attrs as TokenStream2);

	let expanded = if is_module_definition(input.clone()) {
		let cfg = if attrs.is_empty() {
			quote! { #[cfg(test)] }
		} else {
			quote! { #[cfg(any(test, #attrs))] }
		};
		quote! {
			#cfg
			#input
		}
	} else if is_function_definition(input.clone()) {
		quote! {
			#[cfg_attr(test, ::core::prelude::v1::test)]
			#input
		}
	} else {
		panic!("xtest can only be applied to functions or modules");
	};
	expanded.into()
}

fn is_module_definition(input: TokenStream2) -> bool {
	parse2::<ItemMod>(input).is_ok()
}

fn is_function_definition(input: TokenStream2) -> bool {
	parse2::<ItemFn>(input).is_ok()
}
