use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{parse_macro_input, Item};

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
/// Which will include the module if we are testing or the `_test_utils` feature
/// is on.
#[proc_macro_attribute]
pub fn xtest(attrs: TokenStream, item: TokenStream) -> TokenStream {
	let attrs = parse_macro_input!(attrs as TokenStream2);
	let input = parse_macro_input!(item as Item);

	let expanded = match input {
		Item::Mod(item_mod) => {
			let cfg = if attrs.is_empty() {
				quote! { #[cfg_attr(test, test)] }
			} else {
				quote! { #[cfg_attr(test, test)] #[cfg(any(test, #attrs))] }
			};
			quote! {
				#cfg
				#item_mod
			}
		},
		Item::Fn(item_fn) => {
			let cfg_attr = if attrs.is_empty() {
				// export the test if not actually testing
				quote! { #[cfg_attr(test, test)] }
			} else {
				// export the test if the feature is enabled
				quote! { #[cfg_attr(test, test)] #[cfg(any(test, #attrs))] }
			};

			// Check that the function doesn't take args and returns nothing
			if !item_fn.sig.inputs.is_empty() || !matches!(item_fn.sig.output, syn::ReturnType::Default) {
				return syn::Error::new_spanned(
					item_fn.sig,
					"xtest functions must not take arguments and must return nothing",
				)
				.to_compile_error()
				.into();
			}

			quote! {
				#cfg_attr
				#item_fn
			}
		},
		_ => {
			return syn::Error::new_spanned(
				input,
				"xtest can only be applied to functions or modules",
			)
			.to_compile_error()
			.into();
		},
	};

	TokenStream::from(expanded)
}
