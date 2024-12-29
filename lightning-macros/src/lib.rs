// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

#![crate_name = "lightning_macros"]

//! Proc macros used by LDK

#![cfg_attr(not(test), no_std)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

extern crate alloc;

use alloc::string::ToString;
use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::spanned::Spanned;
use syn::{parse, ImplItemFn, Token};
use syn::{parse_macro_input, Item};

fn add_async_method(mut parsed: ImplItemFn) -> TokenStream {
	let output = quote! {
		#[cfg(not(feature = "async-interface"))]
		#parsed
	};

	parsed.sig.asyncness = Some(Token![async](parsed.span()));

	let output = quote! {
		#output

		#[cfg(feature = "async-interface")]
		#parsed
	};

	output.into()
}

/// Makes a method `async`, if the `async-interface` feature is enabled.
#[proc_macro_attribute]
pub fn maybe_async(_attr: TokenStream, item: TokenStream) -> TokenStream {
	if let Ok(parsed) = parse(item) {
		add_async_method(parsed)
	} else {
		(quote! {
			compile_error!("#[maybe_async] can only be used on methods")
		})
		.into()
	}
}

/// Awaits, if the `async-interface` feature is enabled.
#[proc_macro]
pub fn maybe_await(expr: TokenStream) -> TokenStream {
	let expr: proc_macro2::TokenStream = expr.into();
	let quoted = quote! {
		{
			#[cfg(not(feature = "async-interface"))]
			{
				#expr
			}

			#[cfg(feature = "async-interface")]
			{
				#expr.await
			}
		}
	};

	quoted.into()
}

/// An exposed test.  This is a test that will run locally and also be
/// made available to other crates that want to run it in their own context.
///
/// For example:
/// ```rust
/// use lightning_macros::xtest;
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
/// use lightning_macros::xtest;
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
			let (cfg_attr, submit_attr) = if attrs.is_empty() {
				(quote! { #[cfg_attr(test, test)] }, quote! { #[cfg(not(test))] })
			} else {
				(
					quote! { #[cfg_attr(test, test)] #[cfg(any(test, #attrs))] },
					quote! { #[cfg(all(not(test), #attrs))] },
				)
			};

			// Check that the function doesn't take args and returns nothing
			if !item_fn.sig.inputs.is_empty()
				|| !matches!(item_fn.sig.output, syn::ReturnType::Default)
			{
				return syn::Error::new_spanned(
					item_fn.sig,
					"xtest functions must not take arguments and must return nothing",
				)
				.to_compile_error()
				.into();
			}

			// Check for #[should_panic] attribute
			let should_panic =
				item_fn.attrs.iter().any(|attr| attr.path().is_ident("should_panic"));

			let fn_name = &item_fn.sig.ident;
			let fn_name_str = fn_name.to_string();
			quote! {
				#cfg_attr
				#item_fn

				// We submit the test to the inventory only if we're not actually testing
				#submit_attr
				inventory::submit! {
					crate::XTestItem {
						test_fn: #fn_name,
						test_name: #fn_name_str,
						should_panic: #should_panic,
					}
				}
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

/// Collects all externalized tests marked with `#[xtest]`
/// into a vector of `XTestItem`s.  This vector can be
/// retrieved by calling `get_xtests()`.
#[proc_macro]
pub fn xtest_inventory(_input: TokenStream) -> TokenStream {
	let expanded = quote! {
		/// An externalized test item, including the test function, name, and whether it is marked with `#[should_panic]`.
		pub struct XTestItem {
			pub test_fn: fn(),
			pub test_name: &'static str,
			pub should_panic: bool,
		}

		inventory::collect!(XTestItem);

		pub fn get_xtests() -> Vec<&'static XTestItem> {
			inventory::iter::<XTestItem>
				.into_iter()
				.collect()
		}
	};

	TokenStream::from(expanded)
}
