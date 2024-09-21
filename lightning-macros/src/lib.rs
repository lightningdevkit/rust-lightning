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

use proc_macro::TokenStream;
use quote::quote;
use syn::spanned::Spanned;
use syn::{parse, ImplItemFn, ItemImpl, ItemTrait, Token};

fn add_async_trait(mut parsed: ItemTrait) -> TokenStream {
	let output = quote! {
		#[cfg(not(feature = "async-interface"))]
		#parsed
	};

	for mut item in &mut parsed.items {
		if let syn::TraitItem::Fn(f) = &mut item {
			f.sig.asyncness = Some(Token![async](f.span()));
		}
	}

	let output = quote! {
		#output

		#[cfg(feature = "async-interface")]
		#[async_trait(?Send)]
		#parsed
	};

	output.into()
}

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

fn add_async_impl_trait(mut parsed: ItemImpl) -> TokenStream {
	let output = quote! {
		#[cfg(not(feature = "async-interface"))]
		#parsed
	};

	for mut item in &mut parsed.items {
		if let syn::ImplItem::Fn(f) = &mut item {
			f.sig.asyncness = Some(Token![async](f.span()));
		}
	}

	let output = quote! {
		#output

		#[cfg(feature = "async-interface")]
		#[async_trait(?Send)]
		#parsed
	};

	output.into()
}

/// Makes a method or every method of a trait `async`, if the `async-interface` feature is enabled.
///
/// Requires the `async-trait` crate as a dependency whenever this attribute is used on a trait
/// definition or trait implementation.
#[proc_macro_attribute]
pub fn maybe_async(_attr: TokenStream, item: TokenStream) -> TokenStream {
	if let Ok(parsed) = parse(item.clone()) {
		add_async_trait(parsed)
	} else if let Ok(parsed) = parse(item.clone()) {
		add_async_method(parsed)
	} else if let Ok(parsed) = parse(item) {
		add_async_impl_trait(parsed)
	} else {
		(quote! {
			compile_error!("#[maybe_async] can only be used on methods, trait or trait impl blocks")
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
