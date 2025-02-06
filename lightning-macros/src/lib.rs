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
use proc_macro::{Delimiter, Group, TokenStream, TokenTree};
use quote::quote;
use syn::spanned::Spanned;
use syn::{parse, ImplItemFn, Token};

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

fn expect_ident(token: &TokenTree, expected_name: Option<&str>) {
	if let TokenTree::Ident(id) = &token {
		if let Some(exp) = expected_name {
			assert_eq!(id.to_string(), exp, "Expected ident {}, got {:?}", exp, token);
		}
	} else {
		panic!("Expected ident {:?}, got {:?}", expected_name, token);
	}
}

fn expect_punct(token: &TokenTree, expected: char) {
	if let TokenTree::Punct(p) = &token {
		assert_eq!(p.as_char(), expected, "Expected punctuation {}, got {}", expected, p);
	} else {
		panic!("Expected punctuation {}, got {:?}", expected, token);
	}
}

fn token_to_stream(token: TokenTree) -> proc_macro::TokenStream {
	proc_macro::TokenStream::from(token)
}

/// Processes a list of fields in a variant definition (see the docs for [`skip_legacy_fields!`])
fn process_fields(group: Group) -> proc_macro::TokenStream {
	let mut computed_fields = proc_macro::TokenStream::new();
	if group.delimiter() == Delimiter::Brace {
		let mut fields_stream = group.stream().into_iter().peekable();

		let mut new_fields = proc_macro::TokenStream::new();
		loop {
			// The field list should end with .., at which point we break
			let next_tok = fields_stream.peek();
			if let Some(TokenTree::Punct(_)) = next_tok {
				let dot1 = fields_stream.next().unwrap();
				expect_punct(&dot1, '.');
				let dot2 = fields_stream.next().expect("Missing second trailing .");
				expect_punct(&dot2, '.');
				let trailing_dots = [dot1, dot2];
				new_fields.extend(trailing_dots.into_iter().map(token_to_stream));
				assert!(fields_stream.peek().is_none());
				break;
			}

			// Fields should take the form `ref field_name: ty_info` where `ty_info`
			// may be a single ident or may be a group. We skip the field if `ty_info`
			// is a group where the first token is the ident `legacy`.
			let ref_ident = fields_stream.next().unwrap();
			expect_ident(&ref_ident, Some("ref"));
			let field_name_ident = fields_stream.next().unwrap();
			let co = fields_stream.next().unwrap();
			expect_punct(&co, ':');
			let ty_info = fields_stream.next().unwrap();
			let com = fields_stream.next().unwrap();
			expect_punct(&com, ',');

			if let TokenTree::Group(group) = ty_info {
				let first_group_tok = group.stream().into_iter().next().unwrap();
				if let TokenTree::Ident(ident) = first_group_tok {
					if ident.to_string() == "legacy" {
						continue;
					}
				}
			}

			let field = [ref_ident, field_name_ident, com];
			new_fields.extend(field.into_iter().map(token_to_stream));
		}
		let fields_group = Group::new(Delimiter::Brace, new_fields);
		computed_fields.extend(token_to_stream(TokenTree::Group(fields_group)));
	} else {
		computed_fields.extend(token_to_stream(TokenTree::Group(group)));
	}
	computed_fields
}

/// Scans a match statement for legacy fields which should be skipped.
///
/// This is used internally in LDK's TLV serialization logic and is not expected to be used by
/// other crates.
///
/// Wraps a `match self {..}` statement and scans the fields in the match patterns (in the form
/// `ref $field_name: $field_ty`) for types marked `legacy`, skipping those fields.
///
/// Specifically, it expects input like the following, simply dropping `field3` and the
/// `: $field_ty` after each field name.
/// ```ignore
/// match self {
///		Enum::Variant {
///			ref field1: option,
///			ref field2: (option, explicit_type: u64),
///			ref field3: (legacy, u64, {}, {}), // will be skipped
///			..
///		} => expression
///	}
/// ```
#[proc_macro]
pub fn skip_legacy_fields(expr: TokenStream) -> TokenStream {
	let mut stream = expr.into_iter();
	let mut res = TokenStream::new();

	// First expect `match self` followed by a `{}` group...
	let match_ident = stream.next().unwrap();
	expect_ident(&match_ident, Some("match"));
	res.extend(proc_macro::TokenStream::from(match_ident));

	let self_ident = stream.next().unwrap();
	expect_ident(&self_ident, Some("self"));
	res.extend(proc_macro::TokenStream::from(self_ident));

	let arms = stream.next().unwrap();
	if let TokenTree::Group(group) = arms {
		let mut new_arms = TokenStream::new();

		let mut arm_stream = group.stream().into_iter().peekable();
		while arm_stream.peek().is_some() {
			// Each arm should contain Enum::Variant { fields } => init
			// We explicitly check the :s, =, and >, as well as an optional trailing ,
			let enum_ident = arm_stream.next().unwrap();
			let co1 = arm_stream.next().unwrap();
			expect_punct(&co1, ':');
			let co2 = arm_stream.next().unwrap();
			expect_punct(&co2, ':');
			let variant_ident = arm_stream.next().unwrap();
			let fields = arm_stream.next().unwrap();
			let eq = arm_stream.next().unwrap();
			expect_punct(&eq, '=');
			let gt = arm_stream.next().unwrap();
			expect_punct(&gt, '>');
			let init = arm_stream.next().unwrap();

			let next_tok = arm_stream.peek();
			if let Some(TokenTree::Punct(_)) = next_tok {
				expect_punct(next_tok.unwrap(), ',');
				arm_stream.next();
			}

			let computed_fields = if let TokenTree::Group(group) = fields {
				process_fields(group)
			} else {
				panic!("Expected a group for the fields in a match arm");
			};

			let arm_pfx = [enum_ident, co1, co2, variant_ident];
			new_arms.extend(arm_pfx.into_iter().map(token_to_stream));
			new_arms.extend(computed_fields);
			let arm_sfx = [eq, gt, init];
			new_arms.extend(arm_sfx.into_iter().map(token_to_stream));
		}

		let new_arm_group = Group::new(Delimiter::Brace, new_arms);
		res.extend(token_to_stream(TokenTree::Group(new_arm_group)));
	} else {
		panic!("Expected `match self {{..}}` and nothing else");
	}

	assert!(stream.next().is_none(), "Expected `match self {{..}}` and nothing else");

	res
}

/// Scans an enum definition for fields initialized with `legacy` types and drops them.
///
/// This is used internally in LDK's TLV serialization logic and is not expected to be used by
/// other crates.
///
/// Is expected to wrap a struct definition like
/// ```ignore
/// drop_legacy_field_definition!(Self {
/// 	field1: $crate::_ignore_arg!(field1, option),
/// 	field2: $crate::_ignore_arg!(field2, (legacy, u64, {})),
/// })
/// ```
/// and will drop fields defined like `field2` with a type starting with `legacy`.
#[proc_macro]
pub fn drop_legacy_field_definition(expr: TokenStream) -> TokenStream {
	let mut st = if let Ok(parsed) = parse::<syn::Expr>(expr) {
		if let syn::Expr::Struct(st) = parsed {
			st
		} else {
			return (quote! {
				compile_error!("drop_legacy_field_definition!() can only be used on struct expressions")
			})
			.into();
		}
	} else {
		return (quote! {
			compile_error!("drop_legacy_field_definition!() can only be used on expressions")
		})
		.into();
	};
	assert!(st.attrs.is_empty());
	assert!(st.qself.is_none());
	assert!(st.dot2_token.is_none());
	assert!(st.rest.is_none());
	let mut new_fields = syn::punctuated::Punctuated::new();
	core::mem::swap(&mut new_fields, &mut st.fields);
	for field in new_fields {
		if let syn::Expr::Macro(syn::ExprMacro { mac, .. }) = &field.expr {
			let macro_name = mac.path.segments.last().unwrap().ident.to_string();
			let is_init = macro_name == "_ignore_arg";
			// Skip `field_name` and `:`, giving us just the type's group
			let ty_tokens = mac.tokens.clone().into_iter().skip(2).next();
			if let Some(proc_macro2::TokenTree::Group(group)) = ty_tokens {
				let first_token = group.stream().into_iter().next();
				if let Some(proc_macro2::TokenTree::Ident(ident)) = first_token {
					if is_init && ident == "legacy" {
						continue;
					}
				}
			}
		}
		st.fields.push(field);
	}
	let out = syn::Expr::Struct(st);
	quote! { #out }.into()
}
