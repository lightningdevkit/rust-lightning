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
#![cfg_attr(docsrs, feature(doc_cfg))]

extern crate alloc;

use alloc::string::ToString;
use alloc::vec::Vec;

use proc_macro::{Delimiter, Group, TokenStream, TokenTree};
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
/// 	field1: $crate::_init_tlv_based_struct_field!(field1, option),
/// 	field2: $crate::_init_tlv_based_struct_field!(field2, (legacy, u64, {})),
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
			let is_init = macro_name == "_init_tlv_based_struct_field";
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

/// An exposed test.  This is a test that will run locally and also be
/// made available to other crates that want to run it in their own context.
///
/// For example:
/// ```rust
/// use lightning_macros::xtest;
///
/// fn f1() {}
///
/// #[xtest(feature = "_externalize_tests")]
/// pub fn test_f1() {
///     f1();
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

struct AddLogsCtx<'a> {
	methods_with_param: &'a [syn::Ident],
	substructs_logged: &'a [syn::Ident],
}

fn add_logs_to_stmt_list(s: &mut Vec<syn::Stmt>, ctx: &AddLogsCtx) {
	for stmt in s.iter_mut() {
		match stmt {
			syn::Stmt::Expr(ref mut expr, _) => add_logs_to_self_exprs(expr, ctx),
			syn::Stmt::Local(syn::Local { init: Some(l), .. }) => {
				add_logs_to_self_exprs(&mut *l.expr, ctx);
				if let Some((_, e)) = &mut l.diverge {
					add_logs_to_self_exprs(&mut *e, ctx);
				}
			},
			syn::Stmt::Local(syn::Local { init: None, .. }) => {},
			syn::Stmt::Macro(_) => {},
			syn::Stmt::Item(syn::Item::Fn(f)) => {
				add_logs_to_stmt_list(&mut f.block.stmts, ctx);
			},
			syn::Stmt::Item(_) => {},
		}
	}
}

fn add_logs_to_self_exprs(e: &mut syn::Expr, ctx: &AddLogsCtx) {
	match e {
		syn::Expr::Array(e) => {
			for elem in e.elems.iter_mut() {
				add_logs_to_self_exprs(elem, ctx);
			}
		},
		syn::Expr::Assign(e) => {
			add_logs_to_self_exprs(&mut *e.left, ctx);
			add_logs_to_self_exprs(&mut *e.right, ctx);
		},
		syn::Expr::Async(e) => {
			add_logs_to_stmt_list(&mut e.block.stmts, ctx);
		},
		syn::Expr::Await(e) => {
			add_logs_to_self_exprs(&mut *e.base, ctx);
		},
		syn::Expr::Binary(e) => {
			add_logs_to_self_exprs(&mut *e.left, ctx);
			add_logs_to_self_exprs(&mut *e.right, ctx);
		},
		syn::Expr::Block(e) => {
			add_logs_to_stmt_list(&mut e.block.stmts, ctx);
		},
		syn::Expr::Break(e) => {
			if let Some(e) = e.expr.as_mut() {
				add_logs_to_self_exprs(&mut *e, ctx);
			}
		},
		syn::Expr::Call(e) => {
			for a in e.args.iter_mut() {
				add_logs_to_self_exprs(a, ctx);
			}
		},
		syn::Expr::Cast(e) => {
			add_logs_to_self_exprs(&mut *e.expr, ctx);
		},
		syn::Expr::Closure(e) => {
			add_logs_to_self_exprs(&mut *e.body, ctx);
		},
		syn::Expr::Const(_) => {},
		syn::Expr::Continue(e) => {
			
		},
		syn::Expr::Field(e) => {
			
		},
		syn::Expr::ForLoop(e) => {
			add_logs_to_self_exprs(&mut *e.expr, ctx);
			add_logs_to_stmt_list(&mut e.body.stmts, ctx);
		},
		syn::Expr::Group(e) => {
			
		},
		syn::Expr::If(e) => {
			add_logs_to_self_exprs(&mut *e.cond, ctx);
			add_logs_to_stmt_list(&mut e.then_branch.stmts, ctx);
			if let Some((_, branch)) = e.else_branch.as_mut() {
				add_logs_to_self_exprs(&mut *branch, ctx);
			}
		},
		syn::Expr::Index(e) => {
			
		},
		syn::Expr::Infer(e) => {
			
		},
		syn::Expr::Let(e) => {
			add_logs_to_self_exprs(&mut *e.expr, ctx);
		},
		syn::Expr::Lit(e) => {
			
		},
		syn::Expr::Loop(e) => {
			add_logs_to_stmt_list(&mut e.body.stmts, ctx);
		},
		syn::Expr::Macro(e) => {
			
		},
		syn::Expr::Match(e) => {
			add_logs_to_self_exprs(&mut *e.expr, ctx);
			for arm in e.arms.iter_mut() {
				if let Some((_, e)) = arm.guard.as_mut() {
					add_logs_to_self_exprs(&mut *e, ctx);
				}
				add_logs_to_self_exprs(&mut *arm.body, ctx);
			}
		},
		syn::Expr::MethodCall(e) => {
			match &*e.receiver {
				syn::Expr::Path(path) => {
					assert_eq!(path.path.segments.len(), 1, "Multiple segments should instead be parsed as a Field, below");
					let is_self_call =
						path.qself.is_none()
						&& path.path.segments.len() == 1
						&& path.path.segments[0].ident.to_string() == "self";
					if is_self_call && ctx.methods_with_param.iter().any(|m| *m == e.method) {
						e.args.push(parse(quote!(logger).into()).unwrap());
					}
				},
				syn::Expr::Field(field) => {
					if let syn::Expr::Path(p) = &*field.base {
						let is_self_call =
							p.qself.is_none()
							&& p.path.segments.len() == 1
							&& p.path.segments[0].ident.to_string() == "self";
						if let syn::Member::Named(field) = &field.member {
							if is_self_call && ctx.substructs_logged.iter().any(|m| m == field) {
								e.args.push(parse(quote!(logger).into()).unwrap());
							}
						} else {
							add_logs_to_self_exprs(&mut *e.receiver, ctx);
						}
					} else {
						add_logs_to_self_exprs(&mut *e.receiver, ctx);
					}
				},
				_ => add_logs_to_self_exprs(&mut *e.receiver, ctx),
			}
			for a in e.args.iter_mut() {
				add_logs_to_self_exprs(a, ctx);
			}
		},
		syn::Expr::Paren(e) => {
			
		},
		syn::Expr::Path(e) => {
			
		},
		syn::Expr::Range(e) => {
			
		},
		syn::Expr::RawAddr(e) => {
			
		},
		syn::Expr::Reference(e) => {
			
		},
		syn::Expr::Repeat(e) => {
			
		},
		syn::Expr::Return(e) => {
			if let Some(e) = e.expr.as_mut() {
				add_logs_to_self_exprs(&mut *e, ctx);
			}
		},
		syn::Expr::Struct(e) => {
			
		},
		syn::Expr::Try(e) => {
			add_logs_to_self_exprs(&mut *e.expr, ctx);
		},
		syn::Expr::TryBlock(e) => {
			add_logs_to_stmt_list(&mut e.block.stmts, ctx);
		},
		syn::Expr::Tuple(e) => {
			
		},
		syn::Expr::Unary(e) => {
			
		},
		syn::Expr::Unsafe(e) => {
			
		},
		syn::Expr::Verbatim(e) => {
			
		},
		syn::Expr::While(e) => {
			
		},
		syn::Expr::Yield(e) => {
			
		},
		_ => {},
	}
}

/// This attribute, on an `impl` block, will add logging parameters transparently to every method
/// in the `impl` block. It will also pass through the current logger to any calls to modified
/// methods.
///
/// Provided attributes should be in the form `logger: LoggerType $(, substruct: subfield)*`
/// where `LoggerType` is the type of the logger object which is required, and `subfield` is any
/// number of fields (accessible through `self`) which have had their `impl` block(s) similarly
/// modified.
///
/// For example, this translates:
/// ```rust
/// struct B;
/// struct A { field_b: B }
///
/// #[proc_macro_attribute(logger: LogType, substruct: field_b)]
/// impl A {
///		fn f_a(&self) {
///			logger.log();
///		}
/// 	fn f(&self) {
///			self.f_a();
///			self.field_b.f();
/// 	}
/// }
///
/// #[proc_macro_attribute(logger: LogType)]
/// impl B {
///		fn f(&self) {
///			logger.log();
///		}
///	}
/// ```
///
/// to this:
///
/// ```rust
/// struct B;
/// struct A { field_b: B }
///
/// impl A {
///		fn f_a(&self, logger: &LogType) {
///			logger.log();
///		}
/// 	fn f(&self, logger: &LogType) {
///			self.f_a(logger);
///			self.field_b.f(logger);
/// 	}
/// }
///
/// impl B {
///		fn f(&self, logger: &LogType) {
///			logger.log();
///		}
///	}
/// ```
#[proc_macro_attribute]
pub fn add_logging(attrs: TokenStream, expr: TokenStream) -> TokenStream {
	let mut im = if let Ok(parsed) = parse::<syn::Item>(expr) {
		if let syn::Item::Impl(im) = parsed {
			im
		} else {
			return (quote! {
				compile_error!("add_logging can only be used on impl items")
			})
			.into();
		}
	} else {
		return (quote! {
			compile_error!("add_logging can only be used on impl items")
		})
		.into();
	};

	let parsed_attrs = parse::<syn::AngleBracketedGenericArguments>(attrs);
	let (logger_type, substructs_logged) = if let Ok(attrs) = &parsed_attrs {
		if attrs.args.len() < 1 {
			return (quote! {
				compile_error!("add_logging must have at least the `logger: LoggerType` attribute")
			})
			.into();
		}
		let logger_ty = if let syn::GenericArgument::Type(ty) = &attrs.args[0] {
			ty
		} else {
			return (quote! {
				compile_error!("add_logging's attributes must start with `logger:`")
			})
			.into();
		};
		let mut substructs_logged = Vec::new();
		for arg in attrs.args.iter().skip(1) {
			if let syn::GenericArgument::AssocType(syn::AssocType { ident, ty: syn::Type::Path(p), .. }) = arg {
				if ident.to_string() != "substruct" {
					return (quote! {
						compile_error!("add_logging's attributes must be in the form `logger: Logger $(, substruct: field)*")
					})
					.into();
				}
				if p.path.leading_colon.is_some() && p.path.segments.len() != 1 {
					return (quote! {
						compile_error!("add_logging's attributes must be in the form `logger: Logger $(, substruct: field)*")
					})
					.into();
				}
				substructs_logged.push(p.path.segments[0].ident.clone());
			} else {
				return (quote! {
					compile_error!("add_logging's attributes must be in the form `logger: Logger $(, substruct: field)*")
				})
				.into();
			}
		}
		(logger_ty, substructs_logged)
	} else {
		return (quote! {
			compile_error!("add_logging's attributes must be in the form `logger: Logger $(, substruct: field)*")
		})
		.into();
	};

	let mut methods_added = Vec::new();
	for item in im.items.iter_mut() {
		if let syn::ImplItem::Fn(f) = item {
			//if let syn::Visibility::Public(_) = f.vis {
			//} else {
				if f.sig.generics.lt_token.is_none() {
					f.sig.generics.lt_token = Some(Default::default());
					f.sig.generics.gt_token = Some(Default::default());
				}
				f.sig.generics.params.push(parse(quote!(L: Deref).into()).unwrap());
				if f.sig.generics.where_clause.is_none() {
					f.sig.generics.where_clause = Some(parse(quote!(where).into()).unwrap());
				}
				let log_bound = parse(quote!(L::Target: Logger).into()).unwrap();
				f.sig.generics.where_clause.as_mut().unwrap().predicates.push(log_bound);
				f.sig.inputs.push(parse(quote!(logger: &#logger_type).into()).unwrap());
				methods_added.push(f.sig.ident.clone());
			//}
		}
	}

	let ctx = AddLogsCtx {
		methods_with_param: &methods_added[..],
		substructs_logged: &substructs_logged,
	};

	for item in im.items.iter_mut() {
		if let syn::ImplItem::Fn(f) = item {
			add_logs_to_stmt_list(&mut f.block.stmts, &ctx);
		}
	}

	quote! { #im }.into()
}
