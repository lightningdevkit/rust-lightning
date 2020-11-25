//! Printing logic for basic blocks of Rust-mapped code - parts of functions and declarations but
//! not the full mapping logic.

use std::fs::File;
use std::io::Write;
use proc_macro2::{TokenTree, Span};

use crate::types::*;

/// Writes out a C++ wrapper class for the given type, which contains various utilities to access
/// the underlying C-mapped type safely avoiding some common memory management issues by handling
/// resource-freeing and prevending accidental raw copies.
pub fn write_cpp_wrapper(cpp_header_file: &mut File, ty: &str, has_destructor: bool) {
	writeln!(cpp_header_file, "class {} {{", ty).unwrap();
	writeln!(cpp_header_file, "private:").unwrap();
	writeln!(cpp_header_file, "\tLDK{} self;", ty).unwrap();
	writeln!(cpp_header_file, "public:").unwrap();
	writeln!(cpp_header_file, "\t{}(const {}&) = delete;", ty, ty).unwrap();
	if has_destructor {
		writeln!(cpp_header_file, "\t~{}() {{ {}_free(self); }}", ty, ty).unwrap();
	}
	writeln!(cpp_header_file, "\t{}({}&& o) : self(o.self) {{ memset(&o, 0, sizeof({})); }}", ty, ty, ty).unwrap();
	writeln!(cpp_header_file, "\t{}(LDK{}&& m_self) : self(m_self) {{ memset(&m_self, 0, sizeof(LDK{})); }}", ty, ty, ty).unwrap();
	writeln!(cpp_header_file, "\toperator LDK{}() {{ LDK{} res = self; memset(&self, 0, sizeof(LDK{})); return res; }}", ty, ty, ty).unwrap();
	writeln!(cpp_header_file, "\tLDK{}* operator &() {{ return &self; }}", ty).unwrap();
	writeln!(cpp_header_file, "\tLDK{}* operator ->() {{ return &self; }}", ty).unwrap();
	writeln!(cpp_header_file, "\tconst LDK{}* operator &() const {{ return &self; }}", ty).unwrap();
	writeln!(cpp_header_file, "\tconst LDK{}* operator ->() const {{ return &self; }}", ty).unwrap();
	writeln!(cpp_header_file, "}};").unwrap();
}

/// Prints the docs from a given attribute list unless its tagged no export
pub fn writeln_docs<W: std::io::Write>(w: &mut W, attrs: &[syn::Attribute], prefix: &str) {
	for attr in attrs.iter() {
		let tokens_clone = attr.tokens.clone();
		let mut token_iter = tokens_clone.into_iter();
		if let Some(token) = token_iter.next() {
			match token {
				TokenTree::Punct(c) if c.as_char() == '=' => {
					// syn gets '=' from '///' or '//!' as it is syntax for #[doc = ""]
				},
				TokenTree::Group(_) => continue, // eg #[derive()]
				_ => unimplemented!(),
			}
		} else { continue; }
		match attr.style {
			syn::AttrStyle::Inner(_) => {
				match token_iter.next().unwrap() {
					TokenTree::Literal(lit) => {
						// Drop the first and last chars from lit as they are always "
						let doc = format!("{}", lit);
						writeln!(w, "{}//!{}", prefix, &doc[1..doc.len() - 1]).unwrap();
					},
					_ => unimplemented!(),
				}
			},
			syn::AttrStyle::Outer => {
				match token_iter.next().unwrap() {
					TokenTree::Literal(lit) => {
						// Drop the first and last chars from lit as they are always "
						let doc = format!("{}", lit);
						writeln!(w, "{}///{}", prefix, &doc[1..doc.len() - 1]).unwrap();
					},
					_ => unimplemented!(),
				}
			},
		}
	}
}

/// Print the parameters in a method declaration, starting after the open parenthesis, through and
/// including the closing parenthesis and return value, but not including the open bracket or any
/// trailing semicolons.
///
/// Usable both for a function definition and declaration.
///
/// this_param is used when returning Self or accepting a self parameter, and should be the
/// concrete, mapped type.
pub fn write_method_params<W: std::io::Write>(w: &mut W, sig: &syn::Signature, this_param: &str, types: &mut TypeResolver, generics: Option<&GenericTypes>, self_ptr: bool, fn_decl: bool) {
	if sig.constness.is_some() || sig.asyncness.is_some() || sig.unsafety.is_some() ||
			sig.abi.is_some() || sig.variadic.is_some() {
		unimplemented!();
	}
	if sig.generics.lt_token.is_some() {
		for generic in sig.generics.params.iter() {
			match generic {
				syn::GenericParam::Type(_)|syn::GenericParam::Lifetime(_) => {
					// We ignore these, if they're not on skipped args, we'll blow up
					// later, and lifetimes we just hope the C client enforces.
				},
				_ => unimplemented!(),
			}
		}
	}

	let mut first_arg = true;
	let mut num_unused = 0;
	for inp in sig.inputs.iter() {
		match inp {
			syn::FnArg::Receiver(recv) => {
				if !recv.attrs.is_empty() || recv.reference.is_none() { unimplemented!(); }
				write!(w, "this_arg: {}{}",
					match (self_ptr, recv.mutability.is_some()) {
						(true, true) => "*mut ",
						(true, false) => "*const ",
						(false, true) => "&mut ",
						(false, false) => "&",
					}, this_param).unwrap();
				assert!(first_arg);
				first_arg = false;
			},
			syn::FnArg::Typed(arg) => {
				if types.skip_arg(&*arg.ty, generics) { continue; }
				if !arg.attrs.is_empty() { unimplemented!(); }
				// First get the c type so that we can check if it ends up being a reference:
				let mut c_type = Vec::new();
				types.write_c_type(&mut c_type, &*arg.ty, generics, false);
				match &*arg.pat {
					syn::Pat::Ident(ident) => {
						if !ident.attrs.is_empty() || ident.subpat.is_some() {
							unimplemented!();
						}
						write!(w, "{}{}{}: ", if first_arg { "" } else { ", " }, if !fn_decl || c_type[0] == '&' as u8 || c_type[0] == '*' as u8 { "" } else { "mut " }, ident.ident).unwrap();
						first_arg = false;
					},
					syn::Pat::Wild(wild) => {
						if !wild.attrs.is_empty() { unimplemented!(); }
						write!(w, "{}unused_{}: ", if first_arg { "" } else { ", " }, num_unused).unwrap();
						num_unused += 1;
					},
					_ => unimplemented!(),
				}
				w.write(&c_type).unwrap();
			}
		}
	}
	write!(w, ")").unwrap();
	match &sig.output {
		syn::ReturnType::Type(_, rtype) => {
			write!(w, " -> ").unwrap();
			if let Some(mut remaining_path) = first_seg_self(&*rtype) {
				if remaining_path.next().is_none() {
					write!(w, "{}", this_param).unwrap();
					return;
				}
			}
			if let syn::Type::Reference(r) = &**rtype {
				// We can't return a reference, cause we allocate things on the stack.
				types.write_c_type(w, &*r.elem, generics, true);
			} else {
				types.write_c_type(w, &*rtype, generics, true);
			}
		},
		_ => {},
	}
}

/// Print the main part of a method declaration body, starting with a newline after the function
/// open bracket and converting each function parameter to or from C-mapped types. Ends with "let
/// mut ret = " assuming the next print will be the unmapped Rust function to call followed by the
/// parameters we mapped to/from C here.
pub fn write_method_var_decl_body<W: std::io::Write>(w: &mut W, sig: &syn::Signature, extra_indent: &str, types: &TypeResolver, generics: Option<&GenericTypes>, to_c: bool) {
	let mut num_unused = 0;
	for inp in sig.inputs.iter() {
		match inp {
			syn::FnArg::Receiver(_) => {},
			syn::FnArg::Typed(arg) => {
				if types.skip_arg(&*arg.ty, generics) { continue; }
				if !arg.attrs.is_empty() { unimplemented!(); }
				macro_rules! write_new_var {
					($ident: expr, $ty: expr) => {
						if to_c {
							if types.write_to_c_conversion_new_var(w, &$ident, &$ty, generics, false) {
								write!(w, "\n\t{}", extra_indent).unwrap();
							}
						} else {
							if types.write_from_c_conversion_new_var(w, &$ident, &$ty, generics) {
								write!(w, "\n\t{}", extra_indent).unwrap();
							}
						}
					}
				}
				match &*arg.pat {
					syn::Pat::Ident(ident) => {
						if !ident.attrs.is_empty() || ident.subpat.is_some() {
							unimplemented!();
						}
						write_new_var!(ident.ident, *arg.ty);
					},
					syn::Pat::Wild(w) => {
						if !w.attrs.is_empty() { unimplemented!(); }
						write_new_var!(syn::Ident::new(&format!("unused_{}", num_unused), Span::call_site()), *arg.ty);
						num_unused += 1;
					},
					_ => unimplemented!(),
				}
			}
		}
	}
	match &sig.output {
		syn::ReturnType::Type(_, _) => {
			write!(w, "let mut ret = ").unwrap();
		},
		_ => {},
	}
}

/// Prints the parameters in a method call, starting after the open parenthesis and ending with a
/// final return statement returning the method's result. Should be followed by a single closing
/// bracket.
///
/// The return value is expected to be bound to a variable named `ret` which is available after a
/// method-call-ending semicolon.
pub fn write_method_call_params<W: std::io::Write>(w: &mut W, sig: &syn::Signature, extra_indent: &str, types: &TypeResolver, generics: Option<&GenericTypes>, this_type: &str, to_c: bool) {
	let mut first_arg = true;
	let mut num_unused = 0;
	for inp in sig.inputs.iter() {
		match inp {
			syn::FnArg::Receiver(recv) => {
				if !recv.attrs.is_empty() || recv.reference.is_none() { unimplemented!(); }
				if to_c {
					write!(w, "self.this_arg").unwrap();
					first_arg = false;
				}
			},
			syn::FnArg::Typed(arg) => {
				if types.skip_arg(&*arg.ty, generics) {
					if !to_c {
						if !first_arg {
							write!(w, ", ").unwrap();
						}
						first_arg = false;
						types.no_arg_to_rust(w, &*arg.ty, generics);
					}
					continue;
				}
				if !arg.attrs.is_empty() { unimplemented!(); }
				macro_rules! write_ident {
					($ident: expr) => {
						if !first_arg {
							write!(w, ", ").unwrap();
						}
						first_arg = false;
						if to_c {
							types.write_to_c_conversion_inline_prefix(w, &*arg.ty, generics, false);
							write!(w, "{}", $ident).unwrap();
							types.write_to_c_conversion_inline_suffix(w, &*arg.ty, generics, false);
						} else {
							types.write_from_c_conversion_prefix(w, &*arg.ty, generics);
							write!(w, "{}", $ident).unwrap();
							types.write_from_c_conversion_suffix(w, &*arg.ty, generics);
						}
					}
				}
				match &*arg.pat {
					syn::Pat::Ident(ident) => {
						if !ident.attrs.is_empty() || ident.subpat.is_some() {
							unimplemented!();
						}
						write_ident!(ident.ident);
					},
					syn::Pat::Wild(w) => {
						if !w.attrs.is_empty() { unimplemented!(); }
						write_ident!(format!("unused_{}", num_unused));
						num_unused += 1;
					},
					_ => unimplemented!(),
				}
			}
		}
	}
	write!(w, ")").unwrap();
	match &sig.output {
		syn::ReturnType::Type(_, rtype) => {
			write!(w, ";\n\t{}", extra_indent).unwrap();

			if to_c && first_seg_self(&*rtype).is_some() {
				// Assume rather blindly that we're returning an associated trait from a C fn call to a Rust trait object.
				write!(w, "ret").unwrap();
			} else if !to_c && first_seg_self(&*rtype).is_some() {
				if let Some(mut remaining_path) = first_seg_self(&*rtype) {
					if let Some(associated_seg) = get_single_remaining_path_seg(&mut remaining_path) {
						// Build a fake path with only associated_seg and resolve it:
						let mut segments = syn::punctuated::Punctuated::new();
						segments.push(syn::PathSegment {
							ident: associated_seg.clone(), arguments: syn::PathArguments::None });
						let (_, real_path) = generics.unwrap().maybe_resolve_path(&syn::Path {
							leading_colon: None, segments }).unwrap();

						assert_eq!(real_path.segments.len(), 1);
						let real_ident = &real_path.segments.iter().next().unwrap().ident;
						if let Some(t) = types.crate_types.traits.get(&types.maybe_resolve_ident(&real_ident).unwrap()) {
							// We're returning an associated trait from a Rust fn call to a C trait
							// object.
							writeln!(w, "let mut rust_obj = {} {{ inner: Box::into_raw(Box::new(ret)), is_owned: true }};", this_type).unwrap();
							writeln!(w, "\t{}let mut ret = {}_as_{}(&rust_obj);", extra_indent, this_type, t.ident).unwrap();
							writeln!(w, "\t{}// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn", extra_indent).unwrap();
							writeln!(w, "\t{}rust_obj.inner = std::ptr::null_mut();", extra_indent).unwrap();
							writeln!(w, "\t{}ret.free = Some({}_free_void);", extra_indent, this_type).unwrap();
							writeln!(w, "\t{}ret", extra_indent).unwrap();
							return;
						}
					}
				}
				write!(w, "{} {{ inner: Box::into_raw(Box::new(ret)), is_owned: true }}", this_type).unwrap();
			} else if to_c {
				let new_var = types.write_from_c_conversion_new_var(w, &syn::Ident::new("ret", Span::call_site()), rtype, generics);
				if new_var {
					write!(w, "\n\t{}", extra_indent).unwrap();
				}
				types.write_from_c_conversion_prefix(w, &*rtype, generics);
				write!(w, "ret").unwrap();
				types.write_from_c_conversion_suffix(w, &*rtype, generics);
			} else {
				let ret_returned = if let syn::Type::Reference(_) = &**rtype { true } else { false };
				let new_var = types.write_to_c_conversion_new_var(w, &syn::Ident::new("ret", Span::call_site()), &rtype, generics, true);
				if new_var {
					write!(w, "\n\t{}", extra_indent).unwrap();
				}
				types.write_to_c_conversion_inline_prefix(w, &rtype, generics, true);
				write!(w, "{}ret", if ret_returned && !new_var { "*" } else { "" }).unwrap();
				types.write_to_c_conversion_inline_suffix(w, &rtype, generics, true);
			}
		}
		_ => {},
	}
}

/// Prints concrete generic parameters for a struct/trait/function, including the less-than and
/// greater-than symbols, if any generic parameters are defined.
pub fn maybe_write_generics<W: std::io::Write>(w: &mut W, generics: &syn::Generics, types: &TypeResolver, concrete_lifetimes: bool) {
	let mut gen_types = GenericTypes::new();
	assert!(gen_types.learn_generics(generics, types));
	if !generics.params.is_empty() {
		write!(w, "<").unwrap();
		for (idx, generic) in generics.params.iter().enumerate() {
			match generic {
				syn::GenericParam::Type(type_param) => {
					let mut printed_param = false;
					for bound in type_param.bounds.iter() {
						if let syn::TypeParamBound::Trait(trait_bound) = bound {
							assert_simple_bound(&trait_bound);
							write!(w, "{}{}", if idx != 0 { ", " } else { "" }, gen_types.maybe_resolve_ident(&type_param.ident).unwrap()).unwrap();
							if printed_param {
								unimplemented!("Can't print generic params that have multiple non-lifetime bounds");
							}
							printed_param = true;
						}
					}
				},
				syn::GenericParam::Lifetime(lt) => {
					if concrete_lifetimes {
						write!(w, "'static").unwrap();
					} else {
						write!(w, "{}'{}", if idx != 0 { ", " } else { "" }, lt.lifetime.ident).unwrap();
					}
				},
				_ => unimplemented!(),
			}
		}
		write!(w, ">").unwrap();
	}
}


