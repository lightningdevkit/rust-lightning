//! Converts a rust crate into a rust crate containing a number of C-exported wrapper functions and
//! classes (which is exportable using cbindgen).
//! In general, supports convering:
//!  * structs as a pointer to the underlying type (either owned or not owned),
//!  * traits as a void-ptr plus a jump table,
//!  * enums as an equivalent enum with all the inner fields mapped to the mapped types,
//!  * certain containers (tuples, slices, Vecs, Options, and Results currently) to a concrete
//!    version of a defined container template.
//!
//! It also generates relevant memory-management functions and free-standing functions with
//! parameters mapped.

use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::process;

use proc_macro2::{TokenTree, TokenStream, Span};

mod types;
mod blocks;
use types::*;
use blocks::*;

// *************************************
// *** Manually-expanded conversions ***
// *************************************

/// Because we don't expand macros, any code that we need to generated based on their contents has
/// to be completely manual. In this case its all just serialization, so its not too hard.
fn convert_macro<W: std::io::Write>(w: &mut W, macro_path: &syn::Path, stream: &TokenStream, types: &TypeResolver) {
	assert_eq!(macro_path.segments.len(), 1);
	match &format!("{}", macro_path.segments.iter().next().unwrap().ident) as &str {
		"impl_writeable" | "impl_writeable_len_match" => {
			let struct_for = if let TokenTree::Ident(i) = stream.clone().into_iter().next().unwrap() { i } else { unimplemented!(); };
			if let Some(s) = types.maybe_resolve_ident(&struct_for) {
				if !types.crate_types.opaques.get(&s).is_some() { return; }
				writeln!(w, "#[no_mangle]").unwrap();
				writeln!(w, "pub extern \"C\" fn {}_write(obj: &{}) -> crate::c_types::derived::CVec_u8Z {{", struct_for, struct_for).unwrap();
				writeln!(w, "\tcrate::c_types::serialize_obj(unsafe {{ &(*(*obj).inner) }})").unwrap();
				writeln!(w, "}}").unwrap();
				writeln!(w, "#[no_mangle]").unwrap();
				writeln!(w, "pub(crate) extern \"C\" fn {}_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {{", struct_for).unwrap();
				writeln!(w, "\tcrate::c_types::serialize_obj(unsafe {{ &*(obj as *const native{}) }})", struct_for).unwrap();
				writeln!(w, "}}").unwrap();
				writeln!(w, "#[no_mangle]").unwrap();
				writeln!(w, "pub extern \"C\" fn {}_read(ser: crate::c_types::u8slice) -> {} {{", struct_for, struct_for).unwrap();
				writeln!(w, "\tif let Ok(res) = crate::c_types::deserialize_obj(ser) {{").unwrap();
				writeln!(w, "\t\t{} {{ inner: Box::into_raw(Box::new(res)), is_owned: true }}", struct_for).unwrap();
				writeln!(w, "\t}} else {{").unwrap();
				writeln!(w, "\t\t{} {{ inner: std::ptr::null_mut(), is_owned: true }}", struct_for).unwrap();
				writeln!(w, "\t}}\n}}").unwrap();
			}
		},
		_ => {},
	}
}

/// Convert "impl trait_path for for_ty { .. }" for manually-mapped types (ie (de)serialization)
fn maybe_convert_trait_impl<W: std::io::Write>(w: &mut W, trait_path: &syn::Path, for_ty: &syn::Type, types: &mut TypeResolver, generics: &GenericTypes) {
	if let Some(t) = types.maybe_resolve_path(&trait_path, Some(generics)) {
		let for_obj;
		let full_obj_path;
		let mut has_inner = false;
		if let syn::Type::Path(ref p) = for_ty {
			if let Some(ident) = single_ident_generic_path_to_ident(&p.path) {
				for_obj = format!("{}", ident);
				full_obj_path = for_obj.clone();
				has_inner = types.c_type_has_inner_from_path(&types.resolve_path(&p.path, Some(generics)));
			} else { return; }
		} else {
			// We assume that anything that isn't a Path is somehow a generic that ends up in our
			// derived-types module.
			let mut for_obj_vec = Vec::new();
			types.write_c_type(&mut for_obj_vec, for_ty, Some(generics), false);
			full_obj_path = String::from_utf8(for_obj_vec).unwrap();
			assert!(full_obj_path.starts_with(TypeResolver::generated_container_path()));
			for_obj = full_obj_path[TypeResolver::generated_container_path().len() + 2..].into();
		}

		match &t as &str {
			"util::ser::Writeable" => {
				writeln!(w, "#[no_mangle]").unwrap();
				writeln!(w, "pub extern \"C\" fn {}_write(obj: &{}) -> crate::c_types::derived::CVec_u8Z {{", for_obj, full_obj_path).unwrap();

				let ref_type = syn::Type::Reference(syn::TypeReference {
					and_token: syn::Token!(&)(Span::call_site()), lifetime: None, mutability: None,
					elem: Box::new(for_ty.clone()) });
				assert!(!types.write_from_c_conversion_new_var(w, &syn::Ident::new("obj", Span::call_site()), &ref_type, Some(generics)));

				write!(w, "\tcrate::c_types::serialize_obj(").unwrap();
				types.write_from_c_conversion_prefix(w, &ref_type, Some(generics));
				write!(w, "unsafe {{ &*obj }}").unwrap();
				types.write_from_c_conversion_suffix(w, &ref_type, Some(generics));
				writeln!(w, ")").unwrap();

				writeln!(w, "}}").unwrap();
				if has_inner {
					writeln!(w, "#[no_mangle]").unwrap();
					writeln!(w, "pub(crate) extern \"C\" fn {}_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {{", for_obj).unwrap();
					writeln!(w, "\tcrate::c_types::serialize_obj(unsafe {{ &*(obj as *const native{}) }})", for_obj).unwrap();
					writeln!(w, "}}").unwrap();
				}
			},
			"util::ser::Readable"|"util::ser::ReadableArgs" => {
				// Create the Result<Object, DecodeError> syn::Type
				let mut err_segs = syn::punctuated::Punctuated::new();
				err_segs.push(syn::PathSegment { ident: syn::Ident::new("ln", Span::call_site()), arguments: syn::PathArguments::None });
				err_segs.push(syn::PathSegment { ident: syn::Ident::new("msgs", Span::call_site()), arguments: syn::PathArguments::None });
				err_segs.push(syn::PathSegment { ident: syn::Ident::new("DecodeError", Span::call_site()), arguments: syn::PathArguments::None });
				let mut args = syn::punctuated::Punctuated::new();
				args.push(syn::GenericArgument::Type(for_ty.clone()));
				args.push(syn::GenericArgument::Type(syn::Type::Path(syn::TypePath {
					qself: None, path: syn::Path {
						leading_colon: Some(syn::Token![::](Span::call_site())), segments: err_segs,
					}
				})));
				let mut res_segs = syn::punctuated::Punctuated::new();
				res_segs.push(syn::PathSegment {
					ident: syn::Ident::new("Result", Span::call_site()),
					arguments: syn::PathArguments::AngleBracketed(syn::AngleBracketedGenericArguments {
						colon2_token: None, lt_token: syn::Token![<](Span::call_site()), args, gt_token: syn::Token![>](Span::call_site()),
					})
				});
				let res_ty = syn::Type::Path(syn::TypePath { qself: None, path: syn::Path {
					leading_colon: None, segments: res_segs } });

				writeln!(w, "#[no_mangle]").unwrap();
				write!(w, "pub extern \"C\" fn {}_read(ser: crate::c_types::u8slice", for_obj).unwrap();

				let mut arg_conv = Vec::new();
				if t == "util::ser::ReadableArgs" {
					write!(w, ", arg: ").unwrap();
					assert!(trait_path.leading_colon.is_none());
					let args_seg = trait_path.segments.iter().last().unwrap();
					assert_eq!(format!("{}", args_seg.ident), "ReadableArgs");
					if let syn::PathArguments::AngleBracketed(args) = &args_seg.arguments {
						assert_eq!(args.args.len(), 1);
						if let syn::GenericArgument::Type(args_ty) = args.args.iter().next().unwrap() {
							types.write_c_type(w, args_ty, Some(generics), false);

							assert!(!types.write_from_c_conversion_new_var(&mut arg_conv, &syn::Ident::new("arg", Span::call_site()), &args_ty, Some(generics)));

							write!(&mut arg_conv, "\tlet arg_conv = ").unwrap();
							types.write_from_c_conversion_prefix(&mut arg_conv, &args_ty, Some(generics));
							write!(&mut arg_conv, "arg").unwrap();
							types.write_from_c_conversion_suffix(&mut arg_conv, &args_ty, Some(generics));
						} else { unreachable!(); }
					} else { unreachable!(); }
				}
				write!(w, ") -> ").unwrap();
				types.write_c_type(w, &res_ty, Some(generics), false);
				writeln!(w, " {{").unwrap();

				if t == "util::ser::ReadableArgs" {
					w.write(&arg_conv).unwrap();
					write!(w, ";\n\tlet res: ").unwrap();
					// At least in one case we need type annotations here, so provide them.
					types.write_rust_type(w, Some(generics), &res_ty);
					writeln!(w, " = crate::c_types::deserialize_obj_arg(ser, arg_conv);").unwrap();
				} else {
					writeln!(w, "\tlet res = crate::c_types::deserialize_obj(ser);").unwrap();
				}
				write!(w, "\t").unwrap();
				if types.write_to_c_conversion_new_var(w, &syn::Ident::new("res", Span::call_site()), &res_ty, Some(generics), false) {
					write!(w, "\n\t").unwrap();
				}
				types.write_to_c_conversion_inline_prefix(w, &res_ty, Some(generics), false);
				write!(w, "res").unwrap();
				types.write_to_c_conversion_inline_suffix(w, &res_ty, Some(generics), false);
				writeln!(w, "\n}}").unwrap();
			},
			_ => {},
		}
	}
}

/// Convert "TraitA : TraitB" to a single function name and return type.
///
/// This is (obviously) somewhat over-specialized and only useful for TraitB's that only require a
/// single function (eg for serialization).
fn convert_trait_impl_field(trait_path: &str) -> (String, &'static str) {
	match trait_path {
		"util::ser::Writeable" => ("write".to_owned(), "crate::c_types::derived::CVec_u8Z"),
		_ => unimplemented!(),
	}
}

/// Companion to convert_trait_impl_field, write an assignment for the function defined by it for
/// `for_obj` which implements the the trait at `trait_path`.
fn write_trait_impl_field_assign<W: std::io::Write>(w: &mut W, trait_path: &str, for_obj: &syn::Ident) {
	match trait_path {
		"util::ser::Writeable" => {
			writeln!(w, "\t\twrite: {}_write_void,", for_obj).unwrap();
		},
		_ => unimplemented!(),
	}
}

/// Write out the impl block for a defined trait struct which has a supertrait
fn do_write_impl_trait<W: std::io::Write>(w: &mut W, trait_path: &str, trait_name: &syn::Ident, for_obj: &str) {
	match trait_path {
		"util::events::MessageSendEventsProvider" => {
			writeln!(w, "impl lightning::{} for {} {{", trait_path, for_obj).unwrap();
			writeln!(w, "\tfn get_and_clear_pending_msg_events(&self) -> Vec<lightning::util::events::MessageSendEvent> {{").unwrap();
			writeln!(w, "\t\t<crate::{} as lightning::{}>::get_and_clear_pending_msg_events(&self.{})", trait_path, trait_path, trait_name).unwrap();
			writeln!(w, "\t}}\n}}").unwrap();
		},
		"util::ser::Writeable" => {
			writeln!(w, "impl lightning::{} for {} {{", trait_path, for_obj).unwrap();
			writeln!(w, "\tfn write<W: lightning::util::ser::Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {{").unwrap();
			writeln!(w, "\t\tlet vec = (self.write)(self.this_arg);").unwrap();
			writeln!(w, "\t\tw.write_all(vec.as_slice())").unwrap();
			writeln!(w, "\t}}\n}}").unwrap();
		},
		_ => panic!(),
	}
}

// *******************************
// *** Per-Type Printing Logic ***
// *******************************

macro_rules! walk_supertraits { ($t: expr, $types: expr, ($( $pat: pat => $e: expr),*) ) => { {
	if $t.colon_token.is_some() {
		for st in $t.supertraits.iter() {
			match st {
				syn::TypeParamBound::Trait(supertrait) => {
					if supertrait.paren_token.is_some() || supertrait.lifetimes.is_some() {
						unimplemented!();
					}
					// First try to resolve path to find in-crate traits, but if that doesn't work
					// assume its a prelude trait (eg Clone, etc) and just use the single ident.
					let types_opt: Option<&TypeResolver> = $types;
					if let Some(types) = types_opt {
						if let Some(path) = types.maybe_resolve_path(&supertrait.path, None) {
							match (&path as &str, &supertrait.path.segments.iter().last().unwrap().ident) {
								$( $pat => $e, )*
							}
							continue;
						}
					}
					if let Some(ident) = supertrait.path.get_ident() {
						match (&format!("{}", ident) as &str, &ident) {
							$( $pat => $e, )*
						}
					} else if types_opt.is_some() {
						panic!("Supertrait unresolvable and not single-ident");
					}
				},
				syn::TypeParamBound::Lifetime(_) => unimplemented!(),
			}
		}
	}
} } }

/// Prints a C-mapped trait object containing a void pointer and a jump table for each function in
/// the original trait.
/// Implements the native Rust trait and relevant parent traits for the new C-mapped trait.
///
/// Finally, implements Deref<MappedTrait> for MappedTrait which allows its use in types which need
/// a concrete Deref to the Rust trait.
fn writeln_trait<'a, 'b, W: std::io::Write>(w: &mut W, t: &'a syn::ItemTrait, types: &mut TypeResolver<'b, 'a>, extra_headers: &mut File, cpp_headers: &mut File) {
	let trait_name = format!("{}", t.ident);
	match export_status(&t.attrs) {
		ExportStatus::Export => {},
		ExportStatus::NoExport|ExportStatus::TestOnly => return,
	}
	writeln_docs(w, &t.attrs, "");

	let mut gen_types = GenericTypes::new();
	assert!(gen_types.learn_generics(&t.generics, types));
	gen_types.learn_associated_types(&t, types);

	writeln!(w, "#[repr(C)]\npub struct {} {{", trait_name).unwrap();
	writeln!(w, "\tpub this_arg: *mut c_void,").unwrap();
	let mut generated_fields = Vec::new(); // Every field's name except this_arg, used in Clone generation
	for item in t.items.iter() {
		match item {
			&syn::TraitItem::Method(ref m) => {
				match export_status(&m.attrs) {
					ExportStatus::NoExport => {
						// NoExport in this context means we'll hit an unimplemented!() at runtime,
						// so bail out.
						unimplemented!();
					},
					ExportStatus::Export => {},
					ExportStatus::TestOnly => continue,
				}
				if m.default.is_some() { unimplemented!(); }

				gen_types.push_ctx();
				assert!(gen_types.learn_generics(&m.sig.generics, types));

				writeln_docs(w, &m.attrs, "\t");

				if let syn::ReturnType::Type(_, rtype) = &m.sig.output {
					if let syn::Type::Reference(r) = &**rtype {
						// We have to do quite a dance for trait functions which return references
						// - they ultimately require us to have a native Rust object stored inside
						// our concrete trait to return a reference to. However, users may wish to
						// update the value to be returned each time the function is called (or, to
						// make C copies of Rust impls equivalent, we have to be able to).
						//
						// Thus, we store a copy of the C-mapped type (which is just a pointer to
						// the Rust type and a flag to indicate whether deallocation needs to
						// happen) as well as provide an Option<>al function pointer which is
						// called when the trait method is called which allows updating on the fly.
						write!(w, "\tpub {}: ", m.sig.ident).unwrap();
						generated_fields.push(format!("{}", m.sig.ident));
						types.write_c_type(w, &*r.elem, Some(&gen_types), false);
						writeln!(w, ",").unwrap();
						writeln!(w, "\t/// Fill in the {} field as a reference to it will be given to Rust after this returns", m.sig.ident).unwrap();
						writeln!(w, "\t/// Note that this takes a pointer to this object, not the this_ptr like other methods do").unwrap();
						writeln!(w, "\t/// This function pointer may be NULL if {} is filled in when this object is created and never needs updating.", m.sig.ident).unwrap();
						writeln!(w, "\tpub set_{}: Option<extern \"C\" fn(&{})>,", m.sig.ident, trait_name).unwrap();
						generated_fields.push(format!("set_{}", m.sig.ident));
						// Note that cbindgen will now generate
						// typedef struct Thing {..., set_thing: (const Thing*), ...} Thing;
						// which does not compile since Thing is not defined before it is used.
						writeln!(extra_headers, "struct LDK{};", trait_name).unwrap();
						writeln!(extra_headers, "typedef struct LDK{} LDK{};", trait_name, trait_name).unwrap();
						gen_types.pop_ctx();
						continue;
					}
					// Sadly, this currently doesn't do what we want, but it should be easy to get
					// cbindgen to support it. See https://github.com/eqrion/cbindgen/issues/531
					writeln!(w, "\t#[must_use]").unwrap();
				}

				write!(w, "\tpub {}: extern \"C\" fn (", m.sig.ident).unwrap();
				generated_fields.push(format!("{}", m.sig.ident));
				write_method_params(w, &m.sig, "c_void", types, Some(&gen_types), true, false);
				writeln!(w, ",").unwrap();

				gen_types.pop_ctx();
			},
			&syn::TraitItem::Type(_) => {},
			_ => unimplemented!(),
		}
	}
	// Add functions which may be required for supertrait implementations.
	walk_supertraits!(t, Some(&types), (
		("Clone", _) => {
			writeln!(w, "\tpub clone: Option<extern \"C\" fn (this_arg: *const c_void) -> *mut c_void>,").unwrap();
			generated_fields.push("clone".to_owned());
		},
		("std::cmp::Eq", _) => {
			writeln!(w, "\tpub eq: extern \"C\" fn (this_arg: *const c_void, other_arg: &{}) -> bool,", trait_name).unwrap();
			writeln!(extra_headers, "typedef struct LDK{} LDK{};", trait_name, trait_name).unwrap();
			generated_fields.push("eq".to_owned());
		},
		("std::hash::Hash", _) => {
			writeln!(w, "\tpub hash: extern \"C\" fn (this_arg: *const c_void) -> u64,").unwrap();
			generated_fields.push("hash".to_owned());
		},
		("Send", _) => {}, ("Sync", _) => {},
		(s, i) => {
			generated_fields.push(if types.crate_types.traits.get(s).is_none() {
				let (name, ret) = convert_trait_impl_field(s);
				writeln!(w, "\tpub {}: extern \"C\" fn (this_arg: *const c_void) -> {},", name, ret).unwrap();
				name
			} else {
				// For in-crate supertraits, just store a C-mapped copy of the supertrait as a member.
				writeln!(w, "\tpub {}: crate::{},", i, s).unwrap();
				format!("{}", i)
			});
		}
	) );
	writeln!(w, "\tpub free: Option<extern \"C\" fn(this_arg: *mut c_void)>,").unwrap();
	generated_fields.push("free".to_owned());
	writeln!(w, "}}").unwrap();
	// Implement supertraits for the C-mapped struct.
	walk_supertraits!(t, Some(&types), (
		("Send", _) => writeln!(w, "unsafe impl Send for {} {{}}", trait_name).unwrap(),
		("Sync", _) => writeln!(w, "unsafe impl Sync for {} {{}}", trait_name).unwrap(),
		("std::cmp::Eq", _) => {
			writeln!(w, "impl std::cmp::Eq for {} {{}}", trait_name).unwrap();
			writeln!(w, "impl std::cmp::PartialEq for {} {{", trait_name).unwrap();
			writeln!(w, "\tfn eq(&self, o: &Self) -> bool {{ (self.eq)(self.this_arg, o) }}\n}}").unwrap();
		},
		("std::hash::Hash", _) => {
			writeln!(w, "impl std::hash::Hash for {} {{", trait_name).unwrap();
			writeln!(w, "\tfn hash<H: std::hash::Hasher>(&self, hasher: &mut H) {{ hasher.write_u64((self.hash)(self.this_arg)) }}\n}}").unwrap();
		},
		("Clone", _) => {
			writeln!(w, "#[no_mangle]").unwrap();
			writeln!(w, "pub extern \"C\" fn {}_clone(orig: &{}) -> {} {{", trait_name, trait_name, trait_name).unwrap();
			writeln!(w, "\t{} {{", trait_name).unwrap();
			writeln!(w, "\t\tthis_arg: if let Some(f) = orig.clone {{ (f)(orig.this_arg) }} else {{ orig.this_arg }},").unwrap();
			for field in generated_fields.iter() {
				writeln!(w, "\t\t{}: orig.{}.clone(),", field, field).unwrap();
			}
			writeln!(w, "\t}}\n}}").unwrap();
			writeln!(w, "impl Clone for {} {{", trait_name).unwrap();
			writeln!(w, "\tfn clone(&self) -> Self {{").unwrap();
			writeln!(w, "\t\t{}_clone(self)", trait_name).unwrap();
			writeln!(w, "\t}}\n}}").unwrap();
		},
		(s, i) => {
			do_write_impl_trait(w, s, i, &trait_name);
		}
	) );

	// Finally, implement the original Rust trait for the newly created mapped trait.
	writeln!(w, "\nuse {}::{}::{} as rust{};", types.orig_crate, types.module_path, t.ident, trait_name).unwrap();
	write!(w, "impl rust{}", t.ident).unwrap();
	maybe_write_generics(w, &t.generics, types, false);
	writeln!(w, " for {} {{", trait_name).unwrap();
	for item in t.items.iter() {
		match item {
			syn::TraitItem::Method(m) => {
				if let ExportStatus::TestOnly = export_status(&m.attrs) { continue; }
				if m.default.is_some() { unimplemented!(); }
				if m.sig.constness.is_some() || m.sig.asyncness.is_some() || m.sig.unsafety.is_some() ||
						m.sig.abi.is_some() || m.sig.variadic.is_some() {
					unimplemented!();
				}
				gen_types.push_ctx();
				assert!(gen_types.learn_generics(&m.sig.generics, types));
				write!(w, "\tfn {}", m.sig.ident).unwrap();
				types.write_rust_generic_param(w, Some(&gen_types), m.sig.generics.params.iter());
				write!(w, "(").unwrap();
				for inp in m.sig.inputs.iter() {
					match inp {
						syn::FnArg::Receiver(recv) => {
							if !recv.attrs.is_empty() || recv.reference.is_none() { unimplemented!(); }
							write!(w, "&").unwrap();
							if let Some(lft) = &recv.reference.as_ref().unwrap().1 {
								write!(w, "'{} ", lft.ident).unwrap();
							}
							if recv.mutability.is_some() {
								write!(w, "mut self").unwrap();
							} else {
								write!(w, "self").unwrap();
							}
						},
						syn::FnArg::Typed(arg) => {
							if !arg.attrs.is_empty() { unimplemented!(); }
							match &*arg.pat {
								syn::Pat::Ident(ident) => {
									if !ident.attrs.is_empty() || ident.by_ref.is_some() ||
											ident.mutability.is_some() || ident.subpat.is_some() {
										unimplemented!();
									}
									write!(w, ", {}{}: ", if types.skip_arg(&*arg.ty, Some(&gen_types)) { "_" } else { "" }, ident.ident).unwrap();
								}
								_ => unimplemented!(),
							}
							types.write_rust_type(w, Some(&gen_types), &*arg.ty);
						}
					}
				}
				write!(w, ")").unwrap();
				match &m.sig.output {
					syn::ReturnType::Type(_, rtype) => {
						write!(w, " -> ").unwrap();
						types.write_rust_type(w, Some(&gen_types), &*rtype)
					},
					_ => {},
				}
				write!(w, " {{\n\t\t").unwrap();
				match export_status(&m.attrs) {
					ExportStatus::NoExport => {
						unimplemented!();
					},
					_ => {},
				}
				if let syn::ReturnType::Type(_, rtype) = &m.sig.output {
					if let syn::Type::Reference(r) = &**rtype {
						assert_eq!(m.sig.inputs.len(), 1); // Must only take self!
						writeln!(w, "if let Some(f) = self.set_{} {{", m.sig.ident).unwrap();
						writeln!(w, "\t\t\t(f)(self);").unwrap();
						write!(w, "\t\t}}\n\t\t").unwrap();
						types.write_from_c_conversion_to_ref_prefix(w, &*r.elem, Some(&gen_types));
						write!(w, "self.{}", m.sig.ident).unwrap();
						types.write_from_c_conversion_to_ref_suffix(w, &*r.elem, Some(&gen_types));
						writeln!(w, "\n\t}}").unwrap();
						gen_types.pop_ctx();
						continue;
					}
				}
				write_method_var_decl_body(w, &m.sig, "\t", types, Some(&gen_types), true);
				write!(w, "(self.{})(", m.sig.ident).unwrap();
				write_method_call_params(w, &m.sig, "\t", types, Some(&gen_types), "", true);

				writeln!(w, "\n\t}}").unwrap();
				gen_types.pop_ctx();
			},
			&syn::TraitItem::Type(ref t) => {
				if t.default.is_some() || t.generics.lt_token.is_some() { unimplemented!(); }
				let mut bounds_iter = t.bounds.iter();
				match bounds_iter.next().unwrap() {
					syn::TypeParamBound::Trait(tr) => {
						writeln!(w, "\ttype {} = crate::{};", t.ident, types.resolve_path(&tr.path, Some(&gen_types))).unwrap();
					},
					_ => unimplemented!(),
				}
				if bounds_iter.next().is_some() { unimplemented!(); }
			},
			_ => unimplemented!(),
		}
	}
	writeln!(w, "}}\n").unwrap();
	writeln!(w, "// We're essentially a pointer already, or at least a set of pointers, so allow us to be used").unwrap();
	writeln!(w, "// directly as a Deref trait in higher-level structs:").unwrap();
	writeln!(w, "impl std::ops::Deref for {} {{\n\ttype Target = Self;", trait_name).unwrap();
	writeln!(w, "\tfn deref(&self) -> &Self {{\n\t\tself\n\t}}\n}}").unwrap();

	writeln!(w, "/// Calls the free function if one is set").unwrap();
	writeln!(w, "#[no_mangle]\npub extern \"C\" fn {}_free(this_ptr: {}) {{ }}", trait_name, trait_name).unwrap();
	writeln!(w, "impl Drop for {} {{", trait_name).unwrap();
	writeln!(w, "\tfn drop(&mut self) {{").unwrap();
	writeln!(w, "\t\tif let Some(f) = self.free {{").unwrap();
	writeln!(w, "\t\t\tf(self.this_arg);").unwrap();
	writeln!(w, "\t\t}}\n\t}}\n}}").unwrap();

	write_cpp_wrapper(cpp_headers, &trait_name, true);
}

/// Write out a simple "opaque" type (eg structs) which contain a pointer to the native Rust type
/// and a flag to indicate whether Drop'ing the mapped struct drops the underlying Rust type.
///
/// Also writes out a _free function and a C++ wrapper which handles calling _free.
fn writeln_opaque<W: std::io::Write>(w: &mut W, ident: &syn::Ident, struct_name: &str, generics: &syn::Generics, attrs: &[syn::Attribute], types: &TypeResolver, extra_headers: &mut File, cpp_headers: &mut File) {
	// If we directly read the original type by its original name, cbindgen hits
	// https://github.com/eqrion/cbindgen/issues/286 Thus, instead, we import it as a temporary
	// name and then reference it by that name, which works around the issue.
	write!(w, "\nuse {}::{}::{} as native{}Import;\ntype native{} = native{}Import", types.orig_crate, types.module_path, ident, ident, ident, ident).unwrap();
	maybe_write_generics(w, &generics, &types, true);
	writeln!(w, ";\n").unwrap();
	writeln!(extra_headers, "struct native{}Opaque;\ntypedef struct native{}Opaque LDKnative{};", ident, ident, ident).unwrap();
	writeln_docs(w, &attrs, "");
	writeln!(w, "#[must_use]\n#[repr(C)]\npub struct {} {{\n\t/// Nearly everywhere, inner must be non-null, however in places where", struct_name).unwrap();
	writeln!(w, "\t/// the Rust equivalent takes an Option, it may be set to null to indicate None.").unwrap();
	writeln!(w, "\tpub inner: *mut native{},\n\tpub is_owned: bool,\n}}\n", ident).unwrap();
	writeln!(w, "impl Drop for {} {{\n\tfn drop(&mut self) {{", struct_name).unwrap();
	writeln!(w, "\t\tif self.is_owned && !self.inner.is_null() {{").unwrap();
	writeln!(w, "\t\t\tlet _ = unsafe {{ Box::from_raw(self.inner) }};\n\t\t}}\n\t}}\n}}").unwrap();
	writeln!(w, "#[no_mangle]\npub extern \"C\" fn {}_free(this_ptr: {}) {{ }}", struct_name, struct_name).unwrap();
	writeln!(w, "#[allow(unused)]").unwrap();
	writeln!(w, "/// Used only if an object of this type is returned as a trait impl by a method").unwrap();
	writeln!(w, "extern \"C\" fn {}_free_void(this_ptr: *mut c_void) {{", struct_name).unwrap();
	writeln!(w, "\tunsafe {{ let _ = Box::from_raw(this_ptr as *mut native{}); }}\n}}", struct_name).unwrap();
	writeln!(w, "#[allow(unused)]").unwrap();
	writeln!(w, "/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy").unwrap();
	writeln!(w, "impl {} {{", struct_name).unwrap();
	writeln!(w, "\tpub(crate) fn take_inner(mut self) -> *mut native{} {{", struct_name).unwrap();
	writeln!(w, "\t\tassert!(self.is_owned);").unwrap();
	writeln!(w, "\t\tlet ret = self.inner;").unwrap();
	writeln!(w, "\t\tself.inner = std::ptr::null_mut();").unwrap();
	writeln!(w, "\t\tret").unwrap();
	writeln!(w, "\t}}\n}}").unwrap();

	write_cpp_wrapper(cpp_headers, &format!("{}", ident), true);
}

/// Writes out all the relevant mappings for a Rust struct, deferring to writeln_opaque to generate
/// the struct itself, and then writing getters and setters for public, understood-type fields and
/// a constructor if every field is public.
fn writeln_struct<'a, 'b, W: std::io::Write>(w: &mut W, s: &'a syn::ItemStruct, types: &mut TypeResolver<'b, 'a>, extra_headers: &mut File, cpp_headers: &mut File) {
	if export_status(&s.attrs) != ExportStatus::Export { return; }

	let struct_name = &format!("{}", s.ident);
	writeln_opaque(w, &s.ident, struct_name, &s.generics, &s.attrs, types, extra_headers, cpp_headers);

	if let syn::Fields::Named(fields) = &s.fields {
		let mut gen_types = GenericTypes::new();
		assert!(gen_types.learn_generics(&s.generics, types));

		let mut all_fields_settable = true;
		for field in fields.named.iter() {
			if let syn::Visibility::Public(_) = field.vis {
				let export = export_status(&field.attrs);
				match export {
					ExportStatus::Export => {},
					ExportStatus::NoExport|ExportStatus::TestOnly => {
						all_fields_settable = false;
						continue
					},
				}

				if let Some(ident) = &field.ident {
					let ref_type = syn::Type::Reference(syn::TypeReference {
						and_token: syn::Token!(&)(Span::call_site()), lifetime: None, mutability: None,
						elem: Box::new(field.ty.clone()) });
					if types.understood_c_type(&ref_type, Some(&gen_types)) {
						writeln_docs(w, &field.attrs, "");
						write!(w, "#[no_mangle]\npub extern \"C\" fn {}_get_{}(this_ptr: &{}) -> ", struct_name, ident, struct_name).unwrap();
						types.write_c_type(w, &ref_type, Some(&gen_types), true);
						write!(w, " {{\n\tlet mut inner_val = &mut unsafe {{ &mut *this_ptr.inner }}.{};\n\t", ident).unwrap();
						let local_var = types.write_to_c_conversion_new_var(w, &syn::Ident::new("inner_val", Span::call_site()), &ref_type, Some(&gen_types), true);
						if local_var { write!(w, "\n\t").unwrap(); }
						types.write_to_c_conversion_inline_prefix(w, &ref_type, Some(&gen_types), true);
						if local_var {
							write!(w, "inner_val").unwrap();
						} else {
							write!(w, "(*inner_val)").unwrap();
						}
						types.write_to_c_conversion_inline_suffix(w, &ref_type, Some(&gen_types), true);
						writeln!(w, "\n}}").unwrap();
					}

					if types.understood_c_type(&field.ty, Some(&gen_types)) {
						writeln_docs(w, &field.attrs, "");
						write!(w, "#[no_mangle]\npub extern \"C\" fn {}_set_{}(this_ptr: &mut {}, mut val: ", struct_name, ident, struct_name).unwrap();
						types.write_c_type(w, &field.ty, Some(&gen_types), false);
						write!(w, ") {{\n\t").unwrap();
						let local_var = types.write_from_c_conversion_new_var(w, &syn::Ident::new("val", Span::call_site()), &field.ty, Some(&gen_types));
						if local_var { write!(w, "\n\t").unwrap(); }
						write!(w, "unsafe {{ &mut *this_ptr.inner }}.{} = ", ident).unwrap();
						types.write_from_c_conversion_prefix(w, &field.ty, Some(&gen_types));
						write!(w, "val").unwrap();
						types.write_from_c_conversion_suffix(w, &field.ty, Some(&gen_types));
						writeln!(w, ";\n}}").unwrap();
					} else { all_fields_settable = false; }
				} else { all_fields_settable = false; }
			} else { all_fields_settable = false; }
		}

		if all_fields_settable {
			// Build a constructor!
			write!(w, "#[must_use]\n#[no_mangle]\npub extern \"C\" fn {}_new(", struct_name).unwrap();
			for (idx, field) in fields.named.iter().enumerate() {
				if idx != 0 { write!(w, ", ").unwrap(); }
				write!(w, "mut {}_arg: ", field.ident.as_ref().unwrap()).unwrap();
				types.write_c_type(w, &field.ty, Some(&gen_types), false);
			}
			write!(w, ") -> {} {{\n\t", struct_name).unwrap();
			for field in fields.named.iter() {
				let field_name = format!("{}_arg", field.ident.as_ref().unwrap());
				if types.write_from_c_conversion_new_var(w, &syn::Ident::new(&field_name, Span::call_site()), &field.ty, Some(&gen_types)) {
					write!(w, "\n\t").unwrap();
				}
			}
			writeln!(w, "{} {{ inner: Box::into_raw(Box::new(native{} {{", struct_name, s.ident).unwrap();
			for field in fields.named.iter() {
				write!(w, "\t\t{}: ", field.ident.as_ref().unwrap()).unwrap();
				types.write_from_c_conversion_prefix(w, &field.ty, Some(&gen_types));
				write!(w, "{}_arg", field.ident.as_ref().unwrap()).unwrap();
				types.write_from_c_conversion_suffix(w, &field.ty, Some(&gen_types));
				writeln!(w, ",").unwrap();
			}
			writeln!(w, "\t}})), is_owned: true }}\n}}").unwrap();
		}
	}
}

/// Prints a relevant conversion for impl *
///
/// For simple impl Struct {}s, this just outputs the wrapper functions as Struct_fn_name() { .. }.
///
/// For impl Trait for Struct{}s, this non-exported generates wrapper functions as
/// Trait_Struct_fn_name and a Struct_as_Trait(&struct) -> Trait function which returns a populated
/// Trait struct containing a pointer to the passed struct's inner field and the wrapper functions.
///
/// A few non-crate Traits are hard-coded including Default.
fn writeln_impl<W: std::io::Write>(w: &mut W, i: &syn::ItemImpl, types: &mut TypeResolver) {
	match export_status(&i.attrs) {
		ExportStatus::Export => {},
		ExportStatus::NoExport|ExportStatus::TestOnly => return,
	}

	if let syn::Type::Tuple(_) = &*i.self_ty {
		if types.understood_c_type(&*i.self_ty, None) {
			let mut gen_types = GenericTypes::new();
			if !gen_types.learn_generics(&i.generics, types) {
				eprintln!("Not implementing anything for `impl (..)` due to not understood generics");
				return;
			}

			if i.defaultness.is_some() || i.unsafety.is_some() { unimplemented!(); }
			if let Some(trait_path) = i.trait_.as_ref() {
				if trait_path.0.is_some() { unimplemented!(); }
				if types.understood_c_path(&trait_path.1) {
					eprintln!("Not implementing anything for `impl Trait for (..)` - we only support manual defines");
					return;
				} else {
					// Just do a manual implementation:
					maybe_convert_trait_impl(w, &trait_path.1, &*i.self_ty, types, &gen_types);
				}
			} else {
				eprintln!("Not implementing anything for plain `impl (..)` block - we only support `impl Trait for (..)` blocks");
				return;
			}
		}
		return;
	}
	if let &syn::Type::Path(ref p) = &*i.self_ty {
		if p.qself.is_some() { unimplemented!(); }
		if let Some(ident) = single_ident_generic_path_to_ident(&p.path) {
			if let Some(resolved_path) = types.maybe_resolve_non_ignored_ident(&ident) {
				let mut gen_types = GenericTypes::new();
				if !gen_types.learn_generics(&i.generics, types) {
					eprintln!("Not implementing anything for impl {} due to not understood generics", ident);
					return;
				}

				if i.defaultness.is_some() || i.unsafety.is_some() { unimplemented!(); }
				if let Some(trait_path) = i.trait_.as_ref() {
					if trait_path.0.is_some() { unimplemented!(); }
					if types.understood_c_path(&trait_path.1) {
						let full_trait_path = types.resolve_path(&trait_path.1, None);
						let trait_obj = *types.crate_types.traits.get(&full_trait_path).unwrap();
						// We learn the associated types maping from the original trait object.
						// That's great, except that they are unresolved idents, so if we learn
						// mappings from a trai defined in a different file, we may mis-resolve or
						// fail to resolve the mapped types.
						gen_types.learn_associated_types(trait_obj, types);
						let mut impl_associated_types = HashMap::new();
						for item in i.items.iter() {
							match item {
								syn::ImplItem::Type(t) => {
									if let syn::Type::Path(p) = &t.ty {
										if let Some(id) = single_ident_generic_path_to_ident(&p.path) {
											impl_associated_types.insert(&t.ident, id);
										}
									}
								},
								_ => {},
							}
						}

						let export = export_status(&trait_obj.attrs);
						match export {
							ExportStatus::Export => {},
							ExportStatus::NoExport|ExportStatus::TestOnly => return,
						}

						// For cases where we have a concrete native object which implements a
						// trait and need to return the C-mapped version of the trait, provide a
						// From<> implementation which does all the work to ensure free is handled
						// properly. This way we can call this method from deep in the
						// type-conversion logic without actually knowing the concrete native type.
						writeln!(w, "impl From<native{}> for crate::{} {{", ident, full_trait_path).unwrap();
						writeln!(w, "\tfn from(obj: native{}) -> Self {{", ident).unwrap();
						writeln!(w, "\t\tlet mut rust_obj = {} {{ inner: Box::into_raw(Box::new(obj)), is_owned: true }};", ident).unwrap();
						writeln!(w, "\t\tlet mut ret = {}_as_{}(&rust_obj);", ident, trait_obj.ident).unwrap();
						writeln!(w, "\t\t// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn").unwrap();
						writeln!(w, "\t\trust_obj.inner = std::ptr::null_mut();").unwrap();
						writeln!(w, "\t\tret.free = Some({}_free_void);", ident).unwrap();
						writeln!(w, "\t\tret\n\t}}\n}}").unwrap();

						write!(w, "#[no_mangle]\npub extern \"C\" fn {}_as_{}(this_arg: &{}) -> crate::{} {{\n", ident, trait_obj.ident, ident, full_trait_path).unwrap();
						writeln!(w, "\tcrate::{} {{", full_trait_path).unwrap();
						writeln!(w, "\t\tthis_arg: unsafe {{ (*this_arg).inner as *mut c_void }},").unwrap();
						writeln!(w, "\t\tfree: None,").unwrap();

						macro_rules! write_meth {
							($m: expr, $trait: expr, $indent: expr) => {
								let trait_method = $trait.items.iter().filter_map(|item| {
									if let syn::TraitItem::Method(t_m) = item { Some(t_m) } else { None }
								}).find(|trait_meth| trait_meth.sig.ident == $m.sig.ident).unwrap();
								match export_status(&trait_method.attrs) {
									ExportStatus::Export => {},
									ExportStatus::NoExport => {
										write!(w, "{}\t\t//XXX: Need to export {}\n", $indent, $m.sig.ident).unwrap();
										continue;
									},
									ExportStatus::TestOnly => continue,
								}

								let mut printed = false;
								if let syn::ReturnType::Type(_, rtype) = &$m.sig.output {
									if let syn::Type::Reference(r) = &**rtype {
										write!(w, "\n\t\t{}{}: ", $indent, $m.sig.ident).unwrap();
										types.write_empty_rust_val(Some(&gen_types), w, &*r.elem);
										writeln!(w, ",\n{}\t\tset_{}: Some({}_{}_set_{}),", $indent, $m.sig.ident, ident, trait_obj.ident, $m.sig.ident).unwrap();
										printed = true;
									}
								}
								if !printed {
									write!(w, "{}\t\t{}: {}_{}_{},\n", $indent, $m.sig.ident, ident, trait_obj.ident, $m.sig.ident).unwrap();
								}
							}
						}
						for item in trait_obj.items.iter() {
							match item {
								syn::TraitItem::Method(m) => {
									write_meth!(m, trait_obj, "");
								},
								_ => {},
							}
						}
						walk_supertraits!(trait_obj, Some(&types), (
							("Clone", _) => {
								writeln!(w, "\t\tclone: Some({}_clone_void),", ident).unwrap();
							},
							("Sync", _) => {}, ("Send", _) => {},
							("std::marker::Sync", _) => {}, ("std::marker::Send", _) => {},
							(s, t) => {
								if let Some(supertrait_obj) = types.crate_types.traits.get(s) {
									writeln!(w, "\t\t{}: crate::{} {{", t, s).unwrap();
									writeln!(w, "\t\t\tthis_arg: unsafe {{ (*this_arg).inner as *mut c_void }},").unwrap();
									writeln!(w, "\t\t\tfree: None,").unwrap();
									for item in supertrait_obj.items.iter() {
										match item {
											syn::TraitItem::Method(m) => {
												write_meth!(m, supertrait_obj, "\t");
											},
											_ => {},
										}
									}
									write!(w, "\t\t}},\n").unwrap();
								} else {
									write_trait_impl_field_assign(w, s, ident);
								}
							}
						) );
						write!(w, "\t}}\n}}\nuse {}::{} as {}TraitImport;\n", types.orig_crate, full_trait_path, trait_obj.ident).unwrap();

						macro_rules! impl_meth {
							($m: expr, $trait: expr, $indent: expr) => {
								let trait_method = $trait.items.iter().filter_map(|item| {
									if let syn::TraitItem::Method(t_m) = item { Some(t_m) } else { None }
								}).find(|trait_meth| trait_meth.sig.ident == $m.sig.ident).unwrap();
								match export_status(&trait_method.attrs) {
									ExportStatus::Export => {},
									ExportStatus::NoExport|ExportStatus::TestOnly => continue,
								}

								if let syn::ReturnType::Type(_, _) = &$m.sig.output {
									writeln!(w, "#[must_use]").unwrap();
								}
								write!(w, "extern \"C\" fn {}_{}_{}(", ident, trait_obj.ident, $m.sig.ident).unwrap();
								gen_types.push_ctx();
								assert!(gen_types.learn_generics(&$m.sig.generics, types));
								write_method_params(w, &$m.sig, "c_void", types, Some(&gen_types), true, true);
								write!(w, " {{\n\t").unwrap();
								write_method_var_decl_body(w, &$m.sig, "", types, Some(&gen_types), false);
								let mut takes_self = false;
								for inp in $m.sig.inputs.iter() {
									if let syn::FnArg::Receiver(_) = inp {
										takes_self = true;
									}
								}
								if takes_self {
									write!(w, "unsafe {{ &mut *(this_arg as *mut native{}) }}.{}(", ident, $m.sig.ident).unwrap();
								} else {
									write!(w, "{}::{}::{}(", types.orig_crate, resolved_path, $m.sig.ident).unwrap();
								}

								let mut real_type = "".to_string();
								match &$m.sig.output {
									syn::ReturnType::Type(_, rtype) => {
										if let Some(mut remaining_path) = first_seg_self(&*rtype) {
											if let Some(associated_seg) = get_single_remaining_path_seg(&mut remaining_path) {
												real_type = format!("{}", impl_associated_types.get(associated_seg).unwrap());
											}
										}
									},
									_ => {},
								}
								write_method_call_params(w, &$m.sig, "", types, Some(&gen_types), &real_type, false);
								gen_types.pop_ctx();
								write!(w, "\n}}\n").unwrap();
								if let syn::ReturnType::Type(_, rtype) = &$m.sig.output {
									if let syn::Type::Reference(r) = &**rtype {
										assert_eq!($m.sig.inputs.len(), 1); // Must only take self
										writeln!(w, "extern \"C\" fn {}_{}_set_{}(trait_self_arg: &{}) {{", ident, trait_obj.ident, $m.sig.ident, trait_obj.ident).unwrap();
										writeln!(w, "\t// This is a bit race-y in the general case, but for our specific use-cases today, we're safe").unwrap();
										writeln!(w, "\t// Specifically, we must ensure that the first time we're called it can never be in parallel").unwrap();
										write!(w, "\tif ").unwrap();
										types.write_empty_rust_val_check(Some(&gen_types), w, &*r.elem, &format!("trait_self_arg.{}", $m.sig.ident));
										writeln!(w, " {{").unwrap();
										writeln!(w, "\t\tunsafe {{ &mut *(trait_self_arg as *const {}  as *mut {}) }}.{} = {}_{}_{}(trait_self_arg.this_arg);", trait_obj.ident, trait_obj.ident, $m.sig.ident, ident, trait_obj.ident, $m.sig.ident).unwrap();
										writeln!(w, "\t}}").unwrap();
										writeln!(w, "}}").unwrap();
									}
								}
							}
						}

						for item in i.items.iter() {
							match item {
								syn::ImplItem::Method(m) => {
									impl_meth!(m, trait_obj, "");
								},
								syn::ImplItem::Type(_) => {},
								_ => unimplemented!(),
							}
						}
						walk_supertraits!(trait_obj, Some(&types), (
							(s, t) => {
								if let Some(supertrait_obj) = types.crate_types.traits.get(s).cloned() {
									writeln!(w, "use {}::{} as native{}Trait;", types.orig_crate, s, t).unwrap();
									for item in supertrait_obj.items.iter() {
										match item {
											syn::TraitItem::Method(m) => {
												impl_meth!(m, supertrait_obj, "\t");
											},
											_ => {},
										}
									}
								}
							}
						) );
						write!(w, "\n").unwrap();
					} else if path_matches_nongeneric(&trait_path.1, &["From"]) {
					} else if path_matches_nongeneric(&trait_path.1, &["Default"]) {
						write!(w, "#[must_use]\n#[no_mangle]\npub extern \"C\" fn {}_default() -> {} {{\n", ident, ident).unwrap();
						write!(w, "\t{} {{ inner: Box::into_raw(Box::new(Default::default())), is_owned: true }}\n", ident).unwrap();
						write!(w, "}}\n").unwrap();
					} else if path_matches_nongeneric(&trait_path.1, &["core", "cmp", "PartialEq"]) {
					} else if path_matches_nongeneric(&trait_path.1, &["core", "clone", "Clone"]) && types.c_type_has_inner_from_path(&resolved_path) {
						writeln!(w, "impl Clone for {} {{", ident).unwrap();
						writeln!(w, "\tfn clone(&self) -> Self {{").unwrap();
						writeln!(w, "\t\tSelf {{").unwrap();
						writeln!(w, "\t\t\tinner: if self.inner.is_null() {{ std::ptr::null_mut() }} else {{").unwrap();
						writeln!(w, "\t\t\t\tBox::into_raw(Box::new(unsafe {{ &*self.inner }}.clone())) }},").unwrap();
						writeln!(w, "\t\t\tis_owned: true,").unwrap();
						writeln!(w, "\t\t}}\n\t}}\n}}").unwrap();
						writeln!(w, "#[allow(unused)]").unwrap();
						writeln!(w, "/// Used only if an object of this type is returned as a trait impl by a method").unwrap();
						writeln!(w, "pub(crate) extern \"C\" fn {}_clone_void(this_ptr: *const c_void) -> *mut c_void {{", ident).unwrap();
						writeln!(w, "\tBox::into_raw(Box::new(unsafe {{ (*(this_ptr as *mut native{})).clone() }})) as *mut c_void", ident).unwrap();
						writeln!(w, "}}").unwrap();
						writeln!(w, "#[no_mangle]").unwrap();
						writeln!(w, "pub extern \"C\" fn {}_clone(orig: &{}) -> {} {{", ident, ident, ident).unwrap();
						writeln!(w, "\torig.clone()").unwrap();
						writeln!(w, "}}").unwrap();
					} else {
						//XXX: implement for other things like ToString
						// If we have no generics, try a manual implementation:
						maybe_convert_trait_impl(w, &trait_path.1, &*i.self_ty, types, &gen_types);
					}
				} else {
					let declared_type = (*types.get_declared_type(&ident).unwrap()).clone();
					for item in i.items.iter() {
						match item {
							syn::ImplItem::Method(m) => {
								if let syn::Visibility::Public(_) = m.vis {
									match export_status(&m.attrs) {
										ExportStatus::Export => {},
										ExportStatus::NoExport|ExportStatus::TestOnly => continue,
									}
									if m.defaultness.is_some() { unimplemented!(); }
									writeln_docs(w, &m.attrs, "");
									if let syn::ReturnType::Type(_, _) = &m.sig.output {
										writeln!(w, "#[must_use]").unwrap();
									}
									write!(w, "#[no_mangle]\npub extern \"C\" fn {}_{}(", ident, m.sig.ident).unwrap();
									let ret_type = match &declared_type {
										DeclType::MirroredEnum => format!("{}", ident),
										DeclType::StructImported => format!("{}", ident),
										_ => unimplemented!(),
									};
									gen_types.push_ctx();
									assert!(gen_types.learn_generics(&m.sig.generics, types));
									write_method_params(w, &m.sig, &ret_type, types, Some(&gen_types), false, true);
									write!(w, " {{\n\t").unwrap();
									write_method_var_decl_body(w, &m.sig, "", types, Some(&gen_types), false);
									let mut takes_self = false;
									let mut takes_mut_self = false;
									for inp in m.sig.inputs.iter() {
										if let syn::FnArg::Receiver(r) = inp {
											takes_self = true;
											if r.mutability.is_some() { takes_mut_self = true; }
										}
									}
									if takes_mut_self {
										write!(w, "unsafe {{ &mut (*(this_arg.inner as *mut native{})) }}.{}(", ident, m.sig.ident).unwrap();
									} else if takes_self {
										write!(w, "unsafe {{ &*this_arg.inner }}.{}(", m.sig.ident).unwrap();
									} else {
										write!(w, "{}::{}::{}(", types.orig_crate, resolved_path, m.sig.ident).unwrap();
									}
									write_method_call_params(w, &m.sig, "", types, Some(&gen_types), &ret_type, false);
									gen_types.pop_ctx();
									writeln!(w, "\n}}\n").unwrap();
								}
							},
							_ => {},
						}
					}
				}
			} else {
				eprintln!("Not implementing anything for {} due to no-resolve (probably the type isn't pub or its marked not exported)", ident);
			}
		}
	}
}


/// Print a mapping of an enum. If all of the enum's fields are C-mapped in some form (or the enum
/// is unitary), we generate an equivalent enum with all types replaced with their C mapped
/// versions followed by conversion functions which map between the Rust version and the C mapped
/// version.
fn writeln_enum<'a, 'b, W: std::io::Write>(w: &mut W, e: &'a syn::ItemEnum, types: &mut TypeResolver<'b, 'a>, extra_headers: &mut File, cpp_headers: &mut File) {
	match export_status(&e.attrs) {
		ExportStatus::Export => {},
		ExportStatus::NoExport|ExportStatus::TestOnly => return,
	}

	if is_enum_opaque(e) {
		eprintln!("Skipping enum {} as it contains non-unit fields", e.ident);
		writeln_opaque(w, &e.ident, &format!("{}", e.ident), &e.generics, &e.attrs, types, extra_headers, cpp_headers);
		return;
	}
	writeln_docs(w, &e.attrs, "");

	if e.generics.lt_token.is_some() {
		unimplemented!();
	}

	let mut needs_free = false;

	writeln!(w, "#[must_use]\n#[derive(Clone)]\n#[repr(C)]\npub enum {} {{", e.ident).unwrap();
	for var in e.variants.iter() {
		assert_eq!(export_status(&var.attrs), ExportStatus::Export); // We can't partially-export a mirrored enum
		writeln_docs(w, &var.attrs, "\t");
		write!(w, "\t{}", var.ident).unwrap();
		if let syn::Fields::Named(fields) = &var.fields {
			needs_free = true;
			writeln!(w, " {{").unwrap();
			for field in fields.named.iter() {
				if export_status(&field.attrs) == ExportStatus::TestOnly { continue; }
				write!(w, "\t\t{}: ", field.ident.as_ref().unwrap()).unwrap();
				types.write_c_type(w, &field.ty, None, false);
				writeln!(w, ",").unwrap();
			}
			write!(w, "\t}}").unwrap();
		}
		if var.discriminant.is_some() { unimplemented!(); }
		writeln!(w, ",").unwrap();
	}
	writeln!(w, "}}\nuse {}::{}::{} as native{};\nimpl {} {{", types.orig_crate, types.module_path, e.ident, e.ident, e.ident).unwrap();

	macro_rules! write_conv {
		($fn_sig: expr, $to_c: expr, $ref: expr) => {
			writeln!(w, "\t#[allow(unused)]\n\tpub(crate) fn {} {{\n\t\tmatch {} {{", $fn_sig, if $to_c { "native" } else { "self" }).unwrap();
			for var in e.variants.iter() {
				write!(w, "\t\t\t{}{}::{} ", if $to_c { "native" } else { "" }, e.ident, var.ident).unwrap();
				if let syn::Fields::Named(fields) = &var.fields {
					write!(w, "{{").unwrap();
					for field in fields.named.iter() {
						if export_status(&field.attrs) == ExportStatus::TestOnly { continue; }
						write!(w, "{}{}, ", if $ref { "ref " } else { "mut " }, field.ident.as_ref().unwrap()).unwrap();
					}
					write!(w, "}} ").unwrap();
				}
				write!(w, "=>").unwrap();
				if let syn::Fields::Named(fields) = &var.fields {
					write!(w, " {{\n\t\t\t\t").unwrap();
					for field in fields.named.iter() {
						if export_status(&field.attrs) == ExportStatus::TestOnly { continue; }
						let mut sink = ::std::io::sink();
						let mut out: &mut dyn std::io::Write = if $ref { &mut sink } else { w };
						let new_var = if $to_c {
							types.write_to_c_conversion_new_var(&mut out, field.ident.as_ref().unwrap(), &field.ty, None, false)
						} else {
							types.write_from_c_conversion_new_var(&mut out, field.ident.as_ref().unwrap(), &field.ty, None)
						};
						if $ref || new_var {
							if $ref {
								write!(w, "let mut {}_nonref = (*{}).clone();\n\t\t\t\t", field.ident.as_ref().unwrap(), field.ident.as_ref().unwrap()).unwrap();
								if new_var {
									let nonref_ident = syn::Ident::new(&format!("{}_nonref", field.ident.as_ref().unwrap()), Span::call_site());
									if $to_c {
										types.write_to_c_conversion_new_var(w, &nonref_ident, &field.ty, None, false);
									} else {
										types.write_from_c_conversion_new_var(w, &nonref_ident, &field.ty, None);
									}
									write!(w, "\n\t\t\t\t").unwrap();
								}
							} else {
								write!(w, "\n\t\t\t\t").unwrap();
							}
						}
					}
				} else { write!(w, " ").unwrap(); }
				write!(w, "{}{}::{}", if $to_c { "" } else { "native" }, e.ident, var.ident).unwrap();
				if let syn::Fields::Named(fields) = &var.fields {
					write!(w, " {{").unwrap();
					for field in fields.named.iter() {
						if export_status(&field.attrs) == ExportStatus::TestOnly { continue; }
						write!(w, "\n\t\t\t\t\t{}: ", field.ident.as_ref().unwrap()).unwrap();
						if $to_c {
							types.write_to_c_conversion_inline_prefix(w, &field.ty, None, false);
						} else {
							types.write_from_c_conversion_prefix(w, &field.ty, None);
						}
						write!(w, "{}{}",
							field.ident.as_ref().unwrap(),
							if $ref { "_nonref" } else { "" }).unwrap();
						if $to_c {
							types.write_to_c_conversion_inline_suffix(w, &field.ty, None, false);
						} else {
							types.write_from_c_conversion_suffix(w, &field.ty, None);
						}
						write!(w, ",").unwrap();
					}
					writeln!(w, "\n\t\t\t\t}}").unwrap();
					write!(w, "\t\t\t}}").unwrap();
				}
				writeln!(w, ",").unwrap();
			}
			writeln!(w, "\t\t}}\n\t}}").unwrap();
		}
	}

	write_conv!(format!("to_native(&self) -> native{}", e.ident), false, true);
	write_conv!(format!("into_native(self) -> native{}", e.ident), false, false);
	write_conv!(format!("from_native(native: &native{}) -> Self", e.ident), true, true);
	write_conv!(format!("native_into(native: native{}) -> Self", e.ident), true, false);
	writeln!(w, "}}").unwrap();

	if needs_free {
		writeln!(w, "#[no_mangle]\npub extern \"C\" fn {}_free(this_ptr: {}) {{ }}", e.ident, e.ident).unwrap();
	}
	writeln!(w, "#[no_mangle]").unwrap();
	writeln!(w, "pub extern \"C\" fn {}_clone(orig: &{}) -> {} {{", e.ident, e.ident, e.ident).unwrap();
	writeln!(w, "\torig.clone()").unwrap();
	writeln!(w, "}}").unwrap();
	write_cpp_wrapper(cpp_headers, &format!("{}", e.ident), needs_free);
}

fn writeln_fn<'a, 'b, W: std::io::Write>(w: &mut W, f: &'a syn::ItemFn, types: &mut TypeResolver<'b, 'a>) {
	match export_status(&f.attrs) {
		ExportStatus::Export => {},
		ExportStatus::NoExport|ExportStatus::TestOnly => return,
	}
	writeln_docs(w, &f.attrs, "");

	let mut gen_types = GenericTypes::new();
	if !gen_types.learn_generics(&f.sig.generics, types) { return; }

	write!(w, "#[no_mangle]\npub extern \"C\" fn {}(", f.sig.ident).unwrap();
	write_method_params(w, &f.sig, "", types, Some(&gen_types), false, true);
	write!(w, " {{\n\t").unwrap();
	write_method_var_decl_body(w, &f.sig, "", types, Some(&gen_types), false);
	write!(w, "{}::{}::{}(", types.orig_crate, types.module_path, f.sig.ident).unwrap();
	write_method_call_params(w, &f.sig, "", types, Some(&gen_types), "", false);
	writeln!(w, "\n}}\n").unwrap();
}

// ********************************
// *** File/Crate Walking Logic ***
// ********************************
/// A public module
struct ASTModule {
	pub attrs: Vec<syn::Attribute>,
	pub items: Vec<syn::Item>,
	pub submods: Vec<String>,
}
/// A struct containing the syn::File AST for each file in the crate.
struct FullLibraryAST {
	modules: HashMap<String, ASTModule, NonRandomHash>,
}
impl FullLibraryAST {
	fn load_module(&mut self, module: String, attrs: Vec<syn::Attribute>, mut items: Vec<syn::Item>) {
		let mut non_mod_items = Vec::with_capacity(items.len());
		let mut submods = Vec::with_capacity(items.len());
		for item in items.drain(..) {
			match item {
				syn::Item::Mod(m) if m.content.is_some() => {
					if export_status(&m.attrs) == ExportStatus::Export {
						if let syn::Visibility::Public(_) = m.vis {
							let modident = format!("{}", m.ident);
							let modname = if module != "" {
								module.clone() + "::" + &modident
							} else {
								modident.clone()
							};
							self.load_module(modname, m.attrs, m.content.unwrap().1);
							submods.push(modident);
						}
					}
				},
				_ => { non_mod_items.push(item); }
			}
		}
		self.modules.insert(module, ASTModule { attrs, items: non_mod_items, submods });
	}

	pub fn load_lib(lib: syn::File) -> Self {
		assert_eq!(export_status(&lib.attrs), ExportStatus::Export);
		let mut res = Self { modules: HashMap::default() };
		res.load_module("".to_owned(), lib.attrs, lib.items);
		res
	}
}

/// Do the Real Work of mapping an original file to C-callable wrappers. Creates a new file at
/// `out_path` and fills it with wrapper structs/functions to allow calling the things in the AST
/// at `module` from C.
fn convert_file<'a, 'b>(libast: &'a FullLibraryAST, crate_types: &mut CrateTypes<'a>, out_dir: &str, orig_crate: &str, header_file: &mut File, cpp_header_file: &mut File) {
	for (module, astmod) in libast.modules.iter() {
		let ASTModule { ref attrs, ref items, ref submods } = astmod;
		assert_eq!(export_status(&attrs), ExportStatus::Export);

		let new_file_path = if submods.is_empty() {
			format!("{}/{}.rs", out_dir, module.replace("::", "/"))
		} else if module != "" {
			format!("{}/{}/mod.rs", out_dir, module.replace("::", "/"))
		} else {
			format!("{}/lib.rs", out_dir)
		};
		let _ = std::fs::create_dir((&new_file_path.as_ref() as &std::path::Path).parent().unwrap());
		let mut out = std::fs::OpenOptions::new().write(true).create(true).truncate(true)
			.open(new_file_path).expect("Unable to open new src file");

		writeln_docs(&mut out, &attrs, "");

		if module == "" {
			// Special-case the top-level lib.rs with various lint allows and a pointer to the c_types
			// and bitcoin hand-written modules.
			writeln!(out, "#![allow(unknown_lints)]").unwrap();
			writeln!(out, "#![allow(non_camel_case_types)]").unwrap();
			writeln!(out, "#![allow(non_snake_case)]").unwrap();
			writeln!(out, "#![allow(unused_imports)]").unwrap();
			writeln!(out, "#![allow(unused_variables)]").unwrap();
			writeln!(out, "#![allow(unused_mut)]").unwrap();
			writeln!(out, "#![allow(unused_parens)]").unwrap();
			writeln!(out, "#![allow(unused_unsafe)]").unwrap();
			writeln!(out, "#![allow(unused_braces)]").unwrap();
			writeln!(out, "mod c_types;").unwrap();
			writeln!(out, "mod bitcoin;").unwrap();
		} else {
			writeln!(out, "\nuse std::ffi::c_void;\nuse bitcoin::hashes::Hash;\nuse crate::c_types::*;\n").unwrap();
		}

		for m in submods {
			writeln!(out, "pub mod {};", m).unwrap();
		}

		eprintln!("Converting {} entries...", module);

		let import_resolver = ImportResolver::new(module, items);
		let mut type_resolver = TypeResolver::new(orig_crate, module, import_resolver, crate_types);

		for item in items.iter() {
			match item {
				syn::Item::Use(_) => {}, // Handled above
				syn::Item::Static(_) => {},
				syn::Item::Enum(e) => {
					if let syn::Visibility::Public(_) = e.vis {
						writeln_enum(&mut out, &e, &mut type_resolver, header_file, cpp_header_file);
					}
				},
				syn::Item::Impl(i) => {
					writeln_impl(&mut out, &i, &mut type_resolver);
				},
				syn::Item::Struct(s) => {
					if let syn::Visibility::Public(_) = s.vis {
						writeln_struct(&mut out, &s, &mut type_resolver, header_file, cpp_header_file);
					}
				},
				syn::Item::Trait(t) => {
					if let syn::Visibility::Public(_) = t.vis {
						writeln_trait(&mut out, &t, &mut type_resolver, header_file, cpp_header_file);
					}
				},
				syn::Item::Mod(_) => {}, // We don't have to do anything - the top loop handles these.
				syn::Item::Const(c) => {
					// Re-export any primitive-type constants.
					if let syn::Visibility::Public(_) = c.vis {
						if let syn::Type::Path(p) = &*c.ty {
							let resolved_path = type_resolver.resolve_path(&p.path, None);
							if type_resolver.is_primitive(&resolved_path) {
								writeln!(out, "\n#[no_mangle]").unwrap();
								writeln!(out, "pub static {}: {} = {}::{}::{};", c.ident, resolved_path, orig_crate, module, c.ident).unwrap();
							}
						}
					}
				},
				syn::Item::Type(t) => {
					if let syn::Visibility::Public(_) = t.vis {
						match export_status(&t.attrs) {
							ExportStatus::Export => {},
							ExportStatus::NoExport|ExportStatus::TestOnly => continue,
						}

						let mut process_alias = true;
						for tok in t.generics.params.iter() {
							if let syn::GenericParam::Lifetime(_) = tok {}
							else { process_alias = false; }
						}
						if process_alias {
							match &*t.ty {
								syn::Type::Path(_) =>
									writeln_opaque(&mut out, &t.ident, &format!("{}", t.ident), &t.generics, &t.attrs, &type_resolver, header_file, cpp_header_file),
								_ => {}
							}
						}
					}
				},
				syn::Item::Fn(f) => {
					if let syn::Visibility::Public(_) = f.vis {
						writeln_fn(&mut out, &f, &mut type_resolver);
					}
				},
				syn::Item::Macro(m) => {
					if m.ident.is_none() { // If its not a macro definition
						convert_macro(&mut out, &m.mac.path, &m.mac.tokens, &type_resolver);
					}
				},
				syn::Item::Verbatim(_) => {},
				syn::Item::ExternCrate(_) => {},
				_ => unimplemented!(),
			}
		}

		out.flush().unwrap();
	}
}

/// Insert ident -> absolute Path resolutions into imports from the given UseTree and path-prefix.
fn process_use_intern<'a>(u: &'a syn::UseTree, mut path: syn::punctuated::Punctuated<syn::PathSegment, syn::token::Colon2>, imports: &mut HashMap<&'a syn::Ident, syn::Path>) {
	match u {
		syn::UseTree::Path(p) => {
			path.push(syn::PathSegment { ident: p.ident.clone(), arguments: syn::PathArguments::None });
			process_use_intern(&p.tree, path, imports);
		},
		syn::UseTree::Name(n) => {
			path.push(syn::PathSegment { ident: n.ident.clone(), arguments: syn::PathArguments::None });
			imports.insert(&n.ident, syn::Path { leading_colon: Some(syn::Token![::](Span::call_site())), segments: path });
		},
		syn::UseTree::Group(g) => {
			for i in g.items.iter() {
				process_use_intern(i, path.clone(), imports);
			}
		},
		_ => {}
	}
}

/// Map all the Paths in a Type into absolute paths given a set of imports (generated via process_use_intern)
fn resolve_imported_refs(imports: &HashMap<&syn::Ident, syn::Path>, mut ty: syn::Type) -> syn::Type {
	match &mut ty {
		syn::Type::Path(p) => {
			if let Some(ident) = p.path.get_ident() {
				if let Some(newpath) = imports.get(ident) {
					p.path = newpath.clone();
				}
			} else { unimplemented!(); }
		},
		syn::Type::Reference(r) => {
			r.elem = Box::new(resolve_imported_refs(imports, (*r.elem).clone()));
		},
		syn::Type::Slice(s) => {
			s.elem = Box::new(resolve_imported_refs(imports, (*s.elem).clone()));
		},
		syn::Type::Tuple(t) => {
			for e in t.elems.iter_mut() {
				*e = resolve_imported_refs(imports, e.clone());
			}
		},
		_ => unimplemented!(),
	}
	ty
}

/// Walk the FullLibraryAST, deciding how things will be mapped and adding tracking to CrateTypes.
fn walk_ast<'a>(ast_storage: &'a FullLibraryAST, crate_types: &mut CrateTypes<'a>) {
	for (module, astmod) in ast_storage.modules.iter() {
		let ASTModule { ref attrs, ref items, submods: _ } = astmod;
		assert_eq!(export_status(&attrs), ExportStatus::Export);
		let mut import_maps = HashMap::new();

		for item in items.iter() {
			match item {
				syn::Item::Use(u) => {
					process_use_intern(&u.tree, syn::punctuated::Punctuated::new(), &mut import_maps);
				},
				syn::Item::Struct(s) => {
					if let syn::Visibility::Public(_) = s.vis {
						match export_status(&s.attrs) {
							ExportStatus::Export => {},
							ExportStatus::NoExport|ExportStatus::TestOnly => continue,
						}
						let struct_path = format!("{}::{}", module, s.ident);
						crate_types.opaques.insert(struct_path, &s.ident);
					}
				},
				syn::Item::Trait(t) => {
					if let syn::Visibility::Public(_) = t.vis {
						match export_status(&t.attrs) {
							ExportStatus::Export => {},
							ExportStatus::NoExport|ExportStatus::TestOnly => continue,
						}
						let trait_path = format!("{}::{}", module, t.ident);
						walk_supertraits!(t, None, (
							("Clone", _) => {
								crate_types.clonable_types.insert("crate::".to_owned() + &trait_path);
							},
							(_, _) => {}
						) );
						crate_types.traits.insert(trait_path, &t);
					}
				},
				syn::Item::Type(t) => {
					if let syn::Visibility::Public(_) = t.vis {
						match export_status(&t.attrs) {
							ExportStatus::Export => {},
							ExportStatus::NoExport|ExportStatus::TestOnly => continue,
						}
						let type_path = format!("{}::{}", module, t.ident);
						let mut process_alias = true;
						for tok in t.generics.params.iter() {
							if let syn::GenericParam::Lifetime(_) = tok {}
							else { process_alias = false; }
						}
						if process_alias {
							match &*t.ty {
								syn::Type::Path(_) => {
									// If its a path with no generics, assume we don't map the aliased type and map it opaque
									crate_types.opaques.insert(type_path, &t.ident);
								},
								_ => {
									crate_types.type_aliases.insert(type_path, resolve_imported_refs(&import_maps, (*t.ty).clone()));
								}
							}
						}
					}
				},
				syn::Item::Enum(e) if is_enum_opaque(e) => {
					if let syn::Visibility::Public(_) = e.vis {
						match export_status(&e.attrs) {
							ExportStatus::Export => {},
							ExportStatus::NoExport|ExportStatus::TestOnly => continue,
						}
						let enum_path = format!("{}::{}", module, e.ident);
						crate_types.opaques.insert(enum_path, &e.ident);
					}
				},
				syn::Item::Enum(e) => {
					if let syn::Visibility::Public(_) = e.vis {
						match export_status(&e.attrs) {
							ExportStatus::Export => {},
							ExportStatus::NoExport|ExportStatus::TestOnly => continue,
						}
						let enum_path = format!("{}::{}", module, e.ident);
						crate_types.mirrored_enums.insert(enum_path, &e);
					}
				},
				syn::Item::Impl(i) => {
					if let &syn::Type::Path(ref p) = &*i.self_ty {
						if let Some(trait_path) = i.trait_.as_ref() {
							if path_matches_nongeneric(&trait_path.1, &["core", "clone", "Clone"]) {
								// Note, we should probably have more full-featured type resolution here,
								// but for now we don't have any cases where we impl X for A::B.
								let ident = single_ident_generic_path_to_ident(&p.path).expect("impl X for A::B currently unsupported");
								assert!(import_maps.get(&ident).is_none());
								crate_types.clonable_types.insert(format!("crate::{}::{}", module, ident));
							}
						}
					}
				},
				_ => {},
			}
		}
	}
}

fn main() {
	let args: Vec<String> = env::args().collect();
	if args.len() != 6 {
		eprintln!("Usage: target/dir source_crate_name derived_templates.rs extra/includes.h extra/cpp/includes.hpp");
		process::exit(1);
	}

	let mut derived_templates = std::fs::OpenOptions::new().write(true).create(true).truncate(true)
		.open(&args[3]).expect("Unable to open new header file");
	let mut header_file = std::fs::OpenOptions::new().write(true).create(true).truncate(true)
		.open(&args[4]).expect("Unable to open new header file");
	let mut cpp_header_file = std::fs::OpenOptions::new().write(true).create(true).truncate(true)
		.open(&args[5]).expect("Unable to open new header file");

	writeln!(header_file, "#if defined(__GNUC__)").unwrap();
	writeln!(header_file, "#define MUST_USE_STRUCT __attribute__((warn_unused))").unwrap();
	writeln!(header_file, "#define MUST_USE_RES __attribute__((warn_unused_result))").unwrap();
	writeln!(header_file, "#else").unwrap();
	writeln!(header_file, "#define MUST_USE_STRUCT").unwrap();
	writeln!(header_file, "#define MUST_USE_RES").unwrap();
	writeln!(header_file, "#endif").unwrap();
	writeln!(header_file, "#if defined(__clang__)").unwrap();
	writeln!(header_file, "#define NONNULL_PTR _Nonnull").unwrap();
	writeln!(header_file, "#else").unwrap();
	writeln!(header_file, "#define NONNULL_PTR").unwrap();
	writeln!(header_file, "#endif").unwrap();
	writeln!(cpp_header_file, "#include <string.h>\nnamespace LDK {{").unwrap();

	// First parse the full crate's ASTs, caching them so that we can hold references to the AST
	// objects in other datastructures:
	let mut lib_src = String::new();
	std::io::stdin().lock().read_to_string(&mut lib_src).unwrap();
	let lib_syntax = syn::parse_file(&lib_src).expect("Unable to parse file");
	let libast = FullLibraryAST::load_lib(lib_syntax);

	// ...then walk the ASTs tracking what types we will map, and how, so that we can resolve them
	// when parsing other file ASTs...
	let mut libtypes = CrateTypes { traits: HashMap::new(), opaques: HashMap::new(), mirrored_enums: HashMap::new(),
		type_aliases: HashMap::new(), templates_defined: HashMap::default(), template_file: &mut derived_templates,
		clonable_types: HashSet::new() };
	walk_ast(&libast, &mut libtypes);

	// ... finally, do the actual file conversion/mapping, writing out types as we go.
	convert_file(&libast, &mut libtypes, &args[1], &args[2], &mut header_file, &mut cpp_header_file);

	// For container templates which we created while walking the crate, make sure we add C++
	// mapped types so that C++ users can utilize the auto-destructors available.
	for (ty, has_destructor) in libtypes.templates_defined.iter() {
		write_cpp_wrapper(&mut cpp_header_file, ty, *has_destructor);
	}
	writeln!(cpp_header_file, "}}").unwrap();

	header_file.flush().unwrap();
	cpp_header_file.flush().unwrap();
	derived_templates.flush().unwrap();
}
