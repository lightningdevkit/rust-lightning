use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Write;
use std::hash;

use crate::blocks::*;

use proc_macro2::{TokenTree, Span};

// The following utils are used purely to build our known types maps - they break down all the
// types we need to resolve to include the given object, and no more.

pub fn first_seg_self<'a>(t: &'a syn::Type) -> Option<impl Iterator<Item=&syn::PathSegment> + 'a> {
	match t {
		syn::Type::Path(p) => {
			if p.qself.is_some() || p.path.leading_colon.is_some() {
				return None;
			}
			let mut segs = p.path.segments.iter();
			let ty = segs.next().unwrap();
			if !ty.arguments.is_empty() { return None; }
			if format!("{}", ty.ident) == "Self" {
				Some(segs)
			} else { None }
		},
		_ => None,
	}
}

pub fn get_single_remaining_path_seg<'a, I: Iterator<Item=&'a syn::PathSegment>>(segs: &mut I) -> Option<&'a syn::Ident> {
	if let Some(ty) = segs.next() {
		if !ty.arguments.is_empty() { unimplemented!(); }
		if segs.next().is_some() { return None; }
		Some(&ty.ident)
	} else { None }
}

pub fn single_ident_generic_path_to_ident(p: &syn::Path) -> Option<&syn::Ident> {
	if p.segments.len() == 1 {
		Some(&p.segments.iter().next().unwrap().ident)
	} else { None }
}

pub fn path_matches_nongeneric(p: &syn::Path, exp: &[&str]) -> bool {
	if p.segments.len() != exp.len() { return false; }
	for (seg, e) in p.segments.iter().zip(exp.iter()) {
		if seg.arguments != syn::PathArguments::None { return false; }
		if &format!("{}", seg.ident) != *e { return false; }
	}
	true
}

#[derive(Debug, PartialEq)]
pub enum ExportStatus {
	Export,
	NoExport,
	TestOnly,
}
/// Gets the ExportStatus of an object (struct, fn, etc) given its attributes.
pub fn export_status(attrs: &[syn::Attribute]) -> ExportStatus {
	for attr in attrs.iter() {
		let tokens_clone = attr.tokens.clone();
		let mut token_iter = tokens_clone.into_iter();
		if let Some(token) = token_iter.next() {
			match token {
				TokenTree::Punct(c) if c.as_char() == '=' => {
					// Really not sure where syn gets '=' from here -
					// it somehow represents '///' or '//!'
				},
				TokenTree::Group(g) => {
					if format!("{}", single_ident_generic_path_to_ident(&attr.path).unwrap()) == "cfg" {
						let mut iter = g.stream().into_iter();
						if let TokenTree::Ident(i) = iter.next().unwrap() {
							if i == "any" {
								// #[cfg(any(test, feature = ""))]
								if let TokenTree::Group(g) = iter.next().unwrap() {
									if let TokenTree::Ident(i) = g.stream().into_iter().next().unwrap() {
										if i == "test" || i == "feature" {
											// If its cfg(feature(...)) we assume its test-only
											return ExportStatus::TestOnly;
										}
									}
								}
							} else if i == "test" || i == "feature" {
								// If its cfg(feature(...)) we assume its test-only
								return ExportStatus::TestOnly;
							}
						}
					}
					continue; // eg #[derive()]
				},
				_ => unimplemented!(),
			}
		} else { continue; }
		match token_iter.next().unwrap() {
			TokenTree::Literal(lit) => {
				let line = format!("{}", lit);
				if line.contains("(C-not exported)") {
					return ExportStatus::NoExport;
				}
			},
			_ => unimplemented!(),
		}
	}
	ExportStatus::Export
}

pub fn assert_simple_bound(bound: &syn::TraitBound) {
	if bound.paren_token.is_some() || bound.lifetimes.is_some() { unimplemented!(); }
	if let syn::TraitBoundModifier::Maybe(_) = bound.modifier { unimplemented!(); }
}

/// A stack of sets of generic resolutions.
///
/// This tracks the template parameters for a function, struct, or trait, allowing resolution into
/// a concrete type. By pushing a new context onto the stack, this can track a function's template
/// parameters inside of a generic struct or trait.
///
/// It maps both direct types as well as Deref<Target = X>, mapping them via the provided
/// TypeResolver's resolve_path function (ie traits map to the concrete jump table, structs to the
/// concrete C container struct, etc).
pub struct GenericTypes<'a> {
	typed_generics: Vec<HashMap<&'a syn::Ident, (String, Option<&'a syn::Path>)>>,
}
impl<'a> GenericTypes<'a> {
	pub fn new() -> Self {
		Self { typed_generics: vec![HashMap::new()], }
	}

	/// push a new context onto the stack, allowing for a new set of generics to be learned which
	/// will override any lower contexts, but which will still fall back to resoltion via lower
	/// contexts.
	pub fn push_ctx(&mut self) {
		self.typed_generics.push(HashMap::new());
	}
	/// pop the latest context off the stack.
	pub fn pop_ctx(&mut self) {
		self.typed_generics.pop();
	}

	/// Learn the generics in generics in the current context, given a TypeResolver.
	pub fn learn_generics<'b, 'c>(&mut self, generics: &'a syn::Generics, types: &'b TypeResolver<'a, 'c>) -> bool {
		// First learn simple generics...
		for generic in generics.params.iter() {
			match generic {
				syn::GenericParam::Type(type_param) => {
					let mut non_lifetimes_processed = false;
					for bound in type_param.bounds.iter() {
						if let syn::TypeParamBound::Trait(trait_bound) = bound {
							if let Some(ident) = single_ident_generic_path_to_ident(&trait_bound.path) {
								match &format!("{}", ident) as &str { "Send" => continue, "Sync" => continue, _ => {} }
							}
							if path_matches_nongeneric(&trait_bound.path, &["core", "clone", "Clone"]) { continue; }

							assert_simple_bound(&trait_bound);
							if let Some(mut path) = types.maybe_resolve_path(&trait_bound.path, None) {
								if types.skip_path(&path) { continue; }
								if non_lifetimes_processed { return false; }
								non_lifetimes_processed = true;
								let new_ident = if path != "std::ops::Deref" {
									path = "crate::".to_string() + &path;
									Some(&trait_bound.path)
								} else { None };
								self.typed_generics.last_mut().unwrap().insert(&type_param.ident, (path, new_ident));
							} else { return false; }
						}
					}
				},
				_ => {},
			}
		}
		// Then find generics where we are required to pass a Deref<Target=X> and pretend its just X.
		if let Some(wh) = &generics.where_clause {
			for pred in wh.predicates.iter() {
				if let syn::WherePredicate::Type(t) = pred {
					if let syn::Type::Path(p) = &t.bounded_ty {
						if p.qself.is_some() { return false; }
						if p.path.leading_colon.is_some() { return false; }
						let mut p_iter = p.path.segments.iter();
						if let Some(gen) = self.typed_generics.last_mut().unwrap().get_mut(&p_iter.next().unwrap().ident) {
							if gen.0 != "std::ops::Deref" { return false; }
							if &format!("{}", p_iter.next().unwrap().ident) != "Target" { return false; }

							let mut non_lifetimes_processed = false;
							for bound in t.bounds.iter() {
								if let syn::TypeParamBound::Trait(trait_bound) = bound {
									if non_lifetimes_processed { return false; }
									non_lifetimes_processed = true;
									assert_simple_bound(&trait_bound);
									*gen = ("crate::".to_string() + &types.resolve_path(&trait_bound.path, None),
										Some(&trait_bound.path));
								}
							}
						} else { return false; }
					} else { return false; }
				}
			}
		}
		for (_, (_, ident)) in self.typed_generics.last().unwrap().iter() {
			if ident.is_none() { return false; }
		}
		true
	}

	/// Learn the associated types from the trait in the current context.
	pub fn learn_associated_types<'b, 'c>(&mut self, t: &'a syn::ItemTrait, types: &'b TypeResolver<'a, 'c>) {
		for item in t.items.iter() {
			match item {
				&syn::TraitItem::Type(ref t) => {
					if t.default.is_some() || t.generics.lt_token.is_some() { unimplemented!(); }
					let mut bounds_iter = t.bounds.iter();
					match bounds_iter.next().unwrap() {
						syn::TypeParamBound::Trait(tr) => {
							assert_simple_bound(&tr);
							if let Some(mut path) = types.maybe_resolve_path(&tr.path, None) {
								if types.skip_path(&path) { continue; }
								// In general we handle Deref<Target=X> as if it were just X (and
								// implement Deref<Target=Self> for relevant types). We don't
								// bother to implement it for associated types, however, so we just
								// ignore such bounds.
								let new_ident = if path != "std::ops::Deref" {
									path = "crate::".to_string() + &path;
									Some(&tr.path)
								} else { None };
								self.typed_generics.last_mut().unwrap().insert(&t.ident, (path, new_ident));
							} else { unimplemented!(); }
						},
						_ => unimplemented!(),
					}
					if bounds_iter.next().is_some() { unimplemented!(); }
				},
				_ => {},
			}
		}
	}

	/// Attempt to resolve an Ident as a generic parameter and return the full path.
	pub fn maybe_resolve_ident<'b>(&'b self, ident: &syn::Ident) -> Option<&'b String> {
		for gen in self.typed_generics.iter().rev() {
			if let Some(res) = gen.get(ident).map(|(a, _)| a) {
				return Some(res);
			}
		}
		None
	}
	/// Attempt to resolve a Path as a generic parameter and return the full path. as both a string
	/// and syn::Path.
	pub fn maybe_resolve_path<'b>(&'b self, path: &syn::Path) -> Option<(&'b String, &'a syn::Path)> {
		if let Some(ident) = path.get_ident() {
			for gen in self.typed_generics.iter().rev() {
				if let Some(res) = gen.get(ident).map(|(a, b)| (a, b.unwrap())) {
					return Some(res);
				}
			}
		} else {
			// Associated types are usually specified as "Self::Generic", so we check for that
			// explicitly here.
			let mut it = path.segments.iter();
			if path.segments.len() == 2 && format!("{}", it.next().unwrap().ident) == "Self" {
				let ident = &it.next().unwrap().ident;
				for gen in self.typed_generics.iter().rev() {
					if let Some(res) = gen.get(ident).map(|(a, b)| (a, b.unwrap())) {
						return Some(res);
					}
				}
			}
		}
		None
	}
}

#[derive(Clone, PartialEq)]
// The type of declaration and the object itself
pub enum DeclType<'a> {
	MirroredEnum,
	Trait(&'a syn::ItemTrait),
	StructImported,
	StructIgnored,
	EnumIgnored,
}

// templates_defined is walked to write the C++ header, so if we use the default hashing it get
// reordered on each genbindings run. Instead, we use SipHasher (which defaults to 0-keys) so that
// the sorting is stable across runs. It is deprecated, but the "replacement" doesn't actually
// accomplish the same goals, so we just ignore it.
#[allow(deprecated)]
pub type NonRandomHash = hash::BuildHasherDefault<hash::SipHasher>;

/// Top-level struct tracking everything which has been defined while walking the crate.
pub struct CrateTypes<'a> {
	/// This may contain structs or enums, but only when either is mapped as
	/// struct X { inner: *mut originalX, .. }
	pub opaques: HashMap<String, &'a syn::Ident>,
	/// Enums which are mapped as C enums with conversion functions
	pub mirrored_enums: HashMap<String, &'a syn::ItemEnum>,
	/// Traits which are mapped as a pointer + jump table
	pub traits: HashMap<String, &'a syn::ItemTrait>,
	/// Aliases from paths to some other Type
	pub type_aliases: HashMap<String, syn::Type>,
	/// Template continer types defined, map from mangled type name -> whether a destructor fn
	/// exists.
	///
	/// This is used at the end of processing to make C++ wrapper classes
	pub templates_defined: HashMap<String, bool, NonRandomHash>,
	/// The output file for any created template container types, written to as we find new
	/// template containers which need to be defined.
	pub template_file: &'a mut File,
	/// Set of containers which are clonable
	pub clonable_types: HashSet<String>,
}

/// A struct which tracks resolving rust types into C-mapped equivalents, exists for one specific
/// module but contains a reference to the overall CrateTypes tracking.
pub struct TypeResolver<'mod_lifetime, 'crate_lft: 'mod_lifetime> {
	pub orig_crate: &'mod_lifetime str,
	pub module_path: &'mod_lifetime str,
	imports: HashMap<syn::Ident, String>,
	// ident -> is-mirrored-enum
	declared: HashMap<syn::Ident, DeclType<'crate_lft>>,
	pub crate_types: &'mod_lifetime mut CrateTypes<'crate_lft>,
}

/// Returned by write_empty_rust_val_check_suffix to indicate what type of dereferencing needs to
/// happen to get the inner value of a generic.
enum EmptyValExpectedTy {
	/// A type which has a flag for being empty (eg an array where we treat all-0s as empty).
	NonPointer,
	/// A pointer that we want to dereference and move out of.
	OwnedPointer,
	/// A pointer which we want to convert to a reference.
	ReferenceAsPointer,
}

impl<'a, 'c: 'a> TypeResolver<'a, 'c> {
	pub fn new(orig_crate: &'a str, module_path: &'a str, crate_types: &'a mut CrateTypes<'c>) -> Self {
		let mut imports = HashMap::new();
		// Add primitives to the "imports" list:
		imports.insert(syn::Ident::new("bool", Span::call_site()), "bool".to_string());
		imports.insert(syn::Ident::new("u64", Span::call_site()), "u64".to_string());
		imports.insert(syn::Ident::new("u32", Span::call_site()), "u32".to_string());
		imports.insert(syn::Ident::new("u16", Span::call_site()), "u16".to_string());
		imports.insert(syn::Ident::new("u8", Span::call_site()), "u8".to_string());
		imports.insert(syn::Ident::new("usize", Span::call_site()), "usize".to_string());
		imports.insert(syn::Ident::new("str", Span::call_site()), "str".to_string());
		imports.insert(syn::Ident::new("String", Span::call_site()), "String".to_string());

		// These are here to allow us to print native Rust types in trait fn impls even if we don't
		// have C mappings:
		imports.insert(syn::Ident::new("Result", Span::call_site()), "Result".to_string());
		imports.insert(syn::Ident::new("Vec", Span::call_site()), "Vec".to_string());
		imports.insert(syn::Ident::new("Option", Span::call_site()), "Option".to_string());
		Self { orig_crate, module_path, imports, declared: HashMap::new(), crate_types }
	}

	// *************************************************
	// *** Well know type and conversion definitions ***
	// *************************************************

	/// Returns true we if can just skip passing this to C entirely
	fn skip_path(&self, full_path: &str) -> bool {
		full_path == "bitcoin::secp256k1::Secp256k1" ||
		full_path == "bitcoin::secp256k1::Signing" ||
		full_path == "bitcoin::secp256k1::Verification"
	}
	/// Returns true we if can just skip passing this to C entirely
	fn no_arg_path_to_rust(&self, full_path: &str) -> &str {
		if full_path == "bitcoin::secp256k1::Secp256k1" {
			"&bitcoin::secp256k1::Secp256k1::new()"
		} else { unimplemented!(); }
	}

	/// Returns true if the object is a primitive and is mapped as-is with no conversion
	/// whatsoever.
	pub fn is_primitive(&self, full_path: &str) -> bool {
		match full_path {
			"bool" => true,
			"u64" => true,
			"u32" => true,
			"u16" => true,
			"u8" => true,
			"usize" => true,
			_ => false,
		}
	}
	pub fn is_clonable(&self, ty: &str) -> bool {
		if self.crate_types.clonable_types.contains(ty) { return true; }
		if self.is_primitive(ty) { return true; }
		match ty {
			"()" => true,
			"crate::c_types::Signature" => true,
			"crate::c_types::TxOut" => true,
			_ => false,
		}
	}
	/// Gets the C-mapped type for types which are outside of the crate, or which are manually
	/// ignored by for some reason need mapping anyway.
	fn c_type_from_path<'b>(&self, full_path: &'b str, is_ref: bool, ptr_for_ref: bool) -> Option<&'b str> {
		if self.is_primitive(full_path) {
			return Some(full_path);
		}
		match full_path {
			"Result" => Some("crate::c_types::derived::CResult"),
			"Vec" if !is_ref => Some("crate::c_types::derived::CVec"),
			"Option" => Some(""),

			// Note that no !is_ref types can map to an array because Rust and C's call semantics
			// for arrays are different (https://github.com/eqrion/cbindgen/issues/528)

			"[u8; 32]" if !is_ref => Some("crate::c_types::ThirtyTwoBytes"),
			"[u8; 16]" if !is_ref => Some("crate::c_types::SixteenBytes"),
			"[u8; 10]" if !is_ref => Some("crate::c_types::TenBytes"),
			"[u8; 4]" if !is_ref => Some("crate::c_types::FourBytes"),
			"[u8; 3]" if !is_ref => Some("crate::c_types::ThreeBytes"), // Used for RGB values

			"str" if is_ref => Some("crate::c_types::Str"),
			"String" if !is_ref => Some("crate::c_types::derived::CVec_u8Z"),
			"String" if is_ref => Some("crate::c_types::Str"),

			"std::time::Duration" => Some("u64"),

			"bitcoin::secp256k1::key::PublicKey" => Some("crate::c_types::PublicKey"),
			"bitcoin::secp256k1::Signature" => Some("crate::c_types::Signature"),
			"bitcoin::secp256k1::key::SecretKey" if is_ref  => Some("*const [u8; 32]"),
			"bitcoin::secp256k1::key::SecretKey" if !is_ref => Some("crate::c_types::SecretKey"),
			"bitcoin::secp256k1::Error" if !is_ref => Some("crate::c_types::Secp256k1Error"),
			"bitcoin::blockdata::script::Script" if is_ref => Some("crate::c_types::u8slice"),
			"bitcoin::blockdata::script::Script" if !is_ref => Some("crate::c_types::derived::CVec_u8Z"),
			"bitcoin::blockdata::transaction::OutPoint" => Some("crate::chain::transaction::OutPoint"),
			"bitcoin::blockdata::transaction::Transaction" => Some("crate::c_types::Transaction"),
			"bitcoin::blockdata::transaction::TxOut" if !is_ref => Some("crate::c_types::TxOut"),
			"bitcoin::network::constants::Network" => Some("crate::bitcoin::network::Network"),
			"bitcoin::blockdata::block::BlockHeader" if is_ref  => Some("*const [u8; 80]"),
			"bitcoin::blockdata::block::Block" if is_ref  => Some("crate::c_types::u8slice"),

			// Newtypes that we just expose in their original form.
			"bitcoin::hash_types::Txid" if is_ref  => Some("*const [u8; 32]"),
			"bitcoin::hash_types::Txid" if !is_ref => Some("crate::c_types::ThirtyTwoBytes"),
			"bitcoin::hash_types::BlockHash" if is_ref  => Some("*const [u8; 32]"),
			"bitcoin::hash_types::BlockHash" if !is_ref => Some("crate::c_types::ThirtyTwoBytes"),
			"bitcoin::secp256k1::Message" if !is_ref => Some("crate::c_types::ThirtyTwoBytes"),
			"ln::channelmanager::PaymentHash" if is_ref => Some("*const [u8; 32]"),
			"ln::channelmanager::PaymentHash" if !is_ref => Some("crate::c_types::ThirtyTwoBytes"),
			"ln::channelmanager::PaymentPreimage" if is_ref => Some("*const [u8; 32]"),
			"ln::channelmanager::PaymentPreimage" if !is_ref => Some("crate::c_types::ThirtyTwoBytes"),
			"ln::channelmanager::PaymentSecret" if is_ref => Some("crate::c_types::ThirtyTwoBytes"),
			"ln::channelmanager::PaymentSecret" if !is_ref => Some("crate::c_types::ThirtyTwoBytes"),

			// Override the default since Records contain an fmt with a lifetime:
			"util::logger::Record" => Some("*const std::os::raw::c_char"),

			// List of structs we map that aren't detected:
			"ln::features::InitFeatures" if is_ref && ptr_for_ref => Some("crate::ln::features::InitFeatures"),
			"ln::features::InitFeatures" if is_ref => Some("*const crate::ln::features::InitFeatures"),
			"ln::features::InitFeatures" => Some("crate::ln::features::InitFeatures"),
			_ => None,
		}
	}

	fn from_c_conversion_new_var_from_path<'b>(&self, _full_path: &str, _is_ref: bool) -> Option<(&'b str, &'b str)> {
		None
	}
	fn from_c_conversion_prefix_from_path<'b>(&self, full_path: &str, is_ref: bool) -> Option<String> {
		if self.is_primitive(full_path) {
			return Some("".to_owned());
		}
		match full_path {
			"Vec" if !is_ref => Some("local_"),
			"Result" if !is_ref => Some("local_"),
			"Option" if is_ref => Some("&local_"),
			"Option" => Some("local_"),

			"[u8; 32]" if is_ref => Some("unsafe { &*"),
			"[u8; 32]" if !is_ref => Some(""),
			"[u8; 16]" if !is_ref => Some(""),
			"[u8; 10]" if !is_ref => Some(""),
			"[u8; 4]" if !is_ref => Some(""),
			"[u8; 3]" if !is_ref => Some(""),

			"[u8]" if is_ref => Some(""),
			"[usize]" if is_ref => Some(""),

			"str" if is_ref => Some(""),
			"String" if !is_ref => Some("String::from_utf8("),
			// Note that we'll panic for String if is_ref, as we only have non-owned memory, we
			// cannot create a &String.

			"std::time::Duration" => Some("std::time::Duration::from_secs("),

			"bitcoin::secp256k1::key::PublicKey" if is_ref => Some("&"),
			"bitcoin::secp256k1::key::PublicKey" => Some(""),
			"bitcoin::secp256k1::Signature" if is_ref => Some("&"),
			"bitcoin::secp256k1::Signature" => Some(""),
			"bitcoin::secp256k1::key::SecretKey" if is_ref => Some("&::bitcoin::secp256k1::key::SecretKey::from_slice(&unsafe { *"),
			"bitcoin::secp256k1::key::SecretKey" if !is_ref => Some(""),
			"bitcoin::blockdata::script::Script" if is_ref => Some("&::bitcoin::blockdata::script::Script::from(Vec::from("),
			"bitcoin::blockdata::script::Script" if !is_ref => Some("::bitcoin::blockdata::script::Script::from("),
			"bitcoin::blockdata::transaction::Transaction" if is_ref => Some("&"),
			"bitcoin::blockdata::transaction::Transaction" => Some(""),
			"bitcoin::blockdata::transaction::TxOut" if !is_ref => Some(""),
			"bitcoin::network::constants::Network" => Some(""),
			"bitcoin::blockdata::block::BlockHeader" => Some("&::bitcoin::consensus::encode::deserialize(unsafe { &*"),
			"bitcoin::blockdata::block::Block" if is_ref => Some("&::bitcoin::consensus::encode::deserialize("),

			// Newtypes that we just expose in their original form.
			"bitcoin::hash_types::Txid" if is_ref => Some("&::bitcoin::hash_types::Txid::from_slice(&unsafe { &*"),
			"bitcoin::hash_types::Txid" if !is_ref => Some("::bitcoin::hash_types::Txid::from_slice(&"),
			"bitcoin::hash_types::BlockHash" => Some("::bitcoin::hash_types::BlockHash::from_slice(&"),
			"ln::channelmanager::PaymentHash" if !is_ref => Some("::lightning::ln::channelmanager::PaymentHash("),
			"ln::channelmanager::PaymentHash" if is_ref => Some("&::lightning::ln::channelmanager::PaymentHash(unsafe { *"),
			"ln::channelmanager::PaymentPreimage" if !is_ref => Some("::lightning::ln::channelmanager::PaymentPreimage("),
			"ln::channelmanager::PaymentPreimage" if is_ref => Some("&::lightning::ln::channelmanager::PaymentPreimage(unsafe { *"),
			"ln::channelmanager::PaymentSecret" => Some("::lightning::ln::channelmanager::PaymentSecret("),

			// List of structs we map (possibly during processing of other files):
			"ln::features::InitFeatures" if !is_ref => Some("*unsafe { Box::from_raw("),

			// List of traits we map (possibly during processing of other files):
			"crate::util::logger::Logger" => Some(""),

			_ => None,
		}.map(|s| s.to_owned())
	}
	fn from_c_conversion_suffix_from_path<'b>(&self, full_path: &str, is_ref: bool) -> Option<String> {
		if self.is_primitive(full_path) {
			return Some("".to_owned());
		}
		match full_path {
			"Vec" if !is_ref => Some(""),
			"Option" => Some(""),
			"Result" if !is_ref => Some(""),

			"[u8; 32]" if is_ref => Some("}"),
			"[u8; 32]" if !is_ref => Some(".data"),
			"[u8; 16]" if !is_ref => Some(".data"),
			"[u8; 10]" if !is_ref => Some(".data"),
			"[u8; 4]" if !is_ref => Some(".data"),
			"[u8; 3]" if !is_ref => Some(".data"),

			"[u8]" if is_ref => Some(".to_slice()"),
			"[usize]" if is_ref => Some(".to_slice()"),

			"str" if is_ref => Some(".into()"),
			"String" if !is_ref => Some(".into_rust()).unwrap()"),

			"std::time::Duration" => Some(")"),

			"bitcoin::secp256k1::key::PublicKey" => Some(".into_rust()"),
			"bitcoin::secp256k1::Signature" => Some(".into_rust()"),
			"bitcoin::secp256k1::key::SecretKey" if !is_ref => Some(".into_rust()"),
			"bitcoin::secp256k1::key::SecretKey" if is_ref => Some("}[..]).unwrap()"),
			"bitcoin::blockdata::script::Script" if is_ref => Some(".to_slice()))"),
			"bitcoin::blockdata::script::Script" if !is_ref => Some(".into_rust())"),
			"bitcoin::blockdata::transaction::Transaction" => Some(".into_bitcoin()"),
			"bitcoin::blockdata::transaction::TxOut" if !is_ref => Some(".into_rust()"),
			"bitcoin::network::constants::Network" => Some(".into_bitcoin()"),
			"bitcoin::blockdata::block::BlockHeader" => Some(" }).unwrap()"),
			"bitcoin::blockdata::block::Block" => Some(".to_slice()).unwrap()"),

			// Newtypes that we just expose in their original form.
			"bitcoin::hash_types::Txid" if is_ref => Some(" }[..]).unwrap()"),
			"bitcoin::hash_types::Txid" => Some(".data[..]).unwrap()"),
			"bitcoin::hash_types::BlockHash" if !is_ref => Some(".data[..]).unwrap()"),
			"ln::channelmanager::PaymentHash" if !is_ref => Some(".data)"),
			"ln::channelmanager::PaymentHash" if is_ref => Some(" })"),
			"ln::channelmanager::PaymentPreimage" if !is_ref => Some(".data)"),
			"ln::channelmanager::PaymentPreimage" if is_ref => Some(" })"),
			"ln::channelmanager::PaymentSecret" => Some(".data)"),

			// List of structs we map (possibly during processing of other files):
			"ln::features::InitFeatures" if is_ref => Some(".inner) }"),
			"ln::features::InitFeatures" if !is_ref => Some(".take_inner()) }"),

			// List of traits we map (possibly during processing of other files):
			"crate::util::logger::Logger" => Some(""),

			_ => None,
		}.map(|s| s.to_owned())
	}

	fn to_c_conversion_new_var_from_path<'b>(&self, full_path: &str, is_ref: bool) -> Option<(&'b str, &'b str)> {
		if self.is_primitive(full_path) {
			return None;
		}
		match full_path {
			"[u8]" if is_ref => Some(("crate::c_types::u8slice::from_slice(", ")")),
			"[usize]" if is_ref => Some(("crate::c_types::usizeslice::from_slice(", ")")),

			"bitcoin::blockdata::transaction::Transaction" if is_ref => Some(("::bitcoin::consensus::encode::serialize(", ")")),
			"bitcoin::blockdata::transaction::Transaction" if !is_ref => Some(("::bitcoin::consensus::encode::serialize(&", ")")),
			"bitcoin::blockdata::block::BlockHeader" if is_ref => Some(("{ let mut s = [0u8; 80]; s[..].copy_from_slice(&::bitcoin::consensus::encode::serialize(", ")); s }")),
			"bitcoin::blockdata::block::Block" if is_ref => Some(("::bitcoin::consensus::encode::serialize(", ")")),
			"bitcoin::hash_types::Txid" => None,

			// Override the default since Records contain an fmt with a lifetime:
			// TODO: We should include the other record fields
			"util::logger::Record" => Some(("std::ffi::CString::new(format!(\"{}\", ", ".args)).unwrap()")),
			_ => None,
		}.map(|s| s.to_owned())
	}
	fn to_c_conversion_inline_prefix_from_path(&self, full_path: &str, is_ref: bool, ptr_for_ref: bool) -> Option<String> {
		if self.is_primitive(full_path) {
			return Some("".to_owned());
		}
		match full_path {
			"Result" if !is_ref => Some("local_"),
			"Vec" if !is_ref => Some("local_"),
			"Option" => Some("local_"),

			"[u8; 32]" if !is_ref => Some("crate::c_types::ThirtyTwoBytes { data: "),
			"[u8; 32]" if is_ref => Some("&"),
			"[u8; 16]" if !is_ref => Some("crate::c_types::SixteenBytes { data: "),
			"[u8; 10]" if !is_ref => Some("crate::c_types::TenBytes { data: "),
			"[u8; 4]" if !is_ref => Some("crate::c_types::FourBytes { data: "),
			"[u8; 3]" if is_ref => Some("&"),

			"[u8]" if is_ref => Some("local_"),
			"[usize]" if is_ref => Some("local_"),

			"str" if is_ref => Some(""),
			"String" => Some(""),

			"std::time::Duration" => Some(""),

			"bitcoin::secp256k1::key::PublicKey" => Some("crate::c_types::PublicKey::from_rust(&"),
			"bitcoin::secp256k1::Signature" => Some("crate::c_types::Signature::from_rust(&"),
			"bitcoin::secp256k1::key::SecretKey" if is_ref  => Some(""),
			"bitcoin::secp256k1::key::SecretKey" if !is_ref => Some("crate::c_types::SecretKey::from_rust("),
			"bitcoin::secp256k1::Error" if !is_ref => Some("crate::c_types::Secp256k1Error::from_rust("),
			"bitcoin::blockdata::script::Script" if is_ref => Some("crate::c_types::u8slice::from_slice(&"),
			"bitcoin::blockdata::script::Script" if !is_ref => Some(""),
			"bitcoin::blockdata::transaction::Transaction" => Some("crate::c_types::Transaction::from_vec(local_"),
			"bitcoin::blockdata::transaction::OutPoint" => Some("crate::c_types::bitcoin_to_C_outpoint("),
			"bitcoin::blockdata::transaction::TxOut" if !is_ref => Some("crate::c_types::TxOut::from_rust("),
			"bitcoin::blockdata::block::BlockHeader" if is_ref => Some("&local_"),
			"bitcoin::blockdata::block::Block" if is_ref => Some("crate::c_types::u8slice::from_slice(&local_"),

			"bitcoin::hash_types::Txid" if !is_ref => Some("crate::c_types::ThirtyTwoBytes { data: "),

			// Newtypes that we just expose in their original form.
			"bitcoin::hash_types::Txid" if is_ref => Some(""),
			"bitcoin::hash_types::BlockHash" if is_ref => Some(""),
			"bitcoin::hash_types::BlockHash" => Some("crate::c_types::ThirtyTwoBytes { data: "),
			"bitcoin::secp256k1::Message" if !is_ref => Some("crate::c_types::ThirtyTwoBytes { data: "),
			"ln::channelmanager::PaymentHash" if is_ref => Some("&"),
			"ln::channelmanager::PaymentHash" if !is_ref => Some("crate::c_types::ThirtyTwoBytes { data: "),
			"ln::channelmanager::PaymentPreimage" if is_ref => Some("&"),
			"ln::channelmanager::PaymentPreimage" => Some("crate::c_types::ThirtyTwoBytes { data: "),
			"ln::channelmanager::PaymentSecret" if !is_ref => Some("crate::c_types::ThirtyTwoBytes { data: "),

			// Override the default since Records contain an fmt with a lifetime:
			"util::logger::Record" => Some("local_"),

			// List of structs we map (possibly during processing of other files):
			"ln::features::InitFeatures" if is_ref && ptr_for_ref => Some("crate::ln::features::InitFeatures { inner: &mut "),
			"ln::features::InitFeatures" if is_ref => Some("Box::into_raw(Box::new(crate::ln::features::InitFeatures { inner: &mut "),
			"ln::features::InitFeatures" if !is_ref => Some("crate::ln::features::InitFeatures { inner: Box::into_raw(Box::new("),

			_ => None,
		}.map(|s| s.to_owned())
	}
	fn to_c_conversion_inline_suffix_from_path(&self, full_path: &str, is_ref: bool, ptr_for_ref: bool) -> Option<String> {
		if self.is_primitive(full_path) {
			return Some("".to_owned());
		}
		match full_path {
			"Result" if !is_ref => Some(""),
			"Vec" if !is_ref => Some(".into()"),
			"Option" => Some(""),

			"[u8; 32]" if !is_ref => Some(" }"),
			"[u8; 32]" if is_ref => Some(""),
			"[u8; 16]" if !is_ref => Some(" }"),
			"[u8; 10]" if !is_ref => Some(" }"),
			"[u8; 4]" if !is_ref => Some(" }"),
			"[u8; 3]" if is_ref => Some(""),

			"[u8]" if is_ref => Some(""),
			"[usize]" if is_ref => Some(""),

			"str" if is_ref => Some(".into()"),
			"String" if !is_ref => Some(".into_bytes().into()"),
			"String" if is_ref => Some(".as_str().into()"),

			"std::time::Duration" => Some(".as_secs()"),

			"bitcoin::secp256k1::key::PublicKey" => Some(")"),
			"bitcoin::secp256k1::Signature" => Some(")"),
			"bitcoin::secp256k1::key::SecretKey" if !is_ref => Some(")"),
			"bitcoin::secp256k1::key::SecretKey" if is_ref => Some(".as_ref()"),
			"bitcoin::secp256k1::Error" if !is_ref => Some(")"),
			"bitcoin::blockdata::script::Script" if is_ref => Some("[..])"),
			"bitcoin::blockdata::script::Script" if !is_ref => Some(".into_bytes().into()"),
			"bitcoin::blockdata::transaction::Transaction" => Some(")"),
			"bitcoin::blockdata::transaction::OutPoint" => Some(")"),
			"bitcoin::blockdata::transaction::TxOut" if !is_ref => Some(")"),
			"bitcoin::blockdata::block::BlockHeader" if is_ref => Some(""),
			"bitcoin::blockdata::block::Block" if is_ref => Some(")"),

			"bitcoin::hash_types::Txid" if !is_ref => Some(".into_inner() }"),

			// Newtypes that we just expose in their original form.
			"bitcoin::hash_types::Txid" if is_ref => Some(".as_inner()"),
			"bitcoin::hash_types::BlockHash" if is_ref => Some(".as_inner()"),
			"bitcoin::hash_types::BlockHash" => Some(".into_inner() }"),
			"bitcoin::secp256k1::Message" if !is_ref => Some(".as_ref().clone() }"),
			"ln::channelmanager::PaymentHash" if is_ref => Some(".0"),
			"ln::channelmanager::PaymentHash" => Some(".0 }"),
			"ln::channelmanager::PaymentPreimage" if is_ref => Some(".0"),
			"ln::channelmanager::PaymentPreimage" => Some(".0 }"),
			"ln::channelmanager::PaymentSecret" if !is_ref => Some(".0 }"),

			// Override the default since Records contain an fmt with a lifetime:
			"util::logger::Record" => Some(".as_ptr()"),

			// List of structs we map (possibly during processing of other files):
			"ln::features::InitFeatures" if is_ref && ptr_for_ref => Some(", is_owned: false }"),
			"ln::features::InitFeatures" if is_ref => Some(", is_owned: false }))"),
			"ln::features::InitFeatures" => Some(")), is_owned: true }"),

			_ => None,
		}.map(|s| s.to_owned())
	}

	fn empty_val_check_suffix_from_path(&self, full_path: &str) -> Option<&str> {
		match full_path {
			"ln::channelmanager::PaymentSecret" => Some(".data == [0; 32]"),
			"bitcoin::secp256k1::key::PublicKey" => Some(".is_null()"),
			"bitcoin::secp256k1::Signature" => Some(".is_null()"),
			_ => None
		}
	}

	// ****************************
	// *** Container Processing ***
	// ****************************

	/// Returns the module path in the generated mapping crate to the containers which we generate
	/// when writing to CrateTypes::template_file.
	pub fn generated_container_path() -> &'static str {
		"crate::c_types::derived"
	}
	/// Returns the module path in the generated mapping crate to the container templates, which
	/// are then concretized and put in the generated container path/template_file.
	fn container_templ_path() -> &'static str {
		"crate::c_types"
	}

	/// Returns true if this is a "transparent" container, ie an Option or a container which does
	/// not require a generated continer class.
	fn is_transparent_container(&self, full_path: &str, _is_ref: bool) -> bool {
		full_path == "Option"
	}
	/// Returns true if this is a known, supported, non-transparent container.
	fn is_known_container(&self, full_path: &str, is_ref: bool) -> bool {
		(full_path == "Result" && !is_ref) || (full_path == "Vec" && !is_ref) || full_path.ends_with("Tuple")
	}
	fn to_c_conversion_container_new_var<'b>(&self, generics: Option<&GenericTypes>, full_path: &str, is_ref: bool, single_contained: Option<&syn::Type>, var_name: &syn::Ident, var_access: &str)
			// Returns prefix + Vec<(prefix, var-name-to-inline-convert)> + suffix
			// expecting one element in the vec per generic type, each of which is inline-converted
			-> Option<(&'b str, Vec<(String, String)>, &'b str)> {
		match full_path {
			"Result" if !is_ref => {
				Some(("match ",
						vec![(" { Ok(mut o) => crate::c_types::CResultTempl::ok(".to_string(), "o".to_string()),
							(").into(), Err(mut e) => crate::c_types::CResultTempl::err(".to_string(), "e".to_string())],
						").into() }"))
			},
			"Vec" if !is_ref => {
				Some(("Vec::new(); for item in ", vec![(format!(".drain(..) {{ local_{}.push(", var_name), "item".to_string())], "); }"))
			},
			"Slice" => {
				Some(("Vec::new(); for item in ", vec![(format!(".iter() {{ local_{}.push(", var_name), "**item".to_string())], "); }"))
			},
			"Option" => {
				if let Some(syn::Type::Path(p)) = single_contained {
					if self.c_type_has_inner_from_path(&self.resolve_path(&p.path, generics)) {
						if is_ref {
							return Some(("if ", vec![
								(".is_none() { std::ptr::null() } else { ".to_owned(), format!("({}.as_ref().unwrap())", var_access))
								], " }"));
						} else {
							return Some(("if ", vec![
								(".is_none() { std::ptr::null_mut() } else { ".to_owned(), format!("({}.unwrap())", var_access))
								], " }"));
						}
					}
				}
				if let Some(t) = single_contained {
					let mut v = Vec::new();
					self.write_empty_rust_val(generics, &mut v, t);
					let s = String::from_utf8(v).unwrap();
					return Some(("if ", vec![
						(format!(".is_none() {{ {} }} else {{ ", s), format!("({}.unwrap())", var_access))
						], " }"));
				} else { unreachable!(); }
			},
			_ => None,
		}
	}

	/// only_contained_has_inner implies that there is only one contained element in the container
	/// and it has an inner field (ie is an "opaque" type we've defined).
	fn from_c_conversion_container_new_var<'b>(&self, generics: Option<&GenericTypes>, full_path: &str, is_ref: bool, single_contained: Option<&syn::Type>, var_name: &syn::Ident, var_access: &str)
			// Returns prefix + Vec<(prefix, var-name-to-inline-convert)> + suffix
			// expecting one element in the vec per generic type, each of which is inline-converted
			-> Option<(&'b str, Vec<(String, String)>, &'b str)> {
		match full_path {
			"Result" if !is_ref => {
				Some(("match ",
						vec![(".result_ok { true => Ok(".to_string(), format!("(*unsafe {{ Box::from_raw(<*mut _>::take_ptr(&mut {}.contents.result)) }})", var_name)),
						     ("), false => Err(".to_string(), format!("(*unsafe {{ Box::from_raw(<*mut _>::take_ptr(&mut {}.contents.err)) }})", var_name))],
						")}"))
			},
			"Vec"|"Slice" if !is_ref => {
				Some(("Vec::new(); for mut item in ", vec![(format!(".into_rust().drain(..) {{ local_{}.push(", var_name), "item".to_string())], "); }"))
			},
			"Slice" if is_ref => {
				Some(("Vec::new(); for mut item in ", vec![(format!(".as_slice().iter() {{ local_{}.push(", var_name), "item".to_string())], "); }"))
			},
			"Option" => {
				if let Some(syn::Type::Path(p)) = single_contained {
					if self.c_type_has_inner_from_path(&self.resolve_path(&p.path, generics)) {
						if is_ref {
							return Some(("if ", vec![(".inner.is_null() { None } else { Some((*".to_string(), format!("{}", var_name))], ").clone()) }"))
						} else {
							return Some(("if ", vec![(".inner.is_null() { None } else { Some(".to_string(), format!("{}", var_name))], ") }"));
						}
					}
				}

				if let Some(t) = single_contained {
					let mut v = Vec::new();
					let ret_ref = self.write_empty_rust_val_check_suffix(generics, &mut v, t);
					let s = String::from_utf8(v).unwrap();
					match ret_ref {
						EmptyValExpectedTy::ReferenceAsPointer =>
							return Some(("if ", vec![
								(format!("{} {{ None }} else {{ Some(", s), format!("unsafe {{ &mut *{} }}", var_access))
							], ") }")),
						EmptyValExpectedTy::OwnedPointer =>
							return Some(("if ", vec![
								(format!("{} {{ None }} else {{ Some(", s), format!("unsafe {{ *Box::from_raw({}) }}", var_access))
							], ") }")),
						EmptyValExpectedTy::NonPointer =>
							return Some(("if ", vec![
								(format!("{} {{ None }} else {{ Some(", s), format!("{}", var_access))
							], ") }")),
					}
				} else { unreachable!(); }
			},
			_ => None,
		}
	}

	// *************************************************
	// *** Type definition during main.rs processing ***
	// *************************************************

	fn process_use_intern<W: std::io::Write>(&mut self, w: &mut W, u: &syn::UseTree, partial_path: &str) {
		match u {
			syn::UseTree::Path(p) => {
				let new_path = format!("{}::{}", partial_path, p.ident);
				self.process_use_intern(w, &p.tree, &new_path);
			},
			syn::UseTree::Name(n) => {
				let full_path = format!("{}::{}", partial_path, n.ident);
				self.imports.insert(n.ident.clone(), full_path);
			},
			syn::UseTree::Group(g) => {
				for i in g.items.iter() {
					self.process_use_intern(w, i, partial_path);
				}
			},
			syn::UseTree::Rename(r) => {
				let full_path = format!("{}::{}", partial_path, r.ident);
				self.imports.insert(r.rename.clone(), full_path);
			},
			syn::UseTree::Glob(_) => {
				eprintln!("Ignoring * use for {} - this may result in resolution failures", partial_path);
			},
		}
	}
	pub fn process_use<W: std::io::Write>(&mut self, w: &mut W, u: &syn::ItemUse) {
		if let syn::Visibility::Public(_) = u.vis {
			// We actually only use these for #[cfg(fuzztarget)]
			eprintln!("Ignoring pub(use) tree!");
			return;
		}
		if u.leading_colon.is_some() { eprintln!("Ignoring leading-colon use!"); return; }
		match &u.tree {
			syn::UseTree::Path(p) => {
				let new_path = format!("{}", p.ident);
				self.process_use_intern(w, &p.tree, &new_path);
			},
			syn::UseTree::Name(n) => {
				let full_path = format!("{}", n.ident);
				self.imports.insert(n.ident.clone(), full_path);
			},
			_ => unimplemented!(),
		}
	}

	pub fn mirrored_enum_declared(&mut self, ident: &syn::Ident) {
		self.declared.insert(ident.clone(), DeclType::MirroredEnum);
	}
	pub fn enum_ignored(&mut self, ident: &'c syn::Ident) {
		self.declared.insert(ident.clone(), DeclType::EnumIgnored);
	}
	pub fn struct_imported(&mut self, ident: &'c syn::Ident) {
		self.declared.insert(ident.clone(), DeclType::StructImported);
	}
	pub fn struct_ignored(&mut self, ident: &syn::Ident) {
		eprintln!("Not importing {}", ident);
		self.declared.insert(ident.clone(), DeclType::StructIgnored);
	}
	pub fn trait_declared(&mut self, ident: &syn::Ident, t: &'c syn::ItemTrait) {
		self.declared.insert(ident.clone(), DeclType::Trait(t));
	}
	pub fn get_declared_type(&'a self, ident: &syn::Ident) -> Option<&'a DeclType<'c>> {
		self.declared.get(ident)
	}
	/// Returns true if the object at the given path is mapped as X { inner: *mut origX, .. }.
	pub fn c_type_has_inner_from_path(&self, full_path: &str) -> bool{
		self.crate_types.opaques.get(full_path).is_some()
	}

	pub fn maybe_resolve_ident(&self, id: &syn::Ident) -> Option<String> {
		if let Some(imp) = self.imports.get(id) {
			Some(imp.clone())
		} else if self.declared.get(id).is_some() {
			Some(self.module_path.to_string() + "::" + &format!("{}", id))
		} else { None }
	}

	pub fn maybe_resolve_non_ignored_ident(&self, id: &syn::Ident) -> Option<String> {
		if let Some(imp) = self.imports.get(id) {
			Some(imp.clone())
		} else if let Some(decl_type) = self.declared.get(id) {
			match decl_type {
				DeclType::StructIgnored => None,
				_ => Some(self.module_path.to_string() + "::" + &format!("{}", id)),
			}
		} else { None }
	}

	pub fn maybe_resolve_path(&self, p_arg: &syn::Path, generics: Option<&GenericTypes>) -> Option<String> {
		let p = if let Some(gen_types) = generics {
			if let Some((_, synpath)) = gen_types.maybe_resolve_path(p_arg) {
				synpath
			} else { p_arg }
		} else { p_arg };

		if p.leading_colon.is_some() {
			Some(p.segments.iter().enumerate().map(|(idx, seg)| {
				format!("{}{}", if idx == 0 { "" } else { "::" }, seg.ident)
			}).collect())
		} else if let Some(id) = p.get_ident() {
			self.maybe_resolve_ident(id)
		} else {
			if p.segments.len() == 1 {
				let seg = p.segments.iter().next().unwrap();
				return self.maybe_resolve_ident(&seg.ident);
			}
			let mut seg_iter = p.segments.iter();
			let first_seg = seg_iter.next().unwrap();
			let remaining: String = seg_iter.map(|seg| {
				format!("::{}", seg.ident)
			}).collect();
			if let Some(imp) = self.imports.get(&first_seg.ident) {
				if remaining != "" {
					Some(imp.clone() + &remaining)
				} else {
					Some(imp.clone())
				}
			} else { None }
		}
	}
	pub fn resolve_path(&self, p: &syn::Path, generics: Option<&GenericTypes>) -> String {
		self.maybe_resolve_path(p, generics).unwrap()
	}

	// ***********************************
	// *** Original Rust Type Printing ***
	// ***********************************

	fn in_rust_prelude(resolved_path: &str) -> bool {
		match resolved_path {
			"Vec" => true,
			"Result" => true,
			"Option" => true,
			_ => false,
		}
	}

	fn write_rust_path<W: std::io::Write>(&self, w: &mut W, generics_resolver: Option<&GenericTypes>, path: &syn::Path) {
		if let Some(resolved) = self.maybe_resolve_path(&path, generics_resolver) {
			if self.is_primitive(&resolved) {
				write!(w, "{}", path.get_ident().unwrap()).unwrap();
			} else {
				// TODO: We should have a generic "is from a dependency" check here instead of
				// checking for "bitcoin" explicitly.
				if resolved.starts_with("bitcoin::") || Self::in_rust_prelude(&resolved) {
					write!(w, "{}", resolved).unwrap();
				// If we're printing a generic argument, it needs to reference the crate, otherwise
				// the original crate:
				} else if self.maybe_resolve_path(&path, None).as_ref() == Some(&resolved) {
					write!(w, "{}::{}", self.orig_crate, resolved).unwrap();
				} else {
					write!(w, "crate::{}", resolved).unwrap();
				}
			}
			if let syn::PathArguments::AngleBracketed(args) = &path.segments.iter().last().unwrap().arguments {
				self.write_rust_generic_arg(w, generics_resolver, args.args.iter());
			}
		} else {
			if path.leading_colon.is_some() {
				write!(w, "::").unwrap();
			}
			for (idx, seg) in path.segments.iter().enumerate() {
				if idx != 0 { write!(w, "::").unwrap(); }
				write!(w, "{}", seg.ident).unwrap();
				if let syn::PathArguments::AngleBracketed(args) = &seg.arguments {
					self.write_rust_generic_arg(w, generics_resolver, args.args.iter());
				}
			}
		}
	}
	pub fn write_rust_generic_param<'b, W: std::io::Write>(&self, w: &mut W, generics_resolver: Option<&GenericTypes>, generics: impl Iterator<Item=&'b syn::GenericParam>) {
		let mut had_params = false;
		for (idx, arg) in generics.enumerate() {
			if idx != 0 { write!(w, ", ").unwrap(); } else { write!(w, "<").unwrap(); }
			had_params = true;
			match arg {
				syn::GenericParam::Lifetime(lt) => write!(w, "'{}", lt.lifetime.ident).unwrap(),
				syn::GenericParam::Type(t) => {
					write!(w, "{}", t.ident).unwrap();
					if t.colon_token.is_some() { write!(w, ":").unwrap(); }
					for (idx, bound) in t.bounds.iter().enumerate() {
						if idx != 0 { write!(w, " + ").unwrap(); }
						match bound {
							syn::TypeParamBound::Trait(tb) => {
								if tb.paren_token.is_some() || tb.lifetimes.is_some() { unimplemented!(); }
								self.write_rust_path(w, generics_resolver, &tb.path);
							},
							_ => unimplemented!(),
						}
					}
					if t.eq_token.is_some() || t.default.is_some() { unimplemented!(); }
				},
				_ => unimplemented!(),
			}
		}
		if had_params { write!(w, ">").unwrap(); }
	}

	pub fn write_rust_generic_arg<'b, W: std::io::Write>(&self, w: &mut W, generics_resolver: Option<&GenericTypes>, generics: impl Iterator<Item=&'b syn::GenericArgument>) {
		write!(w, "<").unwrap();
		for (idx, arg) in generics.enumerate() {
			if idx != 0 { write!(w, ", ").unwrap(); }
			match arg {
				syn::GenericArgument::Type(t) => self.write_rust_type(w, generics_resolver, t),
				_ => unimplemented!(),
			}
		}
		write!(w, ">").unwrap();
	}
	pub fn write_rust_type<W: std::io::Write>(&self, w: &mut W, generics: Option<&GenericTypes>, t: &syn::Type) {
		match t {
			syn::Type::Path(p) => {
				if p.qself.is_some() {
					unimplemented!();
				}
				self.write_rust_path(w, generics, &p.path);
			},
			syn::Type::Reference(r) => {
				write!(w, "&").unwrap();
				if let Some(lft) = &r.lifetime {
					write!(w, "'{} ", lft.ident).unwrap();
				}
				if r.mutability.is_some() {
					write!(w, "mut ").unwrap();
				}
				self.write_rust_type(w, generics, &*r.elem);
			},
			syn::Type::Array(a) => {
				write!(w, "[").unwrap();
				self.write_rust_type(w, generics, &a.elem);
				if let syn::Expr::Lit(l) = &a.len {
					if let syn::Lit::Int(i) = &l.lit {
						write!(w, "; {}]", i).unwrap();
					} else { unimplemented!(); }
				} else { unimplemented!(); }
			}
			syn::Type::Slice(s) => {
				write!(w, "[").unwrap();
				self.write_rust_type(w, generics, &s.elem);
				write!(w, "]").unwrap();
			},
			syn::Type::Tuple(s) => {
				write!(w, "(").unwrap();
				for (idx, t) in s.elems.iter().enumerate() {
					if idx != 0 { write!(w, ", ").unwrap(); }
					self.write_rust_type(w, generics, &t);
				}
				write!(w, ")").unwrap();
			},
			_ => unimplemented!(),
		}
	}

	/// Prints a constructor for something which is "uninitialized" (but obviously not actually
	/// unint'd memory).
	pub fn write_empty_rust_val<W: std::io::Write>(&self, generics: Option<&GenericTypes>, w: &mut W, t: &syn::Type) {
		match t {
			syn::Type::Path(p) => {
				let resolved = self.resolve_path(&p.path, generics);
				if self.crate_types.opaques.get(&resolved).is_some() {
					write!(w, "crate::{} {{ inner: std::ptr::null_mut(), is_owned: true }}", resolved).unwrap();
				} else {
					// Assume its a manually-mapped C type, where we can just define an null() fn
					write!(w, "{}::null()", self.c_type_from_path(&resolved, false, false).unwrap()).unwrap();
				}
			},
			syn::Type::Array(a) => {
				if let syn::Expr::Lit(l) = &a.len {
					if let syn::Lit::Int(i) = &l.lit {
						if i.base10_digits().parse::<usize>().unwrap() < 32 {
							// Blindly assume that if we're trying to create an empty value for an
							// array < 32 entries that all-0s may be a valid state.
							unimplemented!();
						}
						let arrty = format!("[u8; {}]", i.base10_digits());
						write!(w, "{}", self.to_c_conversion_inline_prefix_from_path(&arrty, false, false).unwrap()).unwrap();
						write!(w, "[0; {}]", i.base10_digits()).unwrap();
						write!(w, "{}", self.to_c_conversion_inline_suffix_from_path(&arrty, false, false).unwrap()).unwrap();
					} else { unimplemented!(); }
				} else { unimplemented!(); }
			}
			_ => unimplemented!(),
		}
	}

	/// Prints a suffix to determine if a variable is empty (ie was set by write_empty_rust_val).
	/// See EmptyValExpectedTy for information on return types.
	fn write_empty_rust_val_check_suffix<W: std::io::Write>(&self, generics: Option<&GenericTypes>, w: &mut W, t: &syn::Type) -> EmptyValExpectedTy {
		match t {
			syn::Type::Path(p) => {
				let resolved = self.resolve_path(&p.path, generics);
				if self.crate_types.opaques.get(&resolved).is_some() {
					write!(w, ".inner.is_null()").unwrap();
					EmptyValExpectedTy::NonPointer
				} else {
					if let Some(suffix) = self.empty_val_check_suffix_from_path(&resolved) {
						write!(w, "{}", suffix).unwrap();
						// We may eventually need to allow empty_val_check_suffix_from_path to specify if we need a deref or not
						EmptyValExpectedTy::NonPointer
					} else {
						write!(w, " == std::ptr::null_mut()").unwrap();
						EmptyValExpectedTy::OwnedPointer
					}
				}
			},
			syn::Type::Array(a) => {
				if let syn::Expr::Lit(l) = &a.len {
					if let syn::Lit::Int(i) = &l.lit {
						write!(w, " == [0; {}]", i.base10_digits()).unwrap();
						EmptyValExpectedTy::NonPointer
					} else { unimplemented!(); }
				} else { unimplemented!(); }
			},
			syn::Type::Slice(_) => {
				// Option<[]> always implies that we want to treat len() == 0 differently from
				// None, so we always map an Option<[]> into a pointer.
				write!(w, " == std::ptr::null_mut()").unwrap();
				EmptyValExpectedTy::ReferenceAsPointer
			},
			_ => unimplemented!(),
		}
	}

	/// Prints a suffix to determine if a variable is empty (ie was set by write_empty_rust_val).
	pub fn write_empty_rust_val_check<W: std::io::Write>(&self, generics: Option<&GenericTypes>, w: &mut W, t: &syn::Type, var_access: &str) {
		match t {
			syn::Type::Path(_) => {
				write!(w, "{}", var_access).unwrap();
				self.write_empty_rust_val_check_suffix(generics, w, t);
			},
			syn::Type::Array(a) => {
				if let syn::Expr::Lit(l) = &a.len {
					if let syn::Lit::Int(i) = &l.lit {
						let arrty = format!("[u8; {}]", i.base10_digits());
						// We don't (yet) support a new-var conversion here.
						assert!(self.from_c_conversion_new_var_from_path(&arrty, false).is_none());
						write!(w, "{}{}{}",
							self.from_c_conversion_prefix_from_path(&arrty, false).unwrap(),
							var_access,
							self.from_c_conversion_suffix_from_path(&arrty, false).unwrap()).unwrap();
						self.write_empty_rust_val_check_suffix(generics, w, t);
					} else { unimplemented!(); }
				} else { unimplemented!(); }
			}
			_ => unimplemented!(),
		}
	}

	// ********************************
	// *** Type conversion printing ***
	// ********************************

	/// Returns true we if can just skip passing this to C entirely
	pub fn skip_arg(&self, t: &syn::Type, generics: Option<&GenericTypes>) -> bool {
		match t {
			syn::Type::Path(p) => {
				if p.qself.is_some() { unimplemented!(); }
				if let Some(full_path) = self.maybe_resolve_path(&p.path, generics) {
					self.skip_path(&full_path)
				} else { false }
			},
			syn::Type::Reference(r) => {
				self.skip_arg(&*r.elem, generics)
			},
			_ => false,
		}
	}
	pub fn no_arg_to_rust<W: std::io::Write>(&self, w: &mut W, t: &syn::Type, generics: Option<&GenericTypes>) {
		match t {
			syn::Type::Path(p) => {
				if p.qself.is_some() { unimplemented!(); }
				if let Some(full_path) = self.maybe_resolve_path(&p.path, generics) {
					write!(w, "{}", self.no_arg_path_to_rust(&full_path)).unwrap();
				}
			},
			syn::Type::Reference(r) => {
				self.no_arg_to_rust(w, &*r.elem, generics);
			},
			_ => {},
		}
	}

	fn write_conversion_inline_intern<W: std::io::Write,
			LP: Fn(&str, bool, bool) -> Option<String>, DL: Fn(&mut W, &DeclType, &str, bool, bool), SC: Fn(bool) -> &'static str>
			(&self, w: &mut W, t: &syn::Type, generics: Option<&GenericTypes>, is_ref: bool, is_mut: bool, ptr_for_ref: bool,
			 tupleconv: &str, prefix: bool, sliceconv: SC, path_lookup: LP, decl_lookup: DL) {
		match t {
			syn::Type::Reference(r) => {
				self.write_conversion_inline_intern(w, &*r.elem, generics, true, r.mutability.is_some(),
					ptr_for_ref, tupleconv, prefix, sliceconv, path_lookup, decl_lookup);
			},
			syn::Type::Path(p) => {
				if p.qself.is_some() {
					unimplemented!();
				}

				let resolved_path = self.resolve_path(&p.path, generics);
				if let Some(aliased_type) = self.crate_types.type_aliases.get(&resolved_path) {
					return self.write_conversion_inline_intern(w, aliased_type, None, is_ref, is_mut, ptr_for_ref, tupleconv, prefix, sliceconv, path_lookup, decl_lookup);
				} else if let Some(c_type) = path_lookup(&resolved_path, is_ref, ptr_for_ref) {
					write!(w, "{}", c_type).unwrap();
				} else if self.crate_types.opaques.get(&resolved_path).is_some() {
					decl_lookup(w, &DeclType::StructImported, &resolved_path, is_ref, is_mut);
				} else if self.crate_types.mirrored_enums.get(&resolved_path).is_some() {
					decl_lookup(w, &DeclType::MirroredEnum, &resolved_path, is_ref, is_mut);
				} else if let Some(t) = self.crate_types.traits.get(&resolved_path) {
					decl_lookup(w, &DeclType::Trait(t), &resolved_path, is_ref, is_mut);
				} else if let Some(ident) = single_ident_generic_path_to_ident(&p.path) {
					if let Some(_) = self.imports.get(ident) {
						// crate_types lookup has to have succeeded:
						panic!("Failed to print inline conversion for {}", ident);
					} else if let Some(decl_type) = self.declared.get(ident) {
						decl_lookup(w, decl_type, &self.maybe_resolve_ident(ident).unwrap(), is_ref, is_mut);
					} else { unimplemented!(); }
				} else { unimplemented!(); }
			},
			syn::Type::Array(a) => {
				// We assume all arrays contain only [int_literal; X]s.
				// This may result in some outputs not compiling.
				if let syn::Expr::Lit(l) = &a.len {
					if let syn::Lit::Int(i) = &l.lit {
						write!(w, "{}", path_lookup(&format!("[u8; {}]", i.base10_digits()), is_ref, ptr_for_ref).unwrap()).unwrap();
					} else { unimplemented!(); }
				} else { unimplemented!(); }
			},
			syn::Type::Slice(s) => {
				// We assume all slices contain only literals or references.
				// This may result in some outputs not compiling.
				if let syn::Type::Path(p) = &*s.elem {
					let resolved = self.resolve_path(&p.path, generics);
					assert!(self.is_primitive(&resolved));
					write!(w, "{}", path_lookup("[u8]", is_ref, ptr_for_ref).unwrap()).unwrap();
				} else if let syn::Type::Reference(r) = &*s.elem {
					if let syn::Type::Path(p) = &*r.elem {
						write!(w, "{}", sliceconv(self.c_type_has_inner_from_path(&self.resolve_path(&p.path, generics)))).unwrap();
					} else { unimplemented!(); }
				} else if let syn::Type::Tuple(t) = &*s.elem {
					assert!(!t.elems.is_empty());
					if prefix {
						write!(w, "&local_").unwrap();
					} else {
						let mut needs_map = false;
						for e in t.elems.iter() {
							if let syn::Type::Reference(_) = e {
								needs_map = true;
							}
						}
						if needs_map {
							write!(w, ".iter().map(|(").unwrap();
							for i in 0..t.elems.len() {
								write!(w, "{}{}", if i != 0 { ", " } else { "" }, ('a' as u8 + i as u8) as char).unwrap();
							}
							write!(w, ")| (").unwrap();
							for (idx, e) in t.elems.iter().enumerate() {
								if let syn::Type::Reference(_) = e {
									write!(w, "{}{}", if idx != 0 { ", " } else { "" }, (idx as u8 + 'a' as u8) as char).unwrap();
								} else if let syn::Type::Path(_) = e {
									write!(w, "{}*{}", if idx != 0 { ", " } else { "" }, (idx as u8 + 'a' as u8) as char).unwrap();
								} else { unimplemented!(); }
							}
							write!(w, ")).collect::<Vec<_>>()[..]").unwrap();
						}
					}
				} else { unimplemented!(); }
			},
			syn::Type::Tuple(t) => {
				if t.elems.is_empty() {
					// cbindgen has poor support for (), see, eg https://github.com/eqrion/cbindgen/issues/527
					// so work around it by just pretending its a 0u8
					write!(w, "{}", tupleconv).unwrap();
				} else {
					if prefix { write!(w, "local_").unwrap(); }
				}
			},
			_ => unimplemented!(),
		}
	}

	fn write_to_c_conversion_inline_prefix_inner<W: std::io::Write>(&self, w: &mut W, t: &syn::Type, generics: Option<&GenericTypes>, is_ref: bool, ptr_for_ref: bool, from_ptr: bool) {
		self.write_conversion_inline_intern(w, t, generics, is_ref, false, ptr_for_ref, "0u8 /*", true, |_| "local_",
				|a, b, c| self.to_c_conversion_inline_prefix_from_path(a, b, c),
				|w, decl_type, decl_path, is_ref, _is_mut| {
					match decl_type {
						DeclType::MirroredEnum if is_ref && ptr_for_ref => write!(w, "crate::{}::from_native(&", decl_path).unwrap(),
						DeclType::MirroredEnum if is_ref => write!(w, "&crate::{}::from_native(&", decl_path).unwrap(),
						DeclType::MirroredEnum => write!(w, "crate::{}::native_into(", decl_path).unwrap(),
						DeclType::EnumIgnored|DeclType::StructImported if is_ref && ptr_for_ref && from_ptr =>
							write!(w, "crate::{} {{ inner: unsafe {{ (", decl_path).unwrap(),
						DeclType::EnumIgnored|DeclType::StructImported if is_ref && ptr_for_ref =>
							write!(w, "crate::{} {{ inner: unsafe {{ ( (&(", decl_path).unwrap(),
						DeclType::EnumIgnored|DeclType::StructImported if is_ref =>
							write!(w, "&crate::{} {{ inner: unsafe {{ (", decl_path).unwrap(),
						DeclType::EnumIgnored|DeclType::StructImported if !is_ref && from_ptr =>
							write!(w, "crate::{} {{ inner: ", decl_path).unwrap(),
						DeclType::EnumIgnored|DeclType::StructImported if !is_ref =>
							write!(w, "crate::{} {{ inner: Box::into_raw(Box::new(", decl_path).unwrap(),
						DeclType::Trait(_) if is_ref => write!(w, "&").unwrap(),
						DeclType::Trait(_) if !is_ref => {},
						_ => panic!("{:?}", decl_path),
					}
				});
	}
	pub fn write_to_c_conversion_inline_prefix<W: std::io::Write>(&self, w: &mut W, t: &syn::Type, generics: Option<&GenericTypes>, ptr_for_ref: bool) {
		self.write_to_c_conversion_inline_prefix_inner(w, t, generics, false, ptr_for_ref, false);
	}
	fn write_to_c_conversion_inline_suffix_inner<W: std::io::Write>(&self, w: &mut W, t: &syn::Type, generics: Option<&GenericTypes>, is_ref: bool, ptr_for_ref: bool, from_ptr: bool) {
		self.write_conversion_inline_intern(w, t, generics, is_ref, false, ptr_for_ref, "*/", false, |_| ".into()",
				|a, b, c| self.to_c_conversion_inline_suffix_from_path(a, b, c),
				|w, decl_type, _full_path, is_ref, _is_mut| match decl_type {
					DeclType::MirroredEnum => write!(w, ")").unwrap(),
					DeclType::EnumIgnored|DeclType::StructImported if is_ref && ptr_for_ref && from_ptr =>
						write!(w, " as *const _) as *mut _ }}, is_owned: false }}").unwrap(),
					DeclType::EnumIgnored|DeclType::StructImported if is_ref && ptr_for_ref =>
						write!(w, ") as *const _) as *mut _) }}, is_owned: false }}").unwrap(),
					DeclType::EnumIgnored|DeclType::StructImported if is_ref =>
						write!(w, " as *const _) as *mut _ }}, is_owned: false }}").unwrap(),
					DeclType::EnumIgnored|DeclType::StructImported if !is_ref && from_ptr =>
						write!(w, ", is_owned: true }}").unwrap(),
					DeclType::EnumIgnored|DeclType::StructImported if !is_ref => write!(w, ")), is_owned: true }}").unwrap(),
					DeclType::Trait(_) if is_ref => {},
					DeclType::Trait(_) => {
						// This is used when we're converting a concrete Rust type into a C trait
						// for use when a Rust trait method returns an associated type.
						// Because all of our C traits implement From<RustTypesImplementingTraits>
						// we can just call .into() here and be done.
						write!(w, ".into()").unwrap()
					},
					_ => unimplemented!(),
				});
	}
	pub fn write_to_c_conversion_inline_suffix<W: std::io::Write>(&self, w: &mut W, t: &syn::Type, generics: Option<&GenericTypes>, ptr_for_ref: bool) {
		self.write_to_c_conversion_inline_suffix_inner(w, t, generics, false, ptr_for_ref, false);
	}

	fn write_from_c_conversion_prefix_inner<W: std::io::Write>(&self, w: &mut W, t: &syn::Type, generics: Option<&GenericTypes>, is_ref: bool, ptr_for_ref: bool) {
		self.write_conversion_inline_intern(w, t, generics, is_ref, false, false, "() /*", true, |_| "&local_",
				|a, b, _c| self.from_c_conversion_prefix_from_path(a, b),
				|w, decl_type, _full_path, is_ref, is_mut| match decl_type {
					DeclType::StructImported if is_ref && ptr_for_ref => write!(w, "unsafe {{ &*(*").unwrap(),
					DeclType::StructImported if is_mut && is_ref => write!(w, "unsafe {{ &mut *").unwrap(),
					DeclType::StructImported if is_ref => write!(w, "unsafe {{ &*").unwrap(),
					DeclType::StructImported if !is_ref => write!(w, "*unsafe {{ Box::from_raw(").unwrap(),
					DeclType::MirroredEnum if is_ref => write!(w, "&").unwrap(),
					DeclType::MirroredEnum => {},
					DeclType::Trait(_) => {},
					_ => unimplemented!(),
				});
	}
	pub fn write_from_c_conversion_prefix<W: std::io::Write>(&self, w: &mut W, t: &syn::Type, generics: Option<&GenericTypes>) {
		self.write_from_c_conversion_prefix_inner(w, t, generics, false, false);
	}
	fn write_from_c_conversion_suffix_inner<W: std::io::Write>(&self, w: &mut W, t: &syn::Type, generics: Option<&GenericTypes>, is_ref: bool, ptr_for_ref: bool) {
		self.write_conversion_inline_intern(w, t, generics, is_ref, false, false, "*/", false,
				|has_inner| match has_inner {
					false => ".iter().collect::<Vec<_>>()[..]",
					true => "[..]",
				},
				|a, b, _c| self.from_c_conversion_suffix_from_path(a, b),
				|w, decl_type, _full_path, is_ref, _is_mut| match decl_type {
					DeclType::StructImported if is_ref && ptr_for_ref => write!(w, ").inner }}").unwrap(),
					DeclType::StructImported if is_ref => write!(w, ".inner }}").unwrap(),
					DeclType::StructImported if !is_ref => write!(w, ".take_inner()) }}").unwrap(),
					DeclType::MirroredEnum if is_ref => write!(w, ".to_native()").unwrap(),
					DeclType::MirroredEnum => write!(w, ".into_native()").unwrap(),
					DeclType::Trait(_) => {},
					_ => unimplemented!(),
				});
	}
	pub fn write_from_c_conversion_suffix<W: std::io::Write>(&self, w: &mut W, t: &syn::Type, generics: Option<&GenericTypes>) {
		self.write_from_c_conversion_suffix_inner(w, t, generics, false, false);
	}
	// Note that compared to the above conversion functions, the following two are generally
	// significantly undertested:
	pub fn write_from_c_conversion_to_ref_prefix<W: std::io::Write>(&self, w: &mut W, t: &syn::Type, generics: Option<&GenericTypes>) {
		self.write_conversion_inline_intern(w, t, generics, false, false, false, "() /*", true, |_| "&local_",
				|a, b, _c| {
					if let Some(conv) = self.from_c_conversion_prefix_from_path(a, b) {
						Some(format!("&{}", conv))
					} else { None }
				},
				|w, decl_type, _full_path, is_ref, _is_mut| match decl_type {
					DeclType::StructImported if !is_ref => write!(w, "unsafe {{ &*").unwrap(),
					_ => unimplemented!(),
				});
	}
	pub fn write_from_c_conversion_to_ref_suffix<W: std::io::Write>(&self, w: &mut W, t: &syn::Type, generics: Option<&GenericTypes>) {
		self.write_conversion_inline_intern(w, t, generics, false, false, false, "*/", false,
				|has_inner| match has_inner {
					false => ".iter().collect::<Vec<_>>()[..]",
					true => "[..]",
				},
				|a, b, _c| self.from_c_conversion_suffix_from_path(a, b),
				|w, decl_type, _full_path, is_ref, _is_mut| match decl_type {
					DeclType::StructImported if !is_ref => write!(w, ".inner }}").unwrap(),
					_ => unimplemented!(),
				});
	}

	fn write_conversion_new_var_intern<'b, W: std::io::Write,
		LP: Fn(&str, bool) -> Option<(&str, &str)>,
		LC: Fn(&str, bool, Option<&syn::Type>, &syn::Ident, &str) ->  Option<(&'b str, Vec<(String, String)>, &'b str)>,
		VP: Fn(&mut W, &syn::Type, Option<&GenericTypes>, bool, bool, bool),
		VS: Fn(&mut W, &syn::Type, Option<&GenericTypes>, bool, bool, bool)>
			(&self, w: &mut W, ident: &syn::Ident, var: &str, t: &syn::Type, generics: Option<&GenericTypes>,
			 mut is_ref: bool, mut ptr_for_ref: bool, to_c: bool,
			 path_lookup: &LP, container_lookup: &LC, var_prefix: &VP, var_suffix: &VS) -> bool {

		macro_rules! convert_container {
			($container_type: expr, $args_len: expr, $args_iter: expr) => { {
				// For slices (and Options), we refuse to directly map them as is_ref when they
				// aren't opaque types containing an inner pointer. This is due to the fact that,
				// in both cases, the actual higher-level type is non-is_ref.
				let ty_has_inner = if self.is_transparent_container(&$container_type, is_ref) || $container_type == "Slice" {
					let ty = $args_iter().next().unwrap();
					if $container_type == "Slice" && to_c {
						// "To C ptr_for_ref" means "return the regular object with is_owned
						// set to false", which is totally what we want in a slice if we're about to
						// set ty_has_inner.
						ptr_for_ref = true;
					}
					if let syn::Type::Reference(t) = ty {
						if let syn::Type::Path(p) = &*t.elem {
							self.c_type_has_inner_from_path(&self.resolve_path(&p.path, generics))
						} else { false }
					} else if let syn::Type::Path(p) = ty {
						self.c_type_has_inner_from_path(&self.resolve_path(&p.path, generics))
					} else { false }
				} else { true };

				// Options get a bunch of special handling, since in general we map Option<>al
				// types into the same C type as non-Option-wrapped types. This ends up being
				// pretty manual here and most of the below special-cases are for Options.
				let mut needs_ref_map = false;
				let mut only_contained_type = None;
				let mut only_contained_has_inner = false;
				let mut contains_slice = false;
				if $args_len == 1 && self.is_transparent_container(&$container_type, is_ref) {
					only_contained_has_inner = ty_has_inner;
					let arg = $args_iter().next().unwrap();
					if let syn::Type::Reference(t) = arg {
						only_contained_type = Some(&*t.elem);
						if let syn::Type::Path(_) = &*t.elem {
							is_ref = true;
						} else if let syn::Type::Slice(_) = &*t.elem {
							contains_slice = true;
						} else { return false; }
						needs_ref_map = true;
					} else if let syn::Type::Path(_) = arg {
						only_contained_type = Some(&arg);
					} else { unimplemented!(); }
				}

				if let Some((prefix, conversions, suffix)) = container_lookup(&$container_type, is_ref && ty_has_inner, only_contained_type, ident, var) {
					assert_eq!(conversions.len(), $args_len);
					write!(w, "let mut local_{}{} = ", ident, if !to_c && needs_ref_map {"_base"} else { "" }).unwrap();
					if only_contained_has_inner && to_c {
						var_prefix(w, $args_iter().next().unwrap(), generics, is_ref, ptr_for_ref, true);
					}
					write!(w, "{}{}", prefix, var).unwrap();

					for ((pfx, var_name), (idx, ty)) in conversions.iter().zip($args_iter().enumerate()) {
						let mut var = std::io::Cursor::new(Vec::new());
						write!(&mut var, "{}", var_name).unwrap();
						let var_access = String::from_utf8(var.into_inner()).unwrap();

						let conv_ty = if needs_ref_map { only_contained_type.as_ref().unwrap() } else { ty };

						write!(w, "{} {{ ", pfx).unwrap();
						let new_var_name = format!("{}_{}", ident, idx);
						let new_var = self.write_conversion_new_var_intern(w, &syn::Ident::new(&new_var_name, Span::call_site()),
								&var_access, conv_ty, generics, contains_slice || (is_ref && ty_has_inner), ptr_for_ref, to_c, path_lookup, container_lookup, var_prefix, var_suffix);
						if new_var { write!(w, " ").unwrap(); }
						if (!only_contained_has_inner || !to_c) && !contains_slice {
							var_prefix(w, conv_ty, generics, is_ref && ty_has_inner, ptr_for_ref, false);
						}

						if !is_ref && !needs_ref_map && to_c && only_contained_has_inner {
							write!(w, "Box::into_raw(Box::new(").unwrap();
						}
						write!(w, "{}{}", if contains_slice { "local_" } else { "" }, if new_var { new_var_name } else { var_access }).unwrap();
						if (!only_contained_has_inner || !to_c) && !contains_slice {
							var_suffix(w, conv_ty, generics, is_ref && ty_has_inner, ptr_for_ref, false);
						}
						if !is_ref && !needs_ref_map && to_c && only_contained_has_inner {
							write!(w, "))").unwrap();
						}
						write!(w, " }}").unwrap();
					}
					write!(w, "{}", suffix).unwrap();
					if only_contained_has_inner && to_c {
						var_suffix(w, $args_iter().next().unwrap(), generics, is_ref, ptr_for_ref, true);
					}
					write!(w, ";").unwrap();
					if !to_c && needs_ref_map {
						write!(w, " let mut local_{} = local_{}_base.as_ref()", ident, ident).unwrap();
						if contains_slice {
							write!(w, ".map(|a| &a[..])").unwrap();
						}
						write!(w, ";").unwrap();
					}
					return true;
				}
			} }
		}

		match t {
			syn::Type::Reference(r) => {
				if let syn::Type::Slice(_) = &*r.elem {
					self.write_conversion_new_var_intern(w, ident, var, &*r.elem, generics, is_ref, ptr_for_ref, to_c, path_lookup, container_lookup, var_prefix, var_suffix)
				} else {
					self.write_conversion_new_var_intern(w, ident, var, &*r.elem, generics, true, ptr_for_ref, to_c, path_lookup, container_lookup, var_prefix, var_suffix)
				}
			},
			syn::Type::Path(p) => {
				if p.qself.is_some() {
					unimplemented!();
				}
				let resolved_path = self.resolve_path(&p.path, generics);
				if let Some(aliased_type) = self.crate_types.type_aliases.get(&resolved_path) {
					return self.write_conversion_new_var_intern(w, ident, var, aliased_type, None, is_ref, ptr_for_ref, to_c, path_lookup, container_lookup, var_prefix, var_suffix);
				}
				if self.is_known_container(&resolved_path, is_ref) || self.is_transparent_container(&resolved_path, is_ref) {
					if let syn::PathArguments::AngleBracketed(args) = &p.path.segments.iter().next().unwrap().arguments {
						convert_container!(resolved_path, args.args.len(), || args.args.iter().map(|arg| {
							if let syn::GenericArgument::Type(ty) = arg {
								ty
							} else { unimplemented!(); }
						}));
					} else { unimplemented!(); }
				}
				if self.is_primitive(&resolved_path) {
					false
				} else if let Some(ty_ident) = single_ident_generic_path_to_ident(&p.path) {
					if let Some((prefix, suffix)) = path_lookup(&resolved_path, is_ref) {
						write!(w, "let mut local_{} = {}{}{};", ident, prefix, var, suffix).unwrap();
						true
					} else if self.declared.get(ty_ident).is_some() {
						false
					} else { false }
				} else { false }
			},
			syn::Type::Array(_) => {
				// We assume all arrays contain only primitive types.
				// This may result in some outputs not compiling.
				false
			},
			syn::Type::Slice(s) => {
				if let syn::Type::Path(p) = &*s.elem {
					let resolved = self.resolve_path(&p.path, generics);
					assert!(self.is_primitive(&resolved));
					let slice_path = format!("[{}]", resolved);
					if let Some((prefix, suffix)) = path_lookup(&slice_path, true) {
						write!(w, "let mut local_{} = {}{}{};", ident, prefix, var, suffix).unwrap();
						true
					} else { false }
				} else if let syn::Type::Reference(ty) = &*s.elem {
					let tyref = [&*ty.elem];
					is_ref = true;
					convert_container!("Slice", 1, || tyref.iter());
					unimplemented!("convert_container should return true as container_lookup should succeed for slices");
				} else if let syn::Type::Tuple(t) = &*s.elem {
					// When mapping into a temporary new var, we need to own all the underlying objects.
					// Thus, we drop any references inside the tuple and convert with non-reference types.
					let mut elems = syn::punctuated::Punctuated::new();
					for elem in t.elems.iter() {
						if let syn::Type::Reference(r) = elem {
							elems.push((*r.elem).clone());
						} else {
							elems.push(elem.clone());
						}
					}
					let ty = [syn::Type::Tuple(syn::TypeTuple {
						paren_token: t.paren_token, elems
					})];
					is_ref = false;
					ptr_for_ref = true;
					convert_container!("Slice", 1, || ty.iter());
					unimplemented!("convert_container should return true as container_lookup should succeed for slices");
				} else { unimplemented!() }
			},
			syn::Type::Tuple(t) => {
				if !t.elems.is_empty() {
					// We don't (yet) support tuple elements which cannot be converted inline
					write!(w, "let (").unwrap();
					for idx in 0..t.elems.len() {
						if idx != 0 { write!(w, ", ").unwrap(); }
						write!(w, "{} orig_{}_{}", if is_ref { "ref" } else { "mut" }, ident, idx).unwrap();
					}
					write!(w, ") = {}{}; ", var, if !to_c { ".to_rust()" } else { "" }).unwrap();
					// Like other template types, tuples are always mapped as their non-ref
					// versions for types which have different ref mappings. Thus, we convert to
					// non-ref versions and handle opaque types with inner pointers manually.
					for (idx, elem) in t.elems.iter().enumerate() {
						if let syn::Type::Path(p) = elem {
							let v_name = format!("orig_{}_{}", ident, idx);
							let tuple_elem_ident = syn::Ident::new(&v_name, Span::call_site());
							if self.write_conversion_new_var_intern(w, &tuple_elem_ident, &v_name, elem, generics,
									false, ptr_for_ref, to_c,
									path_lookup, container_lookup, var_prefix, var_suffix) {
								write!(w, " ").unwrap();
								// Opaque types with inner pointers shouldn't ever create new stack
								// variables, so we don't handle it and just assert that it doesn't
								// here.
								assert!(!self.c_type_has_inner_from_path(&self.resolve_path(&p.path, generics)));
							}
						}
					}
					write!(w, "let mut local_{} = (", ident).unwrap();
					for (idx, elem) in t.elems.iter().enumerate() {
						let ty_has_inner = {
								if to_c {
									// "To C ptr_for_ref" means "return the regular object with
									// is_owned set to false", which is totally what we want
									// if we're about to set ty_has_inner.
									ptr_for_ref = true;
								}
								if let syn::Type::Reference(t) = elem {
									if let syn::Type::Path(p) = &*t.elem {
										self.c_type_has_inner_from_path(&self.resolve_path(&p.path, generics))
									} else { false }
								} else if let syn::Type::Path(p) = elem {
									self.c_type_has_inner_from_path(&self.resolve_path(&p.path, generics))
								} else { false }
							};
						if idx != 0 { write!(w, ", ").unwrap(); }
						var_prefix(w, elem, generics, is_ref && ty_has_inner, ptr_for_ref, false);
						if is_ref && ty_has_inner {
							// For ty_has_inner, the regular var_prefix mapping will take a
							// reference, so deref once here to make sure we keep the original ref.
							write!(w, "*").unwrap();
						}
						write!(w, "orig_{}_{}", ident, idx).unwrap();
						if is_ref && !ty_has_inner {
							// If we don't have an inner variable's reference to maintain, just
							// hope the type is Clonable and use that.
							write!(w, ".clone()").unwrap();
						}
						var_suffix(w, elem, generics, is_ref && ty_has_inner, ptr_for_ref, false);
					}
					write!(w, "){};", if to_c { ".into()" } else { "" }).unwrap();
					true
				} else { false }
			},
			_ => unimplemented!(),
		}
	}

	pub fn write_to_c_conversion_new_var_inner<W: std::io::Write>(&self, w: &mut W, ident: &syn::Ident, var_access: &str, t: &syn::Type, generics: Option<&GenericTypes>, ptr_for_ref: bool) -> bool {
		self.write_conversion_new_var_intern(w, ident, var_access, t, generics, false, ptr_for_ref, true,
			&|a, b| self.to_c_conversion_new_var_from_path(a, b),
			&|a, b, c, d, e| self.to_c_conversion_container_new_var(generics, a, b, c, d, e),
			// We force ptr_for_ref here since we can't generate a ref on one line and use it later
			&|a, b, c, d, e, f| self.write_to_c_conversion_inline_prefix_inner(a, b, c, d, e, f),
			&|a, b, c, d, e, f| self.write_to_c_conversion_inline_suffix_inner(a, b, c, d, e, f))
	}
	pub fn write_to_c_conversion_new_var<W: std::io::Write>(&self, w: &mut W, ident: &syn::Ident, t: &syn::Type, generics: Option<&GenericTypes>, ptr_for_ref: bool) -> bool {
		self.write_to_c_conversion_new_var_inner(w, ident, &format!("{}", ident), t, generics, ptr_for_ref)
	}
	pub fn write_from_c_conversion_new_var<W: std::io::Write>(&self, w: &mut W, ident: &syn::Ident, t: &syn::Type, generics: Option<&GenericTypes>) -> bool {
		self.write_conversion_new_var_intern(w, ident, &format!("{}", ident), t, generics, false, false, false,
			&|a, b| self.from_c_conversion_new_var_from_path(a, b),
			&|a, b, c, d, e| self.from_c_conversion_container_new_var(generics, a, b, c, d, e),
			// We force ptr_for_ref here since we can't generate a ref on one line and use it later
			&|a, b, c, d, e, _f| self.write_from_c_conversion_prefix_inner(a, b, c, d, e),
			&|a, b, c, d, e, _f| self.write_from_c_conversion_suffix_inner(a, b, c, d, e))
	}

	// ******************************************************
	// *** C Container Type Equivalent and alias Printing ***
	// ******************************************************

	fn write_template_generics<'b, W: std::io::Write>(&mut self, w: &mut W, args: &mut dyn Iterator<Item=&'b syn::Type>, generics: Option<&GenericTypes>, is_ref: bool) -> bool {
		assert!(!is_ref); // We don't currently support outer reference types
		for (idx, t) in args.enumerate() {
			if idx != 0 {
				write!(w, ", ").unwrap();
			}
			if let syn::Type::Reference(r_arg) = t {
				if !self.write_c_type_intern(w, &*r_arg.elem, generics, false, false, false) { return false; }

				// While write_c_type_intern, above is correct, we don't want to blindly convert a
				// reference to something stupid, so check that the container is either opaque or a
				// predefined type (currently only Transaction).
				if let syn::Type::Path(p_arg) = &*r_arg.elem {
					let resolved = self.resolve_path(&p_arg.path, generics);
					assert!(self.crate_types.opaques.get(&resolved).is_some() ||
							self.c_type_from_path(&resolved, true, true).is_some(), "Template generics should be opaque or have a predefined mapping");
				} else { unimplemented!(); }
			} else {
				if !self.write_c_type_intern(w, t, generics, false, false, false) { return false; }
			}
		}
		true
	}
	fn check_create_container(&mut self, mangled_container: String, container_type: &str, args: Vec<&syn::Type>, generics: Option<&GenericTypes>, is_ref: bool) -> bool {
		if !self.crate_types.templates_defined.get(&mangled_container).is_some() {
			let mut created_container: Vec<u8> = Vec::new();

			if container_type == "Result" {
				let mut a_ty: Vec<u8> = Vec::new();
				if let syn::Type::Tuple(tup) = args.iter().next().unwrap() {
					if tup.elems.is_empty() {
						write!(&mut a_ty, "()").unwrap();
					} else {
						if !self.write_template_generics(&mut a_ty, &mut args.iter().map(|t| *t).take(1), generics, is_ref) { return false; }
					}
				} else {
					if !self.write_template_generics(&mut a_ty, &mut args.iter().map(|t| *t).take(1), generics, is_ref) { return false; }
				}

				let mut b_ty: Vec<u8> = Vec::new();
				if let syn::Type::Tuple(tup) = args.iter().skip(1).next().unwrap() {
					if tup.elems.is_empty() {
						write!(&mut b_ty, "()").unwrap();
					} else {
						if !self.write_template_generics(&mut b_ty, &mut args.iter().map(|t| *t).skip(1), generics, is_ref) { return false; }
					}
				} else {
					if !self.write_template_generics(&mut b_ty, &mut args.iter().map(|t| *t).skip(1), generics, is_ref) { return false; }
				}

				let ok_str = String::from_utf8(a_ty).unwrap();
				let err_str = String::from_utf8(b_ty).unwrap();
				let is_clonable = self.is_clonable(&ok_str) && self.is_clonable(&err_str);
				write_result_block(&mut created_container, &mangled_container, &ok_str, &err_str, is_clonable);
				if is_clonable {
					self.crate_types.clonable_types.insert(Self::generated_container_path().to_owned() + "::" + &mangled_container);
				}
			} else if container_type == "Vec" {
				let mut a_ty: Vec<u8> = Vec::new();
				if !self.write_template_generics(&mut a_ty, &mut args.iter().map(|t| *t), generics, is_ref) { return false; }
				let ty = String::from_utf8(a_ty).unwrap();
				let is_clonable = self.is_clonable(&ty);
				write_vec_block(&mut created_container, &mangled_container, &ty, is_clonable);
				if is_clonable {
					self.crate_types.clonable_types.insert(Self::generated_container_path().to_owned() + "::" + &mangled_container);
				}
			} else if container_type.ends_with("Tuple") {
				let mut tuple_args = Vec::new();
				let mut is_clonable = true;
				for arg in args.iter() {
					let mut ty: Vec<u8> = Vec::new();
					if !self.write_template_generics(&mut ty, &mut [arg].iter().map(|t| **t), generics, is_ref) { return false; }
					let ty_str = String::from_utf8(ty).unwrap();
					if !self.is_clonable(&ty_str) {
						is_clonable = false;
					}
					tuple_args.push(ty_str);
				}
				write_tuple_block(&mut created_container, &mangled_container, &tuple_args, is_clonable);
				if is_clonable {
					self.crate_types.clonable_types.insert(Self::generated_container_path().to_owned() + "::" + &mangled_container);
				}
			} else {
				unreachable!();
			}
			self.crate_types.templates_defined.insert(mangled_container.clone(), true);

			self.crate_types.template_file.write(&created_container).unwrap();
		}
		true
	}
	fn path_to_generic_args(path: &syn::Path) -> Vec<&syn::Type> {
		if let syn::PathArguments::AngleBracketed(args) = &path.segments.iter().next().unwrap().arguments {
			args.args.iter().map(|gen| if let syn::GenericArgument::Type(t) = gen { t } else { unimplemented!() }).collect()
		} else { unimplemented!(); }
	}
	fn write_c_mangled_container_path_intern<W: std::io::Write>
			(&mut self, w: &mut W, args: Vec<&syn::Type>, generics: Option<&GenericTypes>, ident: &str, is_ref: bool, is_mut: bool, ptr_for_ref: bool, in_type: bool) -> bool {
		let mut mangled_type: Vec<u8> = Vec::new();
		if !self.is_transparent_container(ident, is_ref) {
			write!(w, "C{}_", ident).unwrap();
			write!(mangled_type, "C{}_", ident).unwrap();
		} else { assert_eq!(args.len(), 1); }
		for arg in args.iter() {
			macro_rules! write_path {
				($p_arg: expr, $extra_write: expr) => {
					if let Some(subtype) = self.maybe_resolve_path(&$p_arg.path, generics) {
						if self.is_transparent_container(ident, is_ref) {
							// We dont (yet) support primitives or containers inside transparent
							// containers, so check for that first:
							if self.is_primitive(&subtype) { return false; }
							if self.is_known_container(&subtype, is_ref) { return false; }
							if !in_type {
								if self.c_type_has_inner_from_path(&subtype) {
									if !self.write_c_path_intern(w, &$p_arg.path, generics, is_ref, is_mut, ptr_for_ref) { return false; }
								} else {
									// Option<T> needs to be converted to a *mut T, ie mut ptr-for-ref
									if !self.write_c_path_intern(w, &$p_arg.path, generics, true, true, true) { return false; }
								}
							} else {
								if $p_arg.path.segments.len() == 1 {
									write!(w, "{}", $p_arg.path.segments.iter().next().unwrap().ident).unwrap();
								} else {
									return false;
								}
							}
						} else if self.is_known_container(&subtype, is_ref) || self.is_transparent_container(&subtype, is_ref) {
							if !self.write_c_mangled_container_path_intern(w, Self::path_to_generic_args(&$p_arg.path), generics,
									&subtype, is_ref, is_mut, ptr_for_ref, true) {
								return false;
							}
							self.write_c_mangled_container_path_intern(&mut mangled_type, Self::path_to_generic_args(&$p_arg.path),
								generics, &subtype, is_ref, is_mut, ptr_for_ref, true);
							if let Some(w2) = $extra_write as Option<&mut Vec<u8>> {
								self.write_c_mangled_container_path_intern(w2, Self::path_to_generic_args(&$p_arg.path),
									generics, &subtype, is_ref, is_mut, ptr_for_ref, true);
							}
						} else {
							let id = subtype.rsplitn(2, ':').next().unwrap(); // Get the "Base" name of the resolved type
							write!(w, "{}", id).unwrap();
							write!(mangled_type, "{}", id).unwrap();
							if let Some(w2) = $extra_write as Option<&mut Vec<u8>> {
								write!(w2, "{}", id).unwrap();
							}
						}
					} else { return false; }
				}
			}
			if let syn::Type::Tuple(tuple) = arg {
				if tuple.elems.len() == 0 {
					write!(w, "None").unwrap();
					write!(mangled_type, "None").unwrap();
				} else {
					let mut mangled_tuple_type: Vec<u8> = Vec::new();

					// Figure out what the mangled type should look like. To disambiguate
					// ((A, B), C) and (A, B, C) we prefix the generic args with a _ and suffix
					// them with a Z. Ideally we wouldn't use Z, but not many special chars are
					// available for use in type names.
					write!(w, "C{}Tuple_", tuple.elems.len()).unwrap();
					write!(mangled_type, "C{}Tuple_", tuple.elems.len()).unwrap();
					write!(mangled_tuple_type, "C{}Tuple_", tuple.elems.len()).unwrap();
					for elem in tuple.elems.iter() {
						if let syn::Type::Path(p) = elem {
							write_path!(p, Some(&mut mangled_tuple_type));
						} else if let syn::Type::Reference(refelem) = elem {
							if let syn::Type::Path(p) = &*refelem.elem {
								write_path!(p, Some(&mut mangled_tuple_type));
							} else { return false; }
						} else { return false; }
					}
					write!(w, "Z").unwrap();
					write!(mangled_type, "Z").unwrap();
					write!(mangled_tuple_type, "Z").unwrap();
					if !self.check_create_container(String::from_utf8(mangled_tuple_type).unwrap(),
							&format!("{}Tuple", tuple.elems.len()), tuple.elems.iter().collect(), generics, is_ref) {
						return false;
					}
				}
			} else if let syn::Type::Path(p_arg) = arg {
				write_path!(p_arg, None);
			} else if let syn::Type::Reference(refty) = arg {
				if let syn::Type::Path(p_arg) = &*refty.elem {
					write_path!(p_arg, None);
				} else if let syn::Type::Slice(_) = &*refty.elem {
					// write_c_type will actually do exactly what we want here, we just need to
					// make it a pointer so that its an option. Note that we cannot always convert
					// the Vec-as-slice (ie non-ref types) containers, so sometimes need to be able
					// to edit it, hence we use *mut here instead of *const.
					if args.len() != 1 { return false; }
					write!(w, "*mut ").unwrap();
					self.write_c_type(w, arg, None, true);
				} else { return false; }
			} else if let syn::Type::Array(a) = arg {
				if let syn::Type::Path(p_arg) = &*a.elem {
					let resolved = self.resolve_path(&p_arg.path, generics);
					if !self.is_primitive(&resolved) { return false; }
					if let syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Int(len), .. }) = &a.len {
						if self.c_type_from_path(&format!("[{}; {}]", resolved, len.base10_digits()), is_ref, ptr_for_ref).is_none() { return false; }
						write!(w, "_{}{}", resolved, len.base10_digits()).unwrap();
						write!(mangled_type, "_{}{}", resolved, len.base10_digits()).unwrap();
					} else { return false; }
				} else { return false; }
			} else { return false; }
		}
		if self.is_transparent_container(ident, is_ref) { return true; }
		// Push the "end of type" Z
		write!(w, "Z").unwrap();
		write!(mangled_type, "Z").unwrap();

		// Make sure the type is actually defined:
		self.check_create_container(String::from_utf8(mangled_type).unwrap(), ident, args, generics, is_ref)
	}
	fn write_c_mangled_container_path<W: std::io::Write>(&mut self, w: &mut W, args: Vec<&syn::Type>, generics: Option<&GenericTypes>, ident: &str, is_ref: bool, is_mut: bool, ptr_for_ref: bool) -> bool {
		if !self.is_transparent_container(ident, is_ref) {
			write!(w, "{}::", Self::generated_container_path()).unwrap();
		}
		self.write_c_mangled_container_path_intern(w, args, generics, ident, is_ref, is_mut, ptr_for_ref, false)
	}

	// **********************************
	// *** C Type Equivalent Printing ***
	// **********************************

	fn write_c_path_intern<W: std::io::Write>(&self, w: &mut W, path: &syn::Path, generics: Option<&GenericTypes>, is_ref: bool, is_mut: bool, ptr_for_ref: bool) -> bool {
		let full_path = match self.maybe_resolve_path(&path, generics) {
			Some(path) => path, None => return false };
		if let Some(c_type) = self.c_type_from_path(&full_path, is_ref, ptr_for_ref) {
			write!(w, "{}", c_type).unwrap();
			true
		} else if self.crate_types.traits.get(&full_path).is_some() {
			if is_ref && ptr_for_ref {
				write!(w, "*{} crate::{}", if is_mut { "mut" } else { "const" }, full_path).unwrap();
			} else if is_ref {
				write!(w, "&{}crate::{}", if is_mut { "mut " } else { "" }, full_path).unwrap();
			} else {
				write!(w, "crate::{}", full_path).unwrap();
			}
			true
		} else if self.crate_types.opaques.get(&full_path).is_some() || self.crate_types.mirrored_enums.get(&full_path).is_some() {
			if is_ref && ptr_for_ref {
				// ptr_for_ref implies we're returning the object, which we can't really do for
				// opaque or mirrored types without box'ing them, which is quite a waste, so return
				// the actual object itself (for opaque types we'll set the pointer to the actual
				// type and note that its a reference).
				write!(w, "crate::{}", full_path).unwrap();
			} else if is_ref {
				write!(w, "&{}crate::{}", if is_mut { "mut " } else { "" }, full_path).unwrap();
			} else {
				write!(w, "crate::{}", full_path).unwrap();
			}
			true
		} else {
			false
		}
	}
	fn write_c_type_intern<W: std::io::Write>(&mut self, w: &mut W, t: &syn::Type, generics: Option<&GenericTypes>, is_ref: bool, is_mut: bool, ptr_for_ref: bool) -> bool {
		match t {
			syn::Type::Path(p) => {
				if p.qself.is_some() {
					return false;
				}
				if let Some(full_path) = self.maybe_resolve_path(&p.path, generics) {
					if self.is_known_container(&full_path, is_ref) || self.is_transparent_container(&full_path, is_ref) {
						return self.write_c_mangled_container_path(w, Self::path_to_generic_args(&p.path), generics, &full_path, is_ref, is_mut, ptr_for_ref);
					}
					if let Some(aliased_type) = self.crate_types.type_aliases.get(&full_path).cloned() {
						return self.write_c_type_intern(w, &aliased_type, None, is_ref, is_mut, ptr_for_ref);
					}
				}
				self.write_c_path_intern(w, &p.path, generics, is_ref, is_mut, ptr_for_ref)
			},
			syn::Type::Reference(r) => {
				self.write_c_type_intern(w, &*r.elem, generics, true, r.mutability.is_some(), ptr_for_ref)
			},
			syn::Type::Array(a) => {
				if is_ref && is_mut {
					write!(w, "*mut [").unwrap();
					if !self.write_c_type_intern(w, &a.elem, generics, false, false, ptr_for_ref) { return false; }
				} else if is_ref {
					write!(w, "*const [").unwrap();
					if !self.write_c_type_intern(w, &a.elem, generics, false, false, ptr_for_ref) { return false; }
				} else {
					let mut typecheck = Vec::new();
					if !self.write_c_type_intern(&mut typecheck, &a.elem, generics, false, false, ptr_for_ref) { return false; }
					if typecheck[..] != ['u' as u8, '8' as u8] { return false; }
				}
				if let syn::Expr::Lit(l) = &a.len {
					if let syn::Lit::Int(i) = &l.lit {
						if !is_ref {
							if let Some(ty) = self.c_type_from_path(&format!("[u8; {}]", i.base10_digits()), false, ptr_for_ref) {
								write!(w, "{}", ty).unwrap();
								true
							} else { false }
						} else {
							write!(w, "; {}]", i).unwrap();
							true
						}
					} else { false }
				} else { false }
			}
			syn::Type::Slice(s) => {
				if !is_ref || is_mut { return false; }
				if let syn::Type::Path(p) = &*s.elem {
					let resolved = self.resolve_path(&p.path, generics);
					if self.is_primitive(&resolved) {
						write!(w, "{}::{}slice", Self::container_templ_path(), resolved).unwrap();
						true
					} else { false }
				} else if let syn::Type::Reference(r) = &*s.elem {
					if let syn::Type::Path(p) = &*r.elem {
						// Slices with "real types" inside are mapped as the equivalent non-ref Vec
						let resolved = self.resolve_path(&p.path, generics);
						let mangled_container = if let Some(ident) = self.crate_types.opaques.get(&resolved) {
							format!("CVec_{}Z", ident)
						} else if let Some(en) = self.crate_types.mirrored_enums.get(&resolved) {
							format!("CVec_{}Z", en.ident)
						} else if let Some(id) = p.path.get_ident() {
							format!("CVec_{}Z", id)
						} else { return false; };
						write!(w, "{}::{}", Self::generated_container_path(), mangled_container).unwrap();
						self.check_create_container(mangled_container, "Vec", vec![&*r.elem], generics, false)
					} else { false }
				} else if let syn::Type::Tuple(_) = &*s.elem {
					let mut args = syn::punctuated::Punctuated::new();
					args.push(syn::GenericArgument::Type((*s.elem).clone()));
					let mut segments = syn::punctuated::Punctuated::new();
					segments.push(syn::PathSegment {
						ident: syn::Ident::new("Vec", Span::call_site()),
						arguments: syn::PathArguments::AngleBracketed(syn::AngleBracketedGenericArguments {
							colon2_token: None, lt_token: syn::Token![<](Span::call_site()), args, gt_token: syn::Token![>](Span::call_site()),
						})
					});
					self.write_c_type_intern(w, &syn::Type::Path(syn::TypePath { qself: None, path: syn::Path { leading_colon: None, segments } }), generics, false, is_mut, ptr_for_ref)
				} else { false }
			},
			syn::Type::Tuple(t) => {
				if t.elems.len() == 0 {
					true
				} else {
					self.write_c_mangled_container_path(w, t.elems.iter().collect(), generics,
						&format!("{}Tuple", t.elems.len()), is_ref, is_mut, ptr_for_ref)
				}
			},
			_ => false,
		}
	}
	pub fn write_c_type<W: std::io::Write>(&mut self, w: &mut W, t: &syn::Type, generics: Option<&GenericTypes>, ptr_for_ref: bool) {
		assert!(self.write_c_type_intern(w, t, generics, false, false, ptr_for_ref));
	}
	pub fn understood_c_path(&mut self, p: &syn::Path) -> bool {
		if p.leading_colon.is_some() { return false; }
		self.write_c_path_intern(&mut std::io::sink(), p, None, false, false, false)
	}
	pub fn understood_c_type(&mut self, t: &syn::Type, generics: Option<&GenericTypes>) -> bool {
		self.write_c_type_intern(&mut std::io::sink(), t, generics, false, false, false)
	}
}
