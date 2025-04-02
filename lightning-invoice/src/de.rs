use alloc::string;
#[cfg(not(feature = "std"))]
use core::convert::TryFrom;
use core::fmt;
use core::fmt::{Display, Formatter};
use core::num::ParseIntError;
use core::str::FromStr;
#[cfg(feature = "std")]
use std::error;

use bech32::primitives::decode::{CheckedHrpstring, CheckedHrpstringError};
use bech32::{Fe32, Fe32IterExt};

use crate::prelude::*;
use crate::Bolt11Bech32;
use bitcoin::hashes::sha256;
use bitcoin::hashes::Hash;
use bitcoin::{PubkeyHash, ScriptHash, WitnessVersion};
use lightning_types::payment::PaymentSecret;
use lightning_types::routing::{RouteHint, RouteHintHop, RoutingFees};

use bitcoin::secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use bitcoin::secp256k1::PublicKey;

use super::{
	constants, Bolt11Invoice, Bolt11InvoiceFeatures, Bolt11InvoiceSignature, Bolt11ParseError,
	Bolt11SemanticError, Currency, Description, ExpiryTime, Fallback, MinFinalCltvExpiryDelta,
	ParseOrSemanticError, PayeePubKey, PositiveTimestamp, PrivateRoute, RawBolt11Invoice,
	RawDataPart, RawHrp, RawTaggedField, Sha256, SiPrefix, SignedRawBolt11Invoice, TaggedField,
};

use self::hrp_sm::parse_hrp;

/// Trait for parsing/converting base32 slice.
pub trait FromBase32: Sized {
	/// The associated error which can be returned from parsing (e.g. because of bad padding).
	type Err;

	/// Convert a base32 slice to `Self`.
	fn from_base32(b32: &[Fe32]) -> Result<Self, Self::Err>;
}

// FromBase32 implementations are here, because the trait is in this module.

impl FromBase32 for Vec<u8> {
	type Err = Bolt11ParseError;

	fn from_base32(data: &[Fe32]) -> Result<Self, Self::Err> {
		Ok(data.iter().copied().fes_to_bytes().collect::<Self>())
	}
}

impl<const N: usize> FromBase32 for [u8; N] {
	type Err = Bolt11ParseError;

	fn from_base32(data: &[Fe32]) -> Result<Self, Self::Err> {
		let mut res_arr = [0; N];
		// Do in a for loop to place in the array directly, not using `collect`
		let mut count = 0;
		for elem in data.iter().copied().fes_to_bytes() {
			if count >= N {
				// too many elements
				count += 1;
				break;
			}
			res_arr[count] = elem;
			count += 1;
		}
		if count != N {
			return Err(Bolt11ParseError::InvalidSliceLength(count, N, "<[u8; N]>"));
		}
		Ok(res_arr)
	}
}

impl FromBase32 for PaymentSecret {
	type Err = Bolt11ParseError;

	fn from_base32(field_data: &[Fe32]) -> Result<Self, Self::Err> {
		if field_data.len() != 52 {
			return Err(Bolt11ParseError::InvalidSliceLength(
				field_data.len(),
				52,
				"PaymentSecret",
			));
		}
		let data_bytes = <[u8; 32]>::from_base32(field_data)?;
		Ok(PaymentSecret(data_bytes))
	}
}

impl FromBase32 for Bolt11InvoiceFeatures {
	type Err = Bolt11ParseError;

	/// Convert to byte values, by packing the 5-bit groups,
	/// putting the 5-bit values from left to-right (reverse order),
	/// starting from the rightmost bit,
	/// and taking the resulting 8-bit values (right to left),
	/// with the leading 0's skipped.
	fn from_base32(field_data: &[Fe32]) -> Result<Self, Self::Err> {
		// Fe32 conversion cannot be used, because this unpacks from right, right-to-left
		// Carry bits, 0, 1, 2, 3, or 4 bits
		let mut carry_bits = 0;
		let mut carry = 0u8;
		let expected_raw_length = (field_data.len() * 5 + 7) / 8;
		let mut output = Vec::<u8>::with_capacity(expected_raw_length);

		// Iterate over input in reverse
		for curr_in in field_data.iter().rev() {
			let curr_in_as_u8 = curr_in.to_u8();
			if carry_bits >= 3 {
				// we have a new full byte -- 3, 4 or 5 carry bits, plus 5 new ones
				// For combining with carry '|', '^', or '+' can be used (disjoint bit positions)
				let next = carry + (curr_in_as_u8 << carry_bits);
				output.push(next);
				carry = curr_in_as_u8 >> (8 - carry_bits);
				carry_bits -= 3; // added 5, removed 8
			} else {
				// only 0, 1, or 2 carry bits,  plus 5 new ones
				carry += curr_in_as_u8 << carry_bits;
				carry_bits += 5;
			}
		}

		// No more inputs, output remaining (if any)
		if carry_bits > 0 {
			output.push(carry);
		}

		// This is to double check the estimated length and
		// satisfying mutation test on the capacity, which is mutatable
		debug_assert_eq!(output.len(), expected_raw_length);

		// Trim the highest feature bits
		while !output.is_empty() && output[output.len() - 1] == 0 {
			output.pop();
		}

		Ok(Bolt11InvoiceFeatures::from_le_bytes(output))
	}
}

/// State machine to parse the hrp
mod hrp_sm {
	use core::ops::Range;

	#[derive(PartialEq, Eq, Debug)]
	enum States {
		Start,
		ParseL,
		ParseN,
		ParseCurrencyPrefix,
		ParseAmountNumber,
		ParseAmountSiPrefix,
	}

	impl States {
		fn next_state(&self, read_byte: u8) -> Result<States, super::Bolt11ParseError> {
			let read_symbol = match char::from_u32(read_byte.into()) {
				Some(symb) if symb.is_ascii() => symb,
				_ => return Err(super::Bolt11ParseError::MalformedHRP),
			};
			match *self {
				States::Start => {
					if read_symbol == 'l' {
						Ok(States::ParseL)
					} else {
						Err(super::Bolt11ParseError::MalformedHRP)
					}
				},
				States::ParseL => {
					if read_symbol == 'n' {
						Ok(States::ParseN)
					} else {
						Err(super::Bolt11ParseError::MalformedHRP)
					}
				},
				States::ParseN => {
					if !read_symbol.is_numeric() {
						Ok(States::ParseCurrencyPrefix)
					} else {
						Ok(States::ParseAmountNumber)
					}
				},
				States::ParseCurrencyPrefix => {
					if !read_symbol.is_numeric() {
						Ok(States::ParseCurrencyPrefix)
					} else {
						Ok(States::ParseAmountNumber)
					}
				},
				States::ParseAmountNumber => {
					if read_symbol.is_numeric() {
						Ok(States::ParseAmountNumber)
					} else if ['m', 'u', 'n', 'p'].contains(&read_symbol) {
						Ok(States::ParseAmountSiPrefix)
					} else {
						Err(super::Bolt11ParseError::UnknownSiPrefix)
					}
				},
				States::ParseAmountSiPrefix => Err(super::Bolt11ParseError::MalformedHRP),
			}
		}

		fn is_final(&self) -> bool {
			!(*self == States::ParseL || *self == States::ParseN)
		}
	}

	struct StateMachine {
		state: States,
		position: usize,
		currency_prefix: Option<Range<usize>>,
		amount_number: Option<Range<usize>>,
		amount_si_prefix: Option<Range<usize>>,
	}

	impl StateMachine {
		fn new() -> StateMachine {
			StateMachine {
				state: States::Start,
				position: 0,
				currency_prefix: None,
				amount_number: None,
				amount_si_prefix: None,
			}
		}

		fn update_range(range: &mut Option<Range<usize>>, position: usize) {
			let new_range = match *range {
				None => Range { start: position, end: position + 1 },
				Some(ref r) => Range { start: r.start, end: r.end + 1 },
			};
			*range = Some(new_range);
		}

		fn step(&mut self, c: u8) -> Result<(), super::Bolt11ParseError> {
			let next_state = self.state.next_state(c)?;
			match next_state {
				States::ParseCurrencyPrefix => {
					StateMachine::update_range(&mut self.currency_prefix, self.position)
				},
				States::ParseAmountNumber => {
					StateMachine::update_range(&mut self.amount_number, self.position)
				},
				States::ParseAmountSiPrefix => {
					StateMachine::update_range(&mut self.amount_si_prefix, self.position)
				},
				_ => {},
			}

			self.position += 1;
			self.state = next_state;
			Ok(())
		}

		fn is_final(&self) -> bool {
			self.state.is_final()
		}

		fn currency_prefix(&self) -> &Option<Range<usize>> {
			&self.currency_prefix
		}

		fn amount_number(&self) -> &Option<Range<usize>> {
			&self.amount_number
		}

		fn amount_si_prefix(&self) -> &Option<Range<usize>> {
			&self.amount_si_prefix
		}
	}

	pub fn parse_hrp(input: &str) -> Result<(&str, &str, &str), super::Bolt11ParseError> {
		let mut sm = StateMachine::new();
		for c in input.bytes() {
			sm.step(c)?;
		}

		if !sm.is_final() {
			return Err(super::Bolt11ParseError::MalformedHRP);
		}

		let currency = sm.currency_prefix().clone().map(|r| &input[r]).unwrap_or("");
		let amount = sm.amount_number().clone().map(|r| &input[r]).unwrap_or("");
		let si = sm.amount_si_prefix().clone().map(|r| &input[r]).unwrap_or("");

		Ok((currency, amount, si))
	}
}

impl FromStr for super::Currency {
	type Err = Bolt11ParseError;

	fn from_str(currency_prefix: &str) -> Result<Self, Bolt11ParseError> {
		match currency_prefix {
			"bc" => Ok(Currency::Bitcoin),
			"tb" => Ok(Currency::BitcoinTestnet),
			"bcrt" => Ok(Currency::Regtest),
			"sb" => Ok(Currency::Simnet),
			"tbs" => Ok(Currency::Signet),
			_ => Err(Bolt11ParseError::UnknownCurrency),
		}
	}
}

impl FromStr for SiPrefix {
	type Err = Bolt11ParseError;

	fn from_str(currency_prefix: &str) -> Result<Self, Bolt11ParseError> {
		use crate::SiPrefix::*;
		match currency_prefix {
			"m" => Ok(Milli),
			"u" => Ok(Micro),
			"n" => Ok(Nano),
			"p" => Ok(Pico),
			_ => Err(Bolt11ParseError::UnknownSiPrefix),
		}
	}
}

/// ```
/// use lightning_invoice::Bolt11Invoice;
///
///
/// let invoice = "lnbc100p1psj9jhxdqud3jxktt5w46x7unfv9kz6mn0v3jsnp4q0d3p2sfluzdx45tqcs\
/// h2pu5qc7lgq0xs578ngs6s0s68ua4h7cvspp5q6rmq35js88zp5dvwrv9m459tnk2zunwj5jalqtyxqulh0l\
/// 5gflssp5nf55ny5gcrfl30xuhzj3nphgj27rstekmr9fw3ny5989s300gyus9qyysgqcqpcrzjqw2sxwe993\
/// h5pcm4dxzpvttgza8zhkqxpgffcrf5v25nwpr3cmfg7z54kuqq8rgqqqqqqqq2qqqqq9qq9qrzjqd0ylaqcl\
/// j9424x9m8h2vcukcgnm6s56xfgu3j78zyqzhgs4hlpzvznlugqq9vsqqqqqqqlgqqqqqeqq9qrzjqwldmj9d\
/// ha74df76zhx6l9we0vjdquygcdt3kssupehe64g6yyp5yz5rhuqqwccqqyqqqqlgqqqqjcqq9qrzjqf9e58a\
/// guqr0rcun0ajlvmzq3ek63cw2w282gv3z5uupmuwvgjtq2z55qsqqg6qqqyqqqrtnqqqzq3cqygrzjqvphms\
/// ywntrrhqjcraumvc4y6r8v4z5v593trte429v4hredj7ms5z52usqq9ngqqqqqqqlgqqqqqqgq9qrzjq2v0v\
/// p62g49p7569ev48cmulecsxe59lvaw3wlxm7r982zxa9zzj7z5l0cqqxusqqyqqqqlgqqqqqzsqygarl9fh3\
/// 8s0gyuxjjgux34w75dnc6xp2l35j7es3jd4ugt3lu0xzre26yg5m7ke54n2d5sym4xcmxtl8238xxvw5h5h5\
/// j5r6drg6k6zcqj0fcwg";
///
/// assert!(invoice.parse::<Bolt11Invoice>().is_ok());
/// ```
impl FromStr for Bolt11Invoice {
	type Err = ParseOrSemanticError;

	fn from_str(s: &str) -> Result<Self, <Self as FromStr>::Err> {
		let signed = s.parse::<SignedRawBolt11Invoice>()?;
		Ok(Bolt11Invoice::from_signed(signed)?)
	}
}

/// ```
/// use lightning_invoice::*;
///
/// let invoice = "lnbc100p1psj9jhxdqud3jxktt5w46x7unfv9kz6mn0v3jsnp4q0d3p2sfluzdx45tqcs\
/// h2pu5qc7lgq0xs578ngs6s0s68ua4h7cvspp5q6rmq35js88zp5dvwrv9m459tnk2zunwj5jalqtyxqulh0l\
/// 5gflssp5nf55ny5gcrfl30xuhzj3nphgj27rstekmr9fw3ny5989s300gyus9qyysgqcqpcrzjqw2sxwe993\
/// h5pcm4dxzpvttgza8zhkqxpgffcrf5v25nwpr3cmfg7z54kuqq8rgqqqqqqqq2qqqqq9qq9qrzjqd0ylaqcl\
/// j9424x9m8h2vcukcgnm6s56xfgu3j78zyqzhgs4hlpzvznlugqq9vsqqqqqqqlgqqqqqeqq9qrzjqwldmj9d\
/// ha74df76zhx6l9we0vjdquygcdt3kssupehe64g6yyp5yz5rhuqqwccqqyqqqqlgqqqqjcqq9qrzjqf9e58a\
/// guqr0rcun0ajlvmzq3ek63cw2w282gv3z5uupmuwvgjtq2z55qsqqg6qqqyqqqrtnqqqzq3cqygrzjqvphms\
/// ywntrrhqjcraumvc4y6r8v4z5v593trte429v4hredj7ms5z52usqq9ngqqqqqqqlgqqqqqqgq9qrzjq2v0v\
/// p62g49p7569ev48cmulecsxe59lvaw3wlxm7r982zxa9zzj7z5l0cqqxusqqyqqqqlgqqqqqzsqygarl9fh3\
/// 8s0gyuxjjgux34w75dnc6xp2l35j7es3jd4ugt3lu0xzre26yg5m7ke54n2d5sym4xcmxtl8238xxvw5h5h5\
/// j5r6drg6k6zcqj0fcwg";
///
/// let parsed_1 = invoice.parse::<Bolt11Invoice>();
///
/// let parsed_2 = match invoice.parse::<SignedRawBolt11Invoice>() {
/// 	Ok(signed) => match Bolt11Invoice::from_signed(signed) {
/// 		Ok(invoice) => Ok(invoice),
/// 		Err(e) => Err(ParseOrSemanticError::SemanticError(e)),
/// 	},
/// 	Err(e) => Err(ParseOrSemanticError::ParseError(e)),
/// };
///
/// assert!(parsed_1.is_ok());
/// assert_eq!(parsed_1, parsed_2);
/// ```
impl FromStr for SignedRawBolt11Invoice {
	type Err = Bolt11ParseError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let parsed = CheckedHrpstring::new::<Bolt11Bech32>(s)?;
		let hrp = parsed.hrp();
		// Access original non-packed 32 byte values (as Fe32s)
		// Note: the type argument is needed due to the API peculiarities, but it's not used
		let data: Vec<_> = parsed.fe32_iter::<&mut dyn Iterator<Item = u8>>().collect();

		const SIGNATURE_LEN_5: usize = 104; // number of the 5-bit values (equals to 65 bytes)
		if data.len() < SIGNATURE_LEN_5 {
			return Err(Bolt11ParseError::TooShortDataPart);
		}

		let raw_hrp: RawHrp = hrp.to_string().to_lowercase().parse()?;
		let data_part = RawDataPart::from_base32(&data[..data.len() - SIGNATURE_LEN_5])?;
		let raw_invoice = RawBolt11Invoice { hrp: raw_hrp, data: data_part };
		let hash = raw_invoice.signable_hash();

		Ok(SignedRawBolt11Invoice {
			raw_invoice,
			hash,
			signature: Bolt11InvoiceSignature::from_base32(&data[data.len() - SIGNATURE_LEN_5..])?,
		})
	}
}

impl FromStr for RawHrp {
	type Err = Bolt11ParseError;

	fn from_str(hrp: &str) -> Result<Self, <Self as FromStr>::Err> {
		let parts = parse_hrp(hrp)?;

		let currency = parts.0.parse::<Currency>()?;

		let amount = if !parts.1.is_empty() { Some(parts.1.parse::<u64>()?) } else { None };

		let si_prefix: Option<SiPrefix> = if parts.2.is_empty() {
			None
		} else {
			let si: SiPrefix = parts.2.parse()?;
			if let Some(amt) = amount {
				if amt.checked_mul(si.multiplier()).is_none() {
					return Err(Bolt11ParseError::IntegerOverflowError);
				}
			}
			Some(si)
		};

		Ok(RawHrp { currency, raw_amount: amount, si_prefix })
	}
}

impl FromBase32 for RawDataPart {
	type Err = Bolt11ParseError;

	fn from_base32(data: &[Fe32]) -> Result<Self, Self::Err> {
		const TIMESTAMP_LEN: usize = 7;
		if data.len() < TIMESTAMP_LEN {
			return Err(Bolt11ParseError::TooShortDataPart);
		}

		let timestamp = PositiveTimestamp::from_base32(&data[0..TIMESTAMP_LEN])?;
		let tagged = parse_tagged_parts(&data[TIMESTAMP_LEN..])?;

		Ok(RawDataPart { timestamp, tagged_fields: tagged })
	}
}

impl FromBase32 for PositiveTimestamp {
	type Err = Bolt11ParseError;

	fn from_base32(b32: &[Fe32]) -> Result<Self, Self::Err> {
		if b32.len() != 7 {
			return Err(Bolt11ParseError::InvalidSliceLength(b32.len(), 7, "PositiveTimestamp"));
		}
		let timestamp: u64 = parse_u64_be(b32).expect("7*5bit < 64bit, no overflow possible");
		match PositiveTimestamp::from_unix_timestamp(timestamp) {
			Ok(t) => Ok(t),
			Err(_) => unreachable!(),
		}
	}
}

impl FromBase32 for Bolt11InvoiceSignature {
	type Err = Bolt11ParseError;
	fn from_base32(signature: &[Fe32]) -> Result<Self, Self::Err> {
		if signature.len() != 104 {
			return Err(Bolt11ParseError::InvalidSliceLength(
				signature.len(),
				104,
				"Bolt11InvoiceSignature",
			));
		}
		let recoverable_signature_bytes = <[u8; 65]>::from_base32(signature)?;
		let signature = &recoverable_signature_bytes[0..64];
		let recovery_id = RecoveryId::from_i32(recoverable_signature_bytes[64] as i32)?;

		Ok(Bolt11InvoiceSignature(RecoverableSignature::from_compact(signature, recovery_id)?))
	}
}

macro_rules! define_parse_int_be {
	($name: ident, $ty: ty) => {
		fn $name(digits: &[Fe32]) -> Option<$ty> {
			digits.iter().fold(Some(Default::default()), |acc, b| {
				acc.and_then(|x| x.checked_mul(32))
					.and_then(|x| x.checked_add((Into::<u8>::into(*b)).into()))
			})
		}
	};
}
define_parse_int_be!(parse_u16_be, u16);
define_parse_int_be!(parse_u64_be, u64);

fn parse_tagged_parts(data: &[Fe32]) -> Result<Vec<RawTaggedField>, Bolt11ParseError> {
	let mut parts = Vec::<RawTaggedField>::new();
	let mut data = data;

	while !data.is_empty() {
		if data.len() < 3 {
			return Err(Bolt11ParseError::UnexpectedEndOfTaggedFields);
		}

		// Ignore tag at data[0], it will be handled in the TaggedField parsers and
		// parse the length to find the end of the tagged field's data
		let len = parse_u16_be(&data[1..3]).expect("can't overflow") as usize;
		let last_element = 3 + len;

		if data.len() < last_element {
			return Err(Bolt11ParseError::UnexpectedEndOfTaggedFields);
		}

		// Get the tagged field's data slice
		let field = &data[0..last_element];

		// Set data slice to remaining data
		data = &data[last_element..];

		match TaggedField::from_base32(field) {
			Ok(field) => parts.push(RawTaggedField::KnownSemantics(field)),
			Err(Bolt11ParseError::Skip)
			| Err(Bolt11ParseError::InvalidSliceLength(_, _, _))
			| Err(Bolt11ParseError::Bech32Error(_)) => {
				parts.push(RawTaggedField::UnknownSemantics(field.into()))
			},
			Err(e) => return Err(e),
		}
	}
	Ok(parts)
}

impl FromBase32 for TaggedField {
	type Err = Bolt11ParseError;

	fn from_base32(field: &[Fe32]) -> Result<TaggedField, Bolt11ParseError> {
		if field.len() < 3 {
			return Err(Bolt11ParseError::UnexpectedEndOfTaggedFields);
		}

		let tag = field[0];
		let field_data = &field[3..];

		match tag.to_u8() {
			constants::TAG_PAYMENT_HASH => {
				Ok(TaggedField::PaymentHash(Sha256::from_base32(field_data)?))
			},
			constants::TAG_DESCRIPTION => {
				Ok(TaggedField::Description(Description::from_base32(field_data)?))
			},
			constants::TAG_PAYEE_PUB_KEY => {
				Ok(TaggedField::PayeePubKey(PayeePubKey::from_base32(field_data)?))
			},
			constants::TAG_DESCRIPTION_HASH => {
				Ok(TaggedField::DescriptionHash(Sha256::from_base32(field_data)?))
			},
			constants::TAG_EXPIRY_TIME => {
				Ok(TaggedField::ExpiryTime(ExpiryTime::from_base32(field_data)?))
			},
			constants::TAG_MIN_FINAL_CLTV_EXPIRY_DELTA => Ok(TaggedField::MinFinalCltvExpiryDelta(
				MinFinalCltvExpiryDelta::from_base32(field_data)?,
			)),
			constants::TAG_FALLBACK => {
				Ok(TaggedField::Fallback(Fallback::from_base32(field_data)?))
			},
			constants::TAG_PRIVATE_ROUTE => {
				Ok(TaggedField::PrivateRoute(PrivateRoute::from_base32(field_data)?))
			},
			constants::TAG_PAYMENT_SECRET => {
				Ok(TaggedField::PaymentSecret(PaymentSecret::from_base32(field_data)?))
			},
			constants::TAG_PAYMENT_METADATA => {
				Ok(TaggedField::PaymentMetadata(Vec::<u8>::from_base32(field_data)?))
			},
			constants::TAG_FEATURES => {
				Ok(TaggedField::Features(Bolt11InvoiceFeatures::from_base32(field_data)?))
			},
			_ => {
				// "A reader MUST skip over unknown fields"
				Err(Bolt11ParseError::Skip)
			},
		}
	}
}

impl FromBase32 for Sha256 {
	type Err = Bolt11ParseError;

	fn from_base32(field_data: &[Fe32]) -> Result<Sha256, Bolt11ParseError> {
		if field_data.len() != 52 {
			// "A reader MUST skip over […] a p, [or] h […] field that does not have data_length 52 […]."
			Err(Bolt11ParseError::Skip)
		} else {
			Ok(Sha256(
				sha256::Hash::from_slice(&<[u8; 32]>::from_base32(field_data)?)
					.expect("length was checked before (52 u5 -> 32 u8)"),
			))
		}
	}
}

impl FromBase32 for Description {
	type Err = Bolt11ParseError;

	fn from_base32(field_data: &[Fe32]) -> Result<Description, Bolt11ParseError> {
		let bytes = Vec::<u8>::from_base32(field_data)?;
		let description = String::from_utf8(bytes)?;
		Ok(Description::new(description)
			.expect("Max len is 639=floor(1023*5/8) since the len field is only 10bits long"))
	}
}

impl FromBase32 for PayeePubKey {
	type Err = Bolt11ParseError;

	fn from_base32(field_data: &[Fe32]) -> Result<PayeePubKey, Bolt11ParseError> {
		if field_data.len() != 53 {
			// "A reader MUST skip over […] a n […] field that does not have data_length 53 […]."
			Err(Bolt11ParseError::Skip)
		} else {
			let data_bytes = <[u8; 33]>::from_base32(field_data)?;
			let pub_key = PublicKey::from_slice(&data_bytes)?;
			Ok(pub_key.into())
		}
	}
}

impl FromBase32 for ExpiryTime {
	type Err = Bolt11ParseError;

	fn from_base32(field_data: &[Fe32]) -> Result<ExpiryTime, Bolt11ParseError> {
		match parse_u64_be(field_data).map(ExpiryTime::from_seconds) {
			Some(t) => Ok(t),
			None => Err(Bolt11ParseError::IntegerOverflowError),
		}
	}
}

impl FromBase32 for MinFinalCltvExpiryDelta {
	type Err = Bolt11ParseError;

	fn from_base32(field_data: &[Fe32]) -> Result<MinFinalCltvExpiryDelta, Bolt11ParseError> {
		let expiry = parse_u64_be(field_data);
		if let Some(expiry) = expiry {
			Ok(MinFinalCltvExpiryDelta(expiry))
		} else {
			Err(Bolt11ParseError::IntegerOverflowError)
		}
	}
}

impl FromBase32 for Fallback {
	type Err = Bolt11ParseError;

	fn from_base32(field_data: &[Fe32]) -> Result<Fallback, Bolt11ParseError> {
		if field_data.is_empty() {
			return Err(Bolt11ParseError::UnexpectedEndOfTaggedFields);
		}

		let version = field_data[0].to_u8();
		let bytes = Vec::<u8>::from_base32(&field_data[1..])?;

		match version {
			0..=16 => {
				if bytes.len() < 2 || bytes.len() > 40 {
					return Err(Bolt11ParseError::InvalidSegWitProgramLength);
				}
				let version = WitnessVersion::try_from(version)
					.expect("0 through 16 are valid SegWit versions");
				Ok(Fallback::SegWitProgram { version, program: bytes })
			},
			17 => {
				let pkh = match PubkeyHash::from_slice(&bytes) {
					Ok(pkh) => pkh,
					Err(_) => return Err(Bolt11ParseError::InvalidPubKeyHashLength),
				};
				Ok(Fallback::PubKeyHash(pkh))
			},
			18 => {
				let sh = match ScriptHash::from_slice(&bytes) {
					Ok(sh) => sh,
					Err(_) => return Err(Bolt11ParseError::InvalidScriptHashLength),
				};
				Ok(Fallback::ScriptHash(sh))
			},
			_ => Err(Bolt11ParseError::Skip),
		}
	}
}

impl FromBase32 for PrivateRoute {
	type Err = Bolt11ParseError;

	fn from_base32(field_data: &[Fe32]) -> Result<PrivateRoute, Bolt11ParseError> {
		let bytes = Vec::<u8>::from_base32(field_data)?;

		if bytes.len() % 51 != 0 {
			return Err(Bolt11ParseError::UnexpectedEndOfTaggedFields);
		}

		let mut route_hops = Vec::with_capacity(bytes.len() / 51);

		let mut bytes = bytes.as_slice();
		while !bytes.is_empty() {
			let hop_bytes = &bytes[0..51];
			bytes = &bytes[51..];

			let mut channel_id: [u8; 8] = Default::default();
			channel_id.copy_from_slice(&hop_bytes[33..41]);

			let hop = RouteHintHop {
				src_node_id: PublicKey::from_slice(&hop_bytes[0..33])?,
				short_channel_id: u64::from_be_bytes(channel_id),
				fees: RoutingFees {
					base_msat: u32::from_be_bytes(
						hop_bytes[41..45].try_into().expect("slice too big?"),
					),
					proportional_millionths: u32::from_be_bytes(
						hop_bytes[45..49].try_into().expect("slice too big?"),
					),
				},
				cltv_expiry_delta: u16::from_be_bytes(
					hop_bytes[49..51].try_into().expect("slice too big?"),
				),
				htlc_minimum_msat: None,
				htlc_maximum_msat: None,
			};

			route_hops.push(hop);
		}

		Ok(PrivateRoute(RouteHint(route_hops)))
	}
}

impl Display for Bolt11ParseError {
	fn fmt(&self, f: &mut Formatter) -> fmt::Result {
		match *self {
			// TODO: find a way to combine the first three arms (e as error::Error?)
			Bolt11ParseError::Bech32Error(ref e) => {
				write!(f, "Invalid bech32: {}", e)
			},
			Bolt11ParseError::ParseAmountError(ref e) => {
				write!(f, "Invalid amount in hrp ({})", e)
			},
			Bolt11ParseError::MalformedSignature(ref e) => {
				write!(f, "Invalid secp256k1 signature: {}", e)
			},
			Bolt11ParseError::DescriptionDecodeError(ref e) => {
				write!(f, "Description is not a valid utf-8 string: {}", e)
			},
			Bolt11ParseError::InvalidSliceLength(ref len, ref expected, ref elemen) => {
				write!(f, "Slice had length {} instead of {} for element {}", len, expected, elemen)
			},
			Bolt11ParseError::BadPrefix => f.write_str("did not begin with 'ln'"),
			Bolt11ParseError::UnknownCurrency => f.write_str("currency code unknown"),
			Bolt11ParseError::UnknownSiPrefix => f.write_str("unknown SI prefix"),
			Bolt11ParseError::MalformedHRP => f.write_str("malformed human readable part"),
			Bolt11ParseError::TooShortDataPart => {
				f.write_str("data part too short (should be at least 111 bech32 chars long)")
			},
			Bolt11ParseError::UnexpectedEndOfTaggedFields => {
				f.write_str("tagged fields part ended unexpectedly")
			},
			Bolt11ParseError::PaddingError => f.write_str("some data field had bad padding"),
			Bolt11ParseError::IntegerOverflowError => {
				f.write_str("parsed integer doesn't fit into receiving type")
			},
			Bolt11ParseError::InvalidSegWitProgramLength => {
				f.write_str("fallback SegWit program is too long or too short")
			},
			Bolt11ParseError::InvalidPubKeyHashLength => {
				f.write_str("fallback public key hash has a length unequal 20 bytes")
			},
			Bolt11ParseError::InvalidScriptHashLength => {
				f.write_str("fallback script hash has a length unequal 32 bytes")
			},
			Bolt11ParseError::InvalidRecoveryId => {
				f.write_str("recovery id is out of range (should be in [0,3])")
			},
			Bolt11ParseError::Skip => f.write_str(
				"the tagged field has to be skipped because of an unexpected, but allowed property",
			),
		}
	}
}

impl Display for ParseOrSemanticError {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		match self {
			ParseOrSemanticError::ParseError(err) => err.fmt(f),
			ParseOrSemanticError::SemanticError(err) => err.fmt(f),
		}
	}
}

#[cfg(feature = "std")]
impl error::Error for Bolt11ParseError {}

#[cfg(feature = "std")]
impl error::Error for ParseOrSemanticError {}

macro_rules! from_error {
	($my_error:expr, $extern_error:ty) => {
		impl From<$extern_error> for Bolt11ParseError {
			fn from(e: $extern_error) -> Self {
				$my_error(e)
			}
		}
	};
}

from_error!(Bolt11ParseError::MalformedSignature, bitcoin::secp256k1::Error);
from_error!(Bolt11ParseError::ParseAmountError, ParseIntError);
from_error!(Bolt11ParseError::DescriptionDecodeError, string::FromUtf8Error);

impl From<CheckedHrpstringError> for Bolt11ParseError {
	fn from(e: CheckedHrpstringError) -> Self {
		Self::Bech32Error(e)
	}
}

impl From<Bolt11ParseError> for ParseOrSemanticError {
	fn from(e: Bolt11ParseError) -> Self {
		ParseOrSemanticError::ParseError(e)
	}
}

impl From<crate::Bolt11SemanticError> for ParseOrSemanticError {
	fn from(e: Bolt11SemanticError) -> Self {
		ParseOrSemanticError::SemanticError(e)
	}
}

#[cfg(test)]
mod test {
	use super::FromBase32;
	use crate::de::Bolt11ParseError;
	use bech32::Fe32;
	use bitcoin::hashes::sha256;
	use bitcoin::secp256k1::PublicKey;
	use std::str::FromStr;

	const CHARSET_REV: [i8; 128] = [
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, 15, -1, 10, 17, 21, 20, 26, 30, 7, 5, -1, -1, -1, -1, -1, -1, -1, 29, -1, 24, 13,
		25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1, 1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1,
		-1, -1, -1, 29, -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1, 1, 0, 3, 16, 11, 28,
		12, 14, 6, 4, 2, -1, -1, -1, -1, -1,
	];

	fn from_bech32(bytes_5b: &[u8]) -> Vec<Fe32> {
		bytes_5b.iter().map(|c| Fe32::try_from(CHARSET_REV[*c as usize] as u8).unwrap()).collect()
	}

	#[test]
	fn test_parse_currency_prefix() {
		use crate::Currency;

		assert_eq!("bc".parse::<Currency>(), Ok(Currency::Bitcoin));
		assert_eq!("tb".parse::<Currency>(), Ok(Currency::BitcoinTestnet));
		assert_eq!("bcrt".parse::<Currency>(), Ok(Currency::Regtest));
		assert_eq!("sb".parse::<Currency>(), Ok(Currency::Simnet));
		assert_eq!("tbs".parse::<Currency>(), Ok(Currency::Signet));
		assert_eq!("something_else".parse::<Currency>(), Err(Bolt11ParseError::UnknownCurrency))
	}

	#[test]
	fn test_parse_int_from_bytes_be() {
		use crate::de::parse_u16_be;

		assert_eq!(
			parse_u16_be(&[
				Fe32::try_from(1).unwrap(),
				Fe32::try_from(2).unwrap(),
				Fe32::try_from(3).unwrap(),
				Fe32::try_from(4).unwrap(),
			]),
			Some(34916)
		);
		assert_eq!(
			parse_u16_be(&[
				Fe32::try_from(2).unwrap(),
				Fe32::try_from(0).unwrap(),
				Fe32::try_from(0).unwrap(),
				Fe32::try_from(0).unwrap(),
			]),
			None
		);
	}

	#[test]
	fn test_parse_sha256_hash() {
		use crate::Sha256;

		let input = from_bech32("qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypq".as_bytes());

		let hash = sha256::Hash::from_str(
			"0001020304050607080900010203040506070809000102030405060708090102",
		)
		.unwrap();
		let expected = Ok(Sha256(hash));

		assert_eq!(Sha256::from_base32(&input), expected);

		// make sure hashes of unknown length get skipped
		let input_unexpected_length =
			from_bech32("qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypyq".as_bytes());
		assert_eq!(Sha256::from_base32(&input_unexpected_length), Err(Bolt11ParseError::Skip));
	}

	#[test]
	fn test_parse_description() {
		use crate::Description;

		let input = from_bech32("xysxxatsyp3k7enxv4js".as_bytes());
		let expected = Ok(Description::new("1 cup coffee".to_owned()).unwrap());
		assert_eq!(Description::from_base32(&input), expected);
	}

	#[test]
	fn test_parse_payee_pub_key() {
		use crate::PayeePubKey;

		let input = from_bech32("q0n326hr8v9zprg8gsvezcch06gfaqqhde2aj730yg0durunfhv66".as_bytes());
		let pk_bytes = [
			0x03, 0xe7, 0x15, 0x6a, 0xe3, 0x3b, 0x0a, 0x20, 0x8d, 0x07, 0x44, 0x19, 0x91, 0x63,
			0x17, 0x7e, 0x90, 0x9e, 0x80, 0x17, 0x6e, 0x55, 0xd9, 0x7a, 0x2f, 0x22, 0x1e, 0xde,
			0x0f, 0x93, 0x4d, 0xd9, 0xad,
		];
		let expected = Ok(PayeePubKey(PublicKey::from_slice(&pk_bytes[..]).unwrap()));

		assert_eq!(PayeePubKey::from_base32(&input), expected);

		// expects 33 bytes
		let input_unexpected_length =
			from_bech32("q0n326hr8v9zprg8gsvezcch06gfaqqhde2aj730yg0durunfhvq".as_bytes());
		assert_eq!(PayeePubKey::from_base32(&input_unexpected_length), Err(Bolt11ParseError::Skip));
	}

	#[test]
	fn test_parse_expiry_time() {
		use crate::ExpiryTime;

		let input = from_bech32("pu".as_bytes());
		let expected = Ok(ExpiryTime::from_seconds(60));
		assert_eq!(ExpiryTime::from_base32(&input), expected);

		let input_too_large = from_bech32("sqqqqqqqqqqqq".as_bytes());
		assert_eq!(
			ExpiryTime::from_base32(&input_too_large),
			Err(Bolt11ParseError::IntegerOverflowError)
		);
	}

	#[test]
	fn test_parse_min_final_cltv_expiry_delta() {
		use crate::MinFinalCltvExpiryDelta;

		let input = from_bech32("pr".as_bytes());
		let expected = Ok(MinFinalCltvExpiryDelta(35));

		assert_eq!(MinFinalCltvExpiryDelta::from_base32(&input), expected);
	}

	#[test]
	fn test_parse_fallback() {
		use crate::Fallback;
		use bitcoin::hashes::Hash;
		use bitcoin::{PubkeyHash, ScriptHash, WitnessVersion};

		let cases = vec![
			(
				from_bech32("3x9et2e20v6pu37c5d9vax37wxq72un98".as_bytes()),
				Ok(Fallback::PubKeyHash(
					PubkeyHash::from_slice(&[
						0x31, 0x72, 0xb5, 0x65, 0x4f, 0x66, 0x83, 0xc8, 0xfb, 0x14, 0x69, 0x59,
						0xd3, 0x47, 0xce, 0x30, 0x3c, 0xae, 0x4c, 0xa7,
					])
					.unwrap(),
				)),
			),
			(
				from_bech32("j3a24vwu6r8ejrss3axul8rxldph2q7z9".as_bytes()),
				Ok(Fallback::ScriptHash(
					ScriptHash::from_slice(&[
						0x8f, 0x55, 0x56, 0x3b, 0x9a, 0x19, 0xf3, 0x21, 0xc2, 0x11, 0xe9, 0xb9,
						0xf3, 0x8c, 0xdf, 0x68, 0x6e, 0xa0, 0x78, 0x45,
					])
					.unwrap(),
				)),
			),
			(
				from_bech32("qw508d6qejxtdg4y5r3zarvary0c5xw7k".as_bytes()),
				Ok(Fallback::SegWitProgram {
					version: WitnessVersion::V0,
					program: Vec::from(
						&[
							0x75u8, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c,
							0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
						][..],
					),
				}),
			),
			(vec![Fe32::try_from(21).unwrap(); 41], Err(Bolt11ParseError::Skip)),
			(vec![], Err(Bolt11ParseError::UnexpectedEndOfTaggedFields)),
			(
				vec![Fe32::try_from(1).unwrap(); 81],
				Err(Bolt11ParseError::InvalidSegWitProgramLength),
			),
			(vec![Fe32::try_from(17).unwrap(); 1], Err(Bolt11ParseError::InvalidPubKeyHashLength)),
			(vec![Fe32::try_from(18).unwrap(); 1], Err(Bolt11ParseError::InvalidScriptHashLength)),
		];

		for (input, expected) in cases.into_iter() {
			assert_eq!(Fallback::from_base32(&input), expected);
		}
	}

	#[test]
	fn test_parse_route() {
		use crate::PrivateRoute;
		use lightning_types::routing::{RouteHint, RouteHintHop, RoutingFees};

		let input = from_bech32(
			"q20q82gphp2nflc7jtzrcazrra7wwgzxqc8u7754cdlpfrmccae92qgzqvzq2ps8pqqqqqqpqqqqq9qqqvpeuqa\
			fqxu92d8lr6fvg0r5gv0heeeqgcrqlnm6jhphu9y00rrhy4grqszsvpcgpy9qqqqqqgqqqqq7qqzq".as_bytes()
		);

		let mut expected = Vec::<RouteHintHop>::new();
		expected.push(RouteHintHop {
			src_node_id: PublicKey::from_slice(
				&[
					0x02u8, 0x9e, 0x03, 0xa9, 0x01, 0xb8, 0x55, 0x34, 0xff, 0x1e, 0x92, 0xc4, 0x3c,
					0x74, 0x43, 0x1f, 0x7c, 0xe7, 0x20, 0x46, 0x06, 0x0f, 0xcf, 0x7a, 0x95, 0xc3,
					0x7e, 0x14, 0x8f, 0x78, 0xc7, 0x72, 0x55,
				][..],
			)
			.unwrap(),
			short_channel_id: 0x0102030405060708,
			fees: RoutingFees { base_msat: 1, proportional_millionths: 20 },
			cltv_expiry_delta: 3,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None,
		});
		expected.push(RouteHintHop {
			src_node_id: PublicKey::from_slice(
				&[
					0x03u8, 0x9e, 0x03, 0xa9, 0x01, 0xb8, 0x55, 0x34, 0xff, 0x1e, 0x92, 0xc4, 0x3c,
					0x74, 0x43, 0x1f, 0x7c, 0xe7, 0x20, 0x46, 0x06, 0x0f, 0xcf, 0x7a, 0x95, 0xc3,
					0x7e, 0x14, 0x8f, 0x78, 0xc7, 0x72, 0x55,
				][..],
			)
			.unwrap(),
			short_channel_id: 0x030405060708090a,
			fees: RoutingFees { base_msat: 2, proportional_millionths: 30 },
			cltv_expiry_delta: 4,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None,
		});

		assert_eq!(PrivateRoute::from_base32(&input), Ok(PrivateRoute(RouteHint(expected))));

		assert_eq!(
			PrivateRoute::from_base32(&[Fe32::try_from(0).unwrap(); 40][..]),
			Err(Bolt11ParseError::UnexpectedEndOfTaggedFields)
		);
	}

	#[test]
	fn test_payment_secret_and_features_de_and_ser() {
		use crate::TaggedField::*;
		use crate::{
			Bolt11InvoiceSignature, Currency, PositiveTimestamp, RawBolt11Invoice, RawDataPart,
			RawHrp, Sha256, SiPrefix, SignedRawBolt11Invoice,
		};
		use bitcoin::secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
		use lightning_types::features::Bolt11InvoiceFeatures;

		// Feature bits 9, 15, and 99 are set.
		let expected_features =
			Bolt11InvoiceFeatures::from_le_bytes(vec![0, 130, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8]);
		let invoice_str = "lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdeessp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9q5sqqqqqqqqqqqqqqqpqsq67gye39hfg3zd8rgc80k32tvy9xk2xunwm5lzexnvpx6fd77en8qaq424dxgt56cag2dpt359k3ssyhetktkpqh24jqnjyw6uqd08sgptq44qu";
		let invoice =
			SignedRawBolt11Invoice {
				raw_invoice: RawBolt11Invoice {
					hrp: RawHrp {
						currency: Currency::Bitcoin,
						raw_amount: Some(25),
						si_prefix: Some(SiPrefix::Milli),
					},
					data: RawDataPart {
						timestamp: PositiveTimestamp::from_unix_timestamp(1496314658).unwrap(),
						tagged_fields: vec ! [
								PaymentHash(Sha256(sha256::Hash::from_str(
									"0001020304050607080900010203040506070809000102030405060708090102"
								).unwrap())).into(),
								Description(crate::Description::new("coffee beans".to_owned()).unwrap()).into(),
								PaymentSecret(crate::PaymentSecret([17; 32])).into(),
								Features(expected_features).into()],
					},
				},
				hash: [
					0xb1, 0x96, 0x46, 0xc3, 0xbc, 0x56, 0x76, 0x1d, 0x20, 0x65, 0x6e, 0x0e, 0x32,
					0xec, 0xd2, 0x69, 0x27, 0xb7, 0x62, 0x6e, 0x2a, 0x8b, 0xe6, 0x97, 0x71, 0x9f,
					0xf8, 0x7e, 0x44, 0x54, 0x55, 0xb9,
				],
				signature: Bolt11InvoiceSignature(
					RecoverableSignature::from_compact(
						&[
							0xd7, 0x90, 0x4c, 0xc4, 0xb7, 0x4a, 0x22, 0x26, 0x9c, 0x68, 0xc1, 0xdf,
							0x68, 0xa9, 0x6c, 0x21, 0x4d, 0x65, 0x1b, 0x93, 0x76, 0xe9, 0xf1, 0x64,
							0xd3, 0x60, 0x4d, 0xa4, 0xb7, 0xde, 0xcc, 0xce, 0x0e, 0x82, 0xaa, 0xab,
							0x4c, 0x85, 0xd3, 0x58, 0xea, 0x14, 0xd0, 0xae, 0x34, 0x2d, 0xa3, 0x08,
							0x12, 0xf9, 0x5d, 0x97, 0x60, 0x82, 0xea, 0xac, 0x81, 0x39, 0x11, 0xda,
							0xe0, 0x1a, 0xf3, 0xc1,
						],
						RecoveryId::from_i32(1).unwrap(),
					)
					.unwrap(),
				),
			};
		assert_eq!(invoice_str, invoice.to_string());
		assert_eq!(invoice_str.parse(), Ok(invoice));
	}

	#[test]
	fn test_raw_signed_invoice_deserialization() {
		use crate::TaggedField::*;
		use crate::{
			Bolt11InvoiceSignature, Currency, PositiveTimestamp, RawBolt11Invoice, RawDataPart,
			RawHrp, Sha256, SignedRawBolt11Invoice,
		};
		use bitcoin::secp256k1::ecdsa::{RecoverableSignature, RecoveryId};

		assert_eq!(
			"lnbc1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmw\
			wd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq8rkx3yf5tcsyz3d73gafnh3cax9rn449d9p5uxz9\
			ezhhypd0elx87sjle52x86fux2ypatgddc6k63n7erqz25le42c4u4ecky03ylcqca784w".parse(),
			Ok(SignedRawBolt11Invoice {
				raw_invoice: RawBolt11Invoice {
					hrp: RawHrp {
						currency: Currency::Bitcoin,
						raw_amount: None,
						si_prefix: None,
					},
					data: RawDataPart {
					timestamp: PositiveTimestamp::from_unix_timestamp(1496314658).unwrap(),
					tagged_fields: vec ! [
						PaymentHash(Sha256(sha256::Hash::from_str(
							"0001020304050607080900010203040506070809000102030405060708090102"
						).unwrap())).into(),
						Description(
							crate::Description::new(
								"Please consider supporting this project".to_owned()
							).unwrap()
						).into(),
					],
					},
					},
				hash: [
					0xc3, 0xd4, 0xe8, 0x3f, 0x64, 0x6f, 0xa7, 0x9a, 0x39, 0x3d, 0x75, 0x27,
					0x7b, 0x1d, 0x85, 0x8d, 0xb1, 0xd1, 0xf7, 0xab, 0x71, 0x37, 0xdc, 0xb7,
					0x83, 0x5d, 0xb2, 0xec, 0xd5, 0x18, 0xe1, 0xc9
				],
				signature: Bolt11InvoiceSignature(RecoverableSignature::from_compact(
					& [
						0x38u8, 0xec, 0x68, 0x91, 0x34, 0x5e, 0x20, 0x41, 0x45, 0xbe, 0x8a,
						0x3a, 0x99, 0xde, 0x38, 0xe9, 0x8a, 0x39, 0xd6, 0xa5, 0x69, 0x43,
						0x4e, 0x18, 0x45, 0xc8, 0xaf, 0x72, 0x05, 0xaf, 0xcf, 0xcc, 0x7f,
						0x42, 0x5f, 0xcd, 0x14, 0x63, 0xe9, 0x3c, 0x32, 0x88, 0x1e, 0xad,
						0x0d, 0x6e, 0x35, 0x6d, 0x46, 0x7e, 0xc8, 0xc0, 0x25, 0x53, 0xf9,
						0xaa, 0xb1, 0x5e, 0x57, 0x38, 0xb1, 0x1f, 0x12, 0x7f
					],
					RecoveryId::from_i32(0).unwrap()
				).unwrap()),
				}
			)
		)
	}

	// Test some long invoice test vectors successfully roundtrip. Generated
	// from Lexe proptest: <https://github.com/lexe-app/lexe-public/blob/4bc7018307e5221e1e1ee8b17ce366338fb11a16/common/src/ln/invoice.rs#L183>.
	#[test]
	fn test_deser_long_test_vectors() {
		use crate::Bolt11Invoice;

		#[track_caller]
		fn parse_ok(invoice_str: &str) {
			let invoice = Bolt11Invoice::from_str(invoice_str).unwrap();
			let invoice_str2 = invoice.to_string();
			if invoice_str != invoice_str2 {
				panic!(
					"Invoice does not roundtrip: invoice_str != invoice_str2\n\
					 invoice_str: {invoice_str}\n\
					 invoice_str2: {invoice_str2}\n\
					 \n\
					 {invoice:?}"
				);
			}
		}

		// 1024 B shrunk invoice just above previous limit of 1023 B from Lexe proptest
		parse_ok(
			"lnbc10000000000000000010p1qqqqqqqdtuxpqkzq8sjzqgps4pvyczqq8sjzqgpuysszq0pyyqsrp2zs0sjz\
			 qgps4pxrcfpqyqc2slpyyqsqsv9gwz59s5zqpqyps5rc9qsrs2pqxz5ysyzcfqgysyzs0sjzqgqq8sjzqgps4p\
			 xqqzps4pqpssqgzpxps5ruysszqrps4pg8p2zgpsc2snpuysszqzqsgqvys0pyyqsrcfpqyqvycv9gfqqrcfpq\
			 yq7zggpq8q5zqyruysszqwpgyqxpsjqsgq7zggpqps7zggpq8sjzqgqgqq7zggpqpq7zggpq8q5zqqpuysszq0\
			 pyyqsqs0pyyqspsnqgzpqpqlpyyqsqszpuysszqyzvzpvysrqq8sjzqgqvrp7zggpqpqxpsspp5mf45hs3cgph\
			 h0074r5qmr74y82r26ac4pzdg4nd9mdmsvz6ffqpssp5vr4yra4pcv74h9hk3d0233nqu4gktpuykjamrafrdp\
			 uedqugzh3q9q2sqqqqqysgqcqrpqqxq8pqqqqqqnp4qgvcxpme2q5lng36j9gruwlrtk2f86s3c5xmk87yhvyu\
			 wdeh025q5r9yqwnqegv9hj9nzkhyxaeyq92wcrnqp36pyrc2qzrvswj5g96ey2dn6qqqqqqqqqqqqqqqqqqqqq\
			 qqqqqqqqp9a5vs0t4z56p64xyma8s84yvdx7uhqj0gvrr424fea2wpztq2fwqqqqqqqqqqqqqqqqqqqqqqqqqq\
			 qqqqmy9qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\
			 qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpcnsxc32du9n7amlypuhclzqrt6lkegq\
			 0v3r7nczjv9tv30z7phq80r3dm7pvgykl7gwuenmem93h5xwdwac6ngsmzqc34khrg3qjgsq6qk6lc"
		);
		// 1517 B mainnet invoice from Lexe proptest
		parse_ok(
			"lnbc8735500635020489010p1av5kfs8deupvyk4u5ynj03hmalhhhml0fxc2jlrv9z4lg6s4hnhkz69malhhe\
			 t3x9yqpsxru4a3kwar2qtu2q2ughx367q600s5x7c7tln4k0fu78skxqevaqm8sayhuur377zgf3uf94n57xzh\
			 dw99u42hwc089djn5xj723w7zageflsnzdmyte89tecf2ac7xhg4y3u9f4xpuv2hwxjlsarp0e24fu8tme6rgv\
			 0tqj08z9f4u30rw59k8emhtvs7wye0xfw6x5q5tju2p208rvtkunzwtwghtp22tlnh62gxwhfkxp4cnz7ts3rx\
			 vlzszhv9y00h77lpdvcjyhjtmalh5dn5e8n5w8cqle0vunzduu4nza9y0734qhxday9hzywl0aa0vhzy0qmphc\
			 64d4hduj08dv2krpgqtc2v83gptk34reelxyc7wsgnze890c6nrv6p0cmepatc269eayzjjkqk30n52rfl5dg7\
			 wztl96f7wc2tzx34q909xuajnyt4u4lnk87lwal7z0etdz5tmece0v3u796jfp68nccn05ty54ncfelts3v8g0\
			 sn6v6hsu87zat4r03368ersu87252dd0nswymxzc2pyxl8yy844hspuyj47w0px4u4leefq568sk0rr9th4ql9\
			 f9ykawrczkz5hp22nstg3lrlsa6u2q2ull3kzce2sh0h77sjv0zszhzy4hfh6u0pwux5l3gpthsn72mfu47sw9\
			 zw3hzk7srznp27z0etdp0725me00sn72mgkf0fteehruk0lg6swh34z52puaekzmjlmalhhe6m8ug7z3c8g8zh\
			 jjspp5zj0sm85g5ufng9w7s6p4ucdk80tyvz64sg54v0cy4vgnr37f78sqsp5l6azu2hv6we30er90jrslqpvd\
			 trnrphhesca2wg5q83k52rsu2cq9q2sqqqqqysgqcqr8h2np4qw0ha2k282hm8jh5rcfq0hsp2zhddtlc5vs23\
			 uphyv0lv3k8sqsfgfp4qyrk86tx5xg2aa7et4cdzhnvl5s4nd33ugytt7gamk9tugn9yransr9yq08gpwsn8t2\
			 tq4ducjfhrcz707av0ss20urjh8vldrpmehqxa0stkesvuq82txyqzfhej7qccswy7k5wvcppk63c6zpjytfda\
			 ccadacjtn52lpe6s85rjfqlxzp6frq33xshaz2nr9xjkhd3jj8qg39nmfzvpgmayakqmy9rseakwgcudug7hs4\
			 5wh430ywh7qhj3khczh8gle4cn93ymgfwa7rrvcw9lywyyz58k4p40a3nu9svthaf0qeg8f2ay4tw9p48p70qm\
			 ayu3ejl2q8pj9e2l22h7775tl44hs6ke4sdfgcr6aj8wra4r2v9sj6xa5chd5ctpfg8chtrer3kkp0e6af88lk\
			 rfxcklf2hyslv2hr0xl5lwrm5y5uttxn4ndfz8789znf78nspa3xy68"
		);
		// 1804 B regtest invoice from Lexe proptest
		parse_ok(
			"lnbcrt17124979001314909880p1y6lkcwgd76tfnxksfk2atyy4tzw4nyg6jrx3282s2ygvcxyj64gevhxsjk\
			 2ymhzv3e0p5h5u3kfey92jt9ge44gsfnwycxynm2g3unw3ntt9qh25texe98jcfhxvcxuezxw9tngwrndpy9s4\
			 p4x9eyze2tfe9rxm68tp5yj5jfduen2nny8prhsm6edegn2stww4n4gwp4vfjkvdthd43524n9fa8h262vwesk\
			 g66nw3vnyafn29zhsvfeg9mxummtfp35uumzfqmhy3jwgdh55mt5xpvhgmjn25uku5e5g939wmmnvdfygnrdgd\
			 h56uzcx4a92vfhgdcky3z9gfnrsvp4f4f55j68vak9yufhvdm8x5zrgc6955jvf429zumv89nh2a35wae5yntg\
			 v985jumpxehyv7t92pjrwufs89yh23f5ddy5s568wgchve3cg9ek5nzewgcrzjz0dftxg3nvf4hngje52ac4zm\
			 esxpvk6sfef4hkuetvd4vk6n29wftrw5rvg4yy2vjjwyexc5mnvfd8xknndpqkkenx0q642j35298hwve3dyc5\
			 25jrd3295sm9v9jrqup3wpykg7zd239ns7jgtqu95jz0deaxksjh2fu56n6n2f5x6mm8wa89qjfef385sam2x9\
			 mxcs20gfpnq460d3axzknnf3e4sw2kvf25wjjxddpyg52dw4vx7nn2w9cyu5t8vfnyxjtpg33kssjp24ch536p\
			 d938snmtx345x6r4x93kvv2tff855um3tfekxjted4kxys2kve5hvu6g89z4ynmjgfhnw7tv892rymejgvey77\
			 rcfqe9xjr92d85636fvajxyajndfa92k2nxycx5jtjx4zxsm2y2dyn2up50f5ku3nrfdk4g5npxehkzjjv8y69\
			 gveev4z56denddaxy7tfwe8xx42zgf6kzmnxxpk826ze2s6xk6jrwearw6ejvd8rsvj2fpg525jtd5pp5j2tlt\
			 28m4kakjr84w6ce4fd8e7awy6ncyswcyut760rdnem30ptssp5p5u3xgxxtr6aev8y2w9m30wcw3kyn7fgm8wm\
			 f8qw8wzrqt34zcvq9q2sqqqqqysgqcqypmw9xq8lllllllnp4qt36twam2ca08m3s7vnhre3c0j89589wyw4vd\
			 k7fln0lryxzkdcrur28qwqq3hnyt84vsasuldd2786eysdf4dyuggwsmvw2atftf7spkmpa9dd3efq5tenpqm2\
			 v7vcz2a4s0s7jnqpjn0srysnstnw5y5z9taxn0ue37aqgufxcdsj6f8a2m4pm9udppdzc4shsdqzzx0u0rm4xl\
			 js0dqz3c5zqyvglda7nsqvqfztmlyup7vyuadzav4zyuqwx90ev6nmk53nkhkt0sev9e745wxqtdvrqzgqkaka\
			 zen7e2qmsdauk665g3llg5qtl79t3xulrhjnducehdn72gpmkjvtth7kh6ejpl9dv0qcsxv2jvzzvg0hzdmk3y\
			 jsmydqksdk3h78kc63qnr265h8vyeslqexszppfm7y287t3gxvhw0ulg2wp0rsw3tevz03z50kpy77zdz9snxm\
			 kkwxd76xvj4qvj2f89rrnuvdvzw947ay0kydc077pkec2jet9qwp2tud98s24u65uz07eaxk5jk3e4nggn2caa\
			 ek2p5pkrc6mm6mxjm2ezpdu8p5jstg6tgvnttgac3ygt5ys04t4udujzlshpl7e4f3ff03xe6v24cp6aq4wa"
		);
		// 1870 B testnet invoice from Lexe proptest
		parse_ok(
			"lntb5826417333454665580p1c5rwh5edlhf33hvkj5vav5z3t02a5hxvj3vfv5kuny2f3yzj6zwf9hx3nn2fk\
			 9gepc2a3ywvj6dax5v3jy2d5nxmp3gaxhycjkv38hx4z4d4vyznrp2p24xa6t2pg4w4rrxfens6tcxdhxvvfhx\
			 a8xvvpkgat8xnpe2p44juz9g43hyur00989gvfhwd2kj72wfum4g4mgx5m5cs2rg9d9vnn6xe89ydnnvfpyy52\
			 s2dxx2er4x4xxwstdd5cxwdrjw3nkxnnv2uexxnrxw4t56sjswfn52s2xv4t8xmjtwpn8xm6sfeh4q526dyu8x\
			 3r9gceyw6fhd934qjttvdk57az5w368zdrhwfjxxu35xcmrsmmpd4g8wwtev4tkzutdd32k56mxveuy6c6v2em\
			 yv7zkfp39zjpjgd8hx7n4xph5kceswf6xxmnyfcuxca20fp24z7ncvfhyu5jf2exhw36nwf68s7rh2a6yzjf4d\
			 gukcenfxpchqsjn2pt5x334tf98wsm6dvcrvvfcwapxvk2cdvmk2npcfe68zue3w4f9xc6s2fvrw6nrg3fkskt\
			 e2ftxyc20ffckcd692964sdzjwdp4yvrfdfm9q72pxp3kwat5f4j9xee5da8rss60w92857tgwych55f5w3n8z\
			 mzexpy4jwredejrqm6txf3nxm64ffh8x460dp9yjazhw4yx6dm5xerysnn5wa455k3h2d89ss2fd9axwjp3f4r\
			 9qdmfd4fx6stx2eg9sezrv369w7nvvfvhj4nnwaz5z3ny8qcxcdnvwd64jc2nx9uy2e2gxdrnx6r3w9ykxatxx\
			 g6kk6rv2ekr2emwx5ehy362d3x82dzvddfxs5rcg4vn27npf564qdtg2anycc6523jnwe3e0p65unrpvccrs5m\
			 2fuexgmnj23ay5e34v4xk5jnrwpg4xemfwqe5vjjjw9qk76zsd9yrzu6xdpv5v5ntdejxg6jtv3kx65t6gdhrg\
			 vj3fe34sj2vv3h5kegpp57hjf5kv6clw97y2e063yuz0psrz9a6l49v836dflum00rh8qtn8qsp5gd29qycuze\
			 08xls8l32zjaaf2uqv78v97lg9ss0c699huw980h2q9q2sqqqqqysgqcqr8ulnp4q26hcfwr7qxz7lwwlr2kjc\
			 rws7m2u5j36mm0kxa45uxy6zvsqt2zzfppjdkrm2rlgadt9dq3d6jkv4r2cugmf2kamr28qwuleyzzyyly8a6t\
			 u70eldahx7hzxx5x9gms7vjjr577ps8n4qyds5nern39j0v7czkch2letnt46895jupxgehf208xgxz8d6j8gu\
			 3h2qqtsk9nr9nuquhkqjxw40h2ucpldrawmktxzxdgtkt9a3p95g98nywved8s8laj2a0c98rq5zzdnzddz6nd\
			 w0lvr6u0av9m7859844cgz9vpeq05gw79zqae2s7jzeq66wydyueqtp56qc67g7krv6lj5aahxtmq4y208q5qy\
			 z38cnwl9ma6m5f4nhzqaj0tjxpfrk4nr5arv9d20lvxvddvffhzygmyuvwd959uhdcgcgjejchqt2qncuwpqqk\
			 5vws7dflw8x6esrfwhz7h3jwmhevf445k76nme926sr8drsdveqg7l7t7lnjvhaludqnwk4l2pmevkjf9pla92\
			 4p77v76r7x8jzyy7h59hmk0lgzfsk6c8dpj37hssj7jt4q7jzvy8hq25l3pag37axxanjqnq56c47gpgy6frsy\
			 c0str9w2aahz4h6t7axaka4cwvhwg49r6qgj8kwz2mt6vcje25l9ekvmgq5spqtn"
		);
	}

	// Generate a valid invoice of `MAX_LENGTH` bytes and ensure that it roundtrips.
	#[test]
	fn test_serde_long_invoice() {
		use crate::TaggedField::*;
		use crate::{
			Bolt11Invoice, Bolt11InvoiceFeatures, Bolt11InvoiceSignature, Currency,
			PositiveTimestamp, RawBolt11Invoice, RawDataPart, RawHrp, RawTaggedField, Sha256,
			SignedRawBolt11Invoice,
		};
		use bitcoin::secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
		use bitcoin::secp256k1::PublicKey;
		use lightning_types::routing::{RouteHint, RouteHintHop, RoutingFees};

		// Generate an `UnknownSemantics` field with a given length.
		fn unknown_semantics_field(len: usize) -> Vec<Fe32> {
			assert!(len <= 1023);
			let mut field = Vec::with_capacity(len + 3);
			// Big-endian encoded length prefix
			field.push(Fe32::Q);
			field.push(Fe32::try_from((len >> 5) as u8).unwrap());
			field.push(Fe32::try_from((len & 0x1f) as u8).unwrap());
			// Data
			field.extend(std::iter::repeat(Fe32::P).take(len));
			field
		}

		// Invoice fields
		let payment_hash = sha256::Hash::from_str(
			"0001020304050607080900010203040506070809000102030405060708090102",
		)
		.unwrap();
		let description = std::iter::repeat("A").take(639).collect::<String>();
		let fallback_addr = crate::Fallback::SegWitProgram {
			version: bitcoin::WitnessVersion::V0,
			program: vec![0; 32],
		};
		let payee_pk = PublicKey::from_slice(&[
			0x03, 0x24, 0x65, 0x3e, 0xac, 0x43, 0x44, 0x88, 0x00, 0x2c, 0xc0, 0x6b, 0xbf, 0xb7,
			0xf1, 0x0f, 0xe1, 0x89, 0x91, 0xe3, 0x5f, 0x9f, 0xe4, 0x30, 0x2d, 0xbe, 0xa6, 0xd2,
			0x35, 0x3d, 0xc0, 0xab, 0x1c,
		])
		.unwrap();
		let route_hints = std::iter::repeat(RouteHintHop {
			src_node_id: payee_pk,
			short_channel_id: 0x0102030405060708,
			fees: RoutingFees { base_msat: 1, proportional_millionths: 20 },
			cltv_expiry_delta: 3,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None,
		})
		.take(12)
		.collect::<Vec<_>>();

		// Build raw invoice
		let raw_invoice = RawBolt11Invoice {
			hrp: RawHrp {
				currency: Currency::Bitcoin,
				raw_amount: Some(10000000000000000010),
				si_prefix: Some(crate::SiPrefix::Pico),
			},
			data: RawDataPart {
				timestamp: PositiveTimestamp::from_unix_timestamp(1496314658).unwrap(),
				tagged_fields: vec![
					PaymentHash(Sha256(payment_hash)).into(),
					Description(crate::Description::new(description).unwrap()).into(),
					PayeePubKey(crate::PayeePubKey(payee_pk)).into(),
					ExpiryTime(crate::ExpiryTime(std::time::Duration::from_secs(u64::MAX))).into(),
					MinFinalCltvExpiryDelta(crate::MinFinalCltvExpiryDelta(u64::MAX)).into(),
					Fallback(fallback_addr).into(),
					PrivateRoute(crate::PrivateRoute(RouteHint(route_hints))).into(),
					PaymentSecret(crate::PaymentSecret([17; 32])).into(),
					PaymentMetadata(vec![0x69; 639]).into(),
					Features(Bolt11InvoiceFeatures::from_le_bytes(vec![0xaa; 639])).into(),
					// This invoice is 4458 B w/o unknown semantics fields.
					// Need to add some non-standard fields to reach 7089 B limit.
					RawTaggedField::UnknownSemantics(unknown_semantics_field(1023)),
					RawTaggedField::UnknownSemantics(unknown_semantics_field(1023)),
					RawTaggedField::UnknownSemantics(unknown_semantics_field(576)),
				],
			},
		};

		// Build signed invoice
		let hash = [
			0x75, 0x99, 0xe1, 0x51, 0x7f, 0xa1, 0x0e, 0xb5, 0xc0, 0x79, 0xb4, 0x6e, 0x8e, 0x62,
			0x0c, 0x4f, 0xb0, 0x72, 0x71, 0xd2, 0x81, 0xa1, 0x92, 0x65, 0x9c, 0x90, 0x89, 0x69,
			0xe1, 0xf3, 0xd6, 0x59,
		];
		let signature = &[
			0x6c, 0xbe, 0xbe, 0xfe, 0xd3, 0xfb, 0x07, 0x68, 0xb5, 0x79, 0x98, 0x82, 0x29, 0xab,
			0x0e, 0xcc, 0x8d, 0x3a, 0x81, 0xee, 0xee, 0x07, 0xb3, 0x5d, 0x64, 0xca, 0xb4, 0x12,
			0x33, 0x99, 0x33, 0x2a, 0x31, 0xc2, 0x2c, 0x2b, 0x62, 0x96, 0x4e, 0x37, 0xd7, 0x96,
			0x50, 0x5e, 0xdb, 0xe9, 0xa9, 0x5b, 0x0b, 0x3b, 0x87, 0x22, 0x89, 0xed, 0x95, 0xf1,
			0xf1, 0xdf, 0x2d, 0xb6, 0xbd, 0xf5, 0x0a, 0x20,
		];
		let signature = Bolt11InvoiceSignature(
			RecoverableSignature::from_compact(signature, RecoveryId::from_i32(1).unwrap())
				.unwrap(),
		);
		let signed_invoice = SignedRawBolt11Invoice { raw_invoice, hash, signature };

		// Ensure serialized invoice roundtrips
		let invoice = Bolt11Invoice::from_signed(signed_invoice).unwrap();
		let invoice_str = invoice.to_string();
		assert_eq!(invoice_str.len(), crate::MAX_LENGTH);
		assert_eq!(invoice, Bolt11Invoice::from_str(&invoice_str).unwrap());
	}

	// Test that invoices above the maximum length fail to parse with the expected error.
	#[test]
	fn test_deser_too_long_fails() {
		use crate::{Bolt11Invoice, ParseOrSemanticError, MAX_LENGTH};
		use bech32::primitives::decode::{CheckedHrpstringError, ChecksumError};

		fn parse_is_code_length_err(s: &str) -> bool {
			// Need matches! b/c ChecksumError::CodeLength(_) is marked non-exhaustive
			matches!(
				Bolt11Invoice::from_str(s),
				Err(ParseOrSemanticError::ParseError(Bolt11ParseError::Bech32Error(
					CheckedHrpstringError::Checksum(ChecksumError::CodeLength(_))
				))),
			)
		}

		let mut too_long = String::from("lnbc1");
		too_long.push_str(
			String::from_utf8(vec![b'x'; (MAX_LENGTH + 1) - too_long.len()]).unwrap().as_str(),
		);
		assert!(parse_is_code_length_err(&too_long));
		assert!(!parse_is_code_length_err(&too_long[..too_long.len() - 1]));
	}
}
