#[cfg(feature = "std")]
use std::error;
use core::convert::TryFrom;
use core::fmt;
use core::fmt::{Display, Formatter};
use core::num::ParseIntError;
use core::str;
use core::str::FromStr;

use bech32::{u5, FromBase32};

use bitcoin::{PubkeyHash, ScriptHash};
use bitcoin::address::WitnessVersion;
use bitcoin::hashes::Hash;
use bitcoin::hashes::sha256;
use crate::prelude::*;
use lightning::ln::PaymentSecret;
use lightning::routing::gossip::RoutingFees;
use lightning::routing::router::{RouteHint, RouteHintHop};

use num_traits::{CheckedAdd, CheckedMul};

use secp256k1::ecdsa::{RecoveryId, RecoverableSignature};
use secp256k1::PublicKey;

use super::{Bolt11Invoice, Sha256, TaggedField, ExpiryTime, MinFinalCltvExpiryDelta, Fallback, PayeePubKey, Bolt11InvoiceSignature, PositiveTimestamp,
	Bolt11SemanticError, PrivateRoute, Bolt11ParseError, ParseOrSemanticError, Description, RawTaggedField, Currency, RawHrp, SiPrefix, RawBolt11Invoice,
	constants, SignedRawBolt11Invoice, RawDataPart, Bolt11InvoiceFeatures};

use self::hrp_sm::parse_hrp;

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
		fn next_state(&self, read_symbol: char) -> Result<States, super::Bolt11ParseError> {
			match *self {
				States::Start => {
					if read_symbol == 'l' {
						Ok(States::ParseL)
					} else {
						Err(super::Bolt11ParseError::MalformedHRP)
					}
				}
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
				None => Range {start: position, end: position + 1},
				Some(ref r) => Range {start: r.start, end: r.end + 1},
			};
			*range = Some(new_range);
		}

		fn step(&mut self, c: char) -> Result<(), super::Bolt11ParseError> {
			let next_state = self.state.next_state(c)?;
			match next_state {
				States::ParseCurrencyPrefix => {
					StateMachine::update_range(&mut self.currency_prefix, self.position)
				}
				States::ParseAmountNumber => {
					StateMachine::update_range(&mut self.amount_number, self.position)
				},
				States::ParseAmountSiPrefix => {
					StateMachine::update_range(&mut self.amount_si_prefix, self.position)
				},
				_ => {}
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
		for c in input.chars() {
			sm.step(c)?;
		}

		if !sm.is_final() {
			return Err(super::Bolt11ParseError::MalformedHRP);
		}

		let currency = sm.currency_prefix().clone()
			.map(|r| &input[r]).unwrap_or("");
		let amount = sm.amount_number().clone()
			.map(|r| &input[r]).unwrap_or("");
		let si = sm.amount_si_prefix().clone()
			.map(|r| &input[r]).unwrap_or("");

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
			_ => Err(Bolt11ParseError::UnknownCurrency)
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
			_ => Err(Bolt11ParseError::UnknownSiPrefix)
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
		let (hrp, data, var) = bech32::decode(s)?;

		if var == bech32::Variant::Bech32m {
			// Consider Bech32m addresses to be "Invalid Checksum", since that is what we'd get if
			// we didn't support Bech32m (which lightning does not use).
			return Err(Bolt11ParseError::Bech32Error(bech32::Error::InvalidChecksum));
		}

		if data.len() < 104 {
			return Err(Bolt11ParseError::TooShortDataPart);
		}

		let raw_hrp: RawHrp = hrp.parse()?;
		let data_part = RawDataPart::from_base32(&data[..data.len()-104])?;

		Ok(SignedRawBolt11Invoice {
			raw_invoice: RawBolt11Invoice {
				hrp: raw_hrp,
				data: data_part,
			},
			hash: RawBolt11Invoice::hash_from_parts(
				hrp.as_bytes(),
				&data[..data.len()-104]
			),
			signature: Bolt11InvoiceSignature::from_base32(&data[data.len()-104..])?,
		})
	}
}

impl FromStr for RawHrp {
	type Err = Bolt11ParseError;

	fn from_str(hrp: &str) -> Result<Self, <Self as FromStr>::Err> {
		let parts = parse_hrp(hrp)?;

		let currency = parts.0.parse::<Currency>()?;

		let amount = if !parts.1.is_empty() {
			Some(parts.1.parse::<u64>()?)
		} else {
			None
		};

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

		Ok(RawHrp {
			currency,
			raw_amount: amount,
			si_prefix,
		})
	}
}

impl FromBase32 for RawDataPart {
	type Err = Bolt11ParseError;

	fn from_base32(data: &[u5]) -> Result<Self, Self::Err> {
		if data.len() < 7 { // timestamp length
			return Err(Bolt11ParseError::TooShortDataPart);
		}

		let timestamp = PositiveTimestamp::from_base32(&data[0..7])?;
		let tagged = parse_tagged_parts(&data[7..])?;

		Ok(RawDataPart {
			timestamp,
			tagged_fields: tagged,
		})
	}
}

impl FromBase32 for PositiveTimestamp {
	type Err = Bolt11ParseError;

	fn from_base32(b32: &[u5]) -> Result<Self, Self::Err> {
		if b32.len() != 7 {
			return Err(Bolt11ParseError::InvalidSliceLength("PositiveTimestamp::from_base32()".into()));
		}
		let timestamp: u64 = parse_int_be(b32, 32)
			.expect("7*5bit < 64bit, no overflow possible");
		match PositiveTimestamp::from_unix_timestamp(timestamp) {
			Ok(t) => Ok(t),
			Err(_) => unreachable!(),
		}
	}
}

impl FromBase32 for Bolt11InvoiceSignature {
	type Err = Bolt11ParseError;
	fn from_base32(signature: &[u5]) -> Result<Self, Self::Err> {
		if signature.len() != 104 {
			return Err(Bolt11ParseError::InvalidSliceLength("Bolt11InvoiceSignature::from_base32()".into()));
		}
		let recoverable_signature_bytes = Vec::<u8>::from_base32(signature)?;
		let signature = &recoverable_signature_bytes[0..64];
		let recovery_id = RecoveryId::from_i32(recoverable_signature_bytes[64] as i32)?;

		Ok(Bolt11InvoiceSignature(RecoverableSignature::from_compact(
			signature,
			recovery_id
		)?))
	}
}

pub(crate) fn parse_int_be<T, U>(digits: &[U], base: T) -> Option<T>
	where T: CheckedAdd + CheckedMul + From<u8> + Default,
	      U: Into<u8> + Copy
{
	digits.iter().fold(Some(Default::default()), |acc, b|
		acc
			.and_then(|x| x.checked_mul(&base))
			.and_then(|x| x.checked_add(&(Into::<u8>::into(*b)).into()))
	)
}

fn parse_tagged_parts(data: &[u5]) -> Result<Vec<RawTaggedField>, Bolt11ParseError> {
	let mut parts = Vec::<RawTaggedField>::new();
	let mut data = data;

	while !data.is_empty() {
		if data.len() < 3 {
			return Err(Bolt11ParseError::UnexpectedEndOfTaggedFields);
		}

		// Ignore tag at data[0], it will be handled in the TaggedField parsers and
		// parse the length to find the end of the tagged field's data
		let len = parse_int_be(&data[1..3], 32).expect("can't overflow");
		let last_element = 3 + len;

		if data.len() < last_element {
			return Err(Bolt11ParseError::UnexpectedEndOfTaggedFields);
		}

		// Get the tagged field's data slice
		let field = &data[0..last_element];

		// Set data slice to remaining data
		data = &data[last_element..];

		match TaggedField::from_base32(field) {
			Ok(field) => {
				parts.push(RawTaggedField::KnownSemantics(field))
			},
			Err(Bolt11ParseError::Skip)|Err(Bolt11ParseError::Bech32Error(bech32::Error::InvalidLength)) => {
				parts.push(RawTaggedField::UnknownSemantics(field.into()))
			},
			Err(e) => {return Err(e)}
		}
	}
	Ok(parts)
}

impl FromBase32 for TaggedField {
	type Err = Bolt11ParseError;

	fn from_base32(field: &[u5]) -> Result<TaggedField, Bolt11ParseError> {
		if field.len() < 3 {
			return Err(Bolt11ParseError::UnexpectedEndOfTaggedFields);
		}

		let tag = field[0];
		let field_data =  &field[3..];

		match tag.to_u8() {
			constants::TAG_PAYMENT_HASH =>
				Ok(TaggedField::PaymentHash(Sha256::from_base32(field_data)?)),
			constants::TAG_DESCRIPTION =>
				Ok(TaggedField::Description(Description::from_base32(field_data)?)),
			constants::TAG_PAYEE_PUB_KEY =>
				Ok(TaggedField::PayeePubKey(PayeePubKey::from_base32(field_data)?)),
			constants::TAG_DESCRIPTION_HASH =>
				Ok(TaggedField::DescriptionHash(Sha256::from_base32(field_data)?)),
			constants::TAG_EXPIRY_TIME =>
				Ok(TaggedField::ExpiryTime(ExpiryTime::from_base32(field_data)?)),
			constants::TAG_MIN_FINAL_CLTV_EXPIRY_DELTA =>
				Ok(TaggedField::MinFinalCltvExpiryDelta(MinFinalCltvExpiryDelta::from_base32(field_data)?)),
			constants::TAG_FALLBACK =>
				Ok(TaggedField::Fallback(Fallback::from_base32(field_data)?)),
			constants::TAG_PRIVATE_ROUTE =>
				Ok(TaggedField::PrivateRoute(PrivateRoute::from_base32(field_data)?)),
			constants::TAG_PAYMENT_SECRET =>
				Ok(TaggedField::PaymentSecret(PaymentSecret::from_base32(field_data)?)),
			constants::TAG_PAYMENT_METADATA =>
				Ok(TaggedField::PaymentMetadata(Vec::<u8>::from_base32(field_data)?)),
			constants::TAG_FEATURES =>
				Ok(TaggedField::Features(Bolt11InvoiceFeatures::from_base32(field_data)?)),
			_ => {
				// "A reader MUST skip over unknown fields"
				Err(Bolt11ParseError::Skip)
			}
		}
	}
}

impl FromBase32 for Sha256 {
	type Err = Bolt11ParseError;

	fn from_base32(field_data: &[u5]) -> Result<Sha256, Bolt11ParseError> {
		if field_data.len() != 52 {
			// "A reader MUST skip over […] a p, [or] h […] field that does not have data_length 52 […]."
			Err(Bolt11ParseError::Skip)
		} else {
			Ok(Sha256(sha256::Hash::from_slice(&Vec::<u8>::from_base32(field_data)?)
				.expect("length was checked before (52 u5 -> 32 u8)")))
		}
	}
}

impl FromBase32 for Description {
	type Err = Bolt11ParseError;

	fn from_base32(field_data: &[u5]) -> Result<Description, Bolt11ParseError> {
		let bytes = Vec::<u8>::from_base32(field_data)?;
		let description = String::from(str::from_utf8(&bytes)?);
		Ok(Description::new(description).expect(
			"Max len is 639=floor(1023*5/8) since the len field is only 10bits long"
		))
	}
}

impl FromBase32 for PayeePubKey {
	type Err = Bolt11ParseError;

	fn from_base32(field_data: &[u5]) -> Result<PayeePubKey, Bolt11ParseError> {
		if field_data.len() != 53 {
			// "A reader MUST skip over […] a n […] field that does not have data_length 53 […]."
			Err(Bolt11ParseError::Skip)
		} else {
			let data_bytes = Vec::<u8>::from_base32(field_data)?;
			let pub_key = PublicKey::from_slice(&data_bytes)?;
			Ok(pub_key.into())
		}
	}
}

impl FromBase32 for ExpiryTime {
	type Err = Bolt11ParseError;

	fn from_base32(field_data: &[u5]) -> Result<ExpiryTime, Bolt11ParseError> {
		match parse_int_be::<u64, u5>(field_data, 32)
			.map(ExpiryTime::from_seconds)
		{
			Some(t) => Ok(t),
			None => Err(Bolt11ParseError::IntegerOverflowError),
		}
	}
}

impl FromBase32 for MinFinalCltvExpiryDelta {
	type Err = Bolt11ParseError;

	fn from_base32(field_data: &[u5]) -> Result<MinFinalCltvExpiryDelta, Bolt11ParseError> {
		let expiry = parse_int_be::<u64, u5>(field_data, 32);
		if let Some(expiry) = expiry {
			Ok(MinFinalCltvExpiryDelta(expiry))
		} else {
			Err(Bolt11ParseError::IntegerOverflowError)
		}
	}
}

impl FromBase32 for Fallback {
	type Err = Bolt11ParseError;

	fn from_base32(field_data: &[u5]) -> Result<Fallback, Bolt11ParseError> {
		if field_data.is_empty() {
			return Err(Bolt11ParseError::UnexpectedEndOfTaggedFields);
		}

		let version = field_data[0];
		let bytes = Vec::<u8>::from_base32(&field_data[1..])?;

		match version.to_u8() {
			0..=16 => {
				if bytes.len() < 2 || bytes.len() > 40 {
					return Err(Bolt11ParseError::InvalidSegWitProgramLength);
				}
				let version = WitnessVersion::try_from(version).expect("0 through 16 are valid SegWit versions");
				Ok(Fallback::SegWitProgram {
					version,
					program: bytes
				})
			},
			17 => {
				let pkh = match PubkeyHash::from_slice(&bytes) {
					Ok(pkh) => pkh,
					Err(bitcoin::hashes::Error::InvalidLength(_, _)) => return Err(Bolt11ParseError::InvalidPubKeyHashLength),
				};
				Ok(Fallback::PubKeyHash(pkh))
			}
			18 => {
				let sh = match ScriptHash::from_slice(&bytes) {
					Ok(sh) => sh,
					Err(bitcoin::hashes::Error::InvalidLength(_, _)) => return Err(Bolt11ParseError::InvalidScriptHashLength),
				};
				Ok(Fallback::ScriptHash(sh))
			}
			_ => Err(Bolt11ParseError::Skip)
		}
	}
}

impl FromBase32 for PrivateRoute {
	type Err = Bolt11ParseError;

	fn from_base32(field_data: &[u5]) -> Result<PrivateRoute, Bolt11ParseError> {
		let bytes = Vec::<u8>::from_base32(field_data)?;

		if bytes.len() % 51 != 0 {
			return Err(Bolt11ParseError::UnexpectedEndOfTaggedFields);
		}

		let mut route_hops = Vec::<RouteHintHop>::new();

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
					base_msat: u32::from_be_bytes(hop_bytes[41..45].try_into().expect("slice too big?")),
					proportional_millionths: u32::from_be_bytes(hop_bytes[45..49].try_into().expect("slice too big?")),
				},
				cltv_expiry_delta: u16::from_be_bytes(hop_bytes[49..51].try_into().expect("slice too big?")),
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
			}
			Bolt11ParseError::ParseAmountError(ref e) => {
				write!(f, "Invalid amount in hrp ({})", e)
			}
			Bolt11ParseError::MalformedSignature(ref e) => {
				write!(f, "Invalid secp256k1 signature: {}", e)
			}
			Bolt11ParseError::DescriptionDecodeError(ref e) => {
				write!(f, "Description is not a valid utf-8 string: {}", e)
			}
			Bolt11ParseError::InvalidSliceLength(ref function) => {
				write!(f, "Slice in function {} had the wrong length", function)
			}
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
			Bolt11ParseError::Skip => {
				f.write_str("the tagged field has to be skipped because of an unexpected, but allowed property")
			},
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
    }
}

from_error!(Bolt11ParseError::MalformedSignature, secp256k1::Error);
from_error!(Bolt11ParseError::ParseAmountError, ParseIntError);
from_error!(Bolt11ParseError::DescriptionDecodeError, str::Utf8Error);

impl From<bech32::Error> for Bolt11ParseError {
	fn from(e: bech32::Error) -> Self {
		match e {
			bech32::Error::InvalidPadding => Bolt11ParseError::PaddingError,
			_ => Bolt11ParseError::Bech32Error(e)
		}
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
	use crate::de::Bolt11ParseError;
	use secp256k1::PublicKey;
	use bech32::u5;
	use bitcoin::hashes::sha256;
	use std::str::FromStr;

	const CHARSET_REV: [i8; 128] = [
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		15, -1, 10, 17, 21, 20, 26, 30, 7, 5, -1, -1, -1, -1, -1, -1,
		-1, 29, -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1,
		1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1,
		-1, 29, -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1,
		1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1
	];

	fn from_bech32(bytes_5b: &[u8]) -> Vec<u5> {
		bytes_5b
			.iter()
			.map(|c| u5::try_from_u8(CHARSET_REV[*c as usize] as u8).unwrap())
			.collect()
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
		use crate::de::parse_int_be;

		assert_eq!(parse_int_be::<u32, u8>(&[1, 2, 3, 4], 256), Some(16909060));
		assert_eq!(parse_int_be::<u32, u8>(&[1, 3], 32), Some(35));
		assert_eq!(parse_int_be::<u32, u8>(&[255, 255, 255, 255], 256), Some(4294967295));
		assert_eq!(parse_int_be::<u32, u8>(&[1, 0, 0, 0, 0], 256), None);
	}

	#[test]
	fn test_parse_sha256_hash() {
		use crate::Sha256;
		use bech32::FromBase32;

		let input = from_bech32(
			"qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypq".as_bytes()
		);

		let hash = sha256::Hash::from_str(
			"0001020304050607080900010203040506070809000102030405060708090102"
		).unwrap();
		let expected = Ok(Sha256(hash));

		assert_eq!(Sha256::from_base32(&input), expected);

		// make sure hashes of unknown length get skipped
		let input_unexpected_length = from_bech32(
			"qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypyq".as_bytes()
		);
		assert_eq!(Sha256::from_base32(&input_unexpected_length), Err(Bolt11ParseError::Skip));
	}

	#[test]
	fn test_parse_description() {
		use crate::Description;
		use bech32::FromBase32;

		let input = from_bech32("xysxxatsyp3k7enxv4js".as_bytes());
		let expected = Ok(Description::new("1 cup coffee".to_owned()).unwrap());
		assert_eq!(Description::from_base32(&input), expected);
	}

	#[test]
	fn test_parse_payee_pub_key() {
		use crate::PayeePubKey;
		use bech32::FromBase32;

		let input = from_bech32("q0n326hr8v9zprg8gsvezcch06gfaqqhde2aj730yg0durunfhv66".as_bytes());
		let pk_bytes = [
			0x03, 0xe7, 0x15, 0x6a, 0xe3, 0x3b, 0x0a, 0x20, 0x8d, 0x07, 0x44, 0x19, 0x91, 0x63,
			0x17, 0x7e, 0x90, 0x9e, 0x80, 0x17, 0x6e, 0x55, 0xd9, 0x7a, 0x2f, 0x22, 0x1e, 0xde,
			0x0f, 0x93, 0x4d, 0xd9, 0xad
		];
		let expected = Ok(PayeePubKey(
			PublicKey::from_slice(&pk_bytes[..]).unwrap()
		));

		assert_eq!(PayeePubKey::from_base32(&input), expected);

		// expects 33 bytes
		let input_unexpected_length = from_bech32(
			"q0n326hr8v9zprg8gsvezcch06gfaqqhde2aj730yg0durunfhvq".as_bytes()
		);
		assert_eq!(PayeePubKey::from_base32(&input_unexpected_length), Err(Bolt11ParseError::Skip));
	}

	#[test]
	fn test_parse_expiry_time() {
		use crate::ExpiryTime;
		use bech32::FromBase32;

		let input = from_bech32("pu".as_bytes());
		let expected = Ok(ExpiryTime::from_seconds(60));
		assert_eq!(ExpiryTime::from_base32(&input), expected);

		let input_too_large = from_bech32("sqqqqqqqqqqqq".as_bytes());
		assert_eq!(ExpiryTime::from_base32(&input_too_large), Err(Bolt11ParseError::IntegerOverflowError));
	}

	#[test]
	fn test_parse_min_final_cltv_expiry_delta() {
		use crate::MinFinalCltvExpiryDelta;
		use bech32::FromBase32;

		let input = from_bech32("pr".as_bytes());
		let expected = Ok(MinFinalCltvExpiryDelta(35));

		assert_eq!(MinFinalCltvExpiryDelta::from_base32(&input), expected);
	}

	#[test]
	fn test_parse_fallback() {
		use crate::Fallback;
		use bech32::FromBase32;
		use bitcoin::{PubkeyHash, ScriptHash};
		use bitcoin::address::WitnessVersion;
		use bitcoin::hashes::Hash;

		let cases = vec![
			(
				from_bech32("3x9et2e20v6pu37c5d9vax37wxq72un98".as_bytes()),
				Ok(Fallback::PubKeyHash(PubkeyHash::from_slice(&[
					0x31, 0x72, 0xb5, 0x65, 0x4f, 0x66, 0x83, 0xc8, 0xfb, 0x14, 0x69, 0x59, 0xd3,
					0x47, 0xce, 0x30, 0x3c, 0xae, 0x4c, 0xa7
				]).unwrap()))
			),
			(
				from_bech32("j3a24vwu6r8ejrss3axul8rxldph2q7z9".as_bytes()),
				Ok(Fallback::ScriptHash(ScriptHash::from_slice(&[
					0x8f, 0x55, 0x56, 0x3b, 0x9a, 0x19, 0xf3, 0x21, 0xc2, 0x11, 0xe9, 0xb9, 0xf3,
					0x8c, 0xdf, 0x68, 0x6e, 0xa0, 0x78, 0x45
				]).unwrap()))
			),
			(
				from_bech32("qw508d6qejxtdg4y5r3zarvary0c5xw7k".as_bytes()),
				Ok(Fallback::SegWitProgram {
					version: WitnessVersion::V0,
					program: Vec::from(&[
						0x75u8, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45,
						0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6
					][..])
				})
			),
			(
				vec![u5::try_from_u8(21).unwrap(); 41],
				Err(Bolt11ParseError::Skip)
			),
			(
				vec![],
				Err(Bolt11ParseError::UnexpectedEndOfTaggedFields)
			),
			(
				vec![u5::try_from_u8(1).unwrap(); 81],
				Err(Bolt11ParseError::InvalidSegWitProgramLength)
			),
			(
				vec![u5::try_from_u8(17).unwrap(); 1],
				Err(Bolt11ParseError::InvalidPubKeyHashLength)
			),
			(
				vec![u5::try_from_u8(18).unwrap(); 1],
				Err(Bolt11ParseError::InvalidScriptHashLength)
			)
		];

		for (input, expected) in cases.into_iter() {
			assert_eq!(Fallback::from_base32(&input), expected);
		}
	}

	#[test]
	fn test_parse_route() {
		use lightning::routing::gossip::RoutingFees;
		use lightning::routing::router::{RouteHint, RouteHintHop};
		use crate::PrivateRoute;
		use bech32::FromBase32;

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
					0x7e, 0x14, 0x8f, 0x78, 0xc7, 0x72, 0x55
				][..]
			).unwrap(),
			short_channel_id: 0x0102030405060708,
			fees: RoutingFees {
				base_msat: 1,
				proportional_millionths: 20,
			},
			cltv_expiry_delta: 3,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None
		});
		expected.push(RouteHintHop {
			src_node_id: PublicKey::from_slice(
				&[
					0x03u8, 0x9e, 0x03, 0xa9, 0x01, 0xb8, 0x55, 0x34, 0xff, 0x1e, 0x92, 0xc4, 0x3c,
					0x74, 0x43, 0x1f, 0x7c, 0xe7, 0x20, 0x46, 0x06, 0x0f, 0xcf, 0x7a, 0x95, 0xc3,
					0x7e, 0x14, 0x8f, 0x78, 0xc7, 0x72, 0x55
				][..]
			).unwrap(),
			short_channel_id: 0x030405060708090a,
			fees: RoutingFees {
				base_msat: 2,
				proportional_millionths: 30,
			},
			cltv_expiry_delta: 4,
			htlc_minimum_msat: None,
			htlc_maximum_msat: None
		});

		assert_eq!(PrivateRoute::from_base32(&input), Ok(PrivateRoute(RouteHint(expected))));

		assert_eq!(
			PrivateRoute::from_base32(&[u5::try_from_u8(0).unwrap(); 40][..]),
			Err(Bolt11ParseError::UnexpectedEndOfTaggedFields)
		);
	}

	#[test]
	fn test_payment_secret_and_features_de_and_ser() {
		use lightning::ln::features::Bolt11InvoiceFeatures;
		use secp256k1::ecdsa::{RecoveryId, RecoverableSignature};
		use crate::TaggedField::*;
		use crate::{SiPrefix, SignedRawBolt11Invoice, Bolt11InvoiceSignature, RawBolt11Invoice, RawHrp, RawDataPart,
				 Currency, Sha256, PositiveTimestamp};

		// Feature bits 9, 15, and 99 are set.
		let expected_features = Bolt11InvoiceFeatures::from_le_bytes(vec![0, 130, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8]);
		let invoice_str = "lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdeessp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9q5sqqqqqqqqqqqqqqqpqsq67gye39hfg3zd8rgc80k32tvy9xk2xunwm5lzexnvpx6fd77en8qaq424dxgt56cag2dpt359k3ssyhetktkpqh24jqnjyw6uqd08sgptq44qu";
		let invoice = SignedRawBolt11Invoice {
					raw_invoice: RawBolt11Invoice {
						hrp: RawHrp {
							currency: Currency::Bitcoin,
							raw_amount: Some(25),
							si_prefix: Some(SiPrefix::Milli)
						},
						data: RawDataPart {
							timestamp: PositiveTimestamp::from_unix_timestamp(1496314658).unwrap(),
							tagged_fields: vec ! [
								PaymentHash(Sha256(sha256::Hash::from_str(
									"0001020304050607080900010203040506070809000102030405060708090102"
								).unwrap())).into(),
								Description(crate::Description::new("coffee beans".to_owned()).unwrap()).into(),
								PaymentSecret(crate::PaymentSecret([17; 32])).into(),
								Features(expected_features).into()]}
								},
					hash: [0xb1, 0x96, 0x46, 0xc3, 0xbc, 0x56, 0x76, 0x1d, 0x20, 0x65, 0x6e, 0x0e, 0x32,
									0xec, 0xd2, 0x69, 0x27, 0xb7, 0x62, 0x6e, 0x2a, 0x8b, 0xe6, 0x97, 0x71, 0x9f,
									0xf8, 0x7e, 0x44, 0x54, 0x55, 0xb9],
					signature: Bolt11InvoiceSignature(RecoverableSignature::from_compact(
										&[0xd7, 0x90, 0x4c, 0xc4, 0xb7, 0x4a, 0x22, 0x26, 0x9c, 0x68, 0xc1, 0xdf, 0x68,
											0xa9, 0x6c, 0x21, 0x4d, 0x65, 0x1b, 0x93, 0x76, 0xe9, 0xf1, 0x64, 0xd3, 0x60,
											0x4d, 0xa4, 0xb7, 0xde, 0xcc, 0xce, 0x0e, 0x82, 0xaa, 0xab, 0x4c, 0x85, 0xd3,
											0x58, 0xea, 0x14, 0xd0, 0xae, 0x34, 0x2d, 0xa3, 0x08, 0x12, 0xf9, 0x5d, 0x97,
											0x60, 0x82, 0xea, 0xac, 0x81, 0x39, 0x11, 0xda, 0xe0, 0x1a, 0xf3, 0xc1],
										RecoveryId::from_i32(1).unwrap()
								).unwrap()),
			};
		assert_eq!(invoice_str, invoice.to_string());
		assert_eq!(
			invoice_str.parse(),
			Ok(invoice)
		);
	}

	#[test]
	fn test_raw_signed_invoice_deserialization() {
		use crate::TaggedField::*;
		use secp256k1::ecdsa::{RecoveryId, RecoverableSignature};
		use crate::{SignedRawBolt11Invoice, Bolt11InvoiceSignature, RawBolt11Invoice, RawHrp, RawDataPart, Currency, Sha256,
			 PositiveTimestamp};

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
}
