use std::str::FromStr;
use std::num::ParseIntError;

use bech32;
use bech32::Bech32;

use chrono::{DateTime, Utc, Duration};

use regex::Regex;

use secp256k1;
use secp256k1::key::PublicKey;
use secp256k1::{Signature, Secp256k1};

mod parsers;

/// An Invoice for a payment on the lightning network as defined in
/// [BOLT #11](https://github.com/lightningnetwork/lightning-rfc/blob/master/11-payment-encoding.md#examples).

#[derive(Eq, PartialEq, Debug)]
pub struct Invoice {
    /// The currency deferred from the 3rd and 4th character of the bech32 transaction
    pub currency: Currency,

    /// The amount to pay in pico-satoshis
    pub amount: Option<u64>,

    pub timestamp: DateTime<Utc>,

    /// tagged fields of the payment request
    pub tagged: Vec<TaggedField>,

    pub signature: Signature,
}

#[derive(Eq, PartialEq, Debug)]
pub enum Currency {
    Bitcoin,
    BitcoinTestnet,
}

#[derive(Eq, PartialEq, Debug)]
pub enum TaggedField {
    PaymentHash([u8; 32]),
    Description(String),
    PayeePubKey(PublicKey),
    DescriptionHash([u8; 32]),
    ExpiryTime(Duration),
    MinFinalCltvExpiry(u64),
    Fallback(Fallback),
    Route {
        pubkey: PublicKey,
        short_channel_id: u64,
        fee_base_msat: i32,
        fee_proportional_millionths: i32,
        cltv_expiry_delta: u16,
    }
}

// TODO: better types instead onf byte arrays
#[derive(Eq, PartialEq, Debug)]
pub enum Fallback {
    SegWitScript {
        version: u8,
        script: Vec<u8>,
    },
    PubKeyHash([u8; 20]),
    ScriptHash([u8; 20]),
}

impl Invoice {
    // TODO: maybe rewrite using nom
    fn parse_hrp(hrp: &str) -> Result<(Currency, Option<u64>)> {
        let re = Regex::new(r"^ln([^0-9]*)([0-9]*)([munp]?)$").unwrap();
        let parts = match re.captures(&hrp) {
            Some(capture_group) => capture_group,
            None => return Err(ErrorKind::MalformedHRP.into())
        };

        let currency = parts[0].parse::<Currency>()?;

        let amount = if !parts[1].is_empty() {
            Some(parts[1].parse::<u64>()?)
        } else {
            None
        };

        /// `get_multiplier(x)` will only return `None` if `x` is not "m", "u", "n" or "p", which
        /// due to the above regex ensures that `get_multiplier(x)` iif `x == ""`, so it's ok to
        /// convert a none to 1BTC aka 10^12pBTC.
        let multiplier = parts[2].chars().next().and_then(|suffix| {
            get_multiplier(&suffix)
        }).unwrap_or(1_000_000_000_000);

        Ok((currency, amount.map(|amount| amount * multiplier)))
    }
}

impl FromStr for Invoice {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let Bech32 {hrp, data} = s.parse()?;

        let (currency, amount) = Invoice::parse_hrp(&hrp)?;

        Ok(Invoice {
            currency,
            amount,
            timestamp: Utc::now(),
            tagged: vec![],
            signature: Signature::from_der(&Secp256k1::new(), &[0; 65])?,
        })
    }
}

fn get_multiplier(multiplier: &char) -> Option<u64> {
    match multiplier {
        &'m' => Some(1_000_000_000),
        &'u' => Some(1_000_000),
        &'n' => Some(1_000),
        &'p' => Some(1),
        _ => None
    }
}

impl Currency {
    pub fn get_currency_prefix(&self) -> &'static str {
        match self {
            &Currency::Bitcoin => "bc",
            &Currency::BitcoinTestnet => "tb",
        }
    }

    pub fn from_prefix(prefix: &str) -> Result<Currency> {
        match prefix {
            "bc" => Ok(Currency::Bitcoin),
            "tb" => Ok(Currency::BitcoinTestnet),
            _ => Err(ErrorKind::BadCurrencyPrefix.into())
        }
    }
}

impl FromStr for Currency {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Currency::from_prefix(s)
    }
}

error_chain! {
    foreign_links {
        Bech32Error(bech32::Error);
        ParseIntError(ParseIntError);
        MalformedSignature(secp256k1::Error);
    }

    errors {
        BadLnPrefix {
            description("The invoice did not begin with 'ln'."),
            display("The invoice did not begin with 'ln'."),
        }

        BadCurrencyPrefix {
            description("unsupported currency"),
            display("unsupported currency"),
        }

        MalformedHRP {
            description("malformed human readable part"),
            display("malformed human readable part"),
        }
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn test_currency_code() {
        use super::Currency;
        assert_eq!("bc", Currency::Bitcoin.get_currency_prefix());
        assert_eq!("tb", Currency::BitcoinTestnet.get_currency_prefix());
    }

    // TODO: add more tests once parsers are finished
}