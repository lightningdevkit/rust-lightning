extern crate lightning_invoice;
extern crate bech32;

use lightning_invoice::RawDataPart;
use bech32::{FromBase32, ToBase32, u5};

fn do_test(data: &[u8]) {
    let bech32 = data.iter().map(|x| u5::try_from_u8(x % 32).unwrap()).collect::<Vec<_>>();
    let invoice = match RawDataPart::from_base32(&bech32) {
        Ok(invoice) => invoice,
        Err(_) => return,
    };

    // Our encoding is not worse than the input
    assert!(invoice.to_base32().len() <= bech32.len());

    // Our serialization is loss-less
    assert_eq!(
        RawDataPart::from_base32(&invoice.to_base32()).expect("faild parsing out own encoding"),
        invoice
    );
}

#[cfg(feature = "afl")]
#[macro_use] extern crate afl;
#[cfg(feature = "afl")]
fn main() {
    fuzz!(|data| {
        do_test(&data);
    });
}

#[cfg(feature = "honggfuzz")]
#[macro_use] extern crate honggfuzz;
#[cfg(feature = "honggfuzz")]
fn main() {
    loop {
        fuzz!(|data| {
            do_test(data);
        });
    }
}

#[cfg(test)]
mod tests {
    fn extend_vec_from_hex(hex: &str, out: &mut Vec<u8>) {
        let mut b = 0;
        for (idx, c) in hex.as_bytes().iter().filter(|&&c| c != b'\n').enumerate() {
            b <<= 4;
            match *c {
                b'A'...b'F' => b |= c - b'A' + 10,
                b'a'...b'f' => b |= c - b'a' + 10,
                b'0'...b'9' => b |= c - b'0',
                _ => panic!("Bad hex"),
            }
            if (idx & 1) == 1 {
                out.push(b);
                b = 0;
            }
        }
    }

    #[test]
    fn duplicate_crash() {
        let mut a = Vec::new();
        extend_vec_from_hex("000000", &mut a);
        super::do_test(&a);
    }
}
