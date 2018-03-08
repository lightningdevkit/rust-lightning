use std::fmt::Debug;

use bit_vec::BitVec;

use secp256k1::Secp256k1;
use secp256k1::key::PublicKey;

use super::TaggedField;
use super::TaggedField::*;

use chrono::Duration;

named_args!(parse_u64(len: usize) <u64>, fold_many_m_n!(len, len, take!(1), 0u64, |acc, place: &[u8]| {
    (acc * 32 + (place[0] as u64))
}));

named!(timestamp <&[u8], u32>, map!(call!(parse_u64, 7), |x| x as u32));

named!(data_length <&[u8], usize>, map!(call!(parse_u64, 2), |x| x as usize));

// 0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
// 0 1 2 3 4|0 1 2 3 4|0 1 2 3 4|0 1 2 3 4|0 1 2 3 4|0 1 2 3 4|0 1 2 3 4|0 1 2 3 4|
// TODO: more efficient 5->8 bit/byte conversion (see https://github.com/sipa/bech32/blob/master/ref/python/segwit_addr.py#L80)
named_args!(parse_bytes(len8: usize, len5: usize) <Vec<u8>>, map!(
    fold_many_m_n!(
        len5,
        len5,
        take!(1),
        BitVec::new(),
        |mut acc: BitVec, byte: &[u8]| {
            let byte = byte[0];
            for bit in (0..5).rev() {
                acc.push((byte & (1u8 << bit)) != 0);
            }
            acc
        }
    ),
    |mut bitvec| {
        bitvec.truncate(len8 * 8);
        bitvec.to_bytes()
    }
));

trait ToArray<T> {
    fn to_array_32(&self) -> [T; 32];
}

impl<T: Default + Copy + Debug> ToArray<T> for Vec<T> {
    /// panics if vec is to small
    fn to_array_32(&self) -> [T; 32] {
        let mut array = [T::default(); 32];
        for pos in 0..array.len() {
            array[pos] = self[pos];
        }
        array
    }
}

named!(payment_hash <&[u8], TaggedField>,
    do_parse!(
        tag!(&[1u8]) >>
        verify!(data_length, |len: usize| {len == 52}) >>
        hash: call!(parse_bytes, 32, 52) >>
        (PaymentHash(hash.to_array_32()))
    )
);

named!(description <&[u8], TaggedField>,
    do_parse!(
        tag!(&[13_u8]) >>
        data_length: data_length >>
        text: map_res!(call!(parse_bytes, (data_length * 5 / 8) as usize, data_length as usize), |bytes| {
            String::from_utf8(bytes)
        }) >>
        (Description(text))
    )
);

named!(payee_public_key <&[u8], TaggedField>, map_res!(
    do_parse!(
        tag!(&[19_u8]) >>
        verify!(data_length, |len: usize| {len == 53}) >>
        key: call!(parse_bytes, 33, 53) >>
        (key)
    ), |key: Vec<u8>| {
        PublicKey::from_slice(&Secp256k1::without_caps(), &key).map(|key| {
            PayeePubKey(key)
        })
    }
));

named!(description_hash <&[u8], TaggedField>,
    do_parse!(
        tag!(&[23u8]) >>
        verify!(data_length, |len: usize| {len == 52}) >>
        hash: call!(parse_bytes, 32, 52) >>
        (DescriptionHash(hash.to_array_32()))
    )
);

named!(expiry_time <&[u8], TaggedField>,
    do_parse!(
        tag!(&[6u8]) >>
        data_length: data_length >>
        expiry_time_seconds: call!(parse_u64, data_length) >>
        (ExpiryTime(Duration::seconds(expiry_time_seconds as i64)))
    )
);

#[cfg(test)]
mod test {
    // Reverse character set. Maps ASCII byte -> CHARSET index on [0,31]
    // Copied from rust-bech32
    const CHARSET_REV: [i8; 128] = [
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
        -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
        1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
        -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
        1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
    ];

    #[test]
    // parsing example timestamp "pvjluez" = 1496314658 from BOLT 11
    fn test_timestamp_parser() {
        use super::timestamp;
        use nom::IResult::Done;

        let bytes = "pvjluez".bytes().map(
            |c| CHARSET_REV[c as usize] as u8
        ).collect::<Vec<_>>();
        assert_eq!(timestamp(&bytes), Done(&[][..], 1496314658));
    }

    #[test]
    fn test_payment_hash_parser() {
        use super::TaggedField::PaymentHash;
        use super::payment_hash;
        use nom::IResult::Done;
        use hex::decode;
        use super::ToArray;

        let bytes = "pp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypq".bytes().map(
            |c| CHARSET_REV[c as usize] as u8
        ).collect::<Vec<_>>();


        let expected = PaymentHash(
            decode("0001020304050607080900010203040506070809000102030405060708090102")
                .unwrap()
                .to_array_32()
        );
        assert_eq!(payment_hash(&bytes), Done(&[][..], expected));
    }

    #[test]
    fn test_description_parser() {
        use super::TaggedField::Description;
        use super::description;
        use nom::IResult::Done;

        let bytes = "dq5xysxxatsyp3k7enxv4js".bytes().map(
            |c| CHARSET_REV[c as usize] as u8
        ).collect::<Vec<_>>();

        assert_eq!(description(&bytes), Done(&[][..], Description("1 cup coffee".into())));
    }

    #[test]
    fn test_payee_public_key_parser() {
        use super::TaggedField::PayeePubKey;
        use super::payee_public_key;
        use nom::IResult::Done;
        use hex::decode;
        use secp256k1::key::PublicKey;
        use secp256k1::Secp256k1;

        let bytes = "np4q0n326hr8v9zprg8gsvezcch06gfaqqhde2aj730yg0durunfhv66".bytes().map(
            |c| CHARSET_REV[c as usize] as u8
        ).collect::<Vec<_>>();

        let expected = PublicKey::from_slice(
            &Secp256k1::without_caps(),
            &decode("03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad").unwrap()
        ).unwrap();

        assert_eq!(payee_public_key(&bytes), Done(&[][..], PayeePubKey(expected)));
    }

    #[test]
    fn test_description_hash_parser() {
        use super::TaggedField::DescriptionHash;
        use super::description_hash;
        use nom::IResult::Done;
        use hex::decode;
        use super::ToArray;

        let bytes = "hp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs".bytes().map(
            |c| CHARSET_REV[c as usize] as u8
        ).collect::<Vec<_>>();


        // 3925b6f67e2c340036ed12093dd44e0368df1b6ea26c53dbe4811f58fd5db8c1 = sha256(
        // "One piece of chocolate cake, one icecream cone, one pickle, one slice of swiss cheese, \
        // one slice of salami, one lollypop, one piece of cherry pie, one sausage, one cupcake, \
        // and one slice of watermelon")
        let expected = DescriptionHash(
            decode("3925b6f67e2c340036ed12093dd44e0368df1b6ea26c53dbe4811f58fd5db8c1")
                .unwrap()
                .to_array_32()
        );
        assert_eq!(description_hash(&bytes), Done(&[][..], expected));
    }

    #[test]
    fn test_expiry_time_parser() {
        use super::TaggedField::ExpiryTime;
        use chrono::Duration;
        use super::expiry_time;
        use nom::IResult::Done;

        let bytes = "xqzpu".bytes().map(
            |c| CHARSET_REV[c as usize] as u8
        ).collect::<Vec<_>>();

        let expected = ExpiryTime(Duration::seconds(60));
        assert_eq!(expiry_time(&bytes), Done(&[][..], expected));
    }
}