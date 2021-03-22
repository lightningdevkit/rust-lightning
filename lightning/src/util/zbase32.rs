// This is a modification of base32 encoding to support the zbase32 alphabet.
// The original piece of software can be found at https://github.com/andreasots/base32

/*
Copyright (c) 2015 The base32 Developers

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

const ALPHABET: &'static [u8] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

/// Encodes some bytes as a zbase32 string
pub fn encode(data: &[u8]) -> String {
    let mut ret = Vec::with_capacity((data.len() + 4) / 5 * 8);

    for chunk in data.chunks(5) {
        let buf = {
            let mut buf = [0u8; 5];
            for (i, &b) in chunk.iter().enumerate() {
                buf[i] = b;
            }
            buf
        };

        ret.push(ALPHABET[((buf[0] & 0xF8) >> 3) as usize]);
        ret.push(ALPHABET[(((buf[0] & 0x07) << 2) | ((buf[1] & 0xC0) >> 6)) as usize]);
        ret.push(ALPHABET[((buf[1] & 0x3E) >> 1) as usize]);
        ret.push(ALPHABET[(((buf[1] & 0x01) << 4) | ((buf[2] & 0xF0) >> 4)) as usize]);
        ret.push(ALPHABET[(((buf[2] & 0x0F) << 1) | (buf[3] >> 7)) as usize]);
        ret.push(ALPHABET[((buf[3] & 0x7C) >> 2) as usize]);
        ret.push(ALPHABET[(((buf[3] & 0x03) << 3) | ((buf[4] & 0xE0) >> 5)) as usize]);
        ret.push(ALPHABET[(buf[4] & 0x1F) as usize]);
    }

    ret.truncate((data.len() * 8 + 4) / 5);

    // Check that our capacity calculation doesn't under-shoot in fuzzing
    #[cfg(fuzzing)]
    assert_eq!(ret.capacity(), (data.len() + 4) / 5 * 8);

    String::from_utf8(ret).unwrap()
}

// ASCII 0-Z
const INV_ALPHABET: [i8; 43] = [
    -1, 18, -1, 25, 26, 27, 30, 29, 7, 31, -1, -1, -1, -1, -1, -1, -1,  24, 1, 12, 3, 8, 5, 6, 28,
    21, 9, 10, -1, 11, 2, 16, 13, 14, 4, 22, 17, 19, -1, 20, 15, 0, 23,
];

/// Decodes a zbase32 string to the original bytes, failing if the string was not encoded by a
/// proper zbase32 encoder.
pub fn decode(data: &str) -> Result<Vec<u8>, ()> {
    if !data.is_ascii() {
        return Err(());
    }

    let data = data.as_bytes();
    let output_length = data.len() * 5 / 8;
    if data.len() > (output_length * 8 + 4) / 5 {
        // If the string has more charachters than are required to encode the number of bytes
        // decodable, treat the string as invalid.
        return Err(());
    }

    let mut ret = Vec::with_capacity((data.len() + 7) / 8 * 5);

    for chunk in data.chunks(8) {
        let buf = {
            let mut buf = [0u8; 8];
            for (i, &c) in chunk.iter().enumerate() {
                match INV_ALPHABET.get(c.to_ascii_uppercase().wrapping_sub(b'0') as usize) {
                    Some(&-1) | None => return Err(()),
                    Some(&value) => buf[i] = value as u8,
                };
            }
            buf
        };
        ret.push((buf[0] << 3) | (buf[1] >> 2));
        ret.push((buf[1] << 6) | (buf[2] << 1) | (buf[3] >> 4));
        ret.push((buf[3] << 4) | (buf[4] >> 1));
        ret.push((buf[4] << 7) | (buf[5] << 2) | (buf[6] >> 3));
        ret.push((buf[6] << 5) | buf[7]);
    }
    for c in ret.drain(output_length..) {
        if c != 0 {
            // If the original string had any bits set at positions outside of the encoded data,
            // treat the string as invalid.
            return Err(());
        }
    }

    // Check that our capacity calculation doesn't under-shoot in fuzzing
    #[cfg(fuzzing)]
    assert_eq!(ret.capacity(), (data.len() + 7) / 8 * 5);

    Ok(ret)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_DATA: &[(&str, &[u8])] = &[
        ("",       &[]),
        ("yy",     &[0x00]),
        ("oy",     &[0x80]),
        ("tqrey",   &[0x8b, 0x88, 0x80]),
        ("6n9hq",  &[0xf0, 0xbf, 0xc7]),
        ("4t7ye",  &[0xd4, 0x7a, 0x04]),
        ("6im5sdy", &[0xf5, 0x57, 0xbb, 0x0c]),
        ("ybndrfg8ejkmcpqxot1uwisza345h769", &[0x00, 0x44, 0x32, 0x14, 0xc7, 0x42, 0x54, 0xb6,
                                                    0x35, 0xcf, 0x84, 0x65, 0x3a, 0x56, 0xd7, 0xc6,
                                                    0x75, 0xbe, 0x77, 0xdf])
    ];
 

    #[test]
    fn test_encode() {
        for &(zbase32, data) in TEST_DATA {
            assert_eq!(encode(data), zbase32);
        }
    }

    #[test]
    fn test_decode() {
        for &(zbase32, data) in TEST_DATA {
            assert_eq!(decode(zbase32).unwrap(), data);
        }
    }

    #[test]
    fn test_decode_wrong() {
        const WRONG_DATA: &[&str] = &["00", "l1", "?", "="];

        for &data in WRONG_DATA {
            match decode(data) {
                Ok(_) => assert!(false, "Data shouldn't be decodable"),
                Err(_) => assert!(true),
            }
        }
    }
}
