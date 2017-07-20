use ::cshake::CShake;
use ::utils::{ left_encode, right_encode };


/// Tuple Hash
///
/// `TupleHash` is a SHA-3-derived hash function with variable-length output that is designed to
/// simply hash a tuple of input strings, any or all of which may be empty strings, in an
/// unambiguous way. Such a tuple may consist of any number of strings, including zero, and is
/// represented as a sequence of strings or variables in parentheses like (“a”, “b”, “c”,...,“z”) in this
/// document.
/// `TupleHash` is designed to provide a generic, misuse-resistant way to combine a sequence of
/// strings for hashing such that, for example, a `TupleHash` computed on the tuple ("abc" ,"d") will
/// produce a different hash value than a `TupleHash` computed on the tuple ("ab","cd"), even though
/// all the remaining input parameters are kept the same, and the two resulting concatenated strings,
/// without string encoding, are identical.
/// `TupleHash` supports two security strengths: 128 bits and 256 bits. Changing any input to the
/// function, including the requested output length, will almost certainly change the final output.
#[derive(Clone)]
pub struct TupleHash(CShake);

impl TupleHash {
    #[inline]
    pub fn new_tuplehash128(custom: &[u8]) -> Self {
        TupleHash(CShake::new_cshake128(b"TupleHash", custom))
    }

    #[inline]
    pub fn new_tuplehash256(custom: &[u8]) -> Self {
        TupleHash(CShake::new_cshake256(b"TupleHash", custom))
    }

    pub fn update(&mut self, input: &[&[u8]]) {
        let mut encbuf = [0; 9];

        for buf in input {
            // encode_string(X[i])
            let pos = left_encode(&mut encbuf, buf.len() as u64 * 8);
            self.0.update(&encbuf[pos..]);
            self.0.update(buf);
        }
    }

    #[inline]
    pub fn finalize(mut self, buf: &mut [u8]) {
        let len = buf.len() as u64 * 8;
        self.finalize_with_bitlength(buf, len)
    }

    /// A function on bit strings in which the output can be extended to  any desired length.
    ///
    /// Some applications of `TupleHash` may not know the number of output bits they will need until
    /// after the outputs begin to be produced. For these applications, `TupleHash` can also be used as a
    /// XOF (i.e., the output can be extended to any desired length), which mimics the behavior of
    /// cSHAKE.
    #[inline]
    pub fn finalize_xof(&mut self, buf: &mut [u8]) {
        self.finalize_with_bitlength(buf, 0)
    }

    fn finalize_with_bitlength(&mut self, buf: &mut [u8], bitlength: u64) {
        let mut encbuf = [0; 9];

        // right_encode(L)
        let pos = right_encode(&mut encbuf, bitlength);
        self.0.update(&encbuf[pos..]);

        self.0.finalize(buf)
    }

    #[inline]
    pub fn squeeze(&mut self, buf: &mut [u8]) {
        self.0.squeeze(buf)
    }
}


#[test]
fn test_tuplehash128() {
    let te3 = b"\x00\x01\x02";
    let te6 = b"\x10\x11\x12\x13\x14\x15";
    let te9 = b"\x20\x21\x22\x23\x24\x25\x26\x27\x28";
    let s0 = b"";
    let s1 = b"My Tuple App";


    let output = b"\xC5\xD8\x78\x6C\x1A\xFB\x9B\x82\x11\x1A\xB3\x4B\x65\xB2\xC0\x04\x8F\xA6\x4E\x6D\x48\xE2\x63\x26\x4C\xE1\x70\x7D\x3F\xFC\x8E\xD1";
    let mut buf = vec![0; output.len()];
    let mut hasher = TupleHash::new_tuplehash128(s0);
    hasher.update(&[&te3[..], &te6[..]]);
    hasher.finalize(&mut buf);
    assert_eq!(buf, output);


    let output = b"\x75\xCD\xB2\x0F\xF4\xDB\x11\x54\xE8\x41\xD7\x58\xE2\x41\x60\xC5\x4B\xAE\x86\xEB\x8C\x13\xE7\xF5\xF4\x0E\xB3\x55\x88\xE9\x6D\xFB";
    let mut buf = vec![0; output.len()];
    let mut hasher = TupleHash::new_tuplehash128(s1);
    hasher.update(&[&te3[..], &te6[..]]);
    hasher.finalize(&mut buf);
    assert_eq!(buf, output);


    let output = b"\xE6\x0F\x20\x2C\x89\xA2\x63\x1E\xDA\x8D\x4C\x58\x8C\xA5\xFD\x07\xF3\x9E\x51\x51\x99\x8D\xEC\xCF\x97\x3A\xDB\x38\x04\xBB\x6E\x84";
    let mut buf = vec![0; output.len()];
    let mut hasher = TupleHash::new_tuplehash128(s1);
    hasher.update(&[&te3[..], &te6[..], &te9[..]]);
    hasher.finalize(&mut buf);
    assert_eq!(buf, output);
}

#[test]
fn test_tuplehash256() {
    let te3 = b"\x00\x01\x02";
    let te6 = b"\x10\x11\x12\x13\x14\x15";
    let te9 = b"\x20\x21\x22\x23\x24\x25\x26\x27\x28";
    let s0 = b"";
    let s1 = b"My Tuple App";


    let output = b"\xCF\xB7\x05\x8C\xAC\xA5\xE6\x68\xF8\x1A\x12\xA2\x0A\x21\x95\xCE\x97\xA9\x25\xF1\xDB\xA3\xE7\x44\x9A\x56\xF8\x22\x01\xEC\x60\x73\
                    \x11\xAC\x26\x96\xB1\xAB\x5E\xA2\x35\x2D\xF1\x42\x3B\xDE\x7B\xD4\xBB\x78\xC9\xAE\xD1\xA8\x53\xC7\x86\x72\xF9\xEB\x23\xBB\xE1\x94";
    let mut buf = vec![0; output.len()];
    let mut hasher = TupleHash::new_tuplehash256(s0);
    hasher.update(&[&te3[..], &te6[..]]);
    hasher.finalize(&mut buf);
    assert_eq!(buf, &output[..]);


    let output = b"\x14\x7C\x21\x91\xD5\xED\x7E\xFD\x98\xDB\xD9\x6D\x7A\xB5\xA1\x16\x92\x57\x6F\x5F\xE2\xA5\x06\x5F\x3E\x33\xDE\x6B\xBA\x9F\x3A\xA1\
                    \xC4\xE9\xA0\x68\xA2\x89\xC6\x1C\x95\xAA\xB3\x0A\xEE\x1E\x41\x0B\x0B\x60\x7D\xE3\x62\x0E\x24\xA4\xE3\xBF\x98\x52\xA1\xD4\x36\x7E";
    let mut buf = vec![0; output.len()];
    let mut hasher = TupleHash::new_tuplehash256(s1);
    hasher.update(&[&te3[..], &te6[..]]);
    hasher.finalize(&mut buf);
    assert_eq!(buf, &output[..]);


    let output = b"\x45\x00\x0B\xE6\x3F\x9B\x6B\xFD\x89\xF5\x47\x17\x67\x0F\x69\xA9\xBC\x76\x35\x91\xA4\xF0\x5C\x50\xD6\x88\x91\xA7\x44\xBC\xC6\xE7\
                    \xD6\xD5\xB5\xE8\x2C\x01\x8D\xA9\x99\xED\x35\xB0\xBB\x49\xC9\x67\x8E\x52\x6A\xBD\x8E\x85\xC1\x3E\xD2\x54\x02\x1D\xB9\xE7\x90\xCE";
    let mut buf = vec![0; output.len()];
    let mut hasher = TupleHash::new_tuplehash256(s1);
    hasher.update(&[&te3[..], &te6[..], &te9[..]]);
    hasher.finalize(&mut buf);
    assert_eq!(buf, &output[..]);
}

#[test]
fn test_tuplehash128_xof() {
    let te3 = b"\x00\x01\x02";
    let te6 = b"\x10\x11\x12\x13\x14\x15";
    let te9 = b"\x20\x21\x22\x23\x24\x25\x26\x27\x28";
    let s0 = b"";
    let s1 = b"My Tuple App";


    let output = b"\x2F\x10\x3C\xD7\xC3\x23\x20\x35\x34\x95\xC6\x8D\xE1\xA8\x12\x92\x45\xC6\x32\x5F\x6F\x2A\x3D\x60\x8D\x92\x17\x9C\x96\xE6\x84\x88";
    let mut buf = vec![0; output.len()];
    let mut hasher = TupleHash::new_tuplehash128(s0);
    hasher.update(&[&te3[..], &te6[..]]);
    hasher.finalize_xof(&mut buf);
    hasher.squeeze(&mut buf);
    assert_eq!(buf, output);


    let output = b"\x3F\xC8\xAD\x69\x45\x31\x28\x29\x28\x59\xA1\x8B\x6C\x67\xD7\xAD\x85\xF0\x1B\x32\x81\x5E\x22\xCE\x83\x9C\x49\xEC\x37\x4E\x9B\x9A";
    let mut buf = vec![0; output.len()];
    let mut hasher = TupleHash::new_tuplehash128(s1);
    hasher.update(&[&te3[..], &te6[..]]);
    hasher.finalize_xof(&mut buf);
    hasher.squeeze(&mut buf);
    assert_eq!(buf, output);


    let output = b"\x90\x0F\xE1\x6C\xAD\x09\x8D\x28\xE7\x4D\x63\x2E\xD8\x52\xF9\x9D\xAA\xB7\xF7\xDF\x4D\x99\xE7\x75\x65\x78\x85\xB4\xBF\x76\xD6\xF8";
    let mut buf = vec![0; output.len()];
    let mut hasher = TupleHash::new_tuplehash128(s1);
    hasher.update(&[&te3[..], &te6[..], &te9[..]]);
    hasher.finalize_xof(&mut buf);
    hasher.squeeze(&mut buf);
    assert_eq!(buf, output);
}

#[test]
fn test_tuplehash256_xof() {
    let te3 = b"\x00\x01\x02";
    let te6 = b"\x10\x11\x12\x13\x14\x15";
    let te9 = b"\x20\x21\x22\x23\x24\x25\x26\x27\x28";
    let s0 = b"";
    let s1 = b"My Tuple App";


    let output = b"\x03\xDE\xD4\x61\x0E\xD6\x45\x0A\x1E\x3F\x8B\xC4\x49\x51\xD1\x4F\xBC\x38\x4A\xB0\xEF\xE5\x7B\x00\x0D\xF6\xB6\xDF\x5A\xAE\x7C\xD5\
                        \x68\xE7\x73\x77\xDA\xF1\x3F\x37\xEC\x75\xCF\x5F\xC5\x98\xB6\x84\x1D\x51\xDD\x20\x7C\x99\x1C\xD4\x5D\x21\x0B\xA6\x0A\xC5\x2E\xB9";
    let mut buf = vec![0; output.len()];
    let mut hasher = TupleHash::new_tuplehash256(s0);
    hasher.update(&[&te3[..], &te6[..]]);
    hasher.finalize_xof(&mut buf);
    hasher.squeeze(&mut buf);
    assert_eq!(buf, &output[..]);


    let output = b"\x64\x83\xCB\x3C\x99\x52\xEB\x20\xE8\x30\xAF\x47\x85\x85\x1F\xC5\x97\xEE\x3B\xF9\x3B\xB7\x60\x2C\x0E\xF6\xA6\x5D\x74\x1A\xEC\xA7\
                        \xE6\x3C\x3B\x12\x89\x81\xAA\x05\xC6\xD2\x74\x38\xC7\x9D\x27\x54\xBB\x1B\x71\x91\xF1\x25\xD6\x62\x0F\xCA\x12\xCE\x65\x8B\x24\x42";
    let mut buf = vec![0; output.len()];
    let mut hasher = TupleHash::new_tuplehash256(s1);
    hasher.update(&[&te3[..], &te6[..]]);
    hasher.finalize_xof(&mut buf);
    hasher.squeeze(&mut buf);
    assert_eq!(buf, &output[..]);


    let output = b"\x0C\x59\xB1\x14\x64\xF2\x33\x6C\x34\x66\x3E\xD5\x1B\x2B\x95\x0B\xEC\x74\x36\x10\x85\x6F\x36\xC2\x8D\x1D\x08\x8D\x8A\x24\x46\x28\
                        \x4D\xD0\x98\x30\xA6\xA1\x78\xDC\x75\x23\x76\x19\x9F\xAE\x93\x5D\x86\xCF\xDE\xE5\x91\x3D\x49\x22\xDF\xD3\x69\xB6\x6A\x53\xC8\x97";
    let mut buf = vec![0; output.len()];
    let mut hasher = TupleHash::new_tuplehash256(s1);
    hasher.update(&[&te3[..], &te6[..], &te9[..]]);
    hasher.finalize_xof(&mut buf);
    hasher.squeeze(&mut buf);
    assert_eq!(buf, &output[..]);
}
