use tiny_keccak::XofReader;
use ::cshake::CShake;
use ::utils::{ left_encode, right_encode };


/// Tuple Hash.
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

    pub fn update<T: AsRef<[u8]>>(&mut self, input: &[T]) {
        let mut encbuf = [0; 9];

        for buf in input {
            let buf = buf.as_ref();
            // encode_string(X[i])
            let pos = left_encode(&mut encbuf, buf.len() as u64 * 8);
            self.0.update(&encbuf[pos..]);
            self.0.update(buf);
        }
    }

    #[inline]
    pub fn finalize(mut self, buf: &mut [u8]) {
        self.with_bitlength(buf.len() as u64 * 8);
        self.0.finalize(buf)
    }

    /// A function on bit strings in which the output can be extended to  any desired length.
    ///
    /// Some applications of `TupleHash` may not know the number of output bits they will need until
    /// after the outputs begin to be produced. For these applications, `TupleHash` can also be used as a
    /// XOF (i.e., the output can be extended to any desired length), which mimics the behavior of
    /// cSHAKE.
    #[inline]
    pub fn xof(mut self) -> XofReader {
        self.with_bitlength(0);
        self.0.xof()
    }

    #[inline]
    fn with_bitlength(&mut self, bitlength: u64) {
        let mut encbuf = [0; 9];

        // right_encode(L)
        let pos = right_encode(&mut encbuf, bitlength);
        self.0.update(&encbuf[pos..]);
    }
}
