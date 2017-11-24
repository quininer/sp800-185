use tiny_keccak::XofReader;
use ::cshake::CShake;
use ::utils::{ left_encode, right_encode };


/// KECCAK Message Authentication Code.
///
/// The KECCAK Message Authentication Code (KMAC) algorithm is a PRF and keyed hash
/// function based on `KECCAK`. It provides variable-length output, and unlike `SHAKE` and `cSHAKE`,
/// altering the requested output length generates a new, unrelated output. `KMAC` has two variants,
/// `KMAC128` and `KMAC256`, built from `cSHAKE128` and `cSHAKE256`, respectively. The two
/// variants differ somewhat in their technical security properties. Nonetheless, for most
/// applications, both variants can support any security strength up to 256 bits of security, provided
/// that a long enough key is used.
#[derive(Clone)]
pub struct KMac(CShake);

impl KMac {
    #[inline]
    pub fn new_kmac128(key: &[u8], custom: &[u8]) -> Self {
        let mut kmac = KMac(CShake::new_cshake128(b"KMAC", custom));
        kmac.init(key, 168);
        kmac
    }

    #[inline]
    pub fn new_kmac256(key: &[u8], custom: &[u8]) -> Self {
        let mut kmac = KMac(CShake::new_cshake256(b"KMAC", custom));
        kmac.init(key, 136);
        kmac
    }

    fn init(&mut self, key: &[u8], rate: usize) {
        let mut encbuf = [0; 9];

        // bytepad(encode_string(k))
        let pos = left_encode(&mut encbuf, rate as u64);
        self.0.update(&encbuf[pos..]);

        let pos = left_encode(&mut encbuf, key.len() as u64 * 8);
        self.0.update(&encbuf[pos..]);
        self.0.update(key);

        (self.0).0.fill_block();
    }

    #[inline]
    pub fn update(&mut self, buf: &[u8]) {
        self.0.update(buf)
    }

    #[inline]
    pub fn finalize(mut self, buf: &mut [u8]) {
        self.with_bitlength(buf.len() as u64 * 8);
        self.0.finalize(buf);
    }

    /// A function on bit strings in which the output can be extended to  any desired length.
    ///
    /// Some applications of `KMAC` may not know the number of output bits they will need until after
    /// the outputs begin to be produced. For these applications, `KMAC` can also be used as a XOF (i.e.,
    /// the output can be extended to any desired length), which mimics the behavior of `cSHAKE`.
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
