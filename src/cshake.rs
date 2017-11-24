use tiny_keccak::{ Keccak, XofReader };
use ::utils::left_encode;


/// The customizable SHAKE function.
///
/// The two variants of `cSHAKE`—`cSHAKE128` and `cSHAKE256`—are defined in terms of the
/// `SHAKE` and `KECCAK[c]` functions specified in FIPS 202. `cSHAKE128` provides a 128-bit
/// security strength, while `cSHAKE256` provides a 256-bit security strength.
#[derive(Clone)]
pub struct CShake(pub(crate) Keccak);

impl CShake {
    #[inline]
    pub fn new_cshake128(name: &[u8], custom: &[u8]) -> Self {
        let mut cshake = CShake(Keccak::new(168, 0x04));
        cshake.init(name, custom, 168);
        cshake
    }

    #[inline]
    pub fn new_cshake256(name: &[u8], custom: &[u8]) -> Self {
        let mut cshake = CShake(Keccak::new(136, 0x04));
        cshake.init(name, custom, 136);
        cshake
    }

    fn init(&mut self, name: &[u8], custom: &[u8], rate: usize) {
        let mut encbuf = [0; 9];

        let pos = left_encode(&mut encbuf, rate as u64);
        self.0.absorb(&encbuf[pos..]); // left_encode(rate)

        let pos = left_encode(&mut encbuf, name.len() as u64 * 8);
        self.0.absorb(&encbuf[pos..]); // left_encode(len(N))
        self.0.absorb(name);

        let pos = left_encode(&mut encbuf, custom.len() as u64 * 8);
        self.0.absorb(&encbuf[pos..]); // left_encode(len(S))
        self.0.absorb(custom);

        self.0.fill_block(); // pad zero
    }

    #[inline]
    pub fn update(&mut self, buf: &[u8]) {
        self.0.absorb(buf)
    }

    #[inline]
    pub fn finalize(&mut self, buf: &mut [u8]) {
        self.0.pad();
        self.0.keccakf();
        self.0.squeeze(buf);
    }

    #[inline]
    pub fn xof(self) -> XofReader {
        self.0.xof()
    }
}
