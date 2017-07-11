use tiny_keccak::Keccak;
use ::utils::left_encode;


pub struct CShake(pub Keccak);

impl CShake {
    pub fn cshake128(custom: &[u8]) -> Self {
        let mut cshake = CShake(Keccak::new(168, 0x04));
        let rate_buf = [0; 168];
        cshake.init(custom, &rate_buf);
        cshake
    }

    fn init(&mut self, custom: &[u8], rate_buf: &[u8]) {
        let mut buf = [0; 9];
        let mut sum = 0;

        let pos = left_encode(&mut buf, rate_buf.len() as u64);
        self.0.absorb(&buf[pos..]); // left_encode(rate)
        sum += 9 - pos;

        self.0.absorb(&[1, 0]); // left_encode(0)
                                // skip self.0.absort(&[]);
        sum += 2;

        let pos = left_encode(&mut buf, custom.len() as u64 * 8);
        self.0.absorb(&buf[pos..]); // left_encode(len(S))
        self.0.absorb(custom);
        sum += (9 - pos) + custom.len();

        let pad = rate_buf.len() - (sum % rate_buf.len());
        self.0.absorb(&rate_buf[..pad]);
    }

    #[inline]
    pub fn update(&mut self, buf: &[u8]) {
        self.0.absorb(buf)
    }

    #[inline]
    pub fn finalize(self, buf: &mut [u8]) {
        self.0.finalize(buf)
    }
}


#[test]
fn test_cshake128() {
    let input = b"\x00\x01\x02\x03";
    let custom = b"Email Signature";
    let output = b"\xC1\xC3\x69\x25\xB6\x40\x9A\x04\xF1\xB5\x04\xFC\xBC\xA9\xD8\x2B\x40\x17\x27\x7C\xB5\xED\x2B\x20\x65\xFC\x1D\x38\x14\xD5\xAA\xF5";

    let mut buf = vec![0; output.len()];
    let mut cshake = CShake::cshake128(custom);
    cshake.update(input);
    cshake.finalize(&mut buf);
    assert_eq!(buf, output);
}
