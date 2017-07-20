use tiny_keccak::Keccak;
use rayon::prelude::*;
use ::cshake::CShake;
use ::utils::{ left_encode, right_encode };


/// Parallel Hash
///
/// The purpose of `ParallelHash` 10 is to support the efficient hashing of very long strings, by taking
/// advantage of the parallelism available in modern processors. `ParallelHash` supports the 128- and
/// 256-bit security strengths, and also provides variable-length output. Changing any input
/// parameter to `ParallelHash`, even the requested output length, will result in unrelated output. Like
/// the other functions defined in this document, `ParallelHash` also supports user-selected
/// customization strings.
#[derive(Clone)]
pub struct ParallelHash {
    inner: CShake,
    buf: Vec<u8>,
    n: u64,
    rate: usize,
    blocksize: usize
}

impl ParallelHash {
    #[inline]
    pub fn new_parallelhash128(custom: &[u8], blocksize: usize) -> Self {
        let mut hasher = ParallelHash {
            inner: CShake::new_cshake128(b"ParallelHash", custom),
            buf: Vec::new(),
            n: 0,
            rate: 128,
            blocksize
        };
        hasher.init();
        hasher
    }

    #[inline]
    pub fn new_parallelhash256(custom: &[u8], blocksize: usize) -> Self {
        let mut hasher = ParallelHash {
            inner: CShake::new_cshake256(b"ParallelHash", custom),
            buf: Vec::new(),
            n: 0,
            rate: 256,
            blocksize
        };
        hasher.init();
        hasher
    }

    fn init(&mut self) {
        let mut encbuf = [0; 9];

        // left_encode(B)
        let pos = left_encode(&mut encbuf, self.blocksize as u64);
        self.inner.update(&encbuf[pos..]);
    }

    pub fn update(&mut self, buf: &[u8]) {
        let rate = self.rate;

        let pos = if !self.buf.is_empty() {
            let len = self.blocksize - self.buf.len();

            if buf.len() < len {
                self.buf.extend_from_slice(buf);

                return;
            } else {
                let mut encbuf = vec![0; rate / 4];
                let mut shake = Keccak::new(200 - rate / 4, 0x1f);
                shake.update(&self.buf);
                shake.update(&buf[..len]);
                shake.finalize(&mut encbuf);
                self.inner.update(&encbuf);
                self.buf.clear();
                self.n += 1;
            }
            len
        } else {
            0
        };

        let bufs = buf[pos..].par_chunks(self.blocksize)
            .map(|chunk| if chunk.len() < self.blocksize {
                (false, chunk.into())
            } else {
                // cSHAKE(chunk, rate, "", "")
                let mut encbuf = vec![0; rate / 4];
                let mut shake = Keccak::new(200 - rate / 4, 0x1f);
                shake.update(chunk);
                shake.finalize(&mut encbuf);
                (true, encbuf)
            })
            .collect::<Vec<_>>();
        for (is_hashed, mut buf) in bufs {
            if is_hashed {
                self.inner.update(&buf);
                self.n += 1;
            } else {
                self.buf.append(&mut buf);
            }
        }
    }

    #[inline]
    pub fn finalize(mut self, buf: &mut [u8]) {
        let len = buf.len() as u64 * 8;
        self.finalize_with_bitlength(buf, len)
    }

    /// A function on bit strings in which the output can be extended to  any desired length.
    ///
    /// Some applications of `ParallelHash` may not know the number of output bits they will need until
    /// after the outputs begin to be produced. For these applications, `ParallelHash` can also be used as a
    /// XOF (i.e., the output can be extended to any desired length), which mimics the behavior of
    /// cSHAKE.
    #[inline]
    pub fn finalize_xof(&mut self, buf: &mut [u8]) {
        self.finalize_with_bitlength(buf, 0)
    }

    fn finalize_with_bitlength(&mut self, buf: &mut [u8], bitlength: u64) {
        if !self.buf.is_empty() {
            let mut encbuf = vec![0; self.rate / 4];
            let mut shake = Keccak::new(200 - self.rate / 4, 0x1f);
            shake.update(&self.buf);
            shake.finalize(&mut encbuf);
            self.inner.update(&encbuf);
            self.buf.clear();
            self.n += 1;
        }


        let mut encbuf = [0; 9];

        // right_encode(n)
        let pos = right_encode(&mut encbuf, self.n);
        self.inner.update(&encbuf[pos..]);

        // right_encode(L)
        let pos = right_encode(&mut encbuf, bitlength);
        self.inner.update(&encbuf[pos..]);

        self.inner.finalize(buf);
    }

    #[inline]
    pub fn squeeze(&mut self, buf: &mut [u8]) {
        self.inner.squeeze(buf)
    }
}


#[test]
fn test_parallelhash128() {
    let x192 = b"\x00\x01\x02\x03\x04\x05\x06\x07\x10\x11\x12\x13\x14\x15\x16\x17\x20\x21\x22\x23\x24\x25\x26\x27";
    let s0 = b"";
    let s1 = b"Parallel Data";


    let output = b"\xBA\x8D\xC1\xD1\xD9\x79\x33\x1D\x3F\x81\x36\x03\xC6\x7F\x72\x60\x9A\xB5\xE4\x4B\x94\xA0\xB8\xF9\xAF\x46\x51\x44\x54\xA2\xB4\xF5";
    let mut buf = vec![0; output.len()];
    let mut hasher = ParallelHash::new_parallelhash128(s0, 8);
    hasher.update(x192);
    hasher.finalize(&mut buf);
    assert_eq!(buf, output);



    let output = b"\xFC\x48\x4D\xCB\x3F\x84\xDC\xEE\xDC\x35\x34\x38\x15\x1B\xEE\x58\x15\x7D\x6E\xFE\xD0\x44\x5A\x81\xF1\x65\xE4\x95\x79\x5B\x72\x06";
    let mut buf = vec![0; output.len()];
    let mut hasher = ParallelHash::new_parallelhash128(s1, 8);
    hasher.update(x192);
    hasher.finalize(&mut buf);
    assert_eq!(buf, output);



    let output = b"\xBA\x8D\xC1\xD1\xD9\x79\x33\x1D\x3F\x81\x36\x03\xC6\x7F\x72\x60\x9A\xB5\xE4\x4B\x94\xA0\xB8\xF9\xAF\x46\x51\x44\x54\xA2\xB4\xF5";
    let mut buf = vec![0; output.len()];
    let mut hasher = ParallelHash::new_parallelhash128(s0, 8);
    hasher.update(&x192[..13]);
    hasher.update(&x192[13..]);
    hasher.finalize(&mut buf);
    assert_eq!(buf, output);
}

#[test]
fn test_parallelhash256() {
    let x192 = b"\x00\x01\x02\x03\x04\x05\x06\x07\x10\x11\x12\x13\x14\x15\x16\x17\x20\x21\x22\x23\x24\x25\x26\x27";
    let s0 = b"";
    let s1 = b"Parallel Data";

    let output = b"\xBC\x1E\xF1\x24\xDA\x34\x49\x5E\x94\x8E\xAD\x20\x7D\xD9\x84\x22\x35\xDA\x43\x2D\x2B\xBC\x54\xB4\xC1\x10\xE6\x4C\x45\x11\x05\x53\
                        \x1B\x7F\x2A\x3E\x0C\xE0\x55\xC0\x28\x05\xE7\xC2\xDE\x1F\xB7\x46\xAF\x97\xA1\xDD\x01\xF4\x3B\x82\x4E\x31\xB8\x76\x12\x41\x04\x29";
    let mut buf = vec![0; output.len()];
    let mut hasher = ParallelHash::new_parallelhash256(s0, 8);
    hasher.update(x192);
    hasher.finalize(&mut buf);
    assert_eq!(buf, &output[..]);


    let output = b"\xCD\xF1\x52\x89\xB5\x4F\x62\x12\xB4\xBC\x27\x05\x28\xB4\x95\x26\x00\x6D\xD9\xB5\x4E\x2B\x6A\xDD\x1E\xF6\x90\x0D\xDA\x39\x63\xBB\
                        \x33\xA7\x24\x91\xF2\x36\x96\x9C\xA8\xAF\xAE\xA2\x9C\x68\x2D\x47\xA3\x93\xC0\x65\xB3\x8E\x29\xFA\xE6\x51\xA2\x09\x1C\x83\x31\x10";
    let mut buf = vec![0; output.len()];
    let mut hasher = ParallelHash::new_parallelhash256(s1, 8);
    hasher.update(x192);
    hasher.finalize(&mut buf);
    assert_eq!(buf, &output[..]);


    let output = b"\xBC\x1E\xF1\x24\xDA\x34\x49\x5E\x94\x8E\xAD\x20\x7D\xD9\x84\x22\x35\xDA\x43\x2D\x2B\xBC\x54\xB4\xC1\x10\xE6\x4C\x45\x11\x05\x53\
                        \x1B\x7F\x2A\x3E\x0C\xE0\x55\xC0\x28\x05\xE7\xC2\xDE\x1F\xB7\x46\xAF\x97\xA1\xDD\x01\xF4\x3B\x82\x4E\x31\xB8\x76\x12\x41\x04\x29";
    let mut buf = vec![0; output.len()];
    let mut hasher = ParallelHash::new_parallelhash256(s0, 8);
    hasher.update(&x192[..13]);
    hasher.update(&x192[13..]);
    hasher.finalize(&mut buf);
    assert_eq!(buf, &output[..]);
}

#[test]
fn test_parallelhash128_xof() {
    let x192 = b"\x00\x01\x02\x03\x04\x05\x06\x07\x10\x11\x12\x13\x14\x15\x16\x17\x20\x21\x22\x23\x24\x25\x26\x27";
    let s0 = b"";
    let s1 = b"Parallel Data";


    let output = b"\xFE\x47\xD6\x61\xE4\x9F\xFE\x5B\x7D\x99\x99\x22\xC0\x62\x35\x67\x50\xCA\xF5\x52\x98\x5B\x8E\x8C\xE6\x66\x7F\x27\x27\xC3\xC8\xD3";
    let mut buf = vec![0; output.len()];
    let mut hasher = ParallelHash::new_parallelhash128(s0, 8);
    hasher.update(x192);
    hasher.finalize_xof(&mut buf);
    hasher.squeeze(&mut buf);
    assert_eq!(buf, output);


    let output = b"\xEA\x2A\x79\x31\x40\x82\x0F\x7A\x12\x8B\x8E\xB7\x0A\x94\x39\xF9\x32\x57\xC6\xE6\xE7\x9B\x4A\x54\x0D\x29\x1D\x6D\xAE\x70\x98\xD7";
    let mut buf = vec![0; output.len()];
    let mut hasher = ParallelHash::new_parallelhash128(s1, 8);
    hasher.update(x192);
    hasher.finalize_xof(&mut buf);
    hasher.squeeze(&mut buf);
    assert_eq!(buf, output);
}

#[test]
fn test_parallelhash256_xof() {
    let x192 = b"\x00\x01\x02\x03\x04\x05\x06\x07\x10\x11\x12\x13\x14\x15\x16\x17\x20\x21\x22\x23\x24\x25\x26\x27";
    let s0 = b"";
    let s1 = b"Parallel Data";


    let output = b"\xC1\x0A\x05\x27\x22\x61\x46\x84\x14\x4D\x28\x47\x48\x50\xB4\x10\x75\x7E\x3C\xBA\x87\x65\x1B\xA1\x67\xA5\xCB\xDD\xFF\x7F\x46\x66\
                        \x75\xFB\xF8\x4B\xCA\xE7\x37\x8A\xC4\x44\xBE\x68\x1D\x72\x94\x99\xAF\xCA\x66\x7F\xB8\x79\x34\x8B\xFD\xDA\x42\x78\x63\xC8\x2F\x1C";
    let mut buf = vec![0; output.len()];
    let mut hasher = ParallelHash::new_parallelhash256(s0, 8);
    hasher.update(x192);
    hasher.finalize_xof(&mut buf);
    hasher.squeeze(&mut buf);
    assert_eq!(buf, &output[..]);


    let output = b"\x53\x8E\x10\x5F\x1A\x22\xF4\x4E\xD2\xF5\xCC\x16\x74\xFB\xD4\x0B\xE8\x03\xD9\xC9\x9B\xF5\xF8\xD9\x0A\x2C\x81\x93\xF3\xFE\x6E\xA7\
                        \x68\xE5\xC1\xA2\x09\x87\xE2\xC9\xC6\x5F\xEB\xED\x03\x88\x7A\x51\xD3\x56\x24\xED\x12\x37\x75\x94\xB5\x58\x55\x41\xDC\x37\x7E\xFC";
    let mut buf = vec![0; output.len()];
    let mut hasher = ParallelHash::new_parallelhash256(s1, 8);
    hasher.update(x192);
    hasher.finalize_xof(&mut buf);
    hasher.squeeze(&mut buf);
    assert_eq!(buf, &output[..]);
}
