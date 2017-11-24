use tiny_keccak::{ Keccak, XofReader };
use rayon::prelude::*;
use ::cshake::CShake;
use ::utils::{ left_encode, right_encode };


/// Parallel Hash.
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
        self.with_bitlength(buf.len() as u64 * 8);
        self.inner.finalize(buf)
    }

    /// A function on bit strings in which the output can be extended to  any desired length.
    ///
    /// Some applications of `ParallelHash` may not know the number of output bits they will need until
    /// after the outputs begin to be produced. For these applications, `ParallelHash` can also be used as a
    /// XOF (i.e., the output can be extended to any desired length), which mimics the behavior of
    /// cSHAKE.
    #[inline]
    pub fn xof(mut self) -> XofReader {
        self.with_bitlength(0);
        self.inner.xof()
    }

    #[inline]
    fn with_bitlength(&mut self, bitlength: u64) {
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
    }
}
