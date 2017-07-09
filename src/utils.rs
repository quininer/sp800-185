use byteorder::{ ByteOrder, BigEndian };


pub fn left_encode(buf: &mut [u8], value: u64) -> usize {
    // ref https://cryptologie.net/article/388/shake-cshake-and-some-more-bit-ordering/

    for b in buf.iter_mut() {
        *b = 0;
    }

    let offset = if value == 0 {
        8
    } else {
        BigEndian::write_u64(&mut buf[1..], value.to_le());
        buf.iter()
            .enumerate()
            .find(|&(_, &v)| v != 0)
            .map(|(n, _)| n)
            .unwrap_or_else(|| buf.len())
    };

    buf[offset - 1] = (buf.len() - offset) as u8;
    offset - 1
}


#[test]
fn test_left_encode() {
    let mut buf = [0; 9];
    let n = left_encode(&mut buf, 128);
    assert_eq!(&buf[n..], [1, 128]);

    let mut buf = [0; 9];
    let n = left_encode(&mut buf, 65536);
    assert_eq!(&buf[n..], [3, 1, 0, 0]);

    let mut buf = [0; 9];
    let n = left_encode(&mut buf, 4096);
    assert_eq!(&buf[n..], [2, 16, 0]);

    let mut buf = [0; 9];
    let n = left_encode(&mut buf, 18446744073709551615);
    assert_eq!(&buf[n..], [8, 255, 255, 255, 255, 255, 255, 255, 255]);
}
