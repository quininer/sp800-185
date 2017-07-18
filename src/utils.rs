use byteorder::{ ByteOrder, BigEndian };


pub fn left_encode(buf: &mut [u8], value: u64) -> usize {
    // ref https://cryptologie.net/article/388/shake-cshake-and-some-more-bit-ordering/

    assert_eq!(buf.len(), 9);
    buf.copy_from_slice(&[0; 9]);

    let offset = if value == 0 {
        8
    } else {
        BigEndian::write_u64(&mut buf[1..], value.to_le());
        buf.iter()
            .enumerate()
            .find(|&(_, &v)| v != 0)
            .map(|(n, _)| n)
            .unwrap_or(8)
    };

    buf[offset - 1] = (9 - offset) as u8;
    offset - 1
}


pub fn right_encode(buf: &mut [u8], value: u64) -> usize {
    assert_eq!(buf.len(), 9);
    buf.copy_from_slice(&[0; 9]);

    let offset = if value == 0 {
        7
    } else {
        BigEndian::write_u64(&mut buf[..8], value.to_le());
        buf.iter()
            .enumerate()
            .find(|&(_, &v)| v != 0)
            .map(|(n, _)| n)
            .unwrap_or(7)
    };

    buf[8] = (8 - offset) as u8;
    offset
}


#[test]
fn test_left_encode() {
    let mut buf = [0; 9];
    let n = left_encode(&mut buf, 0);
    assert_eq!(&buf[n..], [1, 0]);

    let n = left_encode(&mut buf, 128);
    assert_eq!(&buf[n..], [1, 128]);

    let n = left_encode(&mut buf, 65536);
    assert_eq!(&buf[n..], [3, 1, 0, 0]);

    let n = left_encode(&mut buf, 4096);
    assert_eq!(&buf[n..], [2, 16, 0]);

    let n = left_encode(&mut buf, 18446744073709551615);
    assert_eq!(&buf[n..], [8, 255, 255, 255, 255, 255, 255, 255, 255]);

    let n = left_encode(&mut buf, 54321);
    assert_eq!(&buf[n..], [2, 212, 49]);
}

#[test]
fn test_right_encode() {
    let mut buf = [0; 9];
    let n = right_encode(&mut buf, 0);
    assert_eq!(&buf[n..], [0, 1]);

    let n = right_encode(&mut buf, 128);
    assert_eq!(&buf[n..], [128, 1]);

    let n = right_encode(&mut buf, 65536);
    assert_eq!(&buf[n..], [1, 0, 0, 3]);

    let n = right_encode(&mut buf, 4096);
    assert_eq!(&buf[n..], [16, 0, 2]);

    let n = right_encode(&mut buf, 18446744073709551615);
    assert_eq!(&buf[n..], [255, 255, 255, 255, 255, 255, 255, 255, 8]);

    let n = right_encode(&mut buf, 12345);
    assert_eq!(&buf[n..], [48, 57, 2]);
}
