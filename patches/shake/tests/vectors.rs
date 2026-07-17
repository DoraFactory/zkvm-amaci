use hex_literal::hex;
use shake::{ExtendableOutput, Shake128, Shake256, Update, XofReader};

fn read_xof<H: Default + Update + ExtendableOutput>(input: &[u8], len: usize) -> Vec<u8> {
    let mut hasher = H::default();
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    let mut output = vec![0; len];
    reader.read(&mut output);
    output
}

#[test]
fn shake128_matches_fips_202_vectors() {
    assert_eq!(
        read_xof::<Shake128>(b"", 32),
        hex!("7f9c2ba4e88f827d616045507605853e d73b8093f6efbc88eb1a6eacfa66ef26")
    );
    assert_eq!(
        read_xof::<Shake128>(b"abc", 32),
        hex!("5881092dd818bf5cf8a3ddb793fbcba7 4097d5c526a6d35f97b83351940f2cc8")
    );
}

#[test]
fn shake256_matches_fips_202_vectors() {
    assert_eq!(
        read_xof::<Shake256>(b"", 64),
        hex!(
            "46b9dd2b0ba88d13233b3feb743eeb24
             3fcd52ea62b81b82b50c27646ed5762f
             d75dc4ddd8c0f200cb05019d67b592f6
             fc821c49479ab48640292eacb3b7c4be"
        )
    );
    assert_eq!(
        read_xof::<Shake256>(b"abc", 32),
        hex!("483366601360a8771c6863080cc4114d 8db44530f8f1e1ee4f94ea37e78b5739")
    );
}

#[test]
fn readers_are_stable_across_chunk_boundaries() {
    let mut hasher = Shake256::default();
    hasher.update(b"amaci-sp1-shake-adapter");
    let mut reader = hasher.finalize_xof();
    let mut chunked = [0u8; 257];
    reader.read(&mut chunked[..1]);
    reader.read(&mut chunked[1..137]);
    reader.read(&mut chunked[137..]);

    assert_eq!(
        chunked.as_slice(),
        read_xof::<Shake256>(b"amaci-sp1-shake-adapter", chunked.len())
    );
}
