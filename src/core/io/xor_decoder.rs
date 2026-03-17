/// Apply the Bitcoin Core XOR obfuscation to `data`.
///
/// The key repeats cyclically over the entire buffer.
/// If the key is all-zero (or empty), the data is returned unchanged.
pub fn xor_decode(data: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() || key.iter().all(|&b| b == 0) {
        return data.to_vec();
    }
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_key_is_identity() {
        let data = vec![0xde, 0xad, 0xbe, 0xef];
        assert_eq!(xor_decode(&data, &[0, 0, 0]), data);
    }

    #[test]
    fn xor_round_trips() {
        let key = vec![0xab, 0xcd];
        let plain = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let enc = xor_decode(&plain, &key);
        let dec = xor_decode(&enc, &key);
        assert_eq!(dec, plain);
    }

    #[test]
    fn empty_key_is_identity() {
        let data = vec![0x11, 0x22];
        assert_eq!(xor_decode(&data, &[]), data);
    }
}
