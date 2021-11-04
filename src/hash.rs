use sha2::{Digest, Sha256, Sha512};


pub fn sha256_digest_str(item: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(item.as_bytes());

    hex::encode(hasher.finalize())
}

pub fn sha256_digest_strs(strs: &[&str]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    for item in strs {
        hasher.update(item.as_bytes());
    }
    let mut bytes = Vec::new();
    bytes.extend(hasher.finalize().iter());
    bytes
}

pub fn sha512_digest_bytes(item: &[u8]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(item);
    hasher.finalize().to_vec()
}
