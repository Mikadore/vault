use rand::RngCore;

pub mod aead;
pub mod aes_xts;

pub fn get_random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0; N];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

#[derive(Debug)]
pub struct Nonce<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> From<[u8; N]> for Nonce<N> {
    fn from(bytes: [u8; N]) -> Self {
        Self { bytes }
    }
}

impl<const N: usize> AsRef<[u8; N]> for Nonce<N> {
    fn as_ref(&self) -> &[u8; N] {
        &self.bytes
    }
}

impl<const N: usize> Nonce<N> {
    pub fn random() -> Self {
        Self::from(get_random_bytes())
    }

    pub fn to_bytes(self) -> [u8; N] {
        self.bytes
    }

    pub fn from_slice(bytes: &[u8]) -> Self {
        assert!(
            bytes.len() >= N,
            "At least N bytes are required for a Nonce"
        );
        let mut nonce = [0; N];
        nonce.copy_from_slice(&bytes[..N]);
        Self::from(nonce)
    }
}

pub type AeadNonce = Nonce<12>;

impl From<&AeadNonce> for ring::aead::Nonce {
    fn from(nonce: &AeadNonce) -> Self {
        ring::aead::Nonce::assume_unique_for_key(nonce.bytes)
    }
}

#[derive(Debug)]
pub struct Key {
    bytes: [u8; Self::KEY_LEN],
}

impl From<[u8; Key::KEY_LEN]> for Key {
    fn from(bytes: [u8; Self::KEY_LEN]) -> Self {
        Self { bytes }
    }
}

impl AsRef<[u8; Key::KEY_LEN]> for Key {
    fn as_ref(&self) -> &[u8; Self::KEY_LEN] {
        &self.bytes
    }
}

impl Key {
    const KEY_LEN: usize = 32;

    pub fn as_slice(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    pub fn to_bytes(self) -> [u8; 32] {
        self.bytes
    }

    pub fn random() -> Self {
        Self {
            bytes: get_random_bytes(),
        }
    }
}
