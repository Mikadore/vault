use crate::container::crypto;
use packed_struct::prelude::*;

use super::crypto::{aead, get_random_bytes, AeadNonce, Key};
use eyre::{ensure, Result};
use ring::pbkdf2::{self, PBKDF2_HMAC_SHA256};
#[derive(PackedStruct, Debug)]
#[packed_struct(endian = "lsb")]
pub struct EncryptedData {
    /// Minimum size is 512, maximum is 65536.
    /// Must be a multiple of the AES block size,
    /// i.e. 16.
    pub block_size: u16,
    /// Total blocks in the file
    pub block_count: u64,
    /// The master data key
    pub master_data_key: [u8; 32],
    /// The master tweak key
    pub master_tweak_key: [u8; 32],
}

#[derive(PackedStruct, Debug)]
#[packed_struct(endian = "lsb")]
pub struct ContainerFileHeader {
    /// Magic string "http://github.com/Mikadore/vault.git"
    pub magic: [u8; 36],
    /// Always 1
    pub version: u32,
    /// Parameters for pbkdf2
    /// used to derive the encryption
    /// key.
    ///
    /// Iteration count
    pub pbkdf2_iterations: u32,
    pub pbkdf2_salt: [u8; 32],
    /// The encrypted header data,
    /// containing the master key and
    /// all other important metadata.
    ///
    /// Authenticating the encrypted data
    /// is considered crutial before accepting
    /// it. Therefore the encrypted header uses
    /// ring's excellent AEAD capabilities (AES-GCM)
    /// for its encryption.
    ///
    /// The IV used to encrypt the data
    pub encrypted_data_iv: [u8; 12],
    /// The auhenticated data, in our case
    /// we're using be the first half (0..16) bytes
    /// of sha256(encryption_key). **Note**:
    /// The value of this field is the **OUTPUT**
    /// of the AES operation given the aforementioned input
    pub encrypted_data_tag: [u8; 16],
    /// 412 bytes are left for the encrypted payload
    pub encrypted_data: [u8; 74],
}

impl ContainerFileHeader {
    pub const SIZE: usize = std::mem::size_of::<Self>();
    pub const MAGIC: &'static [u8; 36] = b"http://github.com/Mikadore/vault.git";
    pub const VERSION: u32 = 1;
    pub const PBKDF2_DEFAULT_ITERATIONS: u32 = 100_000;
    pub const MIN_BLOCK_SIZE: u16 = 512;

    fn hash_password(password: &str, iterations: u32, salt: &[u8; 32]) -> Result<[u8; 32]> {
        let mut hash = [0; 32];
        pbkdf2::derive(
            PBKDF2_HMAC_SHA256,
            std::num::NonZeroU32::new(iterations).unwrap(),
            salt,
            password.as_bytes(),
            &mut hash,
        );
        Ok(hash)
    }

    pub fn decrypt_header(&self, user_password: &str) -> Result<EncryptedData> {
        let user_key =
            Self::hash_password(user_password, self.pbkdf2_iterations, &self.pbkdf2_salt)?;
        let user_key = Key::from(user_key);
        let mut data = self.encrypted_data.to_vec();
        aead::aes_gcm_decrypt(
            &mut data,
            &user_key,
            &AeadNonce::from_slice(&self.encrypted_data_iv),
            &self.encrypted_data_tag,
        )?;
        let decrypted = EncryptedData::unpack_from_slice(&data)?;
        ensure!(
            decrypted.block_size >= Self::MIN_BLOCK_SIZE,
            "Invalid block size {}: minimum block size is {}",
            decrypted.block_size,
            Self::MIN_BLOCK_SIZE,
        );
        ensure!(
            decrypted.block_size as usize % crypto::aes_xts::AES_BLOCK_SIZE == 0,
            "Invalid block size {}: block size must be a multple of {}",
            decrypted.block_size,
            crypto::aes_xts::AES_BLOCK_SIZE,
        );
        ensure!(
            decrypted.block_count > 1,
            "Invalid block count {}: There must be at least one block",
            decrypted.block_count,
        );
        Ok(decrypted)
    }

    pub fn new(
        user_password: &str,
        block_size: u16,
        block_count: usize,
        pbkdf2_iterations: u32,
    ) -> Result<(EncryptedData, Self)> {
        let salt = get_random_bytes();
        let user_key = Self::hash_password(user_password, pbkdf2_iterations, &salt)?;
        let user_key = Key::from(user_key);
        let encrypted_data = EncryptedData {
            block_count: block_count as u64,
            block_size,
            master_data_key: Key::random().to_bytes(),
            master_tweak_key: Key::random().to_bytes(),
        };
        let mut data = encrypted_data.pack().unwrap();
        let nonce = AeadNonce::random();
        let tag = aead::aes_gcm_encrypt(&mut data, &user_key, &nonce)?;
        Ok((
            encrypted_data,
            Self {
                magic: Self::MAGIC.clone(),
                version: Self::VERSION,
                pbkdf2_iterations,
                pbkdf2_salt: salt,
                encrypted_data_iv: nonce.to_bytes(),
                encrypted_data_tag: tag,
                encrypted_data: data,
            },
        ))
    }
}

#[test]
fn test_hash_reproducible() {
    let password = "password123";
    let salt = get_random_bytes();
    let hash_1 = ContainerFileHeader::hash_password(
        password,
        ContainerFileHeader::PBKDF2_DEFAULT_ITERATIONS,
        &salt,
    )
    .unwrap();
    let hash_2 = ContainerFileHeader::hash_password(
        password,
        ContainerFileHeader::PBKDF2_DEFAULT_ITERATIONS,
        &salt,
    )
    .unwrap();
    assert_eq!(hash_1, hash_2);
}

#[test]
fn test_decrypt_header() {
    const GOOD_PASS: &'static str = "ee8c5db0dad81aaf91103c489ed5c099";
    const BAD_PASS: &'static str = "123456789";
    const BLOCK_SIZE: u16 = 4096;
    const BLOCK_COUNT: u64 = 1024;
    let (_, header) = ContainerFileHeader::new(
        GOOD_PASS,
        BLOCK_SIZE,
        BLOCK_COUNT,
        ContainerFileHeader::PBKDF2_DEFAULT_ITERATIONS,
    )
    .unwrap();
    let bad_attempt = header.decrypt_header(BAD_PASS);
    assert!(bad_attempt.is_err());
    let decrypted = header.decrypt_header(GOOD_PASS).unwrap();
    assert_eq!(decrypted.block_count, BLOCK_COUNT);
    assert_eq!(decrypted.block_size, BLOCK_SIZE);
}
