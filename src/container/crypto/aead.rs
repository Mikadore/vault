use super::{AeadNonce, Key};
use eyre::{Context, Result};
use ring::aead::{self, Aad, LessSafeKey, UnboundKey, AES_256_GCM};
use ring::digest::{self, SHA256};

pub type Tag = [u8; 16];

pub fn aes_gcm_encrypt(in_out: &mut [u8], key: &Key, nonce: &AeadNonce) -> Result<Tag> {
    let key_hash = digest::digest(&SHA256, key.as_slice());
    let key_hash = key_hash.as_ref();
    let ring_key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key.as_slice())?);
    ring_key
        .seal_in_place_separate_tag(nonce.into(), Aad::from(&key_hash[0..16]), in_out)
        .wrap_err("Encryption failed")
        .map(|t| t.as_ref().try_into().unwrap())
}

pub fn aes_gcm_decrypt(in_out: &mut [u8], key: &Key, nonce: &AeadNonce, tag: &Tag) -> Result<()> {
    let key_hash = digest::digest(&SHA256, key.as_slice());
    let key_hash = key_hash.as_ref();
    let tag = aead::Tag::from(*tag);
    let ring_key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key.as_slice())?);
    ring_key.open_in_place_separate_tag(
        nonce.into(),
        Aad::from(&key_hash[0..16]),
        tag,
        in_out,
        0..,
    )?;
    Ok(())
}

#[test]
fn test_aead_encrypt_decrypt() {
    let key = Key::random();
    let nonce = AeadNonce::random();
    let plaintext = "Very secret text";

    let mut buffer = plaintext.as_bytes().to_vec();
    let tag = aes_gcm_encrypt(&mut buffer, &key, &nonce).unwrap();
    assert_ne!(buffer, plaintext.as_bytes());
    aes_gcm_decrypt(&mut buffer, &key, &nonce, &tag).unwrap();
    assert_eq!(buffer, plaintext.as_bytes());
}
