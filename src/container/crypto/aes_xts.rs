//! An XTS-AES-256 implementation based off IEEE P1619,
//! I read it from [sci hub](https://sci-hub.se/10.1109/IEEESTD.2019.8637988)
use super::Key;

use aes::{
    cipher::{
        generic_array::GenericArray, inout::InOut, BlockDecryptMut, BlockEncryptMut, KeyInit,
    },
    Aes256,
};

/// Always 128 bits by definition
pub const AES_BLOCK_SIZE: usize = 16;

/// Alias for a block-sized byte array
type Block = [u8; AES_BLOCK_SIZE];

/// Magic used by the spec
/// for multiplying the tweak
const GF_128_FDBK: u8 = 0x87;

#[derive(Debug)]
pub struct Tweak {
    bytes: Block,
}

impl From<Block> for Tweak {
    fn from(bytes: Block) -> Self {
        Self { bytes }
    }
}

impl Tweak {
    /// Returns the contents, then
    /// multiplies the inner bytes
    /// according to the spec. This
    /// is intentionally the only method
    /// giving access to the inner state,
    /// because it should only be used once
    /// per 128bit sub block.  
    pub fn advance(&mut self) -> Block {
        let copy = self.bytes;
        let mut cin = 0;
        let mut cout = 0;
        for byte in self.bytes.iter_mut() {
            cout = (*byte >> 7) & 1;
            *byte = ((*byte << 1) + cin) & 0xFF;
            cin = cout;
        }
        if cout > 0 {
            self.bytes[0] ^= GF_128_FDBK;
        }
        copy
    }
}

/// AES needs to prepare the keys before
/// en/decryption can occur. Since this
/// requires some computation, we're
/// gonna store the `Aes256` instances
/// inside a context
#[derive(Debug)]
pub struct AESContext {
    data_ctx: Aes256,
    tweak_ctx: Aes256,
}

fn xor_inplace<const N: usize>(dst: &mut [u8; N], other: &[u8; N]) {
    for (dst, &src) in dst.iter_mut().zip(other.iter()) {
        *dst = *dst ^ src
    }
}

impl AESContext {
    pub fn new(data_key: Key, tweak_key: Key) -> Self {
        Self {
            data_ctx: Aes256::new(&GenericArray::from(data_key.to_bytes())),
            tweak_ctx: Aes256::new(&GenericArray::from(tweak_key.to_bytes())),
        }
    }

    pub fn block_tweak(&mut self, block_number: usize) -> Tweak {
        let mut bytes = [0; AES_BLOCK_SIZE];
        (&mut bytes[..std::mem::size_of::<usize>()]).copy_from_slice(&block_number.to_le_bytes());
        let mut block = GenericArray::from(bytes);
        self.tweak_ctx
            .encrypt_block_inout_mut(InOut::from(&mut block));
        bytes.copy_from_slice(&block);
        Tweak::from(bytes)
    }

    fn aes_xts_encrypt_block(&mut self, block: &mut Block, tweak_bytes: Block) {
        xor_inplace(block, &tweak_bytes);
        self.data_ctx
            .encrypt_block_inout_mut(InOut::from(GenericArray::from_mut_slice(block)));
        xor_inplace(block, &tweak_bytes);
    }

    fn aes_xts_decrypt_block(&mut self, block: &mut Block, tweak_bytes: Block) {
        xor_inplace(block, &tweak_bytes);
        self.data_ctx
            .decrypt_block_inout_mut(InOut::from(GenericArray::from_mut_slice(block)));
        xor_inplace(block, &tweak_bytes);
    }

    pub fn aes_xts_encrypt(&mut self, data: &mut [u8], block_number: usize) {
        assert!(
            data.len() % AES_BLOCK_SIZE == 0,
            "cipher stealing not implemented; data must be a multiple of the AES block size"
        );
        let mut tweak = self.block_tweak(block_number);
        for i in 0..(data.len() / AES_BLOCK_SIZE) {
            let tweak_bytes = tweak.advance();
            let block = &mut data[i * AES_BLOCK_SIZE..(i + 1) * AES_BLOCK_SIZE];
            self.aes_xts_encrypt_block(block.try_into().unwrap(), tweak_bytes);
        }
    }

    pub fn aes_xts_decrypt(&mut self, data: &mut [u8], block_number: usize) {
        assert!(
            data.len() % AES_BLOCK_SIZE == 0,
            "cipher stealing not implemented; data must be a multiple of the AES block size"
        );
        let mut tweak = self.block_tweak(block_number);
        for i in 0..(data.len() / AES_BLOCK_SIZE) {
            let tweak_bytes = tweak.advance();
            let block = &mut data[i * AES_BLOCK_SIZE..(i + 1) * AES_BLOCK_SIZE];
            self.aes_xts_decrypt_block(block.try_into().unwrap(), tweak_bytes);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::get_random_bytes;
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_ieee_vectors() {
        struct TestVector {
            data_key: Key,
            tweak_key: Key,
            block_number: usize,
            plaintext: [u8; 512],
            ciphertext: [u8; 512],
        }
        let test_vectors = [
            TestVector {
                data_key: Key::from(hex!(
                    "2718281828459045235360287471352662497757247093699959574966967627"
                )),
                tweak_key: Key::from(hex!(
                    "3141592653589793238462643383279502884197169399375105820974944592"
                )),
                block_number: 0xFF,
                plaintext: hex!(
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
                 202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
                 404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f
                 606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f
                 808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f
                 a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf
                 c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf
                 e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
                 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
                 202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
                 404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f
                 606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f
                 808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f
                 a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf
                 c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf
                 e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
                ),
                ciphertext: hex!(
                    "1c3b3a102f770386e4836c99e370cf9bea00803f5e482357a4ae12d414a3e63b
                 5d31e276f8fe4a8d66b317f9ac683f44680a86ac35adfc3345befecb4bb188fd
                 5776926c49a3095eb108fd1098baec70aaa66999a72a82f27d848b21d4a741b0
                 c5cd4d5fff9dac89aeba122961d03a757123e9870f8acf1000020887891429ca
                 2a3e7a7d7df7b10355165c8b9a6d0a7de8b062c4500dc4cd120c0f7418dae3d0
                 b5781c34803fa75421c790dfe1de1834f280d7667b327f6c8cd7557e12ac3a0f
                 93ec05c52e0493ef31a12d3d9260f79a289d6a379bc70c50841473d1a8cc81ec
                 583e9645e07b8d9670655ba5bbcfecc6dc3966380ad8fecb17b6ba02469a020a
                 84e18e8f84252070c13e9f1f289be54fbc481457778f616015e1327a02b140f1
                 505eb309326d68378f8374595c849d84f4c333ec4423885143cb47bd71c5edae
                 9be69a2ffeceb1bec9de244fbe15992b11b77c040f12bd8f6a975a44a0f90c29
                 a9abc3d4d893927284c58754cce294529f8614dcd2aba991925fedc4ae74ffac
                 6e333b93eb4aff0479da9a410e4450e0dd7ae4c6e2910900575da401fc07059f
                 645e8b7e9bfdef33943054ff84011493c27b3429eaedb4ed5376441a77ed4385
                 1ad77f16f541dfd269d50d6a5f14fb0aab1cbb4c1550be97f7ab4066193c4caa
                 773dad38014bd2092fa755c824bb5e54c4f36ffda9fcea70b9c6e693e148c151"
                ),
            },
            TestVector {
                data_key: Key::from(hex!(
                    "2718281828459045235360287471352662497757247093699959574966967627"
                )),
                tweak_key: Key::from(hex!(
                    "3141592653589793238462643383279502884197169399375105820974944592"
                )),
                block_number: 0xFFFF,
                plaintext: hex!(
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
                 202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
                 404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f
                 606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f
                 808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f
                 a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf
                 c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf
                 e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
                 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
                 202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
                 404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f
                 606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f
                 808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f
                 a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf
                 c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf
                 e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
                ),
                ciphertext: hex!(
                    "77a31251618a15e6b92d1d66dffe7b50b50bad552305ba0217a610688eff7e11
                 e1d0225438e093242d6db274fde801d4cae06f2092c728b2478559df58e837c2
                 469ee4a4fa794e4bbc7f39bc026e3cb72c33b0888f25b4acf56a2a9804f1ce6d
                 3d6e1dc6ca181d4b546179d55544aa7760c40d06741539c7e3cd9d2f6650b201
                 3fd0eeb8c2b8e3d8d240ccae2d4c98320a7442e1c8d75a42d6e6cfa4c2eca179
                 8d158c7aecdf82490f24bb9b38e108bcda12c3faf9a21141c3613b58367f922a
                 aa26cd22f23d708dae699ad7cb40a8ad0b6e2784973dcb605684c08b8d6998c6
                 9aac049921871ebb65301a4619ca80ecb485a31d744223ce8ddc2394828d6a80
                 470c092f5ba413c3378fa6054255c6f9df4495862bbb3287681f931b687c888a
                 bf844dfc8fc28331e579928cd12bd2390ae123cf03818d14dedde5c0c24c8ab0
                 18bfca75ca096f2d531f3d1619e785f1ada437cab92e980558b3dce1474afb75
                 bfedbf8ff54cb2618e0244c9ac0d3c66fb51598cd2db11f9be39791abe447c63
                 094f7c453b7ff87cb5bb36b7c79efb0872d17058b83b15ab0866ad8a58656c5a
                 7e20dbdf308b2461d97c0ec0024a2715055249cf3b478ddd4740de654f75ca68
                 6e0d7345c69ed50cdc2a8b332b1f8824108ac937eb050585608ee734097fc090
                 54fbff89eeaeea791f4a7ab1f9868294a4f9e27b42af8100cb9d59cef9645803"
                ),
            },
            TestVector {
                data_key: Key::from(hex!(
                    "2718281828459045235360287471352662497757247093699959574966967627"
                )),
                tweak_key: Key::from(hex!(
                    "3141592653589793238462643383279502884197169399375105820974944592"
                )),
                block_number: 0xffffff,
                plaintext: hex!(
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
                 202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
                 404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f
                 606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f
                 808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f
                 a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf
                 c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf
                 e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
                 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
                 202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
                 404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f
                 606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f
                 808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f
                 a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf
                 c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf
                 e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
                ),
                ciphertext: hex!(
                    "e387aaa58ba483afa7e8eb469778317ecf4cf573aa9d4eac23f2cdf914e4e200
                 a8b490e42ee646802dc6ee2b471b278195d60918ececb44bf79966f83faba049
                 9298ebc699c0c8634715a320bb4f075d622e74c8c932004f25b41e361025b5a8
                 7815391f6108fc4afa6a05d9303c6ba68a128a55705d415985832fdeaae6c8e1
                 9110e84d1b1f199a2692119edc96132658f09da7c623efcec712537a3d94c0bf
                 5d7e352ec94ae5797fdb377dc1551150721adf15bd26a8efc2fcaad56881fa9e
                 62462c28f30ae1ceaca93c345cf243b73f542e2074a705bd2643bb9f7cc79bb6
                 e7091ea6e232df0f9ad0d6cf502327876d82207abf2115cdacf6d5a48f6c1879
                 a65b115f0f8b3cb3c59d15dd8c769bc014795a1837f3901b5845eb491adfefe0
                 97b1fa30a12fc1f65ba22905031539971a10f2f36c321bb51331cdefb39e3964
                 c7ef079994f5b69b2edd83a71ef549971ee93f44eac3938fcdd61d01fa71799d
                 a3a8091c4c48aa9ed263ff0749df95d44fef6a0bb578ec69456aa5408ae32c7a
                 f08ad7ba8921287e3bbee31b767be06a0e705c864a769137df28292283ea81a2
                 480241b44d9921cdbec1bc28dc1fda114bd8e5217ac9d8ebafa720e9da4f9ace
                 231cc949e5b96fe76ffc21063fddc83a6b8679c00d35e09576a875305bed5f36
                 ed242c8900dd1fa965bc950dfce09b132263a1eef52dd6888c309f5a7d712826"
                ),
            },
            TestVector {
                data_key: Key::from(hex!(
                    "2718281828459045235360287471352662497757247093699959574966967627"
                )),
                tweak_key: Key::from(hex!(
                    "3141592653589793238462643383279502884197169399375105820974944592"
                )),
                block_number: 0xffffffff,
                plaintext: hex!(
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
                 202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
                 404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f
                 606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f
                 808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f
                 a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf
                 c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf
                 e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
                 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
                 202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
                 404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f
                 606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f
                 808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f
                 a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf
                 c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf
                 e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
                ),
                ciphertext: hex!(
                    "bf53d2dade78e822a4d949a9bc6766b01b06a8ef70d26748c6a7fc36d80ae4c5
                 520f7c4ab0ac8544424fa405162fef5a6b7f229498063618d39f0003cb5fb8d1
                 c86b643497da1ff945c8d3bedeca4f479702a7a735f043ddb1d6aaade3c4a0ac
                 7ca7f3fa5279bef56f82cd7a2f38672e824814e10700300a055e1630b8f1cb0e
                 919f5e942010a416e2bf48cb46993d3cb6a51c19bacf864785a00bc2ecff15d3
                 50875b246ed53e68be6f55bd7e05cfc2b2ed6432198a6444b6d8c247fab941f5
                 69768b5c429366f1d3f00f0345b96123d56204c01c63b22ce78baf116e525ed9
                 0fdea39fa469494d3866c31e05f295ff21fea8d4e6e13d67e47ce722e9698a1c
                 1048d68ebcde76b86fcf976eab8aa9790268b7068e017a8b9b749409514f1053
                 027fd16c3786ea1bac5f15cb79711ee2abe82f5cf8b13ae73030ef5b9e4457e7
                 5d1304f988d62dd6fc4b94ed38ba831da4b7634971b6cd8ec325d9c61c00f1df
                 73627ed3745a5e8489f3a95c69639c32cd6e1d537a85f75cc844726e8a72fc00
                 77ad22000f1d5078f6b866318c668f1ad03d5a5fced5219f2eabbd0aa5c0f460
                 d183f04404a0d6f469558e81fab24a167905ab4c7878502ad3e38fdbe62a4155
                 6cec37325759533ce8f25f367c87bb5578d667ae93f9e2fd99bcbc5f2fbba88c
                 f6516139420fcff3b7361d86322c4bd84c82f335abb152c4a93411373aaa8220"
                ),
            },
            TestVector {
                data_key: Key::from(hex!(
                    "2718281828459045235360287471352662497757247093699959574966967627"
                )),
                tweak_key: Key::from(hex!(
                    "3141592653589793238462643383279502884197169399375105820974944592"
                )),
                block_number: 0xffffffffff,
                plaintext: hex!(
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
                 202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
                 404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f
                 606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f
                 808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f
                 a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf
                 c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf
                 e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
                 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
                 202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
                 404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f
                 606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f
                 808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f
                 a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf
                 c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf
                 e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
                ),
                ciphertext: hex!(
                    "64497e5a831e4a932c09be3e5393376daa599548b816031d224bbf50a818ed23
                 50eae7e96087c8a0db51ad290bd00c1ac1620857635bf246c176ab463be30b80
                 8da548081ac847b158e1264be25bb0910bbc92647108089415d45fab1b3d2604
                 e8a8eff1ae4020cfa39936b66827b23f371b92200be90251e6d73c5f86de5fd4
                 a950781933d79a28272b782a2ec313efdfcc0628f43d744c2dc2ff3dcb66999b
                 50c7ca895b0c64791eeaa5f29499fb1c026f84ce5b5c72ba1083cddb5ce45434
                 631665c333b60b11593fb253c5179a2c8db813782a004856a1653011e93fb6d8
                 76c18366dd8683f53412c0c180f9c848592d593f8609ca736317d356e13e2bff
                 3a9f59cd9aeb19cd482593d8c46128bb32423b37a9adfb482b99453fbe25a41b
                 f6feb4aa0bef5ed24bf73c762978025482c13115e4015aac992e5613a3b5c2f6
                 85b84795cb6e9b2656d8c88157e52c42f978d8634c43d06fea928f2822e465aa
                 6576e9bf419384506cc3ce3c54ac1a6f67dc66f3b30191e698380bc999b05abc
                 e19dc0c6dcc2dd001ec535ba18deb2df1a101023108318c75dc98611a09dc48a
                 0acdec676fabdf222f07e026f059b672b56e5cbc8e1d21bbd867dd9272120546
                 81d70ea737134cdfce93b6f82ae22423274e58a0821cc5502e2d0ab4585e94de
                 6975be5e0b4efce51cd3e70c25a1fbbbd609d273ad5b0d59631c531f6a0a57b9"
                ),
            },
        ];

        for vector in test_vectors {
            let mut aes_ctx = AESContext::new(vector.data_key, vector.tweak_key);
            let mut tweak = aes_ctx.block_tweak(vector.block_number);
            let tweak_bytes = tweak.advance();

            let mut block = *&vector.plaintext[..AES_BLOCK_SIZE].try_into().unwrap();
            aes_ctx.aes_xts_encrypt_block(&mut block, tweak_bytes);
            assert_eq!(block, &vector.ciphertext[..AES_BLOCK_SIZE]);

            //block = vector.ciphertext;
            //aes_ctx.aes_xts_decrypt(&mut block, vector.block_number);
            //assert_eq!(&block, &vector.plaintext);
        }
    }

    #[test]
    fn test_encrypt_decrypt() {
        let plaintext = get_random_bytes::<1024>();
        let mut aes_ctx = AESContext::new(Key::random(), Key::random());
        let mut block = plaintext;
        aes_ctx.aes_xts_encrypt(&mut block, 0);
        assert_ne!(&block, &plaintext);
        aes_ctx.aes_xts_decrypt(&mut block, 0);
        assert_eq!(&block, &plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_aes_block() {
        let plaintext = get_random_bytes::<AES_BLOCK_SIZE>();
        let mut block = plaintext;
        let data_key = Key::random();
        let tweak_key = Key::random();
        let mut aes_ctx = AESContext::new(data_key, tweak_key);

        let mut tweak = aes_ctx.block_tweak(0);
        let tweak_bytes = tweak.advance();

        aes_ctx.aes_xts_encrypt_block(&mut block, tweak_bytes);
        assert_ne!(&block, &plaintext);

        aes_ctx.aes_xts_decrypt_block(&mut block, tweak_bytes);
        assert_eq!(&block, &plaintext);
    }
}
