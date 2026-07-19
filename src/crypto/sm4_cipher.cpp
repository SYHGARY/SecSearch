// sm4_cipher.cpp
// 使用十六进制表示密文（IV+密文），避免 Base64 兼容性问题
// 密文格式：IV(32个十六进制字符) + SM4-CBC密文(十六进制)
// 生产环境可换回 Base64，但测试阶段 Hex 最稳

#include "crypto/sm4_cipher.h"
#include "crypto/utils.h"
#include <gmssl/sm4.h>
#include <gmssl/rand.h>
#include <stdexcept>
#include <cstring>

namespace crypto {

std::string Sm4Cipher::encrypt(const std::vector<unsigned char>& plaintext,
                               const std::vector<unsigned char>& key) {
    if (key.size() != KEY_LEN) {
        throw std::runtime_error("SM4 key must be 16 bytes");
    }

    // 1. 生成随机 IV
    uint8_t iv[IV_LEN];
    if (rand_bytes(iv, IV_LEN) != 1) {
        throw std::runtime_error("rand_bytes failed");
    }

    // 2. 设置加密密钥
    SM4_KEY sm4_key;
    sm4_set_encrypt_key(&sm4_key, key.data());

    // 3. 加密
    std::vector<unsigned char> cipher(plaintext.size() + 16);
    size_t outlen = cipher.size();
    int ret = sm4_cbc_padding_encrypt(&sm4_key, iv,
                                      plaintext.data(), plaintext.size(),
                                      cipher.data(), &outlen);
    if (ret != 1) {
        throw std::runtime_error("SM4 encryption failed");
    }
    cipher.resize(outlen);

    // 4. 拼接 IV + 密文
    std::vector<unsigned char> combined;
    combined.reserve(IV_LEN + cipher.size());
    combined.insert(combined.end(), iv, iv + IV_LEN);
    combined.insert(combined.end(), cipher.begin(), cipher.end());

    // 5. 十六进制输出
    return binToHex(combined.data(), combined.size());
}

std::vector<unsigned char> Sm4Cipher::decrypt(const std::string& ciphertextHex,
                                              const std::vector<unsigned char>& key) {
    if (key.size() != KEY_LEN) {
        throw std::runtime_error("SM4 key must be 16 bytes");
    }

    // 1. 十六进制解码
    auto combined = hexToBin(ciphertextHex);
    if (combined.size() < IV_LEN) {
        throw std::runtime_error("Ciphertext too short");
    }

    // 2. 提取 IV 和密文
    const uint8_t* iv = combined.data();
    const uint8_t* cipher = combined.data() + IV_LEN;
    size_t cipher_len = combined.size() - IV_LEN;

    // 3. 检查密文长度（必须是 16 的倍数）
    if (cipher_len % 16 != 0) {
        throw std::runtime_error("Invalid ciphertext length (not multiple of 16)");
    }

    // 4. 设置解密密钥
    SM4_KEY sm4_key;
    sm4_set_decrypt_key(&sm4_key, key.data());

    // 5. 解密
    std::vector<unsigned char> plaintext(cipher_len);
    size_t outlen = plaintext.size();
    int ret = sm4_cbc_padding_decrypt(&sm4_key, iv,
                                      cipher, cipher_len,
                                      plaintext.data(), &outlen);
    if (ret != 1) {
        throw std::runtime_error("SM4 decryption failed");
    }
    plaintext.resize(outlen);

    return plaintext;
}

} // namespace crypto
