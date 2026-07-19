// sm4_cipher.cpp
// 实现 SM4-CBC 加解密，使用 GmSSL 提供的 sm4_cbc_padding_encrypt/decrypt
// 使用 rand_bytes 生成安全的随机 IV
// 关键注意：GmSSL 的 outlen 参数既是输入（缓冲区容量）也是输出（实际长度），
//           调用前必须将其设置为输出缓冲区的大小。

#include "crypto/sm4_cipher.h"
#include "crypto/utils.h"
#include <gmssl/sm4.h>    // SM4 算法接口
#include <gmssl/rand.h>   // 安全随机数生成
#include <stdexcept>

namespace crypto {

// 加密函数
std::string Sm4Cipher::encrypt(const std::vector<unsigned char>& plaintext,
                               const std::vector<unsigned char>& key) {
    // 校验密钥长度
    if (key.size() != KEY_LEN) {
        throw std::runtime_error("SM4 key must be 16 bytes");
    }

    // 1. 生成 16 字节随机 IV（使用 GmSSL 的 rand_bytes，符合国密随机性要求）
    uint8_t iv[IV_LEN];
    if (rand_bytes(iv, IV_LEN) != 1) {
        throw std::runtime_error("rand_bytes failed");
    }

    // 2. 设置加密密钥（GmSSL 内部会生成扩展密钥）
    SM4_KEY sm4_key;
    sm4_set_encrypt_key(&sm4_key, key.data());

    // 3. 执行带 PKCS#7 填充的 CBC 加密
    //    输出缓冲区大小至少为 plaintext.size() + 16（最多一个分组填充）
    std::vector<unsigned char> cipher(plaintext.size() + 16);
    size_t outlen = cipher.size();   // ★★★ 必须设置为缓冲区容量 ★★★
    int ret = sm4_cbc_padding_encrypt(&sm4_key, iv,
                                      plaintext.data(), plaintext.size(),
                                      cipher.data(), &outlen);
    if (ret != 1) {
        throw std::runtime_error("SM4 encryption failed");
    }
    cipher.resize(outlen);  // 调整到实际密文长度

    // 4. 拼接 IV + 密文，便于解密时提取 IV
    std::vector<unsigned char> combined;
    combined.reserve(IV_LEN + cipher.size());
    combined.insert(combined.end(), iv, iv + IV_LEN);
    combined.insert(combined.end(), cipher.begin(), cipher.end());

    // 5. Base64 编码后返回
    return base64Encode(combined);
}

// 解密函数
std::vector<unsigned char> Sm4Cipher::decrypt(const std::string& ciphertextBase64,
                                              const std::vector<unsigned char>& key) {
    if (key.size() != KEY_LEN) {
        throw std::runtime_error("SM4 key must be 16 bytes");
    }

    // 1. Base64 解码，还原为 IV + 密文的组合
    auto combined = base64Decode(ciphertextBase64);
    if (combined.size() < IV_LEN) {
        throw std::runtime_error("Ciphertext too short");
    }

    // 2. 提取 IV（前 16 字节）和真正的密文
    const uint8_t* iv = combined.data();
    const uint8_t* cipher = combined.data() + IV_LEN;
    size_t cipher_len = combined.size() - IV_LEN;

    // 3. 设置解密密钥
    SM4_KEY sm4_key;
    sm4_set_decrypt_key(&sm4_key, key.data());

    // 4. 执行带 PKCS#7 填充的 CBC 解密
    //    输出缓冲区大小至少为密文长度（解密后明文长度不会超过密文长度）
    std::vector<unsigned char> plaintext(cipher_len);
    size_t outlen = plaintext.size();   // ★★★ 必须设置为缓冲区容量 ★★★
    int ret = sm4_cbc_padding_decrypt(&sm4_key, iv,
                                      cipher, cipher_len,
                                      plaintext.data(), &outlen);
    if (ret != 1) {
        // 常见失败原因：密钥错误、IV错误、密文被篡改、填充不正确
        throw std::runtime_error("SM4 decryption failed");
    }
    plaintext.resize(outlen);  // 去除填充后的实际明文长度

    return plaintext;
}

} // namespace crypto