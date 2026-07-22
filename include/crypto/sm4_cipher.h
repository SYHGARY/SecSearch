// sm4_cipher.h
// 基于 OpenHiTLS 的 SM4-CBC 加解密
// 密钥 16 字节，密文格式：十六进制(IV + 密文)

#pragma once

#include <vector>
#include <string>
#include <cstdint>

namespace crypto {

class Sm4Cipher {
public:
    static constexpr size_t KEY_LEN = 16;
    static constexpr size_t IV_LEN  = 16;

    // ---- 加密 ----
    // 参数：明文、16字节密钥
    // 返回：十六进制字符串（IV + 密文）
    static std::string encrypt(const std::vector<unsigned char>& plaintext,
                               const std::vector<unsigned char>& key);

    // ---- 解密 ----
    // 参数：密文十六进制、16字节密钥
    // 返回：明文二进制
    static std::vector<unsigned char> decrypt(const std::string& ciphertextHex,
                                              const std::vector<unsigned char>& key);
};

} // namespace crypto