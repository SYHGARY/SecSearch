// sm4_cipher.h
// 功能：提供基于 SM4-CBC 模式的带 PKCS#7 填充的加密与解密
//       密文格式：Base64(随机IV(16字节) + SM4-CBC密文)
// 密钥长度固定为 16 字节

#pragma once

#include <vector>
#include <string>

namespace crypto {

class Sm4Cipher {
public:
    // 加密：输入明文二进制和 16 字节密钥，输出 Base64 编码的密文（含IV）
    static std::string encrypt(const std::vector<unsigned char>& plaintext,
                               const std::vector<unsigned char>& key);

    // 解密：输入 Base64 密文和 16 字节密钥，输出明文二进制
    static std::vector<unsigned char> decrypt(const std::string& ciphertextBase64,
                                              const std::vector<unsigned char>& key);

private:
    static constexpr size_t KEY_LEN = 16;  // SM4 密钥长度
    static constexpr size_t IV_LEN  = 16;  // SM4 分组长度，即 IV 长度
};

} // namespace crypto