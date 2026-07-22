// crypto_service.h
// 统一的加密服务入口

#pragma once

#include <string>
#include <vector>
#include "crypto/key_manager.h"

namespace crypto {

class CryptoService {
public:
    explicit CryptoService(KeyManager& keyMgr);

    struct EncryptResult {
        std::string cipher;      // 密文（十六进制，含IV）
        std::string tag;         // 完整性 Tag（64字符）
        int keyVersion;          // 使用的密钥版本号
    };

    // ---- 加密（自动生成 Tag） ----
    EncryptResult encryptData(const std::vector<unsigned char>& plaintext);

    // ---- 解密（自动校验 Tag） ----
    std::vector<unsigned char> decryptData(const std::string& cipher,
                                           const std::string& tag,
                                           int keyVersion);

    // ---- 生成盲索引 ----
    std::string generateBlindIndex(const std::vector<unsigned char>& data);

    // ---- 验证 Tag ----
    bool verifyTag(const std::string& cipher, const std::string& tag,
                   int keyVersion);

    // ---- 便捷解密（无版本验证） ----
    std::vector<unsigned char> decryptData(const std::string& cipher,
                                           const std::vector<unsigned char>& key);

    KeyManager& getKeyManager() { return keyMgr_; }

private:
    KeyManager& keyMgr_;
};

} // namespace crypto