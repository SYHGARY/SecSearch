// key_manager.h
// 管理三个独立的密钥：加密、索引、Tag
// 每个密钥以密文形式存储在数据库，通过 KEK 解密后缓存

#pragma once

#include <vector>
#include <string>
#include <mutex>

namespace crypto {

class KeyManager {
public:
    // 设置主密钥 KEK（16 字节）
    void init(const std::vector<unsigned char>& kek);

    // 分别加载三个密钥的密文（Base64 格式），用 KEK 解密并缓存
    void loadKeys(const std::string& encryptedEncKey,
                  const std::string& encryptedIdxKey,
                  const std::string& encryptedTagKey);

    // 获取三个密钥
    const std::vector<unsigned char>& getEncryptionKey() const;
    const std::vector<unsigned char>& getIndexKey() const;
    const std::vector<unsigned char>& getTagKey() const;   // ★ 新增

private:
    std::vector<unsigned char> dek_encryption_;
    std::vector<unsigned char> dek_index_;
    std::vector<unsigned char> dek_tag_;        // ★ Tag 密钥

    std::vector<unsigned char> kek_;
    mutable std::mutex mutex_;

    std::vector<unsigned char> decryptDEK(const std::string& cipherBase64);
};

} // namespace crypto
