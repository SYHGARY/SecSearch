// key_manager.h
// 功能：管理数据加密密钥（DEK）和索引生成密钥，它们以密文形式存储在数据库，
//        由主密钥（KEK）解密后缓存到内存中。
// 设计：密钥分离存储，加密密钥用于 SM4，索引密钥用于 HMAC-SM3。
//       本示例中假设数据库存储的 DEK 密文包含两个 16 字节密钥（共 32 字节）。

#pragma once

#include <vector>
#include <string>
#include <mutex>

namespace crypto {

class KeyManager {
public:
    // 初始化：设置主密钥 KEK（16 字节），KEK 应从安全环境获取（如环境变量或HSM）
    void init(const std::vector<unsigned char>& kek);

    // 从数据库加载加密的 DEK（Base64 格式），用 KEK 解密并缓存到内存
    // 参数：encryptedDekBase64 是从 key_config 表读取的 key_cipher 字段
    void loadKeysFromDB(const std::string& encryptedDekBase64);

    // 获取数据加密密钥（用于 SM4 加密/解密）
    const std::vector<unsigned char>& getEncryptionKey() const;

    // 获取索引生成密钥（用于 HMAC-SM3）
    const std::vector<unsigned char>& getIndexKey() const;

private:
    // 缓存的两个工作密钥（解密后）
    std::vector<unsigned char> dek_encryption_;
    std::vector<unsigned char> dek_index_;

    // 主密钥（仅用于解密工作密钥，不持久化）
    std::vector<unsigned char> kek_;

    // 互斥锁，保护多线程安全访问
    mutable std::mutex mutex_;

    // 内部方法：使用 KEK 解密 DEK 密文
    std::vector<unsigned char> decryptDEK(const std::string& cipherBase64);
};

} // namespace crypto