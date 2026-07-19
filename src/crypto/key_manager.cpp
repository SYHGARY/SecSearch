// key_manager.cpp
// 实现密钥管理，包括用 KEK 解密 DEK，并分离出加密密钥和索引密钥

#include "crypto/key_manager.h"
#include "crypto/sm4_cipher.h"   // 用 Sm4Cipher 解密 DEK
#include <stdexcept>

namespace crypto {

// 初始化：保存 KEK
void KeyManager::init(const std::vector<unsigned char>& kek) {
    if (kek.size() != 16) {
        throw std::runtime_error("KEK must be 16 bytes for SM4");
    }
    std::lock_guard<std::mutex> lock(mutex_);
    kek_ = kek;
}

// 从数据库加载 DEK 密文并解密
void KeyManager::loadKeysFromDB(const std::string& encryptedDekBase64) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (kek_.empty()) {
        throw std::runtime_error("KeyManager not initialized with KEK");
    }

    // 1. 用 KEK 解密 DEK 密文，得到 32 字节的原始 DEK
    auto dekBin = decryptDEK(encryptedDekBase64);

    // 2. 检查长度：本示例假定 DEK 为 32 字节，前 16 字节为加密密钥，后 16 字节为索引密钥
    //    实际中您可以根据数据库设计分别加载两个不同的 key_cipher，然后分别解密。
    if (dekBin.size() != 32) {
        throw std::runtime_error("Invalid DEK length, expected 32 bytes");
    }

    // 3. 分离两个密钥
    dek_encryption_.assign(dekBin.begin(), dekBin.begin() + 16);
    dek_index_.assign(dekBin.begin() + 16, dekBin.end());
}

// 获取加密密钥（线程安全）
const std::vector<unsigned char>& KeyManager::getEncryptionKey() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (dek_encryption_.empty()) {
        throw std::runtime_error("Encryption key not loaded");
    }
    return dek_encryption_;
}

// 获取索引密钥（线程安全）
const std::vector<unsigned char>& KeyManager::getIndexKey() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (dek_index_.empty()) {
        throw std::runtime_error("Index key not loaded");
    }
    return dek_index_;
}

// 内部解密函数：直接调用 Sm4Cipher::decrypt，使用 KEK 作为密钥
std::vector<unsigned char> KeyManager::decryptDEK(const std::string& cipherBase64) {
    return Sm4Cipher::decrypt(cipherBase64, kek_);
}

} // namespace crypto