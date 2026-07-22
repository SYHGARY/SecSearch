// key_manager.cpp
// 实现四密钥管理：加载、轮换、状态管理
// 基于 OpenHiTLS

#include "crypto/key_manager.h"
#include "crypto/sm4_cipher.h"

// ★ OpenHiTLS 随机数头文件
#include <hitls/crypto/crypt_eal_rand.h>
#include <hitls/crypto/crypt_errno.h>

#include <stdexcept>
#include <cstring>

namespace crypto {

// ---- 初始化 ----
void KeyManager::init(const std::vector<unsigned char>& kek) {
    if (kek.size() != 16) {
        throw std::runtime_error("KEK must be 16 bytes");
    }
    std::lock_guard<std::mutex> lock(mutex_);
    kek_ = kek;
    initialized_ = true;
}

// ---- 内部：解密 DEK ----
std::vector<unsigned char> KeyManager::decryptDEK(const std::string& cipherBase64) {
    return Sm4Cipher::decrypt(cipherBase64, kek_);
}

// ---- 内部：添加密钥版本 ----
void KeyManager::addKeyVersion(int type, const std::vector<unsigned char>& key,
                               int version, KeyStatus status) {
    if (key.size() != 16) {
        throw std::runtime_error("Key must be 16 bytes");
    }
    KeyInfo info;
    info.key = key;
    info.version = version;
    info.status = status;
    keys_[type - 1][version] = info;
}

// ---- 加载三个密钥 ----
void KeyManager::loadKeys(const std::string& encryptedEncKey,
                          const std::string& encryptedIdxKey,
                          const std::string& encryptedTagKey,
                          int encVersion, int idxVersion, int tagVersion) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_) {
        throw std::runtime_error("KeyManager not initialized");
    }

    // 解密三个密钥
    auto encKey = decryptDEK(encryptedEncKey);
    auto idxKey = decryptDEK(encryptedIdxKey);
    auto tagKey = decryptDEK(encryptedTagKey);

    // 存入（状态为启用）
    addKeyVersion(KEY_TYPE_ENC, encKey, encVersion, KeyStatus::ENABLED);
    addKeyVersion(KEY_TYPE_IDX, idxKey, idxVersion, KeyStatus::ENABLED);
    addKeyVersion(KEY_TYPE_TAG, tagKey, tagVersion, KeyStatus::ENABLED);

    currentEncVersion_ = encVersion;
    currentIdxVersion_ = idxVersion;
    currentTagVersion_ = tagVersion;
}

// ---- 获取当前密钥信息（返回 const 引用） ----
const KeyInfo& KeyManager::getCurrentKeyInfo(int type) const {
    std::lock_guard<std::mutex> lock(mutex_);
    int version;
    switch (type) {
        case KEY_TYPE_ENC: version = currentEncVersion_; break;
        case KEY_TYPE_IDX: version = currentIdxVersion_; break;
        case KEY_TYPE_TAG: version = currentTagVersion_; break;
        default: throw std::runtime_error("Invalid key type");
    }
    const auto& keyMap = keys_[type - 1];
    auto it = keyMap.find(version);
    if (it == keyMap.end()) {
        throw std::runtime_error("Key version not found");
    }
    // ★ 返回 map 中元素的引用，不是临时对象
    return it->second;
}

// ---- 获取三个密钥信息（返回 const 引用） ----
const KeyInfo& KeyManager::getEncryptionKeyInfo() const {
    return getCurrentKeyInfo(KEY_TYPE_ENC);
}
const KeyInfo& KeyManager::getIndexKeyInfo() const {
    return getCurrentKeyInfo(KEY_TYPE_IDX);
}
const KeyInfo& KeyManager::getTagKeyInfo() const {
    return getCurrentKeyInfo(KEY_TYPE_TAG);
}

// ---- 获取当前启用版本的密钥（返回 const 引用） ----
// ★ 这些函数现在返回的是 KeyInfo::key 的引用，由于 KeyInfo 对象存储在 keys_ 中，
//    生命周期与 KeyManager 一致，因此安全。
const std::vector<unsigned char>& KeyManager::getEncryptionKey() const {
    return getEncryptionKeyInfo().key;
}
const std::vector<unsigned char>& KeyManager::getIndexKey() const {
    return getIndexKeyInfo().key;
}
const std::vector<unsigned char>& KeyManager::getTagKey() const {
    return getTagKeyInfo().key;
}

// ---- 按版本获取密钥 ----
bool KeyManager::getEncryptionKeyByVersion(int version,
                                           std::vector<unsigned char>& key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto& keyMap = keys_[KEY_TYPE_ENC - 1];
    auto it = keyMap.find(version);
    if (it == keyMap.end()) return false;
    key = it->second.key;
    return true;
}

bool KeyManager::getIndexKeyByVersion(int version,
                                      std::vector<unsigned char>& key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto& keyMap = keys_[KEY_TYPE_IDX - 1];
    auto it = keyMap.find(version);
    if (it == keyMap.end()) return false;
    key = it->second.key;
    return true;
}

bool KeyManager::getTagKeyByVersion(int version,
                                    std::vector<unsigned char>& key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto& keyMap = keys_[KEY_TYPE_TAG - 1];
    auto it = keyMap.find(version);
    if (it == keyMap.end()) return false;
    key = it->second.key;
    return true;
}

// ---- 内部：密钥轮换 ----
void KeyManager::rotateKey(int type) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto& keyMap = keys_[type - 1];

    int currentVersion;
    switch (type) {
        case KEY_TYPE_ENC: currentVersion = currentEncVersion_; break;
        case KEY_TYPE_IDX: currentVersion = currentIdxVersion_; break;
        case KEY_TYPE_TAG: currentVersion = currentTagVersion_; break;
        default: throw std::runtime_error("Invalid key type");
    }

    auto it = keyMap.find(currentVersion);
    if (it == keyMap.end()) {
        throw std::runtime_error("Current key version not found");
    }

    // 旧密钥降为停用状态
    it->second.status = KeyStatus::DISABLED;

    // 生成新密钥（16字节随机数）
    std::vector<unsigned char> newKey(16);
    int32_t ret = CRYPT_EAL_Randbytes(newKey.data(), 16);
    if (ret != CRYPT_SUCCESS) {
        throw std::runtime_error("Failed to generate new key");
    }

    int newVersion = currentVersion + 1;
    addKeyVersion(type, newKey, newVersion, KeyStatus::ENABLED);

    // 更新当前版本
    switch (type) {
        case KEY_TYPE_ENC: currentEncVersion_ = newVersion; break;
        case KEY_TYPE_IDX: currentIdxVersion_ = newVersion; break;
        case KEY_TYPE_TAG: currentTagVersion_ = newVersion; break;
    }
}

// ---- 三个密钥轮换 ----
void KeyManager::rotateEncryptionKey() { rotateKey(KEY_TYPE_ENC); }
void KeyManager::rotateIndexKey() { rotateKey(KEY_TYPE_IDX); }
void KeyManager::rotateTagKey() { rotateKey(KEY_TYPE_TAG); }

// ---- 密钥状态管理 ----
void KeyManager::setKeyStatus(int type, int version, KeyStatus status) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto& keyMap = keys_[type - 1];
    auto it = keyMap.find(version);
    if (it == keyMap.end()) {
        throw std::runtime_error("Key version not found");
    }
    it->second.status = status;
}

KeyStatus KeyManager::getKeyStatus(int type, int version) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto& keyMap = keys_[type - 1];
    auto it = keyMap.find(version);
    if (it == keyMap.end()) {
        throw std::runtime_error("Key version not found");
    }
    return it->second.status;
}

// ---- 获取当前版本号 ----
int KeyManager::getEncryptionVersion() const { return currentEncVersion_; }
int KeyManager::getIndexVersion() const { return currentIdxVersion_; }
int KeyManager::getTagVersion() const { return currentTagVersion_; }

// ---- 检查密钥是否可用 ----
bool KeyManager::isEncryptionKeyActive() const {
    return getEncryptionKeyInfo().status == KeyStatus::ENABLED;
}
bool KeyManager::isIndexKeyActive() const {
    return getIndexKeyInfo().status == KeyStatus::ENABLED;
}
bool KeyManager::isTagKeyActive() const {
    return getTagKeyInfo().status == KeyStatus::ENABLED;
}

} // namespace crypto