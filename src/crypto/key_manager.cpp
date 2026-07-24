// key_manager.cpp
#include "crypto/key_manager.h"
#include "crypto/sm4_cipher.h"
#include "database/dao.h"

#include <hitls/crypto/crypt_eal_rand.h>
#include <hitls/crypto/crypt_errno.h>

#include <stdexcept>
#include <cstring>
#include <fstream>
#include <iostream>   // 调试输出

namespace crypto {

void KeyManager::init(const std::vector<unsigned char>& kek) {
    if (kek.size() != 16) throw std::runtime_error("KEK must be 16 bytes");
    std::lock_guard<std::mutex> lock(mutex_);
    kek_ = kek;
    initialized_ = true;
    lastRotateTime_ = std::chrono::system_clock::now();
}

std::vector<unsigned char> KeyManager::decryptDEK(const std::string& cipherBase64) {
    return Sm4Cipher::decrypt(cipherBase64, kek_);
}

void KeyManager::addKey(int type, const std::vector<unsigned char>& key, int version, KeyStatus status) {
    addKeyVersion(type, key, version, status);
}

void KeyManager::clearKeys() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (int i = 0; i < 3; ++i) keys_[i].clear();
    currentEncVersion_ = 0;
    currentIdxVersion_ = 0;
    currentTagVersion_ = 0;
}

void KeyManager::addKeyVersion(int type, const std::vector<unsigned char>& key,
                               int version, KeyStatus status) {
    if (key.size() != 16) throw std::runtime_error("Key must be 16 bytes");
    KeyInfo info{key, version, status};
    keys_[type - 1][version] = info;
}

int KeyManager::getCurrentVersion(int type) const {
    switch (type) {
        case KEY_TYPE_ENC: return currentEncVersion_;
        case KEY_TYPE_IDX: return currentIdxVersion_;
        case KEY_TYPE_TAG: return currentTagVersion_;
        default: return 0;
    }
}

// ---- ★ 从数据库加载所有历史密钥（增强调试输出） ----
void KeyManager::loadFromDatabase(database::DAO& dao, const std::vector<unsigned char>& kek) {
    std::lock_guard<std::mutex> lock(mutex_);
    kek_ = kek;
    initialized_ = true;

    // 清空现有密钥
    for (int i = 0; i < 3; ++i) keys_[i].clear();
    currentEncVersion_ = 0;
    currentIdxVersion_ = 0;
    currentTagVersion_ = 0;

    std::cout << "[KeyManager] Loading keys from database..." << std::endl;

    // 从数据库加载三种类型的密钥
    for (int type = 1; type <= 3; ++type) {
        std::cout << "[KeyManager] Loading type " << type << std::endl;
        auto records = dao.loadAllKeysFromConfig(type);
        std::cout << "[KeyManager] Found " << records.size() << " records for type " << type << std::endl;

        for (const auto& rec : records) {
            std::cout << "[KeyManager] Processing type " << type << " version " << rec.version
                      << " status " << static_cast<int>(rec.status) << std::endl;

            try {
                // ★ 用 KEK 解密密文（rec.key 是十六进制字符串的 ASCII 字节）
                std::string cipherHex(rec.key.begin(), rec.key.end());
                std::cout << "[KeyManager] cipherHex length: " << cipherHex.size() << std::endl;
                auto decrypted = Sm4Cipher::decrypt(cipherHex, kek);
                if (decrypted.size() != 16) {
                    std::cerr << "Warning: Decrypted key length " << decrypted.size()
                              << " != 16 for type " << type << " version " << rec.version
                              << ", skipping." << std::endl;
                    continue;
                }
                KeyInfo info;
                info.key = decrypted;
                info.version = rec.version;
                info.status = rec.status;
                keys_[type - 1][rec.version] = info;
                std::cout << "[KeyManager] Successfully loaded type " << type << " version " << rec.version << std::endl;

                // 更新当前版本（取状态为启用的最大版本号）
                if (rec.status == KeyStatus::ENABLED) {
                    int curVer = getCurrentVersion(type);
                    if (rec.version > curVer) {
                        switch (type) {
                            case KEY_TYPE_ENC: currentEncVersion_ = rec.version; break;
                            case KEY_TYPE_IDX: currentIdxVersion_ = rec.version; break;
                            case KEY_TYPE_TAG: currentTagVersion_ = rec.version; break;
                        }
                    }
                }
            } catch (const std::exception& e) {
                std::cerr << "Warning: Failed to decrypt key type " << type
                          << " version " << rec.version << ": " << e.what()
                          << ", skipping." << std::endl;
            }
        }
    }

    std::cout << "[KeyManager] Load complete. Encryption versions: ";
    for (const auto& p : keys_[0]) std::cout << p.first << " ";
    std::cout << std::endl;
    std::cout << "[KeyManager] Index versions: ";
    for (const auto& p : keys_[1]) std::cout << p.first << " ";
    std::cout << std::endl;
    std::cout << "[KeyManager] Tag versions: ";
    for (const auto& p : keys_[2]) std::cout << p.first << " ";
    std::cout << std::endl;

    // 检查是否成功加载至少一个有效版本（三种类型都必须有）
    if (keys_[0].empty() || keys_[1].empty() || keys_[2].empty()) {
        throw std::runtime_error("Failed to load any valid key for all types from database");
    }
}

// ---- ★ 保存密钥到数据库 ----
void KeyManager::saveToDatabase(database::DAO& dao, int type,
                                const std::vector<unsigned char>& key,
                                int version, KeyStatus status) {
    // ★ 用 KEK 加密密钥
    auto cipher = Sm4Cipher::encrypt(key, kek_);
    std::vector<unsigned char> cipherBytes(cipher.begin(), cipher.end());
    dao.saveKeyToConfig(type, cipherBytes, version, status);
    std::cout << "[KeyManager] Saved key type " << type << " version " << version << " to database" << std::endl;
}

void KeyManager::loadKeys(const std::string& encryptedEncKey,
                          const std::string& encryptedIdxKey,
                          const std::string& encryptedTagKey,
                          int encVersion, int idxVersion, int tagVersion) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_) throw std::runtime_error("KeyManager not initialized");

    auto encKey = decryptDEK(encryptedEncKey);
    auto idxKey = decryptDEK(encryptedIdxKey);
    auto tagKey = decryptDEK(encryptedTagKey);

    addKeyVersion(KEY_TYPE_ENC, encKey, encVersion, KeyStatus::ENABLED);
    addKeyVersion(KEY_TYPE_IDX, idxKey, idxVersion, KeyStatus::ENABLED);
    addKeyVersion(KEY_TYPE_TAG, tagKey, tagVersion, KeyStatus::ENABLED);

    currentEncVersion_ = encVersion;
    currentIdxVersion_ = idxVersion;
    currentTagVersion_ = tagVersion;
}

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
    if (it == keyMap.end()) throw std::runtime_error("Key version not found");
    return it->second;
}

const KeyInfo& KeyManager::getEncryptionKeyInfo() const { return getCurrentKeyInfo(KEY_TYPE_ENC); }
const KeyInfo& KeyManager::getIndexKeyInfo() const { return getCurrentKeyInfo(KEY_TYPE_IDX); }
const KeyInfo& KeyManager::getTagKeyInfo() const { return getCurrentKeyInfo(KEY_TYPE_TAG); }

const std::vector<unsigned char>& KeyManager::getEncryptionKey() const {
    return getEncryptionKeyInfo().key;
}
const std::vector<unsigned char>& KeyManager::getIndexKey() const {
    return getIndexKeyInfo().key;
}
const std::vector<unsigned char>& KeyManager::getTagKey() const {
    return getTagKeyInfo().key;
}

bool KeyManager::getEncryptionKeyByVersion(int version, std::vector<unsigned char>& key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto& keyMap = keys_[KEY_TYPE_ENC - 1];
    auto it = keyMap.find(version);
    if (it == keyMap.end()) return false;
    key = it->second.key;
    return true;
}

bool KeyManager::getIndexKeyByVersion(int version, std::vector<unsigned char>& key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto& keyMap = keys_[KEY_TYPE_IDX - 1];
    auto it = keyMap.find(version);
    if (it == keyMap.end()) return false;
    key = it->second.key;
    return true;
}

bool KeyManager::getTagKeyByVersion(int version, std::vector<unsigned char>& key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto& keyMap = keys_[KEY_TYPE_TAG - 1];
    auto it = keyMap.find(version);
    if (it == keyMap.end()) return false;
    key = it->second.key;
    return true;
}

// ---- 获取所有版本号 ----
std::vector<int> KeyManager::getAllEncryptionVersions() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<int> versions;
    for (const auto& pair : keys_[KEY_TYPE_ENC - 1]) versions.push_back(pair.first);
    return versions;
}
std::vector<int> KeyManager::getAllIndexVersions() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<int> versions;
    for (const auto& pair : keys_[KEY_TYPE_IDX - 1]) versions.push_back(pair.first);
    return versions;
}
std::vector<int> KeyManager::getAllTagVersions() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<int> versions;
    for (const auto& pair : keys_[KEY_TYPE_TAG - 1]) versions.push_back(pair.first);
    return versions;
}

// ---- 获取所有版本密钥 ----
std::vector<std::pair<int, std::vector<unsigned char>>> KeyManager::getAllEncryptionKeys() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::pair<int, std::vector<unsigned char>>> result;
    for (const auto& pair : keys_[KEY_TYPE_ENC - 1]) {
        result.push_back({pair.first, pair.second.key});
    }
    return result;
}

std::vector<std::pair<int, std::vector<unsigned char>>> KeyManager::getAllIndexKeys() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::pair<int, std::vector<unsigned char>>> result;
    for (const auto& pair : keys_[KEY_TYPE_IDX - 1]) {
        result.push_back({pair.first, pair.second.key});
    }
    return result;
}

std::vector<std::pair<int, std::vector<unsigned char>>> KeyManager::getAllTagKeys() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::pair<int, std::vector<unsigned char>>> result;
    for (const auto& pair : keys_[KEY_TYPE_TAG - 1]) {
        result.push_back({pair.first, pair.second.key});
    }
    return result;
}

// ---- 密钥轮换 ----
int KeyManager::rotateKey(int type) {
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
    if (it == keyMap.end()) throw std::runtime_error("Current key version not found");

    // 旧版本降为停用
    it->second.status = KeyStatus::DISABLED;

    std::vector<unsigned char> newKey(16);
    int32_t ret = CRYPT_EAL_Randbytes(newKey.data(), 16);
    if (ret != CRYPT_SUCCESS) throw std::runtime_error("Failed to generate new key");

    int newVersion = currentVersion + 1;
    addKeyVersion(type, newKey, newVersion, KeyStatus::ENABLED);

    switch (type) {
        case KEY_TYPE_ENC: currentEncVersion_ = newVersion; break;
        case KEY_TYPE_IDX: currentIdxVersion_ = newVersion; break;
        case KEY_TYPE_TAG: currentTagVersion_ = newVersion; break;
    }

    lastRotateTime_ = std::chrono::system_clock::now();
    return newVersion;
}

int KeyManager::rotateEncryptionKey() { return rotateKey(KEY_TYPE_ENC); }
int KeyManager::rotateIndexKey() { return rotateKey(KEY_TYPE_IDX); }
int KeyManager::rotateTagKey() { return rotateKey(KEY_TYPE_TAG); }

void KeyManager::setKeyStatus(int type, int version, KeyStatus status) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto& keyMap = keys_[type - 1];
    auto it = keyMap.find(version);
    if (it == keyMap.end()) throw std::runtime_error("Key version not found");
    it->second.status = status;
}

KeyStatus KeyManager::getKeyStatus(int type, int version) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto& keyMap = keys_[type - 1];
    auto it = keyMap.find(version);
    if (it == keyMap.end()) throw std::runtime_error("Key version not found");
    return it->second.status;
}

int KeyManager::getEncryptionVersion() const { return currentEncVersion_; }
int KeyManager::getIndexVersion() const { return currentIdxVersion_; }
int KeyManager::getTagVersion() const { return currentTagVersion_; }

bool KeyManager::isEncryptionKeyActive() const {
    return getEncryptionKeyInfo().status == KeyStatus::ENABLED;
}
bool KeyManager::isIndexKeyActive() const {
    return getIndexKeyInfo().status == KeyStatus::ENABLED;
}
bool KeyManager::isTagKeyActive() const {
    return getTagKeyInfo().status == KeyStatus::ENABLED;
}

// ---- 轮换时间管理 ----
std::chrono::system_clock::time_point KeyManager::getLastRotateTime() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return lastRotateTime_;
}
void KeyManager::setLastRotateTime(std::chrono::system_clock::time_point time) {
    std::lock_guard<std::mutex> lock(mutex_);
    lastRotateTime_ = time;
}
void KeyManager::saveRotateTimeToFile(const std::string& filename) {
    auto time_t = std::chrono::system_clock::to_time_t(getLastRotateTime());
    std::ofstream file(filename);
    if (file.is_open()) { file << time_t; file.close(); }
}
void KeyManager::loadRotateTimeFromFile(const std::string& filename) {
    std::ifstream file(filename);
    if (file.is_open()) {
        std::string line;
        if (std::getline(file, line)) {
            try { lastRotateTime_ = std::chrono::system_clock::from_time_t(std::stoll(line)); }
            catch (...) { lastRotateTime_ = std::chrono::system_clock::now(); }
        }
        file.close();
    } else {
        lastRotateTime_ = std::chrono::system_clock::now();
    }
}

} // namespace crypto