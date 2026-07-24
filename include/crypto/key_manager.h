// key_manager.h
// 四密钥管理器：支持多版本存储、轮换、状态管理
// 支持获取所有历史版本密钥用于多版本查询

#pragma once

#include <vector>
#include <string>
#include <map>
#include <mutex>
#include <chrono>

namespace database {
    class DAO;  // 前向声明
}

namespace crypto {

enum class KeyStatus : uint8_t {
    ENABLED = 1,
    DISABLED = 2,
    DESTROYED = 3
};

struct KeyInfo {
    std::vector<unsigned char> key;
    int version;
    KeyStatus status;
};

class KeyManager {
public:
    // ---- 初始化 ----
    void init(const std::vector<unsigned char>& kek);

    // ---- ★ 从数据库加载所有历史密钥 ----
    void loadFromDatabase(database::DAO& dao, const std::vector<unsigned char>& kek);

    // ---- ★ 保存密钥到数据库 ----
    void saveToDatabase(database::DAO& dao, int type,
                        const std::vector<unsigned char>& key,
                        int version, KeyStatus status);

    // ---- 解密工作密钥密文（供从数据库加载） ----
    std::vector<unsigned char> decryptDEK(const std::string& cipherBase64);

    // ---- 添加密钥（从数据库加载时使用） ----
    void addKey(int type, const std::vector<unsigned char>& key, int version, KeyStatus status);
    void clearKeys();

    // ---- 静态加载（测试用） ----
    void loadKeys(const std::string& encryptedEncKey,
                  const std::string& encryptedIdxKey,
                  const std::string& encryptedTagKey,
                  int encVersion = 1,
                  int idxVersion = 1,
                  int tagVersion = 1);

    // ---- 获取当前启用版本 ----
    const std::vector<unsigned char>& getEncryptionKey() const;
    const std::vector<unsigned char>& getIndexKey() const;
    const std::vector<unsigned char>& getTagKey() const;

    // ---- 获取密钥信息 ----
    const KeyInfo& getEncryptionKeyInfo() const;
    const KeyInfo& getIndexKeyInfo() const;
    const KeyInfo& getTagKeyInfo() const;

    // ---- 按版本获取密钥 ----
    bool getEncryptionKeyByVersion(int version, std::vector<unsigned char>& key) const;
    bool getIndexKeyByVersion(int version, std::vector<unsigned char>& key) const;
    bool getTagKeyByVersion(int version, std::vector<unsigned char>& key) const;

    // ---- 获取所有历史版本号 ----
    std::vector<int> getAllEncryptionVersions() const;
    std::vector<int> getAllIndexVersions() const;
    std::vector<int> getAllTagVersions() const;

    // ---- 获取所有版本密钥 ----
    std::vector<std::pair<int, std::vector<unsigned char>>> getAllEncryptionKeys() const;
    std::vector<std::pair<int, std::vector<unsigned char>>> getAllIndexKeys() const;
    std::vector<std::pair<int, std::vector<unsigned char>>> getAllTagKeys() const;

    // ---- 密钥轮换 ----
    int rotateEncryptionKey();
    int rotateIndexKey();
    int rotateTagKey();

    // ---- 密钥状态管理 ----
    void setKeyStatus(int type, int version, KeyStatus status);
    KeyStatus getKeyStatus(int type, int version) const;

    // ---- 获取当前版本号 ----
    int getEncryptionVersion() const;
    int getIndexVersion() const;
    int getTagVersion() const;

    // ---- 检查密钥是否可用 ----
    bool isEncryptionKeyActive() const;
    bool isIndexKeyActive() const;
    bool isTagKeyActive() const;

    // ---- 获取 KEK ----
    const std::vector<unsigned char>& getKEK() const { return kek_; }

    // ---- 轮换时间管理 ----
    std::chrono::system_clock::time_point getLastRotateTime() const;
    void setLastRotateTime(std::chrono::system_clock::time_point time);
    void saveRotateTimeToFile(const std::string& filename);
    void loadRotateTimeFromFile(const std::string& filename);

private:
    enum KeyType { KEY_TYPE_ENC = 1, KEY_TYPE_IDX = 2, KEY_TYPE_TAG = 3 };

    std::vector<unsigned char> kek_;
    mutable std::mutex mutex_;

    // 每种类型按版本号存储所有历史密钥
    std::map<int, KeyInfo> keys_[3];

    int currentEncVersion_ = 0;
    int currentIdxVersion_ = 0;
    int currentTagVersion_ = 0;

    bool initialized_ = false;
    std::chrono::system_clock::time_point lastRotateTime_;

    void addKeyVersion(int type, const std::vector<unsigned char>& key,
                       int version, KeyStatus status);
    const KeyInfo& getCurrentKeyInfo(int type) const;
    int rotateKey(int type);
    int getCurrentVersion(int type) const;
};

} // namespace crypto