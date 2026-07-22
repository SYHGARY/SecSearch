// key_manager.h
// 四密钥管理器：加密密钥、索引密钥、完整性密钥 + 密钥版本管理
// 基于 OpenHiTLS 实现

#pragma once

#include <vector>
#include <string>
#include <map>
#include <mutex>

namespace crypto {

// ---- 密钥状态枚举 ----
enum class KeyStatus : uint8_t {
    ENABLED = 1,      // 启用
    DISABLED = 2,     // 停用（仅可解密历史数据）
    DESTROYED = 3     // 销毁
};

// ---- 单个密钥信息 ----
struct KeyInfo {
    std::vector<unsigned char> key;   // 密钥数据（16字节）
    int version;                      // 版本号
    KeyStatus status;                 // 状态
};

// ---- 密钥管理器 ----
class KeyManager {
public:
    // ---- 初始化 ----
    // 设置主密钥 KEK（用于解密存储的密钥密文）
    void init(const std::vector<unsigned char>& kek);

    // ---- 加载密钥 ----
    // 从数据库加载三个密钥的密文（Base64），用 KEK 解密
    void loadKeys(const std::string& encryptedEncKey,
                  const std::string& encryptedIdxKey,
                  const std::string& encryptedTagKey,
                  int encVersion = 1,
                  int idxVersion = 1,
                  int tagVersion = 1);

    // ---- 获取当前启用版本的密钥（返回引用，直接指向内部存储） ----
    const std::vector<unsigned char>& getEncryptionKey() const;
    const std::vector<unsigned char>& getIndexKey() const;
    const std::vector<unsigned char>& getTagKey() const;

    // ---- 获取密钥信息（返回 const 引用，避免拷贝和临时对象） ----
    const KeyInfo& getEncryptionKeyInfo() const;
    const KeyInfo& getIndexKeyInfo() const;
    const KeyInfo& getTagKeyInfo() const;

    // ---- 按版本获取密钥 ----
    bool getEncryptionKeyByVersion(int version, std::vector<unsigned char>& key) const;
    bool getIndexKeyByVersion(int version, std::vector<unsigned char>& key) const;
    bool getTagKeyByVersion(int version, std::vector<unsigned char>& key) const;

    // ---- 密钥轮换 ----
    void rotateEncryptionKey();
    void rotateIndexKey();
    void rotateTagKey();

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

private:
    // 密钥类型常量
    enum KeyType { KEY_TYPE_ENC = 1, KEY_TYPE_IDX = 2, KEY_TYPE_TAG = 3 };

    std::vector<unsigned char> kek_;          // 主密钥
    mutable std::mutex mutex_;                // 线程安全

    // 密钥存储：类型 -> 版本 -> 密钥信息
    std::map<int, KeyInfo> keys_[3];

    // 当前启用版本
    int currentEncVersion_ = 0;
    int currentIdxVersion_ = 0;
    int currentTagVersion_ = 0;

    bool initialized_ = false;

    // ---- 内部方法 ----
    std::vector<unsigned char> decryptDEK(const std::string& cipherBase64);
    void addKeyVersion(int type, const std::vector<unsigned char>& key,
                       int version, KeyStatus status);

    // ★ 返回 const 引用，指向 keys_ 中存储的对象，生命周期安全
    const KeyInfo& getCurrentKeyInfo(int type) const;
    void rotateKey(int type);
};

} // namespace crypto