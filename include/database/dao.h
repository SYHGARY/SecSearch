// dao.h
// 数据访问对象

#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <mysql/mysql.h>
#include "connection_pool.h"
#include "crypto/key_manager.h"

namespace database {

enum class FieldType : uint8_t {
    NAME    = 1,
    PHONE   = 2,
    ADDRESS = 3
};

struct PlainData {
    std::string name;
    std::string phone;
    std::string address;
};

struct CipherRecord {
    int64_t id;
    std::string cipher;
    std::string tag;
    FieldType fieldType;
    int encKeyVersion;
};

class DAO {
public:
    DAO(ConnectionPool* pool = nullptr);

    // ---- 插入数据 ----
    int64_t insertData(const PlainData& data,
                       const std::vector<unsigned char>& encKey,
                       const std::vector<unsigned char>& idxKey,
                       const std::vector<unsigned char>& tagKey,
                       int encKeyVersion);

    // ---- 多版本精确查询 ----
    std::vector<int64_t> queryByExactIndexMulti(const std::vector<std::string>& blindHashes,
                                                FieldType fieldType);

    // ---- 单版本精确查询（兼容旧接口） ----
    std::vector<int64_t> queryByExactIndex(const std::string& blindHash,
                                           FieldType fieldType) {
        return queryByExactIndexMulti({blindHash}, fieldType);
    }

    // ---- 多版本模糊查询 ----
    std::vector<int64_t> queryByFuzzyKeywordMulti(const std::vector<std::string>& tokenHashes,
                                                  FieldType fieldType);

    // ---- 单版本模糊查询 ----
    std::vector<int64_t> queryByFuzzyKeyword(const std::string& keyword,
                                             FieldType fieldType,
                                             const std::vector<unsigned char>& idxKey);

    // ---- 批量读取密文 ----
    std::vector<CipherRecord> batchSelectCiphers(const std::vector<int64_t>& ids);

    // ---- 更新数据 ----
    bool updateData(int64_t id, const PlainData& newData,
                    const std::vector<unsigned char>& encKey,
                    const std::vector<unsigned char>& idxKey,
                    const std::vector<unsigned char>& tagKey,
                    int encKeyVersion);

    // ---- 删除数据 ----
    bool deleteData(int64_t id);

    // ---- ★ 密钥配置表操作（持久化密钥） ----
    // 加载指定类型的所有密钥记录（密文形式）
    std::vector<crypto::KeyInfo> loadAllKeysFromConfig(int keyType) const;
    // 保存密钥到配置表
    void saveKeyToConfig(int keyType, const std::vector<unsigned char>& key,
                         int version, crypto::KeyStatus status);
    // 更新密钥状态
    void updateKeyStatusInConfig(int keyType, int version, crypto::KeyStatus status);
    // 删除密钥
    void deleteKeyFromConfig(int keyType, int version);

    // ---- 工具方法 ----
    static std::vector<std::string> splitBigram(const std::string& text);

    // ---- 获取原始连接 ----
    MYSQL* getConnection() { return connGuard_->get(); }

private:
    ConnectionPool* pool_;
    std::unique_ptr<ConnectionGuard> connGuard_;

    int64_t insertMainTable(const std::string& nameCipher, const std::string& nameBlind,
                            const std::string& nameTag,
                            const std::string& phoneCipher, const std::string& phoneBlind,
                            const std::string& phoneTag,
                            const std::string& addrCipher, const std::string& addrBlind,
                            const std::string& addrTag,
                            int encKeyVersion);

    void insertFuzzyIndex(int64_t dataId, FieldType type,
                          const std::vector<std::string>& tokenHashes);

    void deleteFuzzyIndex(int64_t dataId);
};

} // namespace database