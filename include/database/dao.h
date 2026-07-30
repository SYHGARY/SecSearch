// dao.h
// 数据访问对象

#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <optional>
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
    std::vector<crypto::KeyInfo> loadAllKeysFromConfig(int keyType) const;
    void saveKeyToConfig(int keyType, const std::vector<unsigned char>& key,
                         int version, crypto::KeyStatus status);
    void updateKeyStatusInConfig(int keyType, int version, crypto::KeyStatus status);
    void deleteKeyFromConfig(int keyType, int version);

    // ---- ★ 索引重建任务管理 ----
    struct RebuildTaskInfo {
        int64_t taskId;
        int fieldCode;
        int64_t startId;
        int64_t endId;
        int64_t lastProcessedId;
        int status;
        int successCount = 0;
        int failCount = 0;
    };

    int64_t createRebuildTask(int fieldCode, int64_t startId, int64_t endId);
    std::optional<RebuildTaskInfo> getPendingRebuildTask();
    void updateRebuildTaskProgress(int64_t taskId, int64_t lastProcessedId,
                                   int successCount, int failCount, int status);
    RebuildTaskInfo getRebuildTaskStatus(int64_t taskId);

    // ---- ★ 按 ID 范围获取记录（用于重建） ----
    struct RebuildRawRecord {
        int64_t id;
        int encKeyVersion;
        std::string nameCipher;
        std::string nameTag;
        std::string phoneCipher;
        std::string phoneTag;
        std::string addressCipher;
        std::string addressTag;
    };
    std::vector<RebuildRawRecord> getRecordsForRebuild(int64_t startId, int64_t endId, int limit);

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