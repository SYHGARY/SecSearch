// dao.h
// 数据访问对象

#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <mysql/mysql.h>
#include "connection_pool.h"

namespace database {

// 字段类型枚举
enum class FieldType : uint8_t {
    NAME    = 1,
    PHONE   = 2,
    ADDRESS = 3
};

// 明文数据结构
struct PlainData {
    std::string name;
    std::string phone;
    std::string address;
};

// ★ 密文记录：增加 encKeyVersion 字段
struct CipherRecord {
    int64_t id;
    std::string cipher;
    std::string tag;
    FieldType fieldType;
    int encKeyVersion;          // 加密密钥版本号
};

// 数据访问对象
class DAO {
public:
    DAO(ConnectionPool* pool = nullptr);

    // ---- 插入数据 ----
    // ★ 增加 encKeyVersion 参数
    int64_t insertData(const PlainData& data,
                       const std::vector<unsigned char>& encKey,
                       const std::vector<unsigned char>& idxKey,
                       const std::vector<unsigned char>& tagKey,
                       int encKeyVersion);

    // ---- 精确查询 ----
    std::vector<int64_t> queryByExactIndex(const std::string& blindHash,
                                           FieldType fieldType);

    // ---- 模糊查询 ----
    std::vector<int64_t> queryByFuzzyKeyword(const std::string& keyword,
                                             FieldType fieldType,
                                             const std::vector<unsigned char>& idxKey);

    // ---- 批量读取密文 ----
    std::vector<CipherRecord> batchSelectCiphers(const std::vector<int64_t>& ids);

    // ---- 更新数据 ----
    // ★ 增加 encKeyVersion 参数
    bool updateData(int64_t id, const PlainData& newData,
                    const std::vector<unsigned char>& encKey,
                    const std::vector<unsigned char>& idxKey,
                    const std::vector<unsigned char>& tagKey,
                    int encKeyVersion);

    // ---- 删除数据 ----
    bool deleteData(int64_t id);

    MYSQL* getConnection() { return connGuard_->get(); }

private:
    ConnectionPool* pool_;
    std::unique_ptr<ConnectionGuard> connGuard_;

    // ---- 插入主表 ----
    // ★ 增加 encKeyVersion 参数
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

    static std::vector<std::string> splitBigram(const std::string& text);
};

} // namespace database