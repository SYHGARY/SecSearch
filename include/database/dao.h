// dao.h
// 数据访问对象：封装所有数据库操作，与 crypto 模块联动

#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <mysql/mysql.h>
#include "connection_pool.h"

namespace database {

// 字段类型枚举（与数据库 field_type 对应）
enum class FieldType : uint8_t {
    NAME    = 1,
    PHONE   = 2,
    ADDRESS = 3
};

// 明文数据结构（业务层传入）
struct PlainData {
    std::string name;
    std::string phone;
    std::string address;
};

// 密文记录（批量查询时返回）
struct CipherRecord {
    int64_t id;
    std::string cipher;   // 密文（十六进制）
    std::string tag;      // 完整性 Tag
    FieldType fieldType;  // 这个密文属于哪个字段
};

class DAO {
public:
    // 构造时自动从连接池获取一个连接
    DAO(ConnectionPool* pool = nullptr);

    // ---- 插入 ----
    // 插入一条完整数据，自动加密、生成盲索引、生成 Tag
    // 参数：明文、加密密钥、索引密钥、Tag 密钥
    // 返回：新记录的 ID
    int64_t insertData(const PlainData& data,
                       const std::vector<unsigned char>& encKey,
                       const std::vector<unsigned char>& idxKey,
                       const std::vector<unsigned char>& tagKey);

    // ---- 精确查询 ----
    // 根据盲索引查询匹配的记录 ID 列表
    std::vector<int64_t> queryByExactIndex(const std::string& blindHash,
                                           FieldType fieldType);

    // ---- 模糊查询 ----
    // 根据关键词进行模糊搜索（Bigram 分词后查倒排索引）
    // 返回候选记录 ID 列表（去重）
    std::vector<int64_t> queryByFuzzyKeyword(const std::string& keyword,
                                             FieldType fieldType,
                                             const std::vector<unsigned char>& idxKey);

    // ---- 批量读取密文 ----
    // 根据 ID 列表批量获取密文和 Tag
    std::vector<CipherRecord> batchSelectCiphers(const std::vector<int64_t>& ids);

    // ---- 更新 ----
    // 更新一条记录（事务内：删旧索引 → 更新主表 → 插新索引）
    bool updateData(int64_t id, const PlainData& newData,
                    const std::vector<unsigned char>& encKey,
                    const std::vector<unsigned char>& idxKey,
                    const std::vector<unsigned char>& tagKey);

    // ---- 删除 ----
    // 删除一条记录（事务内：删索引 → 删主表）
    bool deleteData(int64_t id);

    // 获取原始连接（供事务使用）
    MYSQL* getConnection() { return connGuard_->get(); }

private:
    ConnectionPool* pool_;
    std::unique_ptr<ConnectionGuard> connGuard_;

    // ---- 内部辅助方法 ----
    int64_t insertMainTable(const std::string& nameCipher, const std::string& nameBlind,
                            const std::string& nameTag,
                            const std::string& phoneCipher, const std::string& phoneBlind,
                            const std::string& phoneTag,
                            const std::string& addrCipher, const std::string& addrBlind,
                            const std::string& addrTag);

    void insertFuzzyIndex(int64_t dataId, FieldType type,
                          const std::vector<std::string>& tokenHashes);

    void deleteFuzzyIndex(int64_t dataId);
    void deleteFuzzyIndexForField(int64_t dataId, FieldType type);

    // Bigram 分词工具（静态）
    static std::vector<std::string> splitBigram(const std::string& text);
};

} // namespace database