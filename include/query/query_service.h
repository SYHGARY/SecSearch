// query_service.h
// 查询服务层：支持精确查询和模糊查询，集成批量解密流水线

#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include "database/dao.h"
#include "crypto/key_manager.h"

namespace query {

// ---- 完整记录 ----
struct FullRecord {
    int64_t id;
    std::string name;
    std::string phone;
    std::string address;
    int encKeyVersion;          // 加密密钥版本号
};

// ---- 查询服务类 ----
class QueryService {
public:
    // 构造函数：需要 DAO 和 KeyManager 引用
    QueryService(database::DAO& dao, crypto::KeyManager& keyMgr);

    // ---- 精确查询（等值匹配） ----
    // 支持多版本盲索引匹配，自动遍历所有历史索引密钥
    std::vector<FullRecord> exactQuery(
        const std::string& keyword,
        database::FieldType fieldType,
        const std::vector<unsigned char>& idxKey,
        const std::vector<unsigned char>& encKey,
        const std::vector<unsigned char>& tagKey
    );

    // ---- 模糊查询（中缀匹配） ----
    // 支持多版本 token 匹配，自动遍历所有历史索引密钥
    std::vector<FullRecord> fuzzyQuery(
        const std::string& keyword,
        database::FieldType fieldType,
        const std::vector<unsigned char>& idxKey,
        const std::vector<unsigned char>& encKey,
        const std::vector<unsigned char>& tagKey
    );

private:
    database::DAO& dao_;
    crypto::KeyManager& keyMgr_;

    // ---- 验证完整性 Tag ----
    bool verifyTag(const std::string& cipher, const std::string& tag,
                   const std::vector<unsigned char>& tagKey);

    // ---- 按版本解密（fallback） ----
    std::string decryptFieldWithVersion(const std::string& cipher,
                                        int version,
                                        const std::vector<unsigned char>& fallbackKey);

    // ---- 构建完整记录 ----
    FullRecord buildFullRecord(
        int64_t id,
        const std::string& nameCipher, const std::string& nameTag,
        const std::string& phoneCipher, const std::string& phoneTag,
        const std::string& addrCipher, const std::string& addrTag,
        int encKeyVersion,
        const std::vector<unsigned char>& fallbackEncKey,
        const std::vector<unsigned char>& tagKey
    );

    // ---- ★ 核心方法：获取完整记录（集成生产者-消费者批量解密） ----
    std::vector<FullRecord> fetchFullRecords(
        const std::vector<int64_t>& ids,
        const std::vector<unsigned char>& encKey,
        const std::vector<unsigned char>& tagKey,
        database::FieldType fieldType,
        const std::string* expectedPlain = nullptr
    );
};

// ---- 辅助结构体：用于构建完整记录 ----
struct FullRecordBuilder {
    int64_t id;
    int encKeyVersion;
    std::string nameCipher;
    std::string nameTag;
    std::string phoneCipher;
    std::string phoneTag;
    std::string addrCipher;
    std::string addrTag;
};

} // namespace query