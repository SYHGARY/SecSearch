// query_service.h
// 查询服务层

#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include "../database/dao.h"

namespace query {

// ---- 完整记录（查询结果） ----
struct FullRecord {
    int64_t id;
    std::string name;
    std::string phone;
    std::string address;
};

// ---- ★ 辅助结构体：用于构建完整记录 ----
struct FullRecordBuilder {
    int64_t id;
    std::string nameCipher;
    std::string nameTag;
    std::string phoneCipher;
    std::string phoneTag;
    std::string addrCipher;
    std::string addrTag;
};

// ---- 查询服务 ----
class QueryService {
public:
    explicit QueryService(database::DAO& dao);

    // ---- 精确查询 ----
    std::vector<FullRecord> exactQuery(
        const std::string& keyword,
        database::FieldType fieldType,
        const std::vector<unsigned char>& idxKey,
        const std::vector<unsigned char>& encKey,
        const std::vector<unsigned char>& tagKey
    );

    // ---- 模糊查询 ----
    std::vector<FullRecord> fuzzyQuery(
        const std::string& keyword,
        database::FieldType fieldType,
        const std::vector<unsigned char>& idxKey,
        const std::vector<unsigned char>& encKey,
        const std::vector<unsigned char>& tagKey
    );

private:
    database::DAO& dao_;

    // ---- 内部辅助 ----
    bool verifyTag(const std::string& cipher, const std::string& tag,
                   const std::vector<unsigned char>& tagKey);

    std::string decryptField(const std::string& cipher,
                             const std::vector<unsigned char>& encKey);

    FullRecord buildFullRecord(
        int64_t id,
        const std::string& nameCipher, const std::string& nameTag,
        const std::string& phoneCipher, const std::string& phoneTag,
        const std::string& addrCipher, const std::string& addrTag,
        const std::vector<unsigned char>& encKey,
        const std::vector<unsigned char>& tagKey
    );

    std::vector<FullRecord> fetchFullRecords(
        const std::vector<int64_t>& ids,
        const std::vector<unsigned char>& encKey,
        const std::vector<unsigned char>& tagKey,
        database::FieldType fieldType,
        const std::string* expectedPlain = nullptr
    );
};

} // namespace query