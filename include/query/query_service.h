// query_service.h
// 查询服务层

#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include "database/dao.h"

namespace query {

// ★ FullRecord 增加 encKeyVersion 字段
struct FullRecord {
    int64_t id;
    std::string name;
    std::string phone;
    std::string address;
    int encKeyVersion;
};

// 查询服务类
class QueryService {
public:
    explicit QueryService(database::DAO& dao);

    std::vector<FullRecord> exactQuery(
        const std::string& keyword,
        database::FieldType fieldType,
        const std::vector<unsigned char>& idxKey,
        const std::vector<unsigned char>& encKey,
        const std::vector<unsigned char>& tagKey
    );

    std::vector<FullRecord> fuzzyQuery(
        const std::string& keyword,
        database::FieldType fieldType,
        const std::vector<unsigned char>& idxKey,
        const std::vector<unsigned char>& encKey,
        const std::vector<unsigned char>& tagKey
    );

private:
    database::DAO& dao_;

    bool verifyTag(const std::string& cipher, const std::string& tag,
                   const std::vector<unsigned char>& tagKey);

    std::string decryptField(const std::string& cipher,
                             const std::vector<unsigned char>& encKey);

    FullRecord buildFullRecord(
        int64_t id,
        const std::string& nameCipher, const std::string& nameTag,
        const std::string& phoneCipher, const std::string& phoneTag,
        const std::string& addrCipher, const std::string& addrTag,
        int encKeyVersion,
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

// ★ 辅助结构体：增加 encKeyVersion
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