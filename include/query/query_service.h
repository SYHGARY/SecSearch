// query_service.h
#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include "database/dao.h"
#include "crypto/key_manager.h"

namespace query {

struct FullRecord {
    int64_t id;
    std::string name;
    std::string phone;
    std::string address;
    int encKeyVersion;
};

class QueryService {
public:
    explicit QueryService(database::DAO& dao, crypto::KeyManager& keyMgr);

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
    crypto::KeyManager& keyMgr_;

    // ---- 新声明：按版本验证 Tag ----
    bool verifyTagWithVersion(const std::string& cipher,
                              const std::string& tag,
                              int version,
                              const std::vector<unsigned char>& fallbackKey);

    // 原有的 verifyTag 可以保留或移除，这里我们保留但不使用，或者删除
    bool verifyTag(const std::string& cipher, const std::string& tag,
                   const std::vector<unsigned char>& tagKey);

    std::string decryptFieldWithVersion(const std::string& cipher,
                                        int version,
                                        const std::vector<unsigned char>& fallbackKey);

    FullRecord buildFullRecord(
        int64_t id,
        const std::string& nameCipher, const std::string& nameTag,
        const std::string& phoneCipher, const std::string& phoneTag,
        const std::string& addrCipher, const std::string& addrTag,
        int encKeyVersion,
        const std::vector<unsigned char>& fallbackEncKey,
        const std::vector<unsigned char>& fallbackTagKey
    );

    std::vector<FullRecord> fetchFullRecords(
        const std::vector<int64_t>& ids,
        const std::vector<unsigned char>& encKey,
        const std::vector<unsigned char>& tagKey,
        database::FieldType fieldType,
        const std::string* expectedPlain = nullptr
    );
};

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