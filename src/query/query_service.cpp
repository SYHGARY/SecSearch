// query_service.cpp
// 实现查询服务

#include "query/query_service.h"
#include "crypto/sm4_cipher.h"
#include "crypto/hmac_sm3.h"
#include <map>
#include <stdexcept>

namespace query {

// ---- 构造函数 ----
QueryService::QueryService(database::DAO& dao) : dao_(dao) {}

// ---- 验证 Tag ----
bool QueryService::verifyTag(const std::string& cipher, const std::string& tag,
                             const std::vector<unsigned char>& tagKey) {
    auto cipherBytes = std::vector<unsigned char>(cipher.begin(), cipher.end());
    std::string computedTag = crypto::HmacSm3::hmacHex(cipherBytes, tagKey);
    return computedTag == tag;
}

// ---- 解密单个字段 ----
std::string QueryService::decryptField(const std::string& cipher,
                                       const std::vector<unsigned char>& encKey) {
    auto plainBytes = crypto::Sm4Cipher::decrypt(cipher, encKey);
    return std::string(plainBytes.begin(), plainBytes.end());
}

// ---- 从密文记录构建完整记录 ----
FullRecord QueryService::buildFullRecord(
    int64_t id,
    const std::string& nameCipher, const std::string& nameTag,
    const std::string& phoneCipher, const std::string& phoneTag,
    const std::string& addrCipher, const std::string& addrTag,
    const std::vector<unsigned char>& encKey,
    const std::vector<unsigned char>& tagKey) {

    FullRecord rec;
    rec.id = id;

    if (!nameCipher.empty() && verifyTag(nameCipher, nameTag, tagKey)) {
        rec.name = decryptField(nameCipher, encKey);
    }
    if (!phoneCipher.empty() && verifyTag(phoneCipher, phoneTag, tagKey)) {
        rec.phone = decryptField(phoneCipher, encKey);
    }
    if (!addrCipher.empty() && verifyTag(addrCipher, addrTag, tagKey)) {
        rec.address = decryptField(addrCipher, encKey);
    }

    return rec;
}

// ---- 对候选 ID 列表获取完整记录 ----
std::vector<FullRecord> QueryService::fetchFullRecords(
    const std::vector<int64_t>& ids,
    const std::vector<unsigned char>& encKey,
    const std::vector<unsigned char>& tagKey,
    database::FieldType fieldType,
    const std::string* expectedPlain) {

    if (ids.empty()) return {};

    auto records = dao_.batchSelectCiphers(ids);

    // ★ 按 ID 分组
    std::map<int64_t, FullRecordBuilder> builders;

    for (const auto& r : records) {
        auto& builder = builders[r.id];
        builder.id = r.id;

        if (r.fieldType == database::FieldType::NAME) {
            builder.nameCipher = r.cipher;
            builder.nameTag = r.tag;
        } else if (r.fieldType == database::FieldType::PHONE) {
            builder.phoneCipher = r.cipher;
            builder.phoneTag = r.tag;
        } else if (r.fieldType == database::FieldType::ADDRESS) {
            builder.addrCipher = r.cipher;
            builder.addrTag = r.tag;
        }
    }

    // ★ 构建完整记录
    std::vector<FullRecord> results;

    for (auto& pair : builders) {
        auto& b = pair.second;

        FullRecord rec = buildFullRecord(
            b.id,
            b.nameCipher, b.nameTag,
            b.phoneCipher, b.phoneTag,
            b.addrCipher, b.addrTag,
            encKey, tagKey
        );

        // ★ 碰撞消解
        if (expectedPlain) {
            bool match = false;
            switch (fieldType) {
                case database::FieldType::NAME:
                    match = (rec.name == *expectedPlain);
                    break;
                case database::FieldType::PHONE:
                    match = (rec.phone == *expectedPlain);
                    break;
                case database::FieldType::ADDRESS:
                    match = (rec.address == *expectedPlain);
                    break;
            }
            if (!match) continue;
        }

        results.push_back(rec);
    }

    return results;
}

// ---- 精确查询 ----
std::vector<FullRecord> QueryService::exactQuery(
    const std::string& keyword,
    database::FieldType fieldType,
    const std::vector<unsigned char>& idxKey,
    const std::vector<unsigned char>& encKey,
    const std::vector<unsigned char>& tagKey) {

    auto keywordBytes = std::vector<unsigned char>(keyword.begin(), keyword.end());
    std::string blindHash = crypto::HmacSm3::hmacHex(keywordBytes, idxKey);

    std::vector<int64_t> ids = dao_.queryByExactIndex(blindHash, fieldType);
    if (ids.empty()) return {};

    return fetchFullRecords(ids, encKey, tagKey, fieldType, &keyword);
}

// ---- 模糊查询 ----
std::vector<FullRecord> QueryService::fuzzyQuery(
    const std::string& keyword,
    database::FieldType fieldType,
    const std::vector<unsigned char>& idxKey,
    const std::vector<unsigned char>& encKey,
    const std::vector<unsigned char>& tagKey) {

    std::vector<int64_t> ids = dao_.queryByFuzzyKeyword(keyword, fieldType, idxKey);
    if (ids.empty()) return {};

    auto results = fetchFullRecords(ids, encKey, tagKey, fieldType, nullptr);

    // ★ 模糊查询：过滤包含关键词的记录
    std::vector<FullRecord> finalResults;
    for (const auto& r : results) {
        bool match = false;
        switch (fieldType) {
            case database::FieldType::NAME:
                match = (r.name.find(keyword) != std::string::npos);
                break;
            case database::FieldType::PHONE:
                match = (r.phone.find(keyword) != std::string::npos);
                break;
            case database::FieldType::ADDRESS:
                match = (r.address.find(keyword) != std::string::npos);
                break;
        }
        if (match) {
            finalResults.push_back(r);
        }
    }

    return finalResults;
}

} // namespace query