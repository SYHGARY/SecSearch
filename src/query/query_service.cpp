// query_service.cpp
// 实现查询服务（支持多版本索引密钥，逐版本独立查询并合并）
// 修复：Tag校验按记录版本获取对应Tag密钥

#include "query/query_service.h"
#include "crypto/sm4_cipher.h"
#include "crypto/hmac_sm3.h"
#include <map>
#include <set>
#include <stdexcept>
#include <algorithm>
#include <iostream>

namespace query {

// ---- 构造函数 ----
QueryService::QueryService(database::DAO& dao, crypto::KeyManager& keyMgr)
    : dao_(dao), keyMgr_(keyMgr) {}

// ---- 验证 Tag（使用指定版本的Tag密钥） ----
bool QueryService::verifyTagWithVersion(const std::string& cipher, const std::string& tag,
                                        int version, const std::vector<unsigned char>& fallbackKey) {
    std::vector<unsigned char> tagKey;
    if (!keyMgr_.getTagKeyByVersion(version, tagKey)) {
        // 找不到对应版本，使用fallback
        tagKey = fallbackKey;
    }
    auto cipherBytes = std::vector<unsigned char>(cipher.begin(), cipher.end());
    std::string computedTag = crypto::HmacSm3::hmacHex(cipherBytes, tagKey);
    return computedTag == tag;
}

// ---- 验证 Tag（保留原有，但实际使用上面的） ----
bool QueryService::verifyTag(const std::string& cipher, const std::string& tag,
                             const std::vector<unsigned char>& tagKey) {
    auto cipherBytes = std::vector<unsigned char>(cipher.begin(), cipher.end());
    std::string computedTag = crypto::HmacSm3::hmacHex(cipherBytes, tagKey);
    return computedTag == tag;
}

// ---- ★ 按版本解密 ----
std::string QueryService::decryptFieldWithVersion(const std::string& cipher,
                                                  int version,
                                                  const std::vector<unsigned char>& fallbackKey) {
    std::vector<unsigned char> key;
    if (keyMgr_.getEncryptionKeyByVersion(version, key)) {
        try {
            auto plainBytes = crypto::Sm4Cipher::decrypt(cipher, key);
            return std::string(plainBytes.begin(), plainBytes.end());
        } catch (...) { /* 失败则尝试 fallback */ }
    }
    // 找不到或失败，使用 fallback（当前版本）
    auto plainBytes = crypto::Sm4Cipher::decrypt(cipher, fallbackKey);
    return std::string(plainBytes.begin(), plainBytes.end());
}

// ---- 构建完整记录（按版本验证Tag） ----
FullRecord QueryService::buildFullRecord(
    int64_t id,
    const std::string& nameCipher, const std::string& nameTag,
    const std::string& phoneCipher, const std::string& phoneTag,
    const std::string& addrCipher, const std::string& addrTag,
    int encKeyVersion,
    const std::vector<unsigned char>& fallbackEncKey,
    const std::vector<unsigned char>& fallbackTagKey) {

    FullRecord rec;
    rec.id = id;
    rec.encKeyVersion = encKeyVersion;

    if (!nameCipher.empty() && verifyTagWithVersion(nameCipher, nameTag, encKeyVersion, fallbackTagKey)) {
        rec.name = decryptFieldWithVersion(nameCipher, encKeyVersion, fallbackEncKey);
    }
    if (!phoneCipher.empty() && verifyTagWithVersion(phoneCipher, phoneTag, encKeyVersion, fallbackTagKey)) {
        rec.phone = decryptFieldWithVersion(phoneCipher, encKeyVersion, fallbackEncKey);
    }
    if (!addrCipher.empty() && verifyTagWithVersion(addrCipher, addrTag, encKeyVersion, fallbackTagKey)) {
        rec.address = decryptFieldWithVersion(addrCipher, encKeyVersion, fallbackEncKey);
    }
    return rec;
}

// ---- 获取完整记录 ----
std::vector<FullRecord> QueryService::fetchFullRecords(
    const std::vector<int64_t>& ids,
    const std::vector<unsigned char>& encKey,
    const std::vector<unsigned char>& tagKey,
    database::FieldType fieldType,
    const std::string* expectedPlain) {

    if (ids.empty()) return {};

    auto records = dao_.batchSelectCiphers(ids);

    std::map<int64_t, FullRecordBuilder> builders;
    for (const auto& r : records) {
        auto& b = builders[r.id];
        b.id = r.id;
        b.encKeyVersion = r.encKeyVersion;
        if (r.fieldType == database::FieldType::NAME) {
            b.nameCipher = r.cipher;
            b.nameTag = r.tag;
        } else if (r.fieldType == database::FieldType::PHONE) {
            b.phoneCipher = r.cipher;
            b.phoneTag = r.tag;
        } else if (r.fieldType == database::FieldType::ADDRESS) {
            b.addrCipher = r.cipher;
            b.addrTag = r.tag;
        }
    }

    std::vector<FullRecord> results;
    for (auto& pair : builders) {
        auto& b = pair.second;
        FullRecord rec = buildFullRecord(
            b.id,
            b.nameCipher, b.nameTag,
            b.phoneCipher, b.phoneTag,
            b.addrCipher, b.addrTag,
            b.encKeyVersion,
            encKey,   // fallback加密密钥
            tagKey    // fallback Tag密钥
        );
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

// ---- ★ 精确查询（逐版本独立查询，合并结果） ----
std::vector<FullRecord> QueryService::exactQuery(
    const std::string& keyword,
    database::FieldType fieldType,
    const std::vector<unsigned char>& idxKey,
    const std::vector<unsigned char>& encKey,
    const std::vector<unsigned char>& tagKey) {

    // std::cout << "[QueryService] exactQuery: keyword='" << keyword << "'" << std::endl;
    auto allIdxKeys = keyMgr_.getAllIndexKeys();
    // std::cout << "[QueryService] allIdxKeys size = " << allIdxKeys.size() << std::endl;
    // for (const auto& p : allIdxKeys) {
    //     std::cout << "  version " << p.first << std::endl;
    // }

    auto keywordBytes = std::vector<unsigned char>(keyword.begin(), keyword.end());

    std::vector<int64_t> allIds;
    for (const auto& pair : allIdxKeys) {
        std::string blindHash = crypto::HmacSm3::hmacHex(keywordBytes, pair.second);
        // std::cout << "[QueryService] Computing hash with version " << pair.first << ": " << blindHash.substr(0, 16) << "..." << std::endl;
        auto ids = dao_.queryByExactIndexMulti({blindHash}, fieldType);
        // std::cout << "[QueryService] Found " << ids.size() << " ids for version " << pair.first << std::endl;
        allIds.insert(allIds.end(), ids.begin(), ids.end());
    }

    std::sort(allIds.begin(), allIds.end());
    allIds.erase(std::unique(allIds.begin(), allIds.end()), allIds.end());

    if (allIds.empty()) {
        // std::cout << "[QueryService] No IDs found." << std::endl;
        return {};
    }

    // std::cout << "[QueryService] Total unique IDs: " << allIds.size() << std::endl;
    return fetchFullRecords(allIds, encKey, tagKey, fieldType, &keyword);
}

// ---- ★ 模糊查询（逐版本独立查询，合并结果） ----
std::vector<FullRecord> QueryService::fuzzyQuery(
    const std::string& keyword,
    database::FieldType fieldType,
    const std::vector<unsigned char>& idxKey,
    const std::vector<unsigned char>& encKey,
    const std::vector<unsigned char>& tagKey) {

    // std::cout << "[QueryService] fuzzyQuery: keyword='" << keyword << "'" << std::endl;
    auto allIdxKeys = keyMgr_.getAllIndexKeys();
    // std::cout << "[QueryService] allIdxKeys size = " << allIdxKeys.size() << std::endl;
    // for (const auto& p : allIdxKeys) {
    //     std::cout << "  version " << p.first << std::endl;
    // }

    auto tokens = database::DAO::splitBigram(keyword);
    if (tokens.empty()) {
        // std::cout << "[QueryService] No tokens." << std::endl;
        return {};
    }

    std::vector<int64_t> allIds;
    for (const auto& pair : allIdxKeys) {
        std::vector<std::string> tokenHashes;
        tokenHashes.reserve(tokens.size());
        for (const auto& token : tokens) {
            auto tokenBytes = std::vector<unsigned char>(token.begin(), token.end());
            tokenHashes.push_back(crypto::HmacSm3::hmacHex(tokenBytes, pair.second));
        }
        std::sort(tokenHashes.begin(), tokenHashes.end());
        tokenHashes.erase(std::unique(tokenHashes.begin(), tokenHashes.end()), tokenHashes.end());

        // std::cout << "[QueryService] Querying version " << pair.first << " with " << tokenHashes.size() << " tokens" << std::endl;
        auto ids = dao_.queryByFuzzyKeywordMulti(tokenHashes, fieldType);
        // std::cout << "[QueryService] Found " << ids.size() << " ids for version " << pair.first << std::endl;
        allIds.insert(allIds.end(), ids.begin(), ids.end());
    }

    std::sort(allIds.begin(), allIds.end());
    allIds.erase(std::unique(allIds.begin(), allIds.end()), allIds.end());

    if (allIds.empty()) {
        // std::cout << "[QueryService] No IDs found." << std::endl;
        return {};
    }

    // std::cout << "[QueryService] Total unique IDs: " << allIds.size() << std::endl;
    auto results = fetchFullRecords(allIds, encKey, tagKey, fieldType, nullptr);

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
        if (match) finalResults.push_back(r);
    }
    // std::cout << "[QueryService] Final results after collision resolution: " << finalResults.size() << std::endl;
    return finalResults;
}

} // namespace query