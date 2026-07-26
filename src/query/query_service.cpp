// query_service.cpp
// 实现查询服务，集成生产者-消费者批量解密流水线

#include "query/query_service.h"
#include "decrypt/batch_decryptor.h"
#include "crypto/sm4_cipher.h"
#include "crypto/hmac_sm3.h"
#include <map>
#include <stdexcept>
#include <algorithm>
#include <iostream>

namespace query {

// ---- 构造函数 ----
QueryService::QueryService(database::DAO& dao, crypto::KeyManager& keyMgr)
    : dao_(dao), keyMgr_(keyMgr) {}

// ---- 验证 Tag ----
bool QueryService::verifyTag(const std::string& cipher, const std::string& tag,
                             const std::vector<unsigned char>& tagKey) {
    auto cipherBytes = std::vector<unsigned char>(cipher.begin(), cipher.end());
    std::string computedTag = crypto::HmacSm3::hmacHex(cipherBytes, tagKey);
    return computedTag == tag;
}

// ---- 按版本解密（fallback） ----
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

// ---- 构建完整记录（逐条解密，作为 fallback） ----
FullRecord QueryService::buildFullRecord(
    int64_t id,
    const std::string& nameCipher, const std::string& nameTag,
    const std::string& phoneCipher, const std::string& phoneTag,
    const std::string& addrCipher, const std::string& addrTag,
    int encKeyVersion,
    const std::vector<unsigned char>& fallbackEncKey,
    const std::vector<unsigned char>& tagKey) {

    FullRecord rec;
    rec.id = id;
    rec.encKeyVersion = encKeyVersion;

    if (!nameCipher.empty() && verifyTag(nameCipher, nameTag, tagKey)) {
        rec.name = decryptFieldWithVersion(nameCipher, encKeyVersion, fallbackEncKey);
    }
    if (!phoneCipher.empty() && verifyTag(phoneCipher, phoneTag, tagKey)) {
        rec.phone = decryptFieldWithVersion(phoneCipher, encKeyVersion, fallbackEncKey);
    }
    if (!addrCipher.empty() && verifyTag(addrCipher, addrTag, tagKey)) {
        rec.address = decryptFieldWithVersion(addrCipher, encKeyVersion, fallbackEncKey);
    }
    return rec;
}

// ---- ★ 核心方法：获取完整记录（集成生产者-消费者批量解密） ----
std::vector<FullRecord> QueryService::fetchFullRecords(
    const std::vector<int64_t>& ids,
    const std::vector<unsigned char>& encKey,
    const std::vector<unsigned char>& tagKey,
    database::FieldType fieldType,
    const std::string* expectedPlain) {

    if (ids.empty()) return {};

    // ============================================================
    // 步骤1：批量读取所有密文（IO 优化）
    // ============================================================
    auto records = dao_.batchSelectCiphers(ids);

    // ============================================================
    // 步骤2：按 ID 分组，收集所有字段的密文
    // ============================================================
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

    // ============================================================
    // 步骤3：将所有密文记录收集到一个列表中，用于批量解密
    // ============================================================
    std::vector<database::CipherRecord> allCipherRecords;
    for (const auto& pair : builders) {
        const auto& b = pair.second;
        if (!b.nameCipher.empty()) {
            allCipherRecords.push_back({b.id, b.nameCipher, b.nameTag,
                                        database::FieldType::NAME, b.encKeyVersion});
        }
        if (!b.phoneCipher.empty()) {
            allCipherRecords.push_back({b.id, b.phoneCipher, b.phoneTag,
                                        database::FieldType::PHONE, b.encKeyVersion});
        }
        if (!b.addrCipher.empty()) {
            allCipherRecords.push_back({b.id, b.addrCipher, b.addrTag,
                                        database::FieldType::ADDRESS, b.encKeyVersion});
        }
    }

    // ============================================================
    // 步骤4：★ 生产者-消费者流水线批量解密
    // ============================================================
    decrypt::BatchDecryptor batchDecryptor(dao_, keyMgr_);

    // 显示进度（如果记录数较多）
    bool showProgress = (allCipherRecords.size() > 20);

    auto decryptResults = batchDecryptor.decryptRecords(
        allCipherRecords,
        [showProgress](size_t processed, size_t total) {
            if (showProgress && processed % 10 == 0) {
                std::cout << "\r🔓 批量解密进度: " << processed << "/" << total
                          << " (" << (processed * 100 / total) << "%)" << std::flush;
            }
        }
    );

    if (showProgress) {
        std::cout << std::endl;
    }

    // ============================================================
    // 步骤5：将解密结果按 (ID, fieldType) 缓存
    // ============================================================
    // 由于 DecryptResult 包含 id 和 plaintext，但缺少 fieldType，
    // 我们通过 allCipherRecords 的索引来匹配
    std::map<int64_t, std::map<database::FieldType, std::string>> decryptedCache;

    for (size_t i = 0; i < decryptResults.size(); ++i) {
        const auto& result = decryptResults[i];
        if (result.success) {
            const auto& rec = allCipherRecords[i];
            decryptedCache[rec.id][rec.fieldType] = result.plaintext;
        }
    }

    // ============================================================
    // 步骤6：构建最终结果
    // ============================================================
    std::vector<FullRecord> results;

    for (auto& pair : builders) {
        auto& b = pair.second;

        FullRecord rec;
        rec.id = b.id;
        rec.encKeyVersion = b.encKeyVersion;

        // ★ 从缓存中获取明文
        auto idIt = decryptedCache.find(b.id);
        if (idIt != decryptedCache.end()) {
            auto& fieldMap = idIt->second;
            auto it = fieldMap.find(database::FieldType::NAME);
            if (it != fieldMap.end()) rec.name = it->second;
            it = fieldMap.find(database::FieldType::PHONE);
            if (it != fieldMap.end()) rec.phone = it->second;
            it = fieldMap.find(database::FieldType::ADDRESS);
            if (it != fieldMap.end()) rec.address = it->second;
        }

        // 如果缓存中没有（解密失败），尝试用 fallback
        if (rec.name.empty() && !b.nameCipher.empty()) {
            rec.name = decryptFieldWithVersion(b.nameCipher, b.encKeyVersion, encKey);
        }
        if (rec.phone.empty() && !b.phoneCipher.empty()) {
            rec.phone = decryptFieldWithVersion(b.phoneCipher, b.encKeyVersion, encKey);
        }
        if (rec.address.empty() && !b.addrCipher.empty()) {
            rec.address = decryptFieldWithVersion(b.addrCipher, b.encKeyVersion, encKey);
        }

        // 碰撞消解
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

// ---- 精确查询（多版本盲索引匹配） ----
std::vector<FullRecord> QueryService::exactQuery(
    const std::string& keyword,
    database::FieldType fieldType,
    const std::vector<unsigned char>& idxKey,
    const std::vector<unsigned char>& encKey,
    const std::vector<unsigned char>& tagKey) {

    auto keywordBytes = std::vector<unsigned char>(keyword.begin(), keyword.end());

    // ★ 获取所有历史版本的索引密钥
    auto allIdxKeys = keyMgr_.getAllIndexKeys();

    // ★ 用所有版本分别计算盲索引
    std::vector<std::string> blindHashes;
    for (const auto& pair : allIdxKeys) {
        blindHashes.push_back(crypto::HmacSm3::hmacHex(keywordBytes, pair.second));
    }

    // ★ 去重
    std::sort(blindHashes.begin(), blindHashes.end());
    blindHashes.erase(std::unique(blindHashes.begin(), blindHashes.end()), blindHashes.end());

    // ★ 多版本查询
    std::vector<int64_t> ids = dao_.queryByExactIndexMulti(blindHashes, fieldType);
    if (ids.empty()) return {};

    return fetchFullRecords(ids, encKey, tagKey, fieldType, &keyword);
}

// ---- 模糊查询（多版本 token 匹配） ----
std::vector<FullRecord> QueryService::fuzzyQuery(
    const std::string& keyword,
    database::FieldType fieldType,
    const std::vector<unsigned char>& idxKey,
    const std::vector<unsigned char>& encKey,
    const std::vector<unsigned char>& tagKey) {

    auto tokens = database::DAO::splitBigram(keyword);
    if (tokens.empty()) return {};

    // ★ 获取所有历史版本的索引密钥
    auto allIdxKeys = keyMgr_.getAllIndexKeys();

    // ★ 用所有版本分别计算每个 token 的哈希
    std::vector<std::string> allHashes;
    for (const auto& token : tokens) {
        auto tokenBytes = std::vector<unsigned char>(token.begin(), token.end());
        for (const auto& pair : allIdxKeys) {
            allHashes.push_back(crypto::HmacSm3::hmacHex(tokenBytes, pair.second));
        }
    }

    // ★ 去重
    std::sort(allHashes.begin(), allHashes.end());
    allHashes.erase(std::unique(allHashes.begin(), allHashes.end()), allHashes.end());

    // ★ 多版本模糊查询
    std::vector<int64_t> ids = dao_.queryByFuzzyKeywordMulti(allHashes, fieldType);
    if (ids.empty()) return {};

    auto results = fetchFullRecords(ids, encKey, tagKey, fieldType, nullptr);

    // 碰撞消解：确保明文包含关键词
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
    return finalResults;
}

} // namespace query