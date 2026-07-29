// query_service.cpp
// 实现查询服务，集成生产者-消费者批量解密流水线
// 集成安全审计模块 + 查询限制防护

#include "query/query_service.h"
#include "decrypt/batch_decryptor.h"
#include "crypto/sm4_cipher.h"
#include "crypto/hmac_sm3.h"
#include "audit/audit_logger.h"

#include <map>
#include <set>
#include <stdexcept>
#include <algorithm>
#include <iostream>
#include <deque>

namespace query {

// ---- 构造函数（增加审计器） ----
QueryService::QueryService(database::DAO& dao,
                           crypto::KeyManager& keyMgr,
                           audit::AuditLogger* auditLogger)
    : dao_(dao), keyMgr_(keyMgr), auditLogger_(auditLogger) {}

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

// ---- ★ 核心方法：获取完整记录（集成生产者-消费者批量解密 + 审计） ----
std::vector<FullRecord> QueryService::fetchFullRecords(
    const std::vector<int64_t>& ids,
    const std::vector<unsigned char>& encKey,
    const std::vector<unsigned char>& tagKey,
    database::FieldType fieldType,
    const std::string* expectedPlain) {

    if (ids.empty()) return {};

    // ★ 生成请求ID，用于关联本次查询的所有解密操作
    std::string requestId = audit::AuditLogger::generateRequestId();

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
    // 步骤4：★ 生产者-消费者流水线批量解密（传递 requestId 和 auditLogger）
    // ============================================================
    decrypt::BatchDecryptor batchDecryptor(dao_, keyMgr_);

    bool showProgress = (allCipherRecords.size() > 20);

    // ★ 调用新的 decryptRecords 接口（带 requestId 和 auditLogger）
    auto decryptResults = batchDecryptor.decryptRecords(
        allCipherRecords,
        requestId,                         //  传递请求ID
        auditLogger_,                      //  传递审计器（可为空）
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

        // fallback：如果批量解密失败，尝试单条解密
        if (rec.name.empty() && !b.nameCipher.empty()) {
            rec.name = decryptFieldWithVersion(b.nameCipher, b.encKeyVersion, encKey);
        }
        if (rec.phone.empty() && !b.phoneCipher.empty()) {
            rec.phone = decryptFieldWithVersion(b.phoneCipher, b.encKeyVersion, encKey);
        }
        if (rec.address.empty() && !b.addrCipher.empty()) {
            rec.address = decryptFieldWithVersion(b.addrCipher, b.encKeyVersion, encKey);
        }

        // 精确查询的碰撞消解
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

// ---- ★ 查询限制检查方法 ----

// 1. 检查关键词长度
void QueryService::checkKeywordLength(const std::string& keyword) const {
    if (keyword.length() < MIN_KEYWORD_LENGTH) {
        throw std::runtime_error("查询关键词长度不能小于 " + std::to_string(MIN_KEYWORD_LENGTH) + " 个字符");
    }
}

// 2. 检查候选数量
void QueryService::checkCandidateLimit(size_t candidateCount) const {
    if (candidateCount > MAX_CANDIDATE_COUNT) {
        throw std::runtime_error("查询候选记录数过多（" + std::to_string(candidateCount) +
                                 "），超过限制 " + std::to_string(MAX_CANDIDATE_COUNT) +
                                 "。请使用更精确的关键词。");
    }
}

// 3. 频率限制（滑动窗口）
void QueryService::checkFrequencyLimit() {
    std::lock_guard<std::mutex> lock(freqMutex_);
    auto now = std::chrono::steady_clock::now();
    // 移除 1 秒前的记录
    auto cutoff = now - std::chrono::seconds(1);
    while (!requestTimestamps_.empty() && requestTimestamps_.front() < cutoff) {
        requestTimestamps_.pop_front();
    }
    if (requestTimestamps_.size() >= MAX_REQUESTS_PER_SECOND) {
        throw std::runtime_error("查询频率过高，请稍后再试（每秒最多 " +
                                 std::to_string(MAX_REQUESTS_PER_SECOND) + " 次）");
    }
    requestTimestamps_.push_back(now);
}

// ---- 精确查询（多版本盲索引匹配） ----
std::vector<FullRecord> QueryService::exactQuery(
    const std::string& keyword,
    database::FieldType fieldType,
    const std::vector<unsigned char>& idxKey,
    const std::vector<unsigned char>& encKey,
    const std::vector<unsigned char>& tagKey) {

    // ★ 查询限制检查
    checkFrequencyLimit();                // 频率限制
    checkKeywordLength(keyword);          // 关键词长度

    auto keywordBytes = std::vector<unsigned char>(keyword.begin(), keyword.end());

    auto allIdxKeys = keyMgr_.getAllIndexKeys();

    std::vector<std::string> blindHashes;
    for (const auto& pair : allIdxKeys) {
        blindHashes.push_back(crypto::HmacSm3::hmacHex(keywordBytes, pair.second));
    }

    std::sort(blindHashes.begin(), blindHashes.end());
    blindHashes.erase(std::unique(blindHashes.begin(), blindHashes.end()), blindHashes.end());

    std::vector<int64_t> ids = dao_.queryByExactIndexMulti(blindHashes, fieldType);

    // ★ 候选数量限制
    checkCandidateLimit(ids.size());

    if (ids.empty()) return {};

    return fetchFullRecords(ids, encKey, tagKey, fieldType, &keyword);
}

// ---- ★ 模糊查询（多版本 token 匹配，分别查询每个版本） ----
std::vector<FullRecord> QueryService::fuzzyQuery(
    const std::string& keyword,
    database::FieldType fieldType,
    const std::vector<unsigned char>& idxKey,
    const std::vector<unsigned char>& encKey,
    const std::vector<unsigned char>& tagKey) {

    // ★ 查询限制检查
    checkFrequencyLimit();                // 频率限制
    checkKeywordLength(keyword);          // 关键词长度

    auto tokens = database::DAO::splitBigram(keyword);
    if (tokens.empty()) return {};

    // ★ 获取所有历史版本的索引密钥
    auto allIdxKeys = keyMgr_.getAllIndexKeys();

    // ★ 使用集合去重 ID
    std::set<int64_t> idSet;

    // ★ 对每个索引密钥版本，分别计算 token 哈希并查询
    for (const auto& pair : allIdxKeys) {
        const auto& key = pair.second;
        std::vector<std::string> versionHashes;
        for (const auto& token : tokens) {
            auto tokenBytes = std::vector<unsigned char>(token.begin(), token.end());
            versionHashes.push_back(crypto::HmacSm3::hmacHex(tokenBytes, key));
        }

        // 查询该版本的结果
        auto ids = dao_.queryByFuzzyKeywordMulti(versionHashes, fieldType);
        for (auto id : ids) {
            idSet.insert(id);
        }
    }

    if (idSet.empty()) return {};

    std::vector<int64_t> ids(idSet.begin(), idSet.end());

    // ★ 候选数量限制（去重后的数量）
    checkCandidateLimit(ids.size());

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
