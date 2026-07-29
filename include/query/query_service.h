// query_service.h
// 查询服务层：支持精确查询和模糊查询，集成批量解密流水线
// 集成安全审计模块 + 查询限制防护

#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <deque>
#include <mutex>
#include <chrono>
#include "database/dao.h"
#include "crypto/key_manager.h"

// ★ 前向声明审计模块
namespace audit {
    class AuditLogger;
}

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
    // ★ 构造函数：增加审计日志器（可选）
    QueryService(database::DAO& dao,
                 crypto::KeyManager& keyMgr,
                 audit::AuditLogger* auditLogger = nullptr);

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
    audit::AuditLogger* auditLogger_;   // 审计日志器（可为空）

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

    // ============================================================
    // ★ 查询限制防护
    // ============================================================
    static constexpr size_t MIN_KEYWORD_LENGTH = 2;          // 最小查询关键词长度
    static constexpr size_t MAX_CANDIDATE_COUNT = 10000;     // 最大候选记录数
    static constexpr size_t MAX_REQUESTS_PER_SECOND = 10;    // 每秒最大请求数

    // 频率限制相关（线程安全）
    mutable std::mutex freqMutex_;
    std::deque<std::chrono::steady_clock::time_point> requestTimestamps_;

    // 检查方法（若违反限制则抛出 std::runtime_error）
    void checkKeywordLength(const std::string& keyword) const;
    void checkCandidateLimit(size_t candidateCount) const;
    void checkFrequencyLimit();   // 非 const，因为需要修改时间戳队列
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
