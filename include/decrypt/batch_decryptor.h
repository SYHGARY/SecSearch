// batch_decryptor.h
// 批量解密服务：生产者-消费者流水线模型
// 支持直接传入 CipherRecord 列表进行并发解密
// 集成安全审计模块

#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <functional>
#include <mutex>
#include <condition_variable>
#include <queue>
#include "database/dao.h"
#include "crypto/key_manager.h"

// ★ 前向声明审计模块
namespace audit {
    class AuditLogger;
}

namespace decrypt {

// ---- 解密结果 ----
struct DecryptResult {
    int64_t id;
    std::string plaintext;
    bool success;
    std::string errorMsg;
    int keyVersion;
};

// ---- 批量解密统计 ----
struct DecryptStats {
    size_t total = 0;
    size_t successCount = 0;
    size_t failCount = 0;
    double elapsedMs = 0.0;
};

// ---- 批量解密器 ----
class BatchDecryptor {
public:
    BatchDecryptor(database::DAO& dao, crypto::KeyManager& keyMgr);

    std::vector<DecryptResult> decryptRecords(
        const std::vector<database::CipherRecord>& records,
        const std::string& requestId,
        audit::AuditLogger* auditLogger = nullptr,
        std::function<void(size_t, size_t)> progressCb = nullptr
    );

    std::vector<DecryptResult> decryptBatch(
        const std::vector<int64_t>& ids,
        const std::string& requestId,
        audit::AuditLogger* auditLogger = nullptr,
        std::function<void(size_t, size_t)> progressCb = nullptr
    );

    const DecryptStats& getLastStats() const { return lastStats_; }

private:
    database::DAO& dao_;
    crypto::KeyManager& keyMgr_;
    audit::AuditLogger* auditLogger_ = nullptr;
    std::string currentRequestId_;
    DecryptStats lastStats_;

    bool decryptOneRecord(const database::CipherRecord& record,
                          std::string& plaintext,
                          std::string& errorMsg,
                          int& keyVersion);

    struct Task {
        database::CipherRecord record;
        size_t index;
    };

    struct ResultItem {
        size_t index;
        DecryptResult result;
    };

    void producer(const std::vector<database::CipherRecord>& records,
                  std::queue<Task>& taskQueue,
                  std::mutex& queueMutex,
                  std::condition_variable& queueCV,
                  bool& done);

    void consumer(std::queue<Task>& taskQueue,
                  std::mutex& queueMutex,
                  std::condition_variable& queueCV,
                  bool& done,
                  std::queue<ResultItem>& resultQueue,
                  std::mutex& resultMutex,
                  std::condition_variable& resultCV);
};

} // namespace decrypt