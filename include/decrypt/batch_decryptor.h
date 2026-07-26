// batch_decryptor.h
// 批量解密服务：生产者-消费者流水线模型
// 支持直接传入 CipherRecord 列表进行并发解密

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

namespace decrypt {

// ---- 解密结果 ----
struct DecryptResult {
    int64_t id;                 // 记录ID
    std::string plaintext;      // 解密后的明文
    bool success;               // 是否成功
    std::string errorMsg;       // 错误信息（若失败）
    int keyVersion;             // 使用的密钥版本
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

    // ---- ★ 核心方法：解密 CipherRecord 列表（生产者-消费者） ----
    // 参数：密文记录列表、进度回调（可选）
    // 返回：解密结果列表（与输入顺序一致）
    std::vector<DecryptResult> decryptRecords(
        const std::vector<database::CipherRecord>& records,
        std::function<void(size_t, size_t)> progressCb = nullptr
    );

    // ---- 批量解密（从数据库读取） ----
    std::vector<DecryptResult> decryptBatch(
        const std::vector<int64_t>& ids,
        std::function<void(size_t, size_t)> progressCb = nullptr
    );

    const DecryptStats& getLastStats() const { return lastStats_; }

private:
    database::DAO& dao_;
    crypto::KeyManager& keyMgr_;
    DecryptStats lastStats_;

    // ---- 解密单个密文 ----
    bool decryptOneRecord(const database::CipherRecord& record,
                          std::string& plaintext,
                          std::string& errorMsg,
                          int& keyVersion);

    // ---- 流水线任务结构 ----
    struct Task {
        database::CipherRecord record;
        size_t index;           // 原始顺序索引
    };

    struct ResultItem {
        size_t index;
        DecryptResult result;
    };

    // ---- 生产者：将记录推入队列 ----
    void producer(const std::vector<database::CipherRecord>& records,
                  std::queue<Task>& taskQueue,
                  std::mutex& queueMutex,
                  std::condition_variable& queueCV,
                  bool& done);

    // ---- 消费者：解密密文 ----
    void consumer(std::queue<Task>& taskQueue,
                  std::mutex& queueMutex,
                  std::condition_variable& queueCV,
                  bool& done,
                  std::queue<ResultItem>& resultQueue,
                  std::mutex& resultMutex,
                  std::condition_variable& resultCV,
                  bool& resultDone);
};

} // namespace decrypt