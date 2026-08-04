// batch_decryptor.h
// 生产者-消费者流水线批量解密（有界队列，I/O与计算重叠）

#pragma once

#include <vector>
#include <string>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <functional>
#include <cstdint>

#include "database/dao.h"
#include "crypto/key_manager.h"

namespace audit {
class AuditLogger;
}

namespace decrypt {

// ---- 解密结果 ----
struct DecryptResult {
    int64_t id{};
    std::string plaintext;
    bool success = false;
    std::string errorMsg;
    int keyVersion{};
};

// ---- 批量解密统计 ----
struct DecryptStats {
    size_t total{};
    size_t successCount{};
    size_t failCount{};
    double elapsedMs{};
};

// ---- 批量解密器 ----
class BatchDecryptor {
public:
    /**
     * @param dao          数据库访问对象
     * @param keyMgr       密钥管理器
     * @param workerCount  工作线程数（0表示自动根据CPU核心数设置）
     * @param queueCapacity 任务队列容量
     */
    BatchDecryptor(
        database::DAO& dao,
        crypto::KeyManager& keyMgr,
        size_t workerCount = 0,
        size_t queueCapacity = 32768
    );

    ~BatchDecryptor();

    // 禁止拷贝
    BatchDecryptor(const BatchDecryptor&) = delete;
    BatchDecryptor& operator=(const BatchDecryptor&) = delete;

    /**
     * @brief 解密内存中的密文列表（无I/O，纯CPU并行）
     * @param records   密文记录列表
     * @param requestId 请求ID（用于审计）
     * @param logger    审计日志器（可选）
     * @param progress  进度回调 (已完成数, 总数)
     * @return 解密结果列表（顺序与records一致）
     */
    std::vector<DecryptResult> decryptRecords(
        const std::vector<database::CipherRecord>& records,
        const std::string& requestId,
        audit::AuditLogger* logger = nullptr,
        std::function<void(size_t, size_t)> progress = nullptr
    );

    /**
     * @brief 从数据库批量解密记录（I/O + 计算流水线）
     * @param ids       记录ID列表
     * @param requestId 请求ID（用于审计）
     * @param logger    审计日志器（可选）
     * @param progress  进度回调 (已完成数, 总数)
     * @return 解密结果列表（顺序与ids一致）
     */
    std::vector<DecryptResult> decryptBatch(
        const std::vector<int64_t>& ids,
        const std::string& requestId,
        audit::AuditLogger* logger = nullptr,
        std::function<void(size_t, size_t)> progress = nullptr
    );

    // 获取最近一次解密的统计信息
    const DecryptStats& getLastStats() const { return stats_; }

private:
    // ---- 任务和结果结构 ----
    struct Task {
        database::CipherRecord record;
        size_t index;          // 全局顺序索引
    };

    struct ResultItem {
        size_t index;
        DecryptResult result;
    };

    // ---- 成员变量 ----
    database::DAO& dao_;
    crypto::KeyManager& keyMgr_;

    std::vector<std::thread> workers_;      // 工作线程池

    // 任务队列（有界）
    std::queue<Task> taskQueue_;
    std::mutex taskMutex_;
    std::condition_variable taskNotEmpty_;
    std::condition_variable taskNotFull_;
    size_t queueCapacity_;

    // 结果队列
    std::queue<ResultItem> resultQueue_;
    std::mutex resultMutex_;
    std::condition_variable resultReady_;

    std::atomic<bool> stop_{false};         // 停止标志

    // 审计与统计
    audit::AuditLogger* logger_{nullptr};
    std::string requestId_;
    DecryptStats stats_;

    // ---- 内部函数 ----
    void workerLoop();                      // 工作线程主循环
    void pushTask(Task&& task);             // 入队任务（可能阻塞）
    std::vector<DecryptResult> collectResults(size_t totalTasks, std::function<void(size_t,size_t)> progress);

    bool decryptOneRecord(
        const database::CipherRecord& record,
        std::string& plaintext,
        std::string& error,
        int& keyVersion
    );
};

} // namespace decrypt