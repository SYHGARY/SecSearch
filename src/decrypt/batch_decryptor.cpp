// batch_decryptor.cpp
// 实现生产者-消费者流水线批量解密
// 集成安全审计模块

#include "decrypt/batch_decryptor.h"
#include "crypto/sm4_cipher.h"
#include "crypto/hmac_sm3.h"
#include "audit/audit_logger.h"

#include <thread>
#include <chrono>
#include <stdexcept>
#include <algorithm>
#include <unordered_map>
#include <iostream>

namespace decrypt {

// ---- 构造函数 ----
BatchDecryptor::BatchDecryptor(database::DAO& dao, crypto::KeyManager& keyMgr)
    : dao_(dao), keyMgr_(keyMgr) {}

// ---- 解密单个记录 ----
bool BatchDecryptor::decryptOneRecord(const database::CipherRecord& record,
                                      std::string& plaintext,
                                      std::string& errorMsg,
                                      int& keyVersion) {
    try {
        keyVersion = record.encKeyVersion;

        // 1. 获取对应版本的 Tag 密钥
        std::vector<unsigned char> tagKey;
        if (!keyMgr_.getTagKeyByVersion(record.encKeyVersion, tagKey)) {
            errorMsg = "Tag key version " + std::to_string(record.encKeyVersion) + " not found";
            return false;
        }

        // 2. 验证 Tag
        auto cipherBytes = std::vector<unsigned char>(record.cipher.begin(), record.cipher.end());
        std::string computedTag = crypto::HmacSm3::hmacHex(cipherBytes, tagKey);
        if (computedTag != record.tag) {
            errorMsg = "Integrity check failed (Tag mismatch)";
            return false;
        }

        // 3. 获取对应版本的加密密钥
        std::vector<unsigned char> encKey;
        if (!keyMgr_.getEncryptionKeyByVersion(record.encKeyVersion, encKey)) {
            errorMsg = "Encryption key version " + std::to_string(record.encKeyVersion) + " not found";
            return false;
        }

        // 4. 解密
        auto plainBytes = crypto::Sm4Cipher::decrypt(record.cipher, encKey);
        plaintext = std::string(plainBytes.begin(), plainBytes.end());
        return true;

    } catch (const std::exception& e) {
        errorMsg = e.what();
        return false;
    }
}

// ---- 生产者：将记录推入队列 ----
void BatchDecryptor::producer(const std::vector<database::CipherRecord>& records,
                              std::queue<Task>& taskQueue,
                              std::mutex& queueMutex,
                              std::condition_variable& queueCV,
                              bool& done) {
    for (size_t i = 0; i < records.size(); ++i) {
        Task task;
        task.record = records[i];
        task.index = i;
        {
            std::lock_guard<std::mutex> lock(queueMutex);
            taskQueue.push(task);
        }
        queueCV.notify_one();
    }

    // 标记生产者完成
    {
        std::lock_guard<std::mutex> lock(queueMutex);
        done = true;
    }
    queueCV.notify_all();
}

// ---- 消费者：解密密文（带审计日志） ----
void BatchDecryptor::consumer(std::queue<Task>& taskQueue,
                              std::mutex& queueMutex,
                              std::condition_variable& queueCV,
                              bool& done,
                              std::queue<ResultItem>& resultQueue,
                              std::mutex& resultMutex,
                              std::condition_variable& resultCV,
                              bool& resultDone) {
    while (true) {
        Task task;
        bool hasTask = false;

        {
            std::unique_lock<std::mutex> lock(queueMutex);
            queueCV.wait(lock, [&] { return !taskQueue.empty() || done; });

            if (!taskQueue.empty()) {
                task = taskQueue.front();
                taskQueue.pop();
                hasTask = true;
            } else if (done) {
                break;
            }
        }

        if (hasTask) {
            ResultItem item;
            item.index = task.index;
            item.result.id = task.record.id;

            std::string plaintext, errorMsg;
            int keyVersion;
            bool success = decryptOneRecord(task.record, plaintext, errorMsg, keyVersion);

            item.result.success = success;
            item.result.plaintext = success ? plaintext : "";
            item.result.errorMsg = success ? "" : errorMsg;
            item.result.keyVersion = keyVersion;

            // ★ 如果解密失败且有审计器，记录错误日志
            if (!success && auditLogger_) {
                std::string errorType = audit::DecryptErrorType::DECRYPT_FAILED;
                if (errorMsg.find("Tag mismatch") != std::string::npos)
                    errorType = audit::DecryptErrorType::TAG_MISMATCH;
                else if (errorMsg.find("key") != std::string::npos || errorMsg.find("version") != std::string::npos)
                    errorType = audit::DecryptErrorType::KEY_NOT_FOUND;
                else if (errorMsg.find("Invalid") != std::string::npos)
                    errorType = audit::DecryptErrorType::CIPHER_CORRUPTED;
                auditLogger_->logDecryptError(currentRequestId_, task.record.id, errorType);
            }

            {
                std::lock_guard<std::mutex> lock(resultMutex);
                resultQueue.push(item);
            }
            resultCV.notify_one();
        }
    }
}

// ---- ★ 核心方法：解密 CipherRecord 列表（生产者-消费者） ----
std::vector<DecryptResult> BatchDecryptor::decryptRecords(
    const std::vector<database::CipherRecord>& records,
    const std::string& requestId,
    audit::AuditLogger* auditLogger,
    std::function<void(size_t, size_t)> progressCb) {

    auto startTime = std::chrono::steady_clock::now();

    // ★ 保存当前请求的审计器，供消费者线程使用
    auditLogger_ = auditLogger;
    currentRequestId_ = requestId;

    const size_t total = records.size();
    if (total == 0) {
        lastStats_ = {0, 0, 0, 0.0};
        auditLogger_ = nullptr;
        currentRequestId_.clear();
        return {};
    }

    // ★ 预分配结果向量（保证顺序）
    std::vector<DecryptResult> results(total);

    // 如果数据量很小，直接串行解密（避免线程开销）
    if (total <= 4) {
        for (size_t i = 0; i < total; ++i) {
            results[i].id = records[i].id;
            std::string plaintext, errorMsg;
            int keyVersion;
            bool success = decryptOneRecord(records[i], plaintext, errorMsg, keyVersion);
            results[i].success = success;
            results[i].plaintext = success ? plaintext : "";
            results[i].errorMsg = success ? "" : errorMsg;
            results[i].keyVersion = keyVersion;

            // ★ 记录失败
            if (!success && auditLogger_) {
                std::string errorType = audit::DecryptErrorType::DECRYPT_FAILED;
                if (errorMsg.find("Tag mismatch") != std::string::npos)
                    errorType = audit::DecryptErrorType::TAG_MISMATCH;
                else if (errorMsg.find("key") != std::string::npos || errorMsg.find("version") != std::string::npos)
                    errorType = audit::DecryptErrorType::KEY_NOT_FOUND;
                else if (errorMsg.find("Invalid") != std::string::npos)
                    errorType = audit::DecryptErrorType::CIPHER_CORRUPTED;
                auditLogger_->logDecryptError(currentRequestId_, records[i].id, errorType);
            }

            if (progressCb) progressCb(i + 1, total);
        }

        auto endTime = std::chrono::steady_clock::now();
        lastStats_ = {
            .total = total,
            .successCount = 0,
            .failCount = 0,
            .elapsedMs = std::chrono::duration<double, std::milli>(endTime - startTime).count()
        };
        for (const auto& r : results) {
            if (r.success) lastStats_.successCount++;
            else lastStats_.failCount++;
        }

        auditLogger_ = nullptr;
        currentRequestId_.clear();
        return results;
    }

    // ---- ★ 流水线数据结构 ----
    std::queue<Task> taskQueue;
    std::mutex queueMutex;
    std::condition_variable queueCV;
    bool done = false;

    std::queue<ResultItem> resultQueue;
    std::mutex resultMutex;
    std::condition_variable resultCV;
    bool resultDone = false;

    // 消费者线程数（可根据 CPU 核心数调整）
    const int NUM_CONSUMERS = 3;

    // ---- 启动生产者线程 ----
    std::thread producerThread([this, &records, &taskQueue, &queueMutex, &queueCV, &done]() {
        producer(records, taskQueue, queueMutex, queueCV, done);
    });

    // ---- 启动消费者线程 ----
    std::vector<std::thread> consumerThreads;
    for (int i = 0; i < NUM_CONSUMERS; ++i) {
        consumerThreads.emplace_back([this, &taskQueue, &queueMutex, &queueCV, &done,
                                       &resultQueue, &resultMutex, &resultCV, &resultDone]() {
            consumer(taskQueue, queueMutex, queueCV, done,
                     resultQueue, resultMutex, resultCV, resultDone);
        });
    }

    // ---- 主线程：收集结果 ----
    size_t processed = 0;

    while (processed < total) {
        std::unique_lock<std::mutex> lock(resultMutex);
        resultCV.wait(lock, [&] { return !resultQueue.empty(); });

        while (!resultQueue.empty()) {
            auto item = resultQueue.front();
            resultQueue.pop();
            results[item.index] = item.result;
            processed++;

            if (progressCb) {
                progressCb(processed, total);
            }
        }
    }

    // ---- 等待所有线程结束 ----
    producerThread.join();
    for (auto& t : consumerThreads) {
        t.join();
    }

    // ---- 统计 ----
    size_t successCount = 0, failCount = 0;
    for (const auto& r : results) {
        if (r.success) successCount++;
        else failCount++;
    }

    auto endTime = std::chrono::steady_clock::now();

    lastStats_ = {
        .total = total,
        .successCount = successCount,
        .failCount = failCount,
        .elapsedMs = std::chrono::duration<double, std::milli>(endTime - startTime).count()
    };

    auditLogger_ = nullptr;
    currentRequestId_.clear();
    return results;
}

// ---- 批量解密（从数据库读取） ----
std::vector<DecryptResult> BatchDecryptor::decryptBatch(
    const std::vector<int64_t>& ids,
    const std::string& requestId,
    audit::AuditLogger* auditLogger,
    std::function<void(size_t, size_t)> progressCb) {

    if (ids.empty()) {
        lastStats_ = {0, 0, 0, 0.0};
        return {};
    }

    // ★ 批量读取密文
    auto records = dao_.batchSelectCiphers(ids);

    // ★ 调用核心方法
    return decryptRecords(records, requestId, auditLogger, progressCb);
}

} // namespace decrypt