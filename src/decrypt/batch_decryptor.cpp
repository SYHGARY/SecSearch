// batch_decryptor.cpp
// 生产者-消费者流水线批量解密实现

#include "decrypt/batch_decryptor.h"
#include "crypto/sm4_cipher.h"
#include "crypto/hmac_sm3.h"
#include "audit/audit_logger.h"

#include <chrono>
#include <algorithm>
#include <thread>
#include <cassert>

namespace decrypt {

// ---- 构造函数 ----
BatchDecryptor::BatchDecryptor(
        database::DAO& dao,
        crypto::KeyManager& keyMgr,
        size_t workerCount,
        size_t queueCapacity)
    : dao_(dao),
      keyMgr_(keyMgr),
      queueCapacity_(queueCapacity) {
    if (workerCount == 0) {
        workerCount = 4;
        // std::max<size_t>(2, std::thread::hardware_concurrency());
    }
    for (size_t i = 0; i < workerCount; ++i) {
        workers_.emplace_back(&BatchDecryptor::workerLoop, this);
    }
}

// ---- 析构函数 ----
BatchDecryptor::~BatchDecryptor() {
    stop_ = true;
    taskNotEmpty_.notify_all();
    taskNotFull_.notify_all();
    resultReady_.notify_all();
    for (auto& t : workers_) {
        if (t.joinable()) t.join();
    }
}

// ---- 解密单条记录 ----
bool BatchDecryptor::decryptOneRecord(
        const database::CipherRecord& record,
        std::string& plaintext,
        std::string& error,
        int& keyVersion) {
    try {
        keyVersion = record.encKeyVersion;

        std::vector<unsigned char> tagKey;
        if (!keyMgr_.getTagKeyByVersion(record.encKeyVersion, tagKey)) {
            error = "Tag key version " + std::to_string(record.encKeyVersion) + " not found";
            return false;
        }

        std::vector<unsigned char> cipherBytes(record.cipher.begin(), record.cipher.end());
        std::string calcTag = crypto::HmacSm3::hmacHex(cipherBytes, tagKey);
        if (calcTag != record.tag) {
            error = "Tag verification failed";
            return false;
        }

        std::vector<unsigned char> encKey;
        if (!keyMgr_.getEncryptionKeyByVersion(record.encKeyVersion, encKey)) {
            error = "Encryption key version " + std::to_string(record.encKeyVersion) + " not found";
            return false;
        }

        auto plain = crypto::Sm4Cipher::decrypt(record.cipher, encKey);
        plaintext.assign(plain.begin(), plain.end());

        return true;
    } catch (const std::exception& e) {
        error = e.what();
        return false;
    }
}

// ---- 将任务推入队列（可能阻塞直到队列有空间） ----
void BatchDecryptor::pushTask(Task&& task) {
    std::unique_lock<std::mutex> lock(taskMutex_);
    taskNotFull_.wait(lock, [this]() {
        return stop_ || taskQueue_.size() < queueCapacity_;
    });
    if (stop_) return;
    taskQueue_.push(std::move(task));
    taskNotEmpty_.notify_one();
}

// ---- 工作线程主循环 ----
void BatchDecryptor::workerLoop() {
    while (true) {
        Task task;
        {
            std::unique_lock<std::mutex> lock(taskMutex_);
            taskNotEmpty_.wait(lock, [this]() {
                return stop_ || !taskQueue_.empty();
            });
            if (stop_ && taskQueue_.empty()) {
                return;
            }
            task = std::move(taskQueue_.front());
            taskQueue_.pop();
            taskNotFull_.notify_one();
        }

        // ---- 执行解密 ----
        DecryptResult result;
        result.id = task.record.id;
        std::string plain, error;
        int version = 0;
        bool ok = decryptOneRecord(task.record, plain, error, version);
        result.success = ok;
        result.keyVersion = version;
        if (ok) {
            result.plaintext = std::move(plain);
        } else {
            result.errorMsg = std::move(error);
            if (logger_) {
                std::string errorType = audit::DecryptErrorType::DECRYPT_FAILED;
                if (error.find("Tag") != std::string::npos)
                    errorType = audit::DecryptErrorType::TAG_MISMATCH;
                else if (error.find("key") != std::string::npos || error.find("version") != std::string::npos)
                    errorType = audit::DecryptErrorType::KEY_NOT_FOUND;
                logger_->logDecryptError(requestId_, task.record.id, errorType);
            }
        }

        // ---- 放入结果队列 ----
        {
            std::lock_guard<std::mutex> lock(resultMutex_);
            resultQueue_.push(ResultItem{task.index, std::move(result)});
        }
        resultReady_.notify_one();
    }
}

// ---- 收集结果（供 decryptRecords 和 decryptBatch 复用） ----
std::vector<DecryptResult> BatchDecryptor::collectResults(
        size_t totalTasks,
        std::function<void(size_t, size_t)> progress) {
    std::vector<DecryptResult> results(totalTasks);
    size_t finished = 0;
    while (finished < totalTasks) {
        ResultItem item;
        {
            std::unique_lock<std::mutex> lock(resultMutex_);
            resultReady_.wait(lock, [this]() {
                return !resultQueue_.empty();
            });
            item = std::move(resultQueue_.front());
            resultQueue_.pop();
        }
        assert(item.index < results.size());
        results[item.index] = std::move(item.result);
        ++finished;
        if (progress) {
            progress(finished, totalTasks);
        }
    }
    return results;
}

// ---- 解密内存中的密文列表（纯CPU并行） ----
std::vector<DecryptResult> BatchDecryptor::decryptRecords(
        const std::vector<database::CipherRecord>& records,
        const std::string& requestId,
        audit::AuditLogger* logger,
        std::function<void(size_t, size_t)> progress) {
    auto start = std::chrono::steady_clock::now();

    logger_ = logger;
    requestId_ = requestId;

    const size_t total = records.size();
    if (total == 0) {
        stats_ = {0, 0, 0, 0.0};
        return {};
    }

    // 提交所有任务
    size_t index = 0;
    for (const auto& rec : records) {
        pushTask(Task{rec, index++});
    }

    // 收集结果
    auto results = collectResults(total, progress);

    // 统计
    stats_.total = total;
    stats_.successCount = 0;
    stats_.failCount = 0;
    for (const auto& r : results) {
        if (r.success) ++stats_.successCount;
        else ++stats_.failCount;
    }

    auto end = std::chrono::steady_clock::now();
    stats_.elapsedMs = std::chrono::duration<double, std::milli>(end - start).count();

    return results;
}

// ---- 从数据库批量解密（I/O + 计算流水线） ----
std::vector<DecryptResult> BatchDecryptor::decryptBatch(
        const std::vector<int64_t>& ids,
        const std::string& requestId,
        audit::AuditLogger* logger,
        std::function<void(size_t, size_t)> progress) {
    auto start = std::chrono::steady_clock::now();

    logger_ = logger;
    requestId_ = requestId;

    const size_t totalIds = ids.size();
    if (totalIds == 0) {
        stats_ = {0, 0, 0, 0.0};
        return {};
    }

    const size_t IO_BATCH = 32768;
    size_t index = 0;

    // 生产者：循环读取并提交任务
    for (size_t offset = 0; offset < ids.size(); offset += IO_BATCH) {
        size_t end = std::min(offset + IO_BATCH, ids.size());
        std::vector<int64_t> batchIds(ids.begin() + offset, ids.begin() + end);
        auto records = dao_.batchSelectCiphers(batchIds);
        for (auto& rec : records) {
            pushTask(Task{std::move(rec), index++});
        }
    }

    // 收集结果
    auto results = collectResults(index, progress);

    // 统计
    stats_.total = index;
    stats_.successCount = 0;
    stats_.failCount = 0;
    for (const auto& r : results) {
        if (r.success) ++stats_.successCount;
        else ++stats_.failCount;
    }

    auto end = std::chrono::steady_clock::now();
    stats_.elapsedMs = std::chrono::duration<double, std::milli>(end - start).count();

    return results;
}

} // namespace decrypt