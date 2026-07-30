// audit/index_rebuilder.h
// 索引重建执行器：支持断点续跑、分批处理

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <functional>
#include "database/dao.h"
#include "crypto/key_manager.h"

namespace rebuild {

// ---- 重建进度回调 ----
struct ProgressInfo {
    int64_t taskId;
    int64_t processed;      // 已处理记录数
    int64_t total;          // 总记录数 (end_id - start_id + 1)
    int successCount;
    int failCount;
    std::string currentId;  // 当前处理的 ID
};

// ---- 索引重建器 ----
class IndexRebuilder {
public:
    IndexRebuilder(database::DAO& dao, crypto::KeyManager& keyMgr);

    // ---- 执行重建任务 ----
    // 参数：
    //   taskId          : 任务ID
    //   batchSize       : 每批处理记录数（默认 100）
    //   progressCb      : 进度回调（可选）
    // 返回：成功重建的记录数，失败返回 -1
    int64_t runTask(int64_t taskId, int batchSize = 100,
                    std::function<void(const ProgressInfo&)> progressCb = nullptr);

    // ---- 便捷方法：创建并执行重建任务 ----
    int64_t rebuildField(int fieldCode, int64_t startId, int64_t endId,
                         int batchSize = 100,
                         std::function<void(const ProgressInfo&)> progressCb = nullptr);

private:
    database::DAO& dao_;
    crypto::KeyManager& keyMgr_;

    // 重建单条记录（返回 true 表示成功）
    bool rebuildOneRecord(const database::DAO::RebuildRawRecord& record,
                          int fieldCode,
                          const std::vector<unsigned char>& encKey,
                          const std::vector<unsigned char>& idxKey,
                          const std::vector<unsigned char>& tagKey,
                          std::string& errorMsg);
};

} // namespace rebuild