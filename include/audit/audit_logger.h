// audit/audit_logger.h
// 独立安全审计模块：记录操作日志和解密错误日志
// 不依赖 DAO，只依赖 ConnectionPool，避免循环依赖

#pragma once

#include <string>
#include <cstdint>
#include <memory>
#include "database/connection_pool.h"

namespace audit {

// ---- 操作类型常量 ----
namespace Operation {
    const std::string INSERT         = "INSERT";
    const std::string EXACT_QUERY    = "EXACT_QUERY";
    const std::string FUZZY_QUERY    = "FUZZY_QUERY";
    const std::string UPDATE         = "UPDATE";
    const std::string DELETE         = "DELETE";
    const std::string BATCH_DECRYPT  = "BATCH_DECRYPT";
}

// ---- 解密错误类型常量 ----
namespace DecryptErrorType {
    const std::string TAG_MISMATCH      = "TAG_MISMATCH";
    const std::string DECRYPT_FAILED    = "DECRYPT_FAILED";
    const std::string KEY_NOT_FOUND     = "KEY_NOT_FOUND";
    const std::string CIPHER_CORRUPTED  = "CIPHER_CORRUPTED";
    const std::string UNKNOWN           = "UNKNOWN";
}

// ---- 审计日志记录器 ----
class AuditLogger {
public:
    // 构造函数：接收数据库连接池（共享）
    explicit AuditLogger(database::ConnectionPool* pool);

    // ---- 记录操作审计日志 ----
    // 参数：
    //   requestId     : 请求唯一标识
    //   operation     : 操作类型（见 Operation::xxx）
    //   fieldCode     : 字段类型（1-姓名, 2-手机号, 3-地址），0表示不适用
    //   candidateCount: 候选记录数（查询时使用）
    //   resultCount   : 最终返回记录数 / 受影响行数
    //   durationMs    : 耗时（毫秒）
    //   success       : 是否成功
    //   errorMsg      : 错误信息（可选）
    void logOperation(const std::string& requestId,
                      const std::string& operation,
                      int fieldCode,
                      int candidateCount,
                      int resultCount,
                      int durationMs,
                      bool success,
                      const std::string& errorMsg = "");

    // ---- 记录解密错误日志 ----
    // 参数：
    //   requestId : 关联的请求ID
    //   recordId  : 数据主键ID
    //   errorType : 错误类型（见 DecryptErrorType::xxx）
    void logDecryptError(const std::string& requestId,
                         int64_t recordId,
                         const std::string& errorType);

    // ---- 工具：生成唯一请求ID（基于时间+随机数） ----
    static std::string generateRequestId();

private:
    database::ConnectionPool* pool_;

    // 获取数据库连接的辅助方法
    std::unique_ptr<database::ConnectionGuard> getConnection();
};

} // namespace audit