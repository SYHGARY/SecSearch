// audit/audit_logger.cpp
// 审计日志实现

#include "audit/audit_logger.h"
#include <mysql/mysql.h>
#include <chrono>
#include <random>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <cstring>

namespace audit {

// ---- 构造函数 ----
AuditLogger::AuditLogger(database::ConnectionPool* pool)
    : pool_(pool) {
    if (!pool_) {
        throw std::runtime_error("AuditLogger: ConnectionPool cannot be null");
    }
}

// ---- 获取数据库连接 ----
std::unique_ptr<database::ConnectionGuard> AuditLogger::getConnection() {
    return pool_->getConnection();
}

// ---- 生成唯一请求ID ----
std::string AuditLogger::generateRequestId() {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    static std::uniform_int_distribution<uint64_t> dis;

    auto now = std::chrono::system_clock::now().time_since_epoch().count();
    uint64_t randPart = dis(gen);

    std::stringstream ss;
    ss << std::hex << std::setw(16) << std::setfill('0') << now
       << std::setw(16) << std::setfill('0') << randPart;
    return ss.str();
}

// ---- 记录操作审计日志 ----
void AuditLogger::logOperation(const std::string& requestId,
                               const std::string& operation,
                               int fieldCode,
                               int candidateCount,
                               int resultCount,
                               int durationMs,
                               bool success,
                               const std::string& errorMsg) {
    try {
        auto guard = getConnection();
        MYSQL* conn = guard->get();

        const char* sql = R"(
            INSERT INTO audit_log
            (request_id, operator, operation, field_code, candidate_count,
             result_count, duration_ms, status, error_msg)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        )";

        MYSQL_STMT* stmt = mysql_stmt_init(conn);
        if (!stmt) {
            std::cerr << "WARNING: AuditLogger - mysql_stmt_init failed" << std::endl;
            return;
        }

        if (mysql_stmt_prepare(stmt, sql, strlen(sql)) != 0) {
            std::cerr << "WARNING: AuditLogger - prepare failed: " << mysql_stmt_error(stmt) << std::endl;
            mysql_stmt_close(stmt);
            return;
        }

        std::string operatorName = "system";
        uint8_t status = success ? 1 : 0;
        const char* errMsg = errorMsg.empty() ? nullptr : errorMsg.c_str();

        MYSQL_BIND bind[9];
        memset(bind, 0, sizeof(bind));

        // 每个字段的 NULL 标志
        bool nullFlags[9] = {false, false, false, false, false, false, false, false, false};

        // 1. request_id
        bind[0].buffer_type = MYSQL_TYPE_STRING;
        bind[0].buffer = (char*)requestId.c_str();
        bind[0].buffer_length = requestId.size();
        bind[0].is_null = &nullFlags[0];

        // 2. operator
        bind[1].buffer_type = MYSQL_TYPE_STRING;
        bind[1].buffer = (char*)operatorName.c_str();
        bind[1].buffer_length = operatorName.size();
        bind[1].is_null = &nullFlags[1];

        // 3. operation
        bind[2].buffer_type = MYSQL_TYPE_STRING;
        bind[2].buffer = (char*)operation.c_str();
        bind[2].buffer_length = operation.size();
        bind[2].is_null = &nullFlags[2];

        // 4. field_code
        bind[3].buffer_type = MYSQL_TYPE_TINY;
        bind[3].buffer = (char*)&fieldCode;
        bind[3].is_null = &nullFlags[3];

        // 5. candidate_count
        bind[4].buffer_type = MYSQL_TYPE_LONG;
        bind[4].buffer = (char*)&candidateCount;
        bind[4].is_null = &nullFlags[4];

        // 6. result_count
        bind[5].buffer_type = MYSQL_TYPE_LONG;
        bind[5].buffer = (char*)&resultCount;
        bind[5].is_null = &nullFlags[5];

        // 7. duration_ms
        bind[6].buffer_type = MYSQL_TYPE_LONG;
        bind[6].buffer = (char*)&durationMs;
        bind[6].is_null = &nullFlags[6];

        // 8. status
        bind[7].buffer_type = MYSQL_TYPE_TINY;
        bind[7].buffer = (char*)&status;
        bind[7].is_null = &nullFlags[7];

        // 9. error_msg (可能为 NULL)
        nullFlags[8] = (errMsg == nullptr);
        bind[8].is_null = &nullFlags[8];
        if (errMsg) {
            bind[8].buffer_type = MYSQL_TYPE_STRING;
            bind[8].buffer = (char*)errMsg;
            bind[8].buffer_length = strlen(errMsg);
        } else {
            //  当值为 NULL 时，使用 MYSQL_TYPE_NULL
            bind[8].buffer_type = MYSQL_TYPE_NULL;
            bind[8].buffer = nullptr;
            bind[8].buffer_length = 0;
        }

        if (mysql_stmt_bind_param(stmt, bind) != 0) {
            std::cerr << "WARNING: AuditLogger - bind param failed: " << mysql_stmt_error(stmt) << std::endl;
            mysql_stmt_close(stmt);
            return;
        }

        if (mysql_stmt_execute(stmt) != 0) {
            std::cerr << "WARNING: AuditLogger - execute failed: " << mysql_stmt_error(stmt) << std::endl;
        }

        mysql_stmt_close(stmt);

    } catch (const std::exception& e) {
        std::cerr << "WARNING: AuditLogger exception: " << e.what() << std::endl;
    }
}

// ---- 记录解密错误日志 ----
void AuditLogger::logDecryptError(const std::string& requestId,
                                  int64_t recordId,
                                  const std::string& errorType) {
    try {
        auto guard = getConnection();
        MYSQL* conn = guard->get();

        const char* sql = R"(
            INSERT INTO decrypt_error_log (request_id, record_id, error_type)
            VALUES (?, ?, ?)
        )";

        MYSQL_STMT* stmt = mysql_stmt_init(conn);
        if (!stmt) {
            std::cerr << "WARNING: AuditLogger - mysql_stmt_init failed" << std::endl;
            return;
        }

        if (mysql_stmt_prepare(stmt, sql, strlen(sql)) != 0) {
            std::cerr << "WARNING: AuditLogger - prepare failed: " << mysql_stmt_error(stmt) << std::endl;
            mysql_stmt_close(stmt);
            return;
        }

        MYSQL_BIND bind[3];
        memset(bind, 0, sizeof(bind));

        // NULL 标志数组（所有字段均非空）
        bool nullFlags[3] = {false, false, false};

        bind[0].buffer_type = MYSQL_TYPE_STRING;
        bind[0].buffer = (char*)requestId.c_str();
        bind[0].buffer_length = requestId.size();
        bind[0].is_null = &nullFlags[0];

        bind[1].buffer_type = MYSQL_TYPE_LONGLONG;
        bind[1].buffer = (char*)&recordId;
        bind[1].is_null = &nullFlags[1];

        bind[2].buffer_type = MYSQL_TYPE_STRING;
        bind[2].buffer = (char*)errorType.c_str();
        bind[2].buffer_length = errorType.size();
        bind[2].is_null = &nullFlags[2];

        if (mysql_stmt_bind_param(stmt, bind) != 0) {
            std::cerr << "WARNING: AuditLogger - bind param failed: " << mysql_stmt_error(stmt) << std::endl;
            mysql_stmt_close(stmt);
            return;
        }

        if (mysql_stmt_execute(stmt) != 0) {
            std::cerr << "WARNING: AuditLogger - execute failed: " << mysql_stmt_error(stmt) << std::endl;
        }

        mysql_stmt_close(stmt);

    } catch (const std::exception& e) {
        std::cerr << "WARNING: AuditLogger exception: " << e.what() << std::endl;
    }
}

} // namespace audit