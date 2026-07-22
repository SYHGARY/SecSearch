// transaction.cpp
// 实现 RAII 事务

#include "database/transaction.h"
#include <stdexcept>

namespace database {

// 构造：开始事务
Transaction::Transaction(MYSQL* conn) : conn_(conn) {
    if (mysql_real_query(conn_, "START TRANSACTION", 17) != 0) {
        throw std::runtime_error("Failed to start transaction");
    }
}

// ★ 析构：如果未提交则自动回滚
Transaction::~Transaction() {
    if (!committed_) {
        mysql_real_query(conn_, "ROLLBACK", 7);
    }
}

// 提交事务
void Transaction::commit() {
    if (committed_) return;
    if (mysql_real_query(conn_, "COMMIT", 6) != 0) {
        throw std::runtime_error("Failed to commit transaction");
    }
    committed_ = true;
}

// 手动回滚
void Transaction::rollback() {
    if (committed_) return;
    mysql_real_query(conn_, "ROLLBACK", 7);
    committed_ = true;
}

} // namespace database