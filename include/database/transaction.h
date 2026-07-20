// transaction.h
// RAII 事务：构造时 BEGIN，析构时自动 ROLLBACK（除非调用 commit）

#pragma once

#include <mysql/mysql.h>

namespace database {

class Transaction {
public:
    explicit Transaction(MYSQL* conn);
    ~Transaction();

    void commit();    // 提交事务
    void rollback();  // 手动回滚（通常由析构自动处理）

    Transaction(const Transaction&) = delete;
    Transaction& operator=(const Transaction&) = delete;

private:
    MYSQL* conn_;
    bool committed_ = false;
};

} // namespace database