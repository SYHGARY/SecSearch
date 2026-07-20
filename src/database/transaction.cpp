// transaction.cpp

#include "database/transaction.h"
#include <stdexcept>

namespace database {

Transaction::Transaction(MYSQL* conn) : conn_(conn) {
    if (mysql_real_query(conn_, "START TRANSACTION", 17) != 0) {
        throw std::runtime_error("Failed to start transaction");
    }
}

Transaction::~Transaction() {
    if (!committed_) {
        mysql_real_query(conn_, "ROLLBACK", 7);
    }
}

void Transaction::commit() {
    if (committed_) return;
    if (mysql_real_query(conn_, "COMMIT", 6) != 0) {
        throw std::runtime_error("Failed to commit transaction");
    }
    committed_ = true;
}

void Transaction::rollback() {
    if (committed_) return;
    mysql_real_query(conn_, "ROLLBACK", 7);
    committed_ = true;
}

} // namespace database