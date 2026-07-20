// connection_pool.cpp

#include "database/connection_pool.h"
#include <cstring>

namespace database {

// ---- ConnectionGuard ----
ConnectionGuard::ConnectionGuard(MYSQL* conn, std::mutex* mutex, std::vector<MYSQL*>* pool)
    : conn_(conn), mutex_(mutex), pool_(pool) {}

ConnectionGuard::~ConnectionGuard() {
    if (conn_) {
        std::lock_guard<std::mutex> lock(*mutex_);
        pool_->push_back(conn_);  // 归还连接
    }
}

// ---- ConnectionPool ----
void ConnectionPool::init(const std::string& host, const std::string& user,
                          const std::string& passwd, const std::string& db,
                          unsigned int port, size_t poolSize) {
    if (initialized_) return;
    host_ = host; user_ = user; passwd_ = passwd; db_ = db;
    port_ = port; poolSize_ = poolSize;

    mysql_library_init(0, nullptr, nullptr);

    for (size_t i = 0; i < poolSize_; ++i) {
        MYSQL* conn = createConnection();
        if (!conn) throw std::runtime_error("Failed to create MySQL connection");
        connections_.push_back(conn);
    }
    initialized_ = true;
}

MYSQL* ConnectionPool::createConnection() {
    MYSQL* conn = mysql_init(nullptr);
    if (!conn) return nullptr;

    bool reconnect = 1;
    mysql_options(conn, MYSQL_OPT_RECONNECT, &reconnect);
    mysql_options(conn, MYSQL_SET_CHARSET_NAME, "utf8mb4");

    if (!mysql_real_connect(conn, host_.c_str(), user_.c_str(), passwd_.c_str(),
                            db_.c_str(), port_, nullptr, 0)) {
        mysql_close(conn);
        return nullptr;
    }
    return conn;
}

std::unique_ptr<ConnectionGuard> ConnectionPool::getConnection() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (connections_.empty()) {
        throw std::runtime_error("No available MySQL connection");
    }
    MYSQL* conn = connections_.back();
    connections_.pop_back();

    // 检查连接是否存活，断开则重建
    if (mysql_ping(conn) != 0) {
        mysql_close(conn);
        conn = createConnection();
        if (!conn) throw std::runtime_error("Failed to reconnect MySQL");
    }
    return std::make_unique<ConnectionGuard>(conn, &mutex_, &connections_);
}

void ConnectionPool::closeAll() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (MYSQL* conn : connections_) mysql_close(conn);
    connections_.clear();
    mysql_library_end();
    initialized_ = false;
}

ConnectionPool::~ConnectionPool() { if (initialized_) closeAll(); }

ConnectionPool& getGlobalConnectionPool() {
    static ConnectionPool pool;
    return pool;
}

} // namespace database