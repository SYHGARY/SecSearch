// connection_pool.h
// 功能：管理 MySQL 连接池，支持多线程安全获取/归还

#pragma once

#include <mysql/mysql.h>
#include <string>
#include <vector>
#include <mutex>
#include <memory>
#include <stdexcept>

namespace database {

// RAII 连接守卫：构造时从池中取出，析构时自动归还
class ConnectionGuard {
public:
    ConnectionGuard(MYSQL* conn, std::mutex* mutex, std::vector<MYSQL*>* pool);
    ~ConnectionGuard();
    MYSQL* get() { return conn_; }
    
    ConnectionGuard(const ConnectionGuard&) = delete;
    ConnectionGuard& operator=(const ConnectionGuard&) = delete;

private:
    MYSQL* conn_;
    std::mutex* mutex_;
    std::vector<MYSQL*>* pool_;
};

// 连接池
class ConnectionPool {
public:
    void init(const std::string& host, const std::string& user,
              const std::string& passwd, const std::string& db,
              unsigned int port = 3306, size_t poolSize = 10);
    
    std::unique_ptr<ConnectionGuard> getConnection();
    void closeAll();
    ~ConnectionPool();

private:
    std::string host_, user_, passwd_, db_;
    unsigned int port_;
    size_t poolSize_;
    std::vector<MYSQL*> connections_;
    std::mutex mutex_;
    bool initialized_ = false;

    MYSQL* createConnection();
    void destroyConnection(MYSQL* conn);
};

// 全局单例
ConnectionPool& getGlobalConnectionPool();

} // namespace database