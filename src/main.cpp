// main.cpp
// 交互式命令行程序，提供增删改查功能
// 支持密钥多版本管理、主动轮换、定时轮换、持久化到 key_config 表
// 主密钥 KEK 从密钥文件读取，不再硬编码
// 基于 OpenHiTLS 加密库
// 集成安全审计模块（独立 audit 组件）
// 集成索引重建模块

#include "database/dao.h"
#include "database/connection_pool.h"
#include "query/query_service.h"
#include "crypto/key_manager.h"
#include "crypto/sm4_cipher.h"
#include "crypto/hmac_sm3.h"
#include "crypto/utils.h"
#include "audit/audit_logger.h"
#include "audit/index_rebuilder.h"

#include <hitls/crypto/crypt_eal_init.h>
#include <hitls/crypto/crypt_errno.h>

#include <iostream>
#include <string>
#include <limits>
#include <vector>
#include <iomanip>
#include <cstring>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <algorithm>
#include <memory>

#ifdef _WIN32
    #include <conio.h>
#else
    #include <termios.h>
    #include <unistd.h>
#endif

using namespace database;
using namespace query;

// ---- 全局变量 ----
crypto::KeyManager g_keyMgr;
std::vector<unsigned char> g_encKey;
std::vector<unsigned char> g_idxKey;
std::vector<unsigned char> g_tagKey;

// ---- ★ 全局审计日志器 ----
std::unique_ptr<audit::AuditLogger> g_auditLogger;

// ---- 定时轮换配置 ----
const int AUTO_ROTATE_DAYS = 90;
const std::string ROTATE_TIME_FILE = ".key_rotate_time";

// ---- ★ 密钥文件搜索路径 ----
const std::vector<std::string> KEK_SEARCH_PATHS = {
    "/etc/secsearch/kek.key",
    "/usr/local/etc/secsearch/kek.key",
    "/home/songyihang/.secsearch/kek.key",
    "./kek.key",
    "./.kek.key"
};

// ---- 辅助函数 ----

std::string getStringInput(const std::string& prompt) {
    std::string value;
    std::cout << prompt;
    std::getline(std::cin, value);
    return value;
}

int getIntInput(const std::string& prompt, int defaultVal = 0) {
    std::string line;
    while (true) {
        std::cout << prompt;
        std::getline(std::cin, line);
        if (line.empty()) return defaultVal;
        try {
            return std::stoi(line);
        } catch (const std::exception&) {
            std::cout << "输入无效，请输入数字。" << std::endl;
        }
    }
}

std::string getPasswordInput(const std::string& prompt) {
    std::cout << prompt;
    std::string password;
#ifdef _WIN32
    char ch;
    while ((ch = _getch()) != '\r') {
        if (ch == '\b') {
            if (!password.empty()) {
                password.pop_back();
                std::cout << "\b \b";
            }
        } else if (ch != '\r') {
            password.push_back(ch);
            std::cout << '*';
        }
    }
    std::cout << std::endl;
#else
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    std::getline(std::cin, password);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cout << std::endl;
#endif
    return password;
}

FieldType getFieldType() {
    std::cout << "请选择字段类型：" << std::endl;
    std::cout << "  1. 姓名" << std::endl;
    std::cout << "  2. 手机号" << std::endl;
    std::cout << "  3. 地址" << std::endl;
    int choice = getIntInput("请输入数字 (1-3): ", 1);
    switch (choice) {
        case 1: return FieldType::NAME;
        case 2: return FieldType::PHONE;
        case 3: return FieldType::ADDRESS;
        default: return FieldType::NAME;
    }
}

void printFullRecords(const std::vector<FullRecord>& results) {
    if (results.empty()) {
        std::cout << "未找到匹配记录。" << std::endl;
        return;
    }

    std::cout << "\n查询结果（共 " << results.size() << " 条）：" << std::endl;
    std::cout << "+-----+------------------+------------------+----------------------------------------+-------+" << std::endl;
    std::cout << "| ID  | 姓名             | 手机号           | 地址                                   | 密钥版本 |" << std::endl;
    std::cout << "+-----+------------------+------------------+----------------------------------------+-------+" << std::endl;

    for (const auto& r : results) {
        std::string name = r.name.size() > 16 ? r.name.substr(0, 13) + "..." : r.name;
        std::string phone = r.phone.size() > 16 ? r.phone.substr(0, 13) + "..." : r.phone;
        std::string addr = r.address.size() > 38 ? r.address.substr(0, 35) + "..." : r.address;

        std::cout << "| " << std::setw(3) << r.id << " | "
                  << std::setw(16) << name << " | "
                  << std::setw(16) << phone << " | "
                  << std::setw(38) << addr << " | "
                  << std::setw(5) << r.encKeyVersion << " |" << std::endl;
    }
    std::cout << "+-----+------------------+------------------+----------------------------------------+-------+" << std::endl;
}

// ---- ★ 查找密钥文件 ----
std::string findKEKFile() {
    for (const auto& path : KEK_SEARCH_PATHS) {
        std::ifstream test(path);
        if (test.is_open()) {
            test.close();
            return path;
        }
    }
    return "";
}

// ---- 定时轮换检查和执行 ----
bool checkAndAutoRotate(database::DAO& dao) {
    g_keyMgr.loadRotateTimeFromFile(ROTATE_TIME_FILE);
    auto lastTime = g_keyMgr.getLastRotateTime();
    auto now = std::chrono::system_clock::now();

    auto diff = std::chrono::duration_cast<std::chrono::hours>(now - lastTime).count();
    int days = diff / 24;

    if (days >= AUTO_ROTATE_DAYS) {
        std::cout << "\n🔄 【定时轮换】距上次轮换已 " << days << " 天，超过 " << AUTO_ROTATE_DAYS << " 天阈值，自动轮换..." << std::endl;
        try {
            int newEncVer = g_keyMgr.rotateEncryptionKey();
            int newIdxVer = g_keyMgr.rotateIndexKey();
            int newTagVer = g_keyMgr.rotateTagKey();

            auto encKey = g_keyMgr.getEncryptionKey();
            auto idxKey = g_keyMgr.getIndexKey();
            auto tagKey = g_keyMgr.getTagKey();
            g_keyMgr.saveToDatabase(dao, 1, encKey, newEncVer, crypto::KeyStatus::ENABLED);
            g_keyMgr.saveToDatabase(dao, 2, idxKey, newIdxVer, crypto::KeyStatus::ENABLED);
            g_keyMgr.saveToDatabase(dao, 3, tagKey, newTagVer, crypto::KeyStatus::ENABLED);

            g_keyMgr.saveRotateTimeToFile(ROTATE_TIME_FILE);

            g_encKey = g_keyMgr.getEncryptionKey();
            g_idxKey = g_keyMgr.getIndexKey();
            g_tagKey = g_keyMgr.getTagKey();

            std::cout << "✅ 定时轮换完成！（已保存到 key_config）" << std::endl;
            std::cout << "   加密密钥: 版本 " << newEncVer << " (启用)" << std::endl;
            std::cout << "   索引密钥: 版本 " << newIdxVer << " (启用)" << std::endl;
            std::cout << "   Tag 密钥: 版本 " << newTagVer << " (启用)" << std::endl;
            return true;
        } catch (const std::exception& e) {
            std::cerr << "❌ 定时轮换失败: " << e.what() << std::endl;
            return false;
        }
    }
    return false;
}

// ---- ★ 密钥管理 ----
void keyManagement(database::DAO& dao) {
    std::cout << "\n========== 🔑 密钥管理 ==========" << std::endl;
    std::cout << "当前加密密钥版本: " << g_keyMgr.getEncryptionVersion() << " (启用)" << std::endl;
    std::cout << "当前索引密钥版本: " << g_keyMgr.getIndexVersion() << " (启用)" << std::endl;
    std::cout << "当前 Tag 密钥版本: " << g_keyMgr.getTagVersion() << " (启用)" << std::endl;

    auto allEnc = g_keyMgr.getAllEncryptionVersions();
    std::cout << "所有加密密钥版本: ";
    for (int v : allEnc) std::cout << v << " ";
    std::cout << std::endl;

    auto lastTime = g_keyMgr.getLastRotateTime();
    auto time_t = std::chrono::system_clock::to_time_t(lastTime);
    std::cout << "上次轮换时间: " << std::ctime(&time_t);

    auto now = std::chrono::system_clock::now();
    auto diff = std::chrono::duration_cast<std::chrono::hours>(now - lastTime).count();
    std::cout << "距上次轮换: " << (diff / 24) << " 天 (阈值: " << AUTO_ROTATE_DAYS << " 天)";
    if (diff / 24 >= AUTO_ROTATE_DAYS) std::cout << " ⚠️ 已超过阈值！";
    std::cout << std::endl;

    std::cout << "----------------------------------------" << std::endl;
    std::cout << "  1. 轮换加密密钥" << std::endl;
    std::cout << "  2. 轮换索引密钥" << std::endl;
    std::cout << "  3. 轮换 Tag 密钥" << std::endl;
    std::cout << "  4. 全部轮换" << std::endl;
    std::cout << "  5. 查看所有密钥版本" << std::endl;
    std::cout << "  6. 重置轮换计时器" << std::endl;
    std::cout << "  0. 返回" << std::endl;

    int choice = getIntInput("请选择: ", 0);
    switch (choice) {
        case 1: {
            int v = g_keyMgr.rotateEncryptionKey();
            auto key = g_keyMgr.getEncryptionKey();
            g_keyMgr.saveToDatabase(dao, 1, key, v, crypto::KeyStatus::ENABLED);
            g_keyMgr.saveRotateTimeToFile(ROTATE_TIME_FILE);
            g_encKey = g_keyMgr.getEncryptionKey();
            std::cout << "✅ 加密密钥已轮换，新版本: " << v << " (已保存到数据库)" << std::endl;
            break;
        }
        case 2: {
            int v = g_keyMgr.rotateIndexKey();
            auto key = g_keyMgr.getIndexKey();
            g_keyMgr.saveToDatabase(dao, 2, key, v, crypto::KeyStatus::ENABLED);
            g_keyMgr.saveRotateTimeToFile(ROTATE_TIME_FILE);
            g_idxKey = g_keyMgr.getIndexKey();
            std::cout << "✅ 索引密钥已轮换，新版本: " << v << " (已保存到数据库)" << std::endl;
            break;
        }
        case 3: {
            int v = g_keyMgr.rotateTagKey();
            auto key = g_keyMgr.getTagKey();
            g_keyMgr.saveToDatabase(dao, 3, key, v, crypto::KeyStatus::ENABLED);
            g_keyMgr.saveRotateTimeToFile(ROTATE_TIME_FILE);
            g_tagKey = g_keyMgr.getTagKey();
            std::cout << "✅ Tag 密钥已轮换，新版本: " << v << " (已保存到数据库)" << std::endl;
            break;
        }
        case 4: {
            int ev = g_keyMgr.rotateEncryptionKey();
            int iv = g_keyMgr.rotateIndexKey();
            int tv = g_keyMgr.rotateTagKey();
            auto ekey = g_keyMgr.getEncryptionKey();
            auto ikey = g_keyMgr.getIndexKey();
            auto tkey = g_keyMgr.getTagKey();
            g_keyMgr.saveToDatabase(dao, 1, ekey, ev, crypto::KeyStatus::ENABLED);
            g_keyMgr.saveToDatabase(dao, 2, ikey, iv, crypto::KeyStatus::ENABLED);
            g_keyMgr.saveToDatabase(dao, 3, tkey, tv, crypto::KeyStatus::ENABLED);
            g_keyMgr.saveRotateTimeToFile(ROTATE_TIME_FILE);
            g_encKey = g_keyMgr.getEncryptionKey();
            g_idxKey = g_keyMgr.getIndexKey();
            g_tagKey = g_keyMgr.getTagKey();
            std::cout << "✅ 全部轮换完成！加密:" << ev << " 索引:" << iv << " Tag:" << tv << std::endl;
            break;
        }
        case 5: {
            auto encV = g_keyMgr.getAllEncryptionVersions();
            auto idxV = g_keyMgr.getAllIndexVersions();
            auto tagV = g_keyMgr.getAllTagVersions();
            std::cout << "加密密钥版本: ";
            for (int v : encV) std::cout << v << " ";
            std::cout << "\n索引密钥版本: ";
            for (int v : idxV) std::cout << v << " ";
            std::cout << "\nTag 密钥版本: ";
            for (int v : tagV) std::cout << v << " ";
            std::cout << std::endl;
            break;
        }
        case 6: {
            g_keyMgr.setLastRotateTime(std::chrono::system_clock::now());
            g_keyMgr.saveRotateTimeToFile(ROTATE_TIME_FILE);
            std::cout << "✅ 计时器已重置" << std::endl;
            break;
        }
        default: break;
    }
}

// ---- ★ 索引重建 ----
void rebuildIndex(DAO& dao) {
    std::cout << "\n========== 🔧 索引重建 ==========" << std::endl;
    std::cout << "请选择要重建的字段类型：" << std::endl;
    std::cout << "  1. 姓名" << std::endl;
    std::cout << "  2. 手机号" << std::endl;
    std::cout << "  3. 地址" << std::endl;
    int fieldCode = getIntInput("请输入数字 (1-3): ", 1);

    int64_t startId = getIntInput("请输入起始 ID (包含): ", 1);
    int64_t endId = getIntInput("请输入结束 ID (包含): ", 0);
    if (endId <= 0 || endId < startId) {
        std::cout << "❌ 无效的 ID 范围" << std::endl;
        return;
    }

    int batchSize = getIntInput("每批处理记录数 (默认 100): ", 100);
    if (batchSize <= 0) batchSize = 100;

    std::cout << "⏳ 开始重建索引... (请耐心等待)" << std::endl;

    try {
        rebuild::IndexRebuilder rebuilder(dao, g_keyMgr);

        auto progressCb = [](const rebuild::ProgressInfo& p) {
            // 每 100 条打印一次进度
            if (p.processed % 100 == 0 || p.processed == p.total) {
                std::cout << "\r   进度: " << p.processed << "/" << p.total
                          << " (成功: " << p.successCount << ", 失败: " << p.failCount << ")"
                          << std::flush;
            }
        };

        int64_t result = rebuilder.rebuildField(fieldCode, startId, endId, batchSize, progressCb);
        std::cout << std::endl;

        if (result >= 0) {
            std::cout << "✅ 索引重建完成！成功: " << result << " 条" << std::endl;
        } else {
            std::cout << "❌ 索引重建失败" << std::endl;
        }
    } catch (const std::exception& e) {
        std::cout << "❌ 重建失败: " << e.what() << std::endl;
    }
}

// ---- ★ 业务功能（加入审计日志） ----

void insertData(DAO& dao) {
    std::cout << "\n========== 插入数据 ==========" << std::endl;
    PlainData data;
    data.name = getStringInput("请输入姓名: ");
    data.phone = getStringInput("请输入手机号: ");
    data.address = getStringInput("请输入地址: ");

    std::string requestId = audit::AuditLogger::generateRequestId();
    auto start = std::chrono::steady_clock::now();
    bool success = true;
    std::string errorMsg;
    int resultCount = 0;
    int fieldCode = 0;

    try {
        int encVersion = g_keyMgr.getEncryptionVersion();
        int64_t id = dao.insertData(data, g_encKey, g_idxKey, g_tagKey, encVersion);
        std::cout << "✅ 插入成功！ID = " << id << " (密钥版本: " << encVersion << ")" << std::endl;
        resultCount = 1;
        checkAndAutoRotate(dao);
    } catch (const std::exception& e) {
        success = false;
        errorMsg = e.what();
        std::cout << "❌ 插入失败: " << e.what() << std::endl;
    }

    auto end = std::chrono::steady_clock::now();
    int durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    if (g_auditLogger) {
        g_auditLogger->logOperation(requestId, audit::Operation::INSERT,
                                    fieldCode, 0, resultCount,
                                    durationMs, success, errorMsg);
    }
}

void exactQuery(QueryService& qs) {
    std::cout << "\n========== 精确查询 ==========" << std::endl;
    FieldType ft = getFieldType();
    std::string keyword = getStringInput("请输入查询关键词: ");
    if (keyword.empty()) { std::cout << "关键词不能为空。" << std::endl; return; }

    std::string requestId = audit::AuditLogger::generateRequestId();
    auto start = std::chrono::steady_clock::now();
    bool success = true;
    std::string errorMsg;
    int candidateCount = 0, resultCount = 0;
    int fieldCode = static_cast<int>(ft);

    try {
        auto results = qs.exactQuery(keyword, ft, g_idxKey, g_encKey, g_tagKey);
        candidateCount = results.size();
        resultCount = results.size();
        printFullRecords(results);
    } catch (const std::exception& e) {
        success = false;
        errorMsg = e.what();
        std::cout << "❌ 查询失败: " << e.what() << std::endl;
    }

    auto end = std::chrono::steady_clock::now();
    int durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    if (g_auditLogger) {
        g_auditLogger->logOperation(requestId, audit::Operation::EXACT_QUERY,
                                    fieldCode, candidateCount, resultCount,
                                    durationMs, success, errorMsg);
    }
}

void fuzzyQuery(QueryService& qs) {
    std::cout << "\n========== 模糊查询 ==========" << std::endl;
    std::cout << "（支持中缀匹配，如 '张' 匹配 '张三'、'张伟'）" << std::endl;
    FieldType ft = getFieldType();
    std::string keyword = getStringInput("请输入查询关键词: ");
    if (keyword.empty()) { std::cout << "关键词不能为空。" << std::endl; return; }

    std::string requestId = audit::AuditLogger::generateRequestId();
    auto start = std::chrono::steady_clock::now();
    bool success = true;
    std::string errorMsg;
    int candidateCount = 0, resultCount = 0;
    int fieldCode = static_cast<int>(ft);

    try {
        auto results = qs.fuzzyQuery(keyword, ft, g_idxKey, g_encKey, g_tagKey);
        candidateCount = results.size();
        resultCount = results.size();
        printFullRecords(results);
    } catch (const std::exception& e) {
        success = false;
        errorMsg = e.what();
        std::cout << "❌ 查询失败: " << e.what() << std::endl;
    }

    auto end = std::chrono::steady_clock::now();
    int durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    if (g_auditLogger) {
        g_auditLogger->logOperation(requestId, audit::Operation::FUZZY_QUERY,
                                    fieldCode, candidateCount, resultCount,
                                    durationMs, success, errorMsg);
    }
}

void updateData(DAO& dao) {
    std::cout << "\n========== 更新数据 ==========" << std::endl;
    int64_t id = getIntInput("请输入要更新的记录 ID: ", 0);
    if (id <= 0) { std::cout << "无效的 ID。" << std::endl; return; }

    PlainData newData;
    std::cout << "请输入新数据：" << std::endl;
    newData.name = getStringInput("  新姓名: ");
    newData.phone = getStringInput("  新手机号: ");
    newData.address = getStringInput("  新地址: ");

    std::string requestId = audit::AuditLogger::generateRequestId();
    auto start = std::chrono::steady_clock::now();
    bool success = true;
    std::string errorMsg;
    int resultCount = 0;

    try {
        int encVersion = g_keyMgr.getEncryptionVersion();
        bool ok = dao.updateData(id, newData, g_encKey, g_idxKey, g_tagKey, encVersion);
        if (ok) {
            std::cout << "✅ 更新成功！(新密钥版本: " << encVersion << ")" << std::endl;
            resultCount = 1;
        } else {
            success = false;
            errorMsg = "记录不存在或更新失败";
            std::cout << "❌ 更新失败（记录可能不存在）。" << std::endl;
        }
    } catch (const std::exception& e) {
        success = false;
        errorMsg = e.what();
        std::cout << "❌ 更新失败: " << e.what() << std::endl;
    }

    auto end = std::chrono::steady_clock::now();
    int durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    if (g_auditLogger) {
        g_auditLogger->logOperation(requestId, audit::Operation::UPDATE,
                                    0, 0, resultCount,
                                    durationMs, success, errorMsg);
    }
}

void deleteData(DAO& dao) {
    std::cout << "\n========== 删除数据 ==========" << std::endl;
    int64_t id = getIntInput("请输入要删除的记录 ID: ", 0);
    if (id <= 0) { std::cout << "无效的 ID。" << std::endl; return; }

    std::cout << "⚠️ 确认删除 ID = " << id << " ? (y/N): ";
    std::string confirm;
    std::getline(std::cin, confirm);
    if (confirm != "y" && confirm != "Y") { std::cout << "已取消。" << std::endl; return; }

    std::string requestId = audit::AuditLogger::generateRequestId();
    auto start = std::chrono::steady_clock::now();
    bool success = true;
    std::string errorMsg;
    int resultCount = 0;

    try {
        if (dao.deleteData(id)) {
            std::cout << "✅ 删除成功！" << std::endl;
            resultCount = 1;
        } else {
            success = false;
            errorMsg = "记录不存在或删除失败";
            std::cout << "❌ 删除失败。" << std::endl;
        }
    } catch (const std::exception& e) {
        success = false;
        errorMsg = e.what();
        std::cout << "❌ 删除失败: " << e.what() << std::endl;
    }

    auto end = std::chrono::steady_clock::now();
    int durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    if (g_auditLogger) {
        g_auditLogger->logOperation(requestId, audit::Operation::DELETE,
                                    0, 0, resultCount,
                                    durationMs, success, errorMsg);
    }
}

void showMenu() {
    std::cout << "\n╔═══════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║              🔐 密文数据库查询系统                        ║" << std::endl;
    std::cout << "╠═══════════════════════════════════════════════════════════╣" << std::endl;
    std::cout << "║  1. 插入数据                                              ║" << std::endl;
    std::cout << "║  2. 精确查询（等值匹配）                                  ║" << std::endl;
    std::cout << "║  3. 模糊查询（中缀匹配）                                  ║" << std::endl;
    std::cout << "║  4. 更新数据                                              ║" << std::endl;
    std::cout << "║  5. 删除数据                                              ║" << std::endl;
    std::cout << "║  6. 密钥管理                                              ║" << std::endl;
    std::cout << "║  7. 索引重建                                              ║" << std::endl;
    std::cout << "║  0. 退出                                                  ║" << std::endl;
    std::cout << "╚═══════════════════════════════════════════════════════════╝" << std::endl;
}

// ---- 主函数 ----
int main() {
    try {
        // ============================================================
        // 1. 获取数据库连接信息
        // ============================================================
        std::cout << "╔═══════════════════════════════════════════════════════════╗" << std::endl;
        std::cout << "║              🔐 密文数据库查询系统                        ║" << std::endl;
        std::cout << "╚═══════════════════════════════════════════════════════════╝" << std::endl;
        std::cout << "\n【数据库连接配置】" << std::endl;

        std::string host = getStringInput("数据库地址 (默认 127.0.0.1): ");
        if (host.empty()) host = "127.0.0.1";
        std::string user = getStringInput("用户名 (默认 root): ");
        if (user.empty()) user = "root";
        std::string password = getPasswordInput("请输入数据库密码: ");
        std::string db = getStringInput("数据库名 (默认 testdb): ");
        if (db.empty()) db = "testdb";
        int port = getIntInput("端口号 (默认 3306): ", 3306);

        // ============================================================
        // 2. 初始化 OpenHiTLS
        // ============================================================
        std::cout << "\n🔐 正在初始化加密引擎..." << std::endl;
        int32_t ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
        if (ret != CRYPT_SUCCESS) {
            std::cerr << "❌ OpenHiTLS 初始化失败，错误码: " << std::hex << ret << std::dec << std::endl;
            return 1;
        }
        std::cout << "✅ 加密引擎初始化成功！" << std::endl;

        // ============================================================
        // 3. 连接数据库
        // ============================================================
        std::cout << "\n🔌 正在连接数据库..." << std::endl;
        getGlobalConnectionPool().init(host, user, password, db, port, 5);
        std::cout << "✅ 数据库连接成功！" << std::endl;

        // ============================================================
        // 4. 初始化 DAO
        // ============================================================
        DAO dao;

        // ============================================================
        // 5. ★ 查找并加载 KEK 密钥文件
        // ============================================================
        std::cout << "\n🔑 正在加载主密钥..." << std::endl;

        std::string kekFilePath = findKEKFile();
        if (kekFilePath.empty()) {
            std::cerr << "❌ 未找到密钥文件" << std::endl;
            std::cerr << "请在以下位置之一放置密钥文件：" << std::endl;
            for (const auto& path : KEK_SEARCH_PATHS) {
                std::cerr << "  " << path << std::endl;
            }
            std::cerr << "\n生成命令: openssl rand -hex 16 > ~/.secsearch/kek.key" << std::endl;
            std::cerr << "（注意：需要先创建目录 mkdir -p ~/.secsearch）" << std::endl;
            return 1;
        }

        std::cout << "📍 密钥文件位置: " << kekFilePath << std::endl;

        std::vector<unsigned char> kek;
        try {
            kek = crypto::readKeyFromFile(kekFilePath);
            std::cout << "✅ KEK 加载成功（16 字节）" << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "❌ " << e.what() << std::endl;
            return 1;
        }

        // ============================================================
        // 6. 初始化密钥管理器（从 key_config 表加载）
        // ============================================================
        std::cout << "🔑 正在从 key_config 表加载密钥..." << std::endl;

        g_keyMgr.init(kek);

        try {
            g_keyMgr.loadFromDatabase(dao, kek);
            std::cout << "✅ 从 key_config 加载成功！" << std::endl;
            std::cout << "   加密密钥版本数: " << g_keyMgr.getAllEncryptionVersions().size() << std::endl;
            std::cout << "   索引密钥版本数: " << g_keyMgr.getAllIndexVersions().size() << std::endl;
            std::cout << "   Tag 密钥版本数: " << g_keyMgr.getAllTagVersions().size() << std::endl;
            std::cout << "   当前加密密钥版本: " << g_keyMgr.getEncryptionVersion() << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "❌ 从 key_config 加载失败: " << e.what() << std::endl;
            std::cerr << "   正在初始化初始密钥..." << std::endl;

            std::vector<unsigned char> initEnc(16, 0xA0);
            std::vector<unsigned char> initIdx(16, 0xB0);
            std::vector<unsigned char> initTag(16, 0xC0);

            g_keyMgr.saveToDatabase(dao, 1, initEnc, 1, crypto::KeyStatus::ENABLED);
            g_keyMgr.saveToDatabase(dao, 2, initIdx, 1, crypto::KeyStatus::ENABLED);
            g_keyMgr.saveToDatabase(dao, 3, initTag, 1, crypto::KeyStatus::ENABLED);

            g_keyMgr.loadFromDatabase(dao, kek);
            std::cout << "✅ 初始密钥已生成并保存到 key_config" << std::endl;
        }

        g_encKey = g_keyMgr.getEncryptionKey();
        g_idxKey = g_keyMgr.getIndexKey();
        g_tagKey = g_keyMgr.getTagKey();

        std::cout << "✅ 密钥加载成功！当前加密密钥版本: " << g_keyMgr.getEncryptionVersion() << std::endl;

        // ============================================================
        // 7. ★ 初始化全局审计日志器
        // ============================================================
        std::cout << "\n📋 正在初始化审计模块..." << std::endl;
        g_auditLogger = std::make_unique<audit::AuditLogger>(&getGlobalConnectionPool());
        std::cout << "✅ 审计模块初始化成功！" << std::endl;

        // ============================================================
        // 8. 初始化 QueryService
        // ============================================================
        QueryService qs(dao, g_keyMgr, g_auditLogger.get());

        // ============================================================
        // 9. 定时轮换检查
        // ============================================================
        g_keyMgr.loadRotateTimeFromFile(ROTATE_TIME_FILE);
        checkAndAutoRotate(dao);

        std::cout << "\n🎉 系统初始化完成！" << std::endl;

        // ============================================================
        // 10. 主循环
        // ============================================================
        int choice = -1;
        while (choice != 0) {
            showMenu();
            choice = getIntInput("请输入操作编号: ", -1);

            switch (choice) {
                case 1: insertData(dao); break;
                case 2: exactQuery(qs); break;
                case 3: fuzzyQuery(qs); break;
                case 4: updateData(dao); break;
                case 5: deleteData(dao); break;
                case 6: keyManagement(dao); break;
                case 7: rebuildIndex(dao); break;       // ★ 索引重建
                case 0: std::cout << "👋 再见！" << std::endl; break;
                default: std::cout << "❌ 无效选项，请输入 0-7。" << std::endl;
            }
        }

        // ============================================================
        // 11. 清理
        // ============================================================
        getGlobalConnectionPool().closeAll();
        std::cout << "🔐 正在清理加密引擎..." << std::endl;
        CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
        std::cout << "✅ 加密引擎清理完成！" << std::endl;

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "\n❌ 程序启动失败: " << e.what() << std::endl;
        return 1;
    }
}