// main.cpp
// 交互式命令行程序，提供增删改查功能
// 用户通过菜单选择操作类型，输入数据后执行
// ★ 基于 OpenHiTLS 加密库

#include "database/dao.h"
#include "database/connection_pool.h"
#include "query/query_service.h"
#include "crypto/key_manager.h"
#include "crypto/sm4_cipher.h"
#include "crypto/hmac_sm3.h"

// ★ OpenHiTLS 初始化和清理头文件
#include <hitls/crypto/crypt_eal_init.h>
#include <hitls/crypto/crypt_errno.h>

#include <iostream>
#include <string>
#include <limits>
#include <vector>
#include <iomanip>

// 密码输入头文件
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

// ---- 辅助函数 ----

void clearInput() {
    std::cin.clear();
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

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
        if (line.empty()) {
            return defaultVal;
        }
        try {
            int value = std::stoi(line);
            return value;
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
        default:
            std::cout << "输入无效，默认使用姓名。" << std::endl;
            return FieldType::NAME;
    }
}

// ★ 打印查询结果（含密钥版本号）
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

// ---- 功能函数 ----

// 1. 插入数据
void insertData(DAO& dao) {
    std::cout << "\n========== 插入数据 ==========" << std::endl;

    PlainData data;
    data.name = getStringInput("请输入姓名: ");
    data.phone = getStringInput("请输入手机号: ");
    data.address = getStringInput("请输入地址: ");

    try {
        int encVersion = g_keyMgr.getEncryptionVersion();
        int64_t id = dao.insertData(data, g_encKey, g_idxKey, g_tagKey, encVersion);
        std::cout << "✅ 插入成功！记录 ID = " << id << " (密钥版本: " << encVersion << ")" << std::endl;
    } catch (const std::exception& e) {
        std::cout << "❌ 插入失败: " << e.what() << std::endl;
    }
}

// 2. 精确查询
void exactQuery(QueryService& qs) {
    std::cout << "\n========== 精确查询 ==========" << std::endl;
    FieldType fieldType = getFieldType();
    std::string keyword = getStringInput("请输入查询关键词: ");

    if (keyword.empty()) {
        std::cout << "关键词不能为空。" << std::endl;
        return;
    }

    try {
        auto results = qs.exactQuery(keyword, fieldType, g_idxKey, g_encKey, g_tagKey);
        printFullRecords(results);
    } catch (const std::exception& e) {
        std::cout << "❌ 查询失败: " << e.what() << std::endl;
    }
}

// 3. 模糊查询
void fuzzyQuery(QueryService& qs) {
    std::cout << "\n========== 模糊查询 ==========" << std::endl;
    std::cout << "（支持中缀匹配，如输入 '张' 可匹配 '张三'、'张伟'）" << std::endl;
    FieldType fieldType = getFieldType();
    std::string keyword = getStringInput("请输入查询关键词: ");

    if (keyword.empty()) {
        std::cout << "关键词不能为空。" << std::endl;
        return;
    }

    try {
        auto results = qs.fuzzyQuery(keyword, fieldType, g_idxKey, g_encKey, g_tagKey);
        printFullRecords(results);
    } catch (const std::exception& e) {
        std::cout << "❌ 查询失败: " << e.what() << std::endl;
    }
}

// 4. 更新数据
void updateData(DAO& dao) {
    std::cout << "\n========== 更新数据 ==========" << std::endl;
    int64_t id = getIntInput("请输入要更新的记录 ID: ", 0);

    if (id <= 0) {
        std::cout << "无效的 ID。" << std::endl;
        return;
    }

    try {
        PlainData newData;
        std::cout << "请输入新数据：" << std::endl;
        newData.name = getStringInput("  新姓名: ");
        newData.phone = getStringInput("  新手机号: ");
        newData.address = getStringInput("  新地址: ");

        int encVersion = g_keyMgr.getEncryptionVersion();
        bool success = dao.updateData(id, newData, g_encKey, g_idxKey, g_tagKey, encVersion);
        if (success) {
            std::cout << "✅ 更新成功！(新密钥版本: " << encVersion << ")" << std::endl;
        } else {
            std::cout << "❌ 更新失败（可能记录不存在）。" << std::endl;
        }
    } catch (const std::exception& e) {
        std::cout << "❌ 更新失败: " << e.what() << std::endl;
    }
}

// 5. 删除数据
void deleteData(DAO& dao) {
    std::cout << "\n========== 删除数据 ==========" << std::endl;
    int64_t id = getIntInput("请输入要删除的记录 ID: ", 0);

    if (id <= 0) {
        std::cout << "无效的 ID。" << std::endl;
        return;
    }

    std::cout << "⚠️  确认删除 ID = " << id << " 的记录？(y/N): ";
    std::string confirm;
    std::getline(std::cin, confirm);

    if (confirm != "y" && confirm != "Y") {
        std::cout << "操作已取消。" << std::endl;
        return;
    }

    try {
        bool success = dao.deleteData(id);
        if (success) {
            std::cout << "✅ 删除成功！" << std::endl;
        } else {
            std::cout << "❌ 删除失败（记录可能不存在）。" << std::endl;
        }
    } catch (const std::exception& e) {
        std::cout << "❌ 删除失败: " << e.what() << std::endl;
    }
}

// 6. 查看所有记录
void listAllRecords(DAO& dao) {
    std::cout << "\n========== 查看所有记录 ==========" << std::endl;
    std::cout << "（显示姓名包含'张'或手机号包含'138'的记录）" << std::endl;

    QueryService qs(dao);
    try {
        auto results = qs.fuzzyQuery("张", FieldType::NAME, g_idxKey, g_encKey, g_tagKey);
        if (results.empty()) {
            results = qs.fuzzyQuery("138", FieldType::PHONE, g_idxKey, g_encKey, g_tagKey);
        }
        if (results.empty()) {
            std::cout << "数据库中没有记录。" << std::endl;
        } else {
            printFullRecords(results);
        }
    } catch (const std::exception& e) {
        std::cout << "❌ 查询失败: " << e.what() << std::endl;
    }
}

// ---- 主菜单 ----
void showMenu() {
    std::cout << "\n╔═══════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║              🔐 密文数据库查询系统                        ║" << std::endl;
    std::cout << "╠═══════════════════════════════════════════════════════════╣" << std::endl;
    std::cout << "║  1. 插入数据                                              ║" << std::endl;
    std::cout << "║  2. 精确查询（等值匹配）                                   ║" << std::endl;
    std::cout << "║  3. 模糊查询（中缀匹配）                                   ║" << std::endl;
    std::cout << "║  4. 更新数据                                              ║" << std::endl;
    std::cout << "║  5. 删除数据                                              ║" << std::endl;
    std::cout << "║  6. 查看所有记录（调试）                                   ║" << std::endl;
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
        // 2. 初始化 OpenHiTLS 加密库
        // ============================================================
        std::cout << "\n🔐 正在初始化加密引擎..." << std::endl;
        int32_t ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
        if (ret != CRYPT_SUCCESS) {
            std::cerr << "❌ OpenHiTLS 初始化失败，错误码: " << std::hex << ret << std::dec << std::endl;
            return 1;
        }
        std::cout << "✅ 加密引擎初始化成功！" << std::endl;

        // ============================================================
        // 3. 初始化连接池
        // ============================================================
        std::cout << "\n🔌 正在连接数据库..." << std::endl;
        getGlobalConnectionPool().init(host, user, password, db, port, 5);
        std::cout << "✅ 数据库连接成功！" << std::endl;

        // ============================================================
        // 4. 初始化密钥管理器
        // ============================================================
        std::cout << "🔑 正在加载密钥..." << std::endl;

        std::vector<unsigned char> kek(16, 0x11);
        g_keyMgr.init(kek);

        std::vector<unsigned char> rawEnc(16, 0xA0);
        std::vector<unsigned char> rawIdx(16, 0xB0);
        std::vector<unsigned char> rawTag(16, 0xC0);

        std::string encCipher = crypto::Sm4Cipher::encrypt(rawEnc, kek);
        std::string idxCipher = crypto::Sm4Cipher::encrypt(rawIdx, kek);
        std::string tagCipher = crypto::Sm4Cipher::encrypt(rawTag, kek);

        g_keyMgr.loadKeys(encCipher, idxCipher, tagCipher);

        g_encKey = g_keyMgr.getEncryptionKey();
        g_idxKey = g_keyMgr.getIndexKey();
        g_tagKey = g_keyMgr.getTagKey();

        std::cout << "✅ 密钥加载成功！当前加密密钥版本: " << g_keyMgr.getEncryptionVersion() << std::endl;

        // ============================================================
        // 5. 初始化 DAO 和 QueryService
        // ============================================================
        DAO dao;
        QueryService qs(dao);

        std::cout << "\n🎉 系统初始化完成！" << std::endl;

        // ============================================================
        // 6. 主循环
        // ============================================================
        int choice = -1;
        while (choice != 0) {
            showMenu();
            choice = getIntInput("请输入操作编号: ", -1);

            switch (choice) {
                case 1:
                    insertData(dao);
                    break;
                case 2:
                    exactQuery(qs);
                    break;
                case 3:
                    fuzzyQuery(qs);
                    break;
                case 4:
                    updateData(dao);
                    break;
                case 5:
                    deleteData(dao);
                    break;
                case 6:
                    listAllRecords(dao);
                    break;
                case 0:
                    std::cout << "👋 再见！" << std::endl;
                    break;
                default:
                    std::cout << "❌ 无效选项，请输入 0-6。" << std::endl;
            }
        }

        // ============================================================
        // 7. 清理资源
        // ============================================================
        getGlobalConnectionPool().closeAll();

        std::cout << "🔐 正在清理加密引擎..." << std::endl;
        CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
        std::cout << "✅ 加密引擎清理完成！" << std::endl;

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "\n❌ 程序启动失败: " << e.what() << std::endl;
        std::cerr << "请检查数据库连接配置和密钥设置。" << std::endl;
        return 1;
    }
}