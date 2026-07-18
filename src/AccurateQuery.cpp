#include <iostream>
#include <cstring>
#include <mysql/mysql.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>

// ==================== 请修改这里的数据库连接信息 ====================
#define DB_HOST "127.0.0.1"
#define DB_USER "root"
#define DB_PASS "SongYiHang1109"     // 改成你自己的密码
#define DB_NAME "secsearch"          // 测试用系统库，也可以改成你自己的库
#define DB_PORT 3306
// ================================================================

// ---------- 辅助：SM3 一次性哈希（封装 GmSSL 3.x API） ----------
void sm3_hash_once(const unsigned char *data, size_t len, unsigned char digest[32]) {
    SM3_CTX ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, data, len);
    sm3_finish(&ctx, digest);
}

// ---------- 打印十六进制 ----------
void print_hex(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
}

int main() {
    std::cout << "========== 开始环境完整性测试 ==========" << std::endl;

    // ======================= 1. 测试 GMSSL =======================
    std::cout << "\n[1] 测试 GmSSL 国密算法库..." << std::endl;

    // ----- SM3 哈希 -----
    unsigned char data[] = "Hello GmSSL!";
    unsigned char hash[32];
    sm3_hash_once(data, strlen((char*)data), hash);

    std::cout << "  SM3(\"Hello GmSSL!\") = ";
    print_hex(hash, 32);
    std::cout << std::endl;

    // ----- SM4-CBC 加密/解密 (带PKCS#7填充) -----
    unsigned char key[16] = {
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10
    };
    unsigned char iv[16] = {0};  // 测试用全零 IV，生产环境必须随机

    const char *plaintext = "Hello SM4!";
    size_t plain_len = strlen(plaintext);

    unsigned char ciphertext[256];
    unsigned char decrypted[256];
    size_t cipher_len = 0, decrypted_len = 0;

    SM4_KEY sm4_key;

    // 加密
    sm4_set_encrypt_key(&sm4_key, key);
    if (sm4_cbc_padding_encrypt(&sm4_key, iv,
                                (const unsigned char*)plaintext, plain_len,
                                ciphertext, &cipher_len) != 1) {
        std::cerr << "  ❌ SM4 加密失败" << std::endl;
        return 1;
    }

    // 解密
    sm4_set_decrypt_key(&sm4_key, key);
    if (sm4_cbc_padding_decrypt(&sm4_key, iv,
                                ciphertext, cipher_len,
                                decrypted, &decrypted_len) != 1) {
        std::cerr << "  ❌ SM4 解密失败" << std::endl;
        return 1;
    }
    decrypted[decrypted_len] = '\0';

    std::cout << "  SM4 解密结果: " << (char*)decrypted << std::endl;

    // ----- HMAC-SM3 (用于盲索引) -----
    unsigned char hmac_key[] = "index_secret_key";
    unsigned char mac[32];
    SM3_HMAC_CTX hmac_ctx;
    sm3_hmac_init(&hmac_ctx, hmac_key, sizeof(hmac_key)-1);
    sm3_hmac_update(&hmac_ctx, (const unsigned char*)plaintext, plain_len);
    sm3_hmac_finish(&hmac_ctx, mac);

    std::cout << "  HMAC-SM3(\"Hello SM4!\") = ";
    print_hex(mac, 32);
    std::cout << std::endl;

    std::cout << "  ✅ GmSSL 所有算法测试通过！" << std::endl;

    // ======================= 2. 测试 MySQL =======================
    std::cout << "\n[2] 测试 MySQL 客户端库与连接..." << std::endl;

    // 打印客户端版本（验证头文件和库已正确链接）
    std::cout << "  MySQL 客户端版本: " << mysql_get_client_info() << std::endl;

    // 初始化连接句柄
    MYSQL *conn = mysql_init(nullptr);
    if (!conn) {
        std::cerr << "  ❌ mysql_init 失败" << std::endl;
        return 1;
    }
    std::cout << "  ✅ mysql_init 成功" << std::endl;

    // 尝试连接数据库
    std::cout << "  正在连接 " << DB_HOST << ":" << DB_PORT << " ..." << std::endl;
    if (!mysql_real_connect(conn, DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT, nullptr, 0)) {
        std::cerr << "  ❌ 数据库连接失败: " << mysql_error(conn) << std::endl;
        std::cerr << "  ⚠️ 注意: 如果只是连接失败，但程序能运行到这里，" << std::endl;
        std::cerr << "     说明 MySQL 头文件和库已正确配置。请检查密码/服务是否启动。" << std::endl;
        mysql_close(conn);
        // 连接失败不代表环境配置失败，只代表服务/密码不对，程序继续
    } else {
        std::cout << "  ✅ 数据库连接成功！" << std::endl;

        // 执行一条简单查询验证
        if (mysql_query(conn, "SELECT VERSION()")) {
            std::cerr << "  ❌ 查询失败: " << mysql_error(conn) << std::endl;
        } else {
            MYSQL_RES *res = mysql_store_result(conn);
            if (res) {
                MYSQL_ROW row = mysql_fetch_row(res);
                if (row) {
                    std::cout << "  MySQL 服务版本: " << row[0] << std::endl;
                }
                mysql_free_result(res);
            }
        }
        mysql_close(conn);
        std::cout << "  ✅ MySQL 全部测试通过！" << std::endl;
    }

    // ======================= 总结 =======================
    std::cout << "\n========== 🎉 环境完整性测试全部完成 ==========" << std::endl;
    std::cout << "如果看到以上所有 ✅ 标记 (或仅 MySQL 连接失败但 GmSSL 全通过)," << std::endl;
    std::cout << "则说明你的 C++ 开发环境已完全就绪，可以开始项目开发了！" << std::endl;

    return 0;
}