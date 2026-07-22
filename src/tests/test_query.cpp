// test_query.cpp
// 测试查询服务

#include "query/query_service.h"
#include "database/dao.h"
#include "crypto/key_manager.h"
#include "crypto/sm4_cipher.h"
#include "crypto/hmac_sm3.h"
#include <iostream>
#include <vector>

int main() {
    try {
        // ---- 1. 初始化连接池 ----
        database::getGlobalConnectionPool().init(
            "127.0.0.1", "root", "U202312485", "secsearch", 3306, 5
        );

        // ---- 2. 初始化密钥管理器 ----
        crypto::KeyManager keyMgr;
        std::vector<unsigned char> kek(16, 0x11);
        keyMgr.init(kek);

        // 模拟加载三个密钥
        std::vector<unsigned char> rawEnc(16, 0xA0);
        std::vector<unsigned char> rawIdx(16, 0xB0);
        std::vector<unsigned char> rawTag(16, 0xC0);

        std::string encCipher = crypto::Sm4Cipher::encrypt(rawEnc, kek);
        std::string idxCipher = crypto::Sm4Cipher::encrypt(rawIdx, kek);
        std::string tagCipher = crypto::Sm4Cipher::encrypt(rawTag, kek);

        keyMgr.loadKeys(encCipher, idxCipher, tagCipher);

        auto encKey = keyMgr.getEncryptionKey();
        auto idxKey = keyMgr.getIndexKey();
        auto tagKey = keyMgr.getTagKey();

        // ---- 3. 插入测试数据 ----
        database::DAO dao;
        database::PlainData data1{"张三", "13800138000", "北京市朝阳区"};
        database::PlainData data2{"张伟", "13900139000", "上海市浦东新区"};
        database::PlainData data3{"李四", "13700137000", "广州市天河区"};
        database::PlainData data4{"王五", "13811112222", "北京市海淀区"};
        database::PlainData data5{"赵六", "13822223333", "深圳市南山区"};

        dao.insertData(data1, encKey, idxKey, tagKey);
        dao.insertData(data2, encKey, idxKey, tagKey);
        dao.insertData(data3, encKey, idxKey, tagKey);
        dao.insertData(data4, encKey, idxKey, tagKey);
        dao.insertData(data5, encKey, idxKey, tagKey);
        std::cout << "✅ 插入 5 条测试数据" << std::endl;

    // ---- 4. 查询服务 ----
    query::QueryService qs(dao);

    // ---- 4.1 姓名模糊查询 ----
    auto nameResults = qs.fuzzyQuery("张", database::FieldType::NAME,
                                    idxKey, encKey, tagKey);
    std::cout << "\n【姓名模糊查询】关键词: 张" << std::endl;
    for (const auto& r : nameResults) {
        std::cout << "  ID=" << r.id << ", 姓名=" << r.plaintext << std::endl;
    }

    // ---- 4.2 手机号模糊查询 ----
    auto phoneResults = qs.fuzzyQuery("138", database::FieldType::PHONE,
                                    idxKey, encKey, tagKey);
    std::cout << "\n【手机号模糊查询】关键词: 138" << std::endl;
    for (const auto& r : phoneResults) {
        std::cout << "  ID=" << r.id << ", 手机号=" << r.plaintext << std::endl;
    }

    // ---- 4.3 地址模糊查询 ----
    auto addrResults = qs.fuzzyQuery("北京", database::FieldType::ADDRESS,
                                    idxKey, encKey, tagKey);
    std::cout << "\n【地址模糊查询】关键词: 北京" << std::endl;
    for (const auto& r : addrResults) {
        std::cout << "  ID=" << r.id << ", 地址=" << r.plaintext << std::endl;
    }

    // ---- 4.4 手机号精确查询 ----
    auto phoneExact = qs.exactQuery("13800138000", database::FieldType::PHONE,
                                    idxKey, encKey, tagKey);
    std::cout << "\n【手机号精确查询】关键词: 13800138000" << std::endl;
    for (const auto& r : phoneExact) {
        std::cout << "  ID=" << r.id << ", 手机号=" << r.plaintext << std::endl;
    }

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "❌ 错误: " << e.what() << std::endl;
        return 1;
    }
}