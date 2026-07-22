// test_db.cpp
// 测试数据库模块 + crypto 模块的集成

#include "database/dao.h"
#include "crypto/key_manager.h"
#include "crypto/sm4_cipher.h"
#include "crypto/hmac_sm3.h"
#include <iostream>
#include <vector>

int main() {
    try {
        // 1. 初始化连接池（修改为你的数据库配置）
        database::getGlobalConnectionPool().init(
            "127.0.0.1", "root", "U202312485", "secsearch", 3306, 5
        );

        // 2. 初始化密钥管理器
        crypto::KeyManager keyMgr;
        std::vector<unsigned char> kek(16, 0x11);
        keyMgr.init(kek);

        // 3. 模拟从数据库加载三个密钥（这里直接用测试数据）
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

        // 4. 创建 DAO 并插入数据
        database::DAO dao;
        database::PlainData data{"张三", "13800138000", "北京市朝阳区"};

        int64_t id = dao.insertData(data, encKey, idxKey, tagKey);
        std::cout << "✅ 插入成功，ID = " << id << std::endl;

        // 5. 精确查询测试
        auto nameBytes = std::vector<unsigned char>(data.name.begin(), data.name.end());
        std::string nameBlind = crypto::HmacSm3::hmacHex(nameBytes, idxKey);
        auto ids = dao.queryByExactIndex(nameBlind, database::FieldType::NAME);
        std::cout << "✅ 精确查询找到 " << ids.size() << " 条记录" << std::endl;

        // 6. 模糊查询测试
        auto fuzzyIds = dao.queryByFuzzyKeyword("张", database::FieldType::NAME, idxKey);
        std::cout << "✅ 模糊查询找到 " << fuzzyIds.size() << " 条记录" << std::endl;

        // 7. 批量读取密文
        auto records = dao.batchSelectCiphers(ids);
        std::cout << "✅ 批量读取到 " << records.size() << " 条密文" << std::endl;

        // 8. 验证 Tag 并解密（演示第一条）
        if (!records.empty()) {
            auto cipherBytes = std::vector<unsigned char>(records[0].cipher.begin(),
                                                          records[0].cipher.end());
            std::string computedTag = crypto::HmacSm3::hmacHex(cipherBytes, tagKey);
            if (computedTag == records[0].tag) {
                auto plain = crypto::Sm4Cipher::decrypt(records[0].cipher, encKey);
                std::string recovered(plain.begin(), plain.end());
                std::cout << "✅ 解密结果: " << recovered << std::endl;
            } else {
                std::cout << "❌ Tag 校验失败，数据可能被篡改" << std::endl;
            }
        }

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "❌ 错误: " << e.what() << std::endl;
        return 1;
    }
}