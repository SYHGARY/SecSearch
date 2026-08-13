// SecSearch_PerfCompare.cpp
// 对比 GmSSL（串行）vs OpenHiTLS（流水线并行）
// 硬编码开关：可独立控制 GmSSL 的 I/O 模式（逐条/批量）

#include "database/dao.h"
#include "database/connection_pool.h"
#include "crypto/key_manager.h"
#include "crypto/sm4_cipher.h"
#include "crypto/hmac_sm3.h"
#include "crypto/utils.h"
#include "decrypt/batch_decryptor.h"

#include <hitls/crypto/crypt_eal_init.h>

// GmSSL
#include <gmssl/sm4.h>
#include <gmssl/sm3.h>
#include <gmssl/hmac.h>
#include <gmssl/digest.h>

#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <chrono>
#include <thread>
#include <mutex>
#include <algorithm>
#include <map>
#include <cstring>

using namespace crypto;
using namespace database;
using namespace decrypt;

// 控制 GmSSL 对照组的 I/O 模式：
//   true  = 批量读取（用于排除 I/O 干扰，公平对比算法性能）
//   false = 逐条读取（完全模拟最初始的情况，I/O 成为瓶颈）
static const bool GMSSL_BATCH_IO = true;   

static const bool OPENHITLS_BATCH_IO = true; 

// 批量读取的批次大小
static const size_t BATCH_SIZE = 20000;

// ================================================================

const size_t POOL_SIZE = 20;

// ================================================================
// 辅助函数
// ================================================================
void initKeyManager(KeyManager& keyMgr) {
    std::vector<unsigned char> kek(16, 0x11);
    keyMgr.init(kek);
    std::vector<unsigned char> rawEnc(16, 0xA0);
    std::vector<unsigned char> rawIdx(16, 0xB0);
    std::vector<unsigned char> rawTag(16, 0xC0);
    std::string encCipher = Sm4Cipher::encrypt(rawEnc, kek);
    std::string idxCipher = Sm4Cipher::encrypt(rawIdx, kek);
    std::string tagCipher = Sm4Cipher::encrypt(rawTag, kek);
    keyMgr.loadKeys(encCipher, idxCipher, tagCipher);
}

std::string randomName(int seed) {
    static const std::vector<std::string> surnames = {"张","王","李","赵","刘","陈","杨","黄","周","吴"};
    static const std::vector<std::string> names = {"伟","芳","娜","敏","静","强","磊","洋","艳","勇",
                                                    "军","杰","娟","涛","明","超","秀英","霞","平","刚"};
    return surnames[seed % surnames.size()] + names[(seed * 7) % names.size()];
}

std::string randomPhone(int seed) {
    std::string prefixes[] = {"138","139","137","136","135","158","159","188","189","187"};
    std::string prefix = prefixes[seed % 10];
    std::string suffix = std::to_string(10000000 + (seed * 1234567) % 90000000);
    return prefix + suffix.substr(0, 8);
}

std::string randomAddress(int seed) {
    std::vector<std::string> cities = {"北京市","上海市","广州市","深圳市","武汉市","成都市","杭州市","南京市"};
    std::vector<std::string> districts = {"朝阳区","海淀区","浦东新区","天河区","南山区","武昌区","武侯区","西湖区"};
    std::vector<std::string> roads = {"建国路","人民路","中山路","解放路","建设路","和平路","友谊路","文化路"};
    return cities[seed % cities.size()] + districts[(seed*3)%districts.size()] +
           roads[(seed*5)%roads.size()] + std::to_string(seed % 1000) + "号";
}

// ================================================================
// GmSSL HMAC-SM3 封装
// ================================================================
static void gmsslHmacSm3(const uint8_t* key, size_t keylen,
                          const uint8_t* data, size_t datalen,
                          uint8_t mac[32]) {
    size_t maclen = 32;
    hmac(DIGEST_sm3(), key, keylen, data, datalen, mac, &maclen);
}

// ================================================================
// GmSSL 单条解密
// ================================================================
bool gmsslDecryptRecord(const CipherRecord& rec,
                        const uint8_t* encKey, const uint8_t* tagKey,
                        std::string& plaintext, bool debug = false) {
    uint8_t calcTag[32];
    gmsslHmacSm3(tagKey, 16,
                 (const uint8_t*)rec.cipher.data(), rec.cipher.size(),
                 calcTag);
    std::string calcTagHex = binToHex(calcTag, 32);

    if (calcTagHex != rec.tag) {
        return false;
    }

    auto cipherBin = hexToBin(rec.cipher);
    if (cipherBin.size() < 16) return false;

    uint8_t iv[16];
    memcpy(iv, cipherBin.data(), 16);
    const uint8_t* cipherData = cipherBin.data() + 16;
    size_t cipherLen = cipherBin.size() - 16;
    if (cipherLen == 0 || cipherLen % 16 != 0) return false;

    SM4_KEY decKey;
    sm4_set_decrypt_key(&decKey, encKey);
    std::vector<uint8_t> plain(cipherLen);
    sm4_cbc_decrypt_blocks(&decKey, iv, cipherData, cipherLen / 16, plain.data());

    if (plain.empty()) return false;
    uint8_t padLen = plain.back();
    if (padLen == 0 || padLen > 16 || padLen > plain.size()) return false;
    for (size_t i = 0; i < padLen; i++) {
        if (plain[plain.size() - 1 - i] != padLen) return false;
    }
    plain.resize(plain.size() - padLen);

    plaintext.assign(plain.begin(), plain.end());
    return true;
}

// ================================================================
// 测试数据集
// ================================================================
struct TestDataset {
    std::vector<int64_t> ids;
    std::map<int64_t, PlainData> plainMap;
};

TestDataset generateTestData(DAO& dao, KeyManager& keyMgr, int count) {
    TestDataset dataset;
    auto encKey = keyMgr.getEncryptionKey();
    auto idxKey = keyMgr.getIndexKey();
    auto tagKey = keyMgr.getTagKey();
    int encVer = keyMgr.getEncryptionVersion();

    std::cout << "  正在生成 " << count << " 条测试数据并写入 MySQL..." << std::endl;
    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < count; ++i) {
        PlainData data{randomName(i), randomPhone(i), randomAddress(i)};
        try {
            int64_t id = dao.insertData(data, encKey, idxKey, tagKey, encVer);
            dataset.ids.push_back(id);
            dataset.plainMap[id] = data;
        } catch (const std::exception& e) {
            std::cerr << "  插入第 " << i << " 条失败: " << e.what() << std::endl;
        }
        if ((i + 1) % 1000 == 0) {
            auto now = std::chrono::high_resolution_clock::now();
            double elapsed = std::chrono::duration<double, std::milli>(now - start).count();
            std::cout << "    已插入 " << (i + 1) << " 条, 耗时 " << elapsed << "ms" << std::endl;
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    double totalMs = std::chrono::duration<double, std::milli>(end - start).count();
    std::cout << "  完成！共插入 " << dataset.ids.size()
              << " 条, 总耗时 " << totalMs << "ms, 平均 "
              << (totalMs / count) << "ms/条" << std::endl;

    return dataset;
}

void cleanupData(DAO& dao, const std::vector<int64_t>& ids) {
    std::cout << "  正在清理 " << ids.size() << " 条测试数据..." << std::endl;
    for (auto id : ids) {
        try { dao.deleteData(id); } catch (...) {}
    }
    std::cout << "  清理完成" << std::endl;
}

// ================================================================
// 对照组：GmSSL 串行解密（根据 GMSSL_BATCH_IO 决定 I/O 模式）
// ================================================================
double benchmarkGmSSL(DAO& dao, const TestDataset& dataset,
                      const std::vector<unsigned char>& encKey,
                      const std::vector<unsigned char>& tagKey,
                      int& passCount, int& totalRecords) {
    passCount = 0;
    totalRecords = 0;

    if (GMSSL_BATCH_IO) {
        std::cout << "  运行 GmSSL 串行解密（批量读取 MySQL）..." << std::endl;
    } else {
        std::cout << "  运行 GmSSL 串行解密（逐条读取 MySQL，模拟最初始情况）..." << std::endl;
    }

    auto start = std::chrono::high_resolution_clock::now();

    if (GMSSL_BATCH_IO) {
        // ---- 批量读取模式 ----
        for (size_t offset = 0; offset < dataset.ids.size(); offset += BATCH_SIZE) {
            size_t end = std::min(offset + BATCH_SIZE, dataset.ids.size());
            std::vector<int64_t> batchIds(dataset.ids.begin() + offset, dataset.ids.begin() + end);
            auto records = dao.batchSelectCiphers(batchIds);

            for (const auto& rec : records) {
                totalRecords++;
                std::string plaintext;
                bool debug = (totalRecords == 1);
                if (gmsslDecryptRecord(rec, encKey.data(), tagKey.data(), plaintext, debug)) {
                    auto it = dataset.plainMap.find(rec.id);
                    if (it != dataset.plainMap.end()) {
                        const std::string* expected = nullptr;
                        if (rec.fieldType == FieldType::NAME) expected = &it->second.name;
                        else if (rec.fieldType == FieldType::PHONE) expected = &it->second.phone;
                        else if (rec.fieldType == FieldType::ADDRESS) expected = &it->second.address;
                        if (expected && plaintext == *expected) {
                            passCount++;
                        }
                    }
                }
            }
        }

    } else {
        // ---- 逐条读取模式 ----
        for (auto id : dataset.ids) {
            auto records = dao.batchSelectCiphers({id});
            for (const auto& rec : records) {
                totalRecords++;
                std::string plaintext;
                bool debug = (totalRecords == 1);
                if (gmsslDecryptRecord(rec, encKey.data(), tagKey.data(), plaintext, debug)) {
                    auto it = dataset.plainMap.find(rec.id);
                    if (it != dataset.plainMap.end()) {
                        const std::string* expected = nullptr;
                        if (rec.fieldType == FieldType::NAME) expected = &it->second.name;
                        else if (rec.fieldType == FieldType::PHONE) expected = &it->second.phone;
                        else if (rec.fieldType == FieldType::ADDRESS) expected = &it->second.address;
                        if (expected && plaintext == *expected) {
                            passCount++;
                        }
                    }
                }
            }
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    double ms = std::chrono::duration<double, std::milli>(end - start).count();
    std::cout << "  完成: 耗时 " << std::fixed << std::setprecision(1) << ms
              << " ms, 密文记录 " << totalRecords
              << " 条, 校验通过 " << passCount << " 条" << std::endl;
    return ms;
}

// ================================================================
// 实验组：OpenHiTLS 流水线解密（根据 OPENHITLS_BATCH_IO 决定 I/O 模式）
// ================================================================
double benchmarkOpenHiTLS(BatchDecryptor& decryptor,
                          DAO& dao,
                          const TestDataset& dataset,
                          int& passCount, int& totalRecords) {
    passCount = 0;
    totalRecords = 0;

    if (OPENHITLS_BATCH_IO) {
        std::cout << "  运行 OpenHiTLS 流水线解密（批量读取 MySQL + 多线程并行）..." << std::endl;
    } else {
        std::cout << "  运行 OpenHiTLS 流水线解密（逐条读取 MySQL + 多线程并行，仅计算并行）..." << std::endl;
    }

    std::string requestId = "perf-compare-" + std::to_string(time(nullptr));

    auto start = std::chrono::high_resolution_clock::now();

    if (OPENHITLS_BATCH_IO) {
        // ---- 批量读取模式 ----
        auto results = decryptor.decryptBatch(dataset.ids, requestId, nullptr, nullptr);
        totalRecords = results.size();
        for (const auto& r : results) {
            if (r.success) passCount++;
        }

    } else {
        // ---- 逐条读取模式 ----
        std::vector<CipherRecord> allRecords;
        for (auto id : dataset.ids) {
            auto records = dao.batchSelectCiphers({id});
            for (const auto& rec : records) {
                allRecords.push_back(rec);
            }
        }
        auto results = decryptor.decryptRecords(allRecords, requestId, nullptr, nullptr);
        totalRecords = results.size();
        for (const auto& r : results) {
            if (r.success) passCount++;
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    double ms = std::chrono::duration<double, std::milli>(end - start).count();

    std::cout << "  完成: 耗时 " << std::fixed << std::setprecision(1) << ms
              << " ms, 密文记录 " << totalRecords
              << " 条, 校验通过 " << passCount << " 条" << std::endl;
    return ms;
}

// ================================================================
// 打印对比结果表格
// ================================================================
void printResultTable(int dataCount,
                      double gmsslMs, int gmsslPass, int gmsslTotal,
                      double hitlsMs, int hitlsPass, int hitlsTotal) {
    double gmsslThroughput = dataCount * 1000.0 / gmsslMs;
    double hitlsThroughput = dataCount * 1000.0 / hitlsMs;
    double improvement = (hitlsThroughput - gmsslThroughput) / gmsslThroughput * 100;

    std::cout << "\n";
    std::cout << "  ┌─────────────────────────┬──────────┬──────────┬──────────┬──────────┐" << std::endl;
    std::cout << "  │ 方案                    │ 总耗时ms │ 通过数   │ 条/秒    │ 提升率   │" << std::endl;
    std::cout << "  ├─────────────────────────┼──────────┼──────────┼──────────┼──────────┤" << std::endl;

    const char* gmsslIOMode = GMSSL_BATCH_IO ? "批量" : "逐条";
    const char* hitlsIOMode = OPENHITLS_BATCH_IO ? "批量" : "逐条";

    printf("  │ GmSSL 串行 (%sI/O)    │ %8.1f │ %5d/%d │ %8.1f │   0.0%% │\n",
           gmsslIOMode, gmsslMs, gmsslPass, gmsslTotal, gmsslThroughput);
    printf("  │ OpenHiTLS 流水线 (%sI/O) │ %8.1f │ %5d/%d │ %8.1f │ %5.1f%% │\n",
           hitlsIOMode, hitlsMs, hitlsPass, hitlsTotal, hitlsThroughput, improvement);
    std::cout << "  └─────────────────────────┴──────────┴──────────┴──────────┴──────────┘" << std::endl;
    std::cout << "  （条/秒按原始数据条数 " << dataCount << " 计算，每条含3个字段密文）" << std::endl;

    if (improvement >= 50) {
        std::cout << "  ✅ 吞吐量提升 " << std::fixed << std::setprecision(1) << improvement
                  << "%, 达到50%以上目标！" << std::endl;
    } else {
        std::cout << "  ⚠️  吞吐量提升 " << std::fixed << std::setprecision(1) << improvement
                  << "%, 未达到50%目标" << std::endl;
    }
}

// ================================================================
// 单次测试流程
// ================================================================
void runSingleTest(DAO& dao, BatchDecryptor& decryptor, KeyManager& keyMgr, int dataCount) {
    std::cout << "\n";
    std::cout << "  ═════════════════════════════════════════════════════════" << std::endl;
    std::cout << "  性能对比: GmSSL 串行 vs OpenHiTLS 流水线" << std::endl;
    std::cout << "  数据量: " << dataCount << " 条（每条含 name/phone/address 3个字段密文）" << std::endl;
    std::cout << "  GmSSL I/O 模式: " << (GMSSL_BATCH_IO ? "批量读取" : "逐条读取（模拟初始）") << std::endl;
    std::cout << "  OpenHiTLS I/O 模式: " << (OPENHITLS_BATCH_IO ? "批量读取" : "逐条读取") << std::endl;
    std::cout << "  ═════════════════════════════════════════════════════════" << std::endl;

    auto dataset = generateTestData(dao, keyMgr, dataCount);
    if (dataset.ids.empty()) {
        std::cout << "  ⚠️  数据生成失败" << std::endl;
        return;
    }

    auto encKey = keyMgr.getEncryptionKey();
    auto tagKey = keyMgr.getTagKey();

    std::cout << "\n  ── 对照组: GmSSL 串行解密 ──" << std::endl;
    int gmsslPass = 0, gmsslTotal = 0;
    double gmsslMs = benchmarkGmSSL(dao, dataset, encKey, tagKey, gmsslPass, gmsslTotal);

    std::cout << "\n  ── 实验组: OpenHiTLS 流水线解密 ──" << std::endl;
    int hitlsPass = 0, hitlsTotal = 0;
    double hitlsMs = benchmarkOpenHiTLS(decryptor, dao, dataset, hitlsPass, hitlsTotal);

    printResultTable(dataCount,
                     gmsslMs, gmsslPass, gmsslTotal,
                     hitlsMs, hitlsPass, hitlsTotal);

    std::cout << "\n";
    cleanupData(dao, dataset.ids);
}

// ================================================================
// 主函数
// ================================================================
int main() {
    CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);

    try {
        std::cout << "\n[初始化] 连接数据库..." << std::endl;
        getGlobalConnectionPool().init(
            "127.0.0.1", "root", "U202312485", "secsearch", 3306, POOL_SIZE
        );
        std::cout << "  ✅ 数据库连接成功 (池大小: " << POOL_SIZE << ")" << std::endl;

        std::cout << "[初始化] 加载密钥..." << std::endl;
        KeyManager keyMgr;
        initKeyManager(keyMgr);
        std::cout << "  ✅ 密钥加载成功" << std::endl;

        DAO dao(&getGlobalConnectionPool());
        BatchDecryptor decryptor(dao, keyMgr);


        while (true) {
            std::cout << "\n";
            std::cout << "  请选择测试数据量:" << std::endl;
            std::cout << "    1. 1千条 (快速测试)" << std::endl;
            std::cout << "    2. 1万条 (推荐)" << std::endl;
            std::cout << "    3. 10万条 (耗时较长)" << std::endl;
            std::cout << "    0. 退出" << std::endl;
            std::cout << "\n  请输入选择: ";

            std::string input;
            std::getline(std::cin, input);
            int choice = 0;
            try { choice = std::stoi(input); } catch (...) { choice = 0; }

            int dataCount = 0;
            switch (choice) {
                case 1: dataCount = 1000; break;
                case 2: dataCount = 10000; break;
                case 3: dataCount = 100000; break;
                case 0:
                    std::cout << "  退出程序" << std::endl;
                    getGlobalConnectionPool().closeAll();
                    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
                    return 0;
                default:
                    std::cout << "  无效选择，请重新输入" << std::endl;
                    continue;
            }

            try {
                runSingleTest(dao, decryptor, keyMgr, dataCount);
            } catch (const std::exception& e) {
                std::cerr << "\n  ❌ 测试异常: " << e.what() << std::endl;
            }

            std::cout << "\n  按回车返回菜单...";
            std::getline(std::cin, input);
        }
    } catch (const std::exception& e) {
        std::cerr << "\n❌ 初始化失败: " << e.what() << std::endl;
        getGlobalConnectionPool().closeAll();
        CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
        return 1;
    }

    return 0;
}
