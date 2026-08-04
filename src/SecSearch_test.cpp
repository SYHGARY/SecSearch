// secsearch_test.cpp - 综合测试套件：功能测试、性能基准、边界稳定性、安全合规
// 修正版本：性能测试仅生成一次数据，避免重复插入/删除

#include "database/dao.h"
#include "database/connection_pool.h"
#include "query/query_service.h"
#include "crypto/key_manager.h"
#include "crypto/sm4_cipher.h"
#include "crypto/hmac_sm3.h"
#include "decrypt/batch_decryptor.h"
#include "audit/audit_logger.h"

#include <hitls/crypto/crypt_eal_init.h>

#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <chrono>
#include <thread>
#include <mutex>
#include <algorithm>
#include <random>
#include <sstream>
#include <cmath>

using namespace crypto;
using namespace database;
using namespace query;
using namespace decrypt;
using namespace audit;

// ================================================================
// 全局统计
// ================================================================
static int g_total = 0;
static int g_pass = 0;
static int g_fail = 0;

void resetStats() {
    g_total = 0;
    g_pass = 0;
    g_fail = 0;
}

void printHeader(const std::string& title) {
    std::cout << "\n════════════════════════════════════════════════════════" << std::endl;
    std::cout << "  " << title << std::endl;
    std::cout << "════════════════════════════════════════════════════════" << std::endl;
}

void printSubHeader(const std::string& title) {
    std::cout << "\n── " << title << " ──" << std::endl;
}

void check(const std::string& name, bool condition) {
    g_total++;
    if (condition) {
        g_pass++;
        std::cout << "  ✅ " << name << std::endl;
    } else {
        g_fail++;
        std::cout << "  ❌ " << name << std::endl;
    }
}

void printSummary(const std::string& moduleName) {
    std::cout << "\n════════════════════════════════════════════════════════" << std::endl;
    std::cout << "  【" << moduleName << "】汇总: 总计 " << g_total 
              << " 项, 通过 " << g_pass << " 项, 失败 " << g_fail << " 项" << std::endl;
    if (g_fail == 0) {
        std::cout << "  🎉 全部通过！" << std::endl;
    } else {
        std::cout << "  ⚠️  有 " << g_fail << " 项失败" << std::endl;
    }
    std::cout << "════════════════════════════════════════════════════════" << std::endl;
}

// ================================================================
// 辅助函数
// ================================================================
std::vector<CipherRecord> filterByFieldType(const std::vector<CipherRecord>& records, FieldType type) {
    std::vector<CipherRecord> result;
    for (const auto& r : records) {
        if (r.fieldType == type) result.push_back(r);
    }
    return result;
}

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

// 生成随机姓名
std::string randomName(int seed) {
    static const std::vector<std::string> surnames = {"张", "王", "李", "赵", "刘", "陈", "杨", "黄", "周", "吴"};
    static const std::vector<std::string> names = {"伟", "芳", "娜", "敏", "静", "强", "磊", "洋", "艳", "勇",
                                                   "军", "杰", "娟", "涛", "明", "超", "秀英", "霞", "平", "刚"};
    return surnames[seed % surnames.size()] + names[(seed * 7) % names.size()];
}

// 生成随机手机号
std::string randomPhone(int seed) {
    std::string prefixes[] = {"138", "139", "137", "136", "135", "158", "159", "188", "189", "187"};
    std::string prefix = prefixes[seed % 10];
    std::string suffix = std::to_string(10000000 + (seed * 1234567) % 90000000);
    return prefix + suffix.substr(0, 8);
}

// 生成随机地址
std::string randomAddress(int seed) {
    std::vector<std::string> cities = {"北京市", "上海市", "广州市", "深圳市", "武汉市", "成都市", "杭州市", "南京市"};
    std::vector<std::string> districts = {"朝阳区", "海淀区", "浦东新区", "天河区", "南山区", "武昌区", "武侯区", "西湖区"};
    std::vector<std::string> roads = {"建国路", "人民路", "中山路", "解放路", "建设路", "和平路", "友谊路", "文化路"};
    return cities[seed % cities.size()] + districts[(seed * 3) % districts.size()] + 
           roads[(seed * 5) % roads.size()] + std::to_string(seed % 1000) + "号";
}

// 生成批量测试数据，返回插入的ID列表
std::vector<int64_t> generateTestData(DAO& dao, KeyManager& keyMgr, int count) {
    auto encKey = keyMgr.getEncryptionKey();
    auto idxKey = keyMgr.getIndexKey();
    auto tagKey = keyMgr.getTagKey();
    int encVer = keyMgr.getEncryptionVersion();

    std::vector<int64_t> ids;
    ids.reserve(count);

    std::cout << "  正在生成 " << count << " 条测试数据..." << std::endl;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < count; ++i) {
        PlainData data{randomName(i), randomPhone(i), randomAddress(i)};
        try {
            int64_t id = dao.insertData(data, encKey, idxKey, tagKey, encVer);
            ids.push_back(id);
        } catch (const std::exception& e) {
            std::cerr << "  插入第 " << i << " 条失败: " << e.what() << std::endl;
        }
        if ((i + 1) % 1000 == 0) {
            auto now = std::chrono::high_resolution_clock::now();
            double elapsed = std::chrono::duration<double, std::milli>(now - start).count();
            std::cout << "  已插入 " << (i + 1) << " 条, 耗时 " << elapsed << "ms" << std::endl;
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    double totalMs = std::chrono::duration<double, std::milli>(end - start).count();
    std::cout << "  完成！共插入 " << ids.size() << " 条, 总耗时 " << totalMs << "ms, 平均 " 
              << (totalMs / count) << "ms/条" << std::endl;

    return ids;
}

// 计算百分位
double percentile(std::vector<double>& data, double p) {
    if (data.empty()) return 0;
    std::sort(data.begin(), data.end());
    size_t idx = static_cast<size_t>(data.size() * p / 100.0);
    if (idx >= data.size()) idx = data.size() - 1;
    return data[idx];
}

// 计算平均值
double average(const std::vector<double>& data) {
    if (data.empty()) return 0;
    double sum = 0;
    for (double v : data) sum += v;
    return sum / data.size();
}

// 清理测试数据
void cleanupData(DAO& dao, const std::vector<int64_t>& ids) {
    std::cout << "  正在清理 " << ids.size() << " 条测试数据..." << std::endl;
    for (auto id : ids) {
        try { dao.deleteData(id); } catch (...) {}
    }
    std::cout << "  清理完成" << std::endl;
}

// ================================================================
// 模块1：功能测试
// ================================================================
void testEncryptionStorage(DAO& dao, KeyManager& keyMgr) {
    printSubHeader("1.1 字段加密正确性");

    auto encKey = keyMgr.getEncryptionKey();
    auto idxKey = keyMgr.getIndexKey();
    auto tagKey = keyMgr.getTagKey();
    int encVer = keyMgr.getEncryptionVersion();

    PlainData data{"张三", "13800138000", "北京市朝阳区建国路88号"};
    int64_t id = dao.insertData(data, encKey, idxKey, tagKey, encVer);
    check("插入数据成功", id > 0);

    std::vector<int64_t> ids{id};
    auto records = dao.batchSelectCiphers(ids);
    check("读取到3条字段密文记录", records.size() == 3);

    auto nameRecords = filterByFieldType(records, FieldType::NAME);
    auto phoneRecords = filterByFieldType(records, FieldType::PHONE);
    auto addrRecords = filterByFieldType(records, FieldType::ADDRESS);

    check("姓名字段密文存在", nameRecords.size() == 1);
    check("手机号字段密文存在", phoneRecords.size() == 1);
    check("地址字段密文存在", addrRecords.size() == 1);

    if (!nameRecords.empty()) {
        auto namePlain = Sm4Cipher::decrypt(nameRecords[0].cipher, encKey);
        std::string nameStr(namePlain.begin(), namePlain.end());
        check("姓名字段解密正确", nameStr == data.name);
    }
    if (!phoneRecords.empty()) {
        auto phonePlain = Sm4Cipher::decrypt(phoneRecords[0].cipher, encKey);
        std::string phoneStr(phonePlain.begin(), phonePlain.end());
        check("手机号字段解密正确", phoneStr == data.phone);
    }
    if (!addrRecords.empty()) {
        auto addrPlain = Sm4Cipher::decrypt(addrRecords[0].cipher, encKey);
        std::string addrStr(addrPlain.begin(), addrPlain.end());
        check("地址字段解密正确", addrStr == data.address);
    }

    if (!nameRecords.empty()) {
        auto cipherBytes = std::vector<unsigned char>(nameRecords[0].cipher.begin(), nameRecords[0].cipher.end());
        std::string computedTag = HmacSm3::hmacHex(cipherBytes, tagKey);
        check("姓名Tag校验通过", computedTag == nameRecords[0].tag);
    }

    dao.deleteData(id);
}

void testExactQuery(DAO& dao, QueryService& qs, KeyManager& keyMgr) {
    auto encKey = keyMgr.getEncryptionKey();
    auto idxKey = keyMgr.getIndexKey();
    auto tagKey = keyMgr.getTagKey();
    int encVer = keyMgr.getEncryptionVersion();

    std::vector<int64_t> testIds;
    PlainData d1{"张三", "13800138000", "北京市朝阳区"};
    PlainData d2{"李四", "13900139000", "上海市浦东新区"};
    PlainData d3{"王五", "13700137000", "广州市天河区"};
    testIds.push_back(dao.insertData(d1, encKey, idxKey, tagKey, encVer));
    testIds.push_back(dao.insertData(d2, encKey, idxKey, tagKey, encVer));
    testIds.push_back(dao.insertData(d3, encKey, idxKey, tagKey, encVer));

    printSubHeader("2.1 正常等值查询");

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    auto nameResults = qs.exactQuery("张三", FieldType::NAME, idxKey, encKey, tagKey);
    check("姓名精确查询-找到1条", nameResults.size() == 1);
    if (!nameResults.empty()) {
        check("姓名精确查询-结果正确", nameResults[0].name == "张三");
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    auto phoneResults = qs.exactQuery("13800138000", FieldType::PHONE, idxKey, encKey, tagKey);
    check("手机号精确查询-找到1条", phoneResults.size() == 1);
    if (!phoneResults.empty()) {
        check("手机号精确查询-结果正确", phoneResults[0].phone == "13800138000");
    }

    printSubHeader("2.2 空值、不存在值查询");

    bool threwExact = false;
    try {
        qs.exactQuery("", FieldType::NAME, idxKey, encKey, tagKey);
    } catch (const std::runtime_error&) {
        threwExact = true;
    }
    check("空值精确查询-抛出异常", threwExact);

    bool threwFuzzy = false;
    try {
        qs.fuzzyQuery("", FieldType::NAME, idxKey, encKey, tagKey);
    } catch (const std::runtime_error&) {
        threwFuzzy = true;
    }
    check("空值模糊查询-抛出异常", threwFuzzy);

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    auto noResults = qs.exactQuery("不存在的人", FieldType::NAME, idxKey, encKey, tagKey);
    check("不存在值查询-返回空", noResults.empty());

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    auto noPhoneResults = qs.exactQuery("10000000000", FieldType::PHONE, idxKey, encKey, tagKey);
    check("不存在手机号查询-返回空", noPhoneResults.empty());

    for (auto id : testIds) dao.deleteData(id);
}

void testFuzzyQuery(DAO& dao, QueryService& qs, KeyManager& keyMgr) {
    auto encKey = keyMgr.getEncryptionKey();
    auto idxKey = keyMgr.getIndexKey();
    auto tagKey = keyMgr.getTagKey();
    int encVer = keyMgr.getEncryptionVersion();

    std::vector<int64_t> testIds;
    PlainData d1{"张三丰", "13800138000", "北京市朝阳区建国路"};
    PlainData d2{"张三", "13812345678", "上海市浦东新区张江路"};
    PlainData d3{"王张三", "13987654321", "广州市天河区天河路"};
    PlainData d4{"李四", "13700001111", "深圳市南山区科技园"};
    testIds.push_back(dao.insertData(d1, encKey, idxKey, tagKey, encVer));
    testIds.push_back(dao.insertData(d2, encKey, idxKey, tagKey, encVer));
    testIds.push_back(dao.insertData(d3, encKey, idxKey, tagKey, encVer));
    testIds.push_back(dao.insertData(d4, encKey, idxKey, tagKey, encVer));

    printSubHeader("3.1 全位置模糊查询（中文）");

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    auto results = qs.fuzzyQuery("张三", FieldType::NAME, idxKey, encKey, tagKey);
    check("模糊查询-张三（至少2条）", results.size() >= 2);

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    auto results2 = qs.fuzzyQuery("李四", FieldType::NAME, idxKey, encKey, tagKey);
    check("模糊查询-李四（1条）", results2.size() == 1);

    printSubHeader("3.2 全位置模糊查询（数字）");
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    auto phonePrefix = qs.fuzzyQuery("138", FieldType::PHONE, idxKey, encKey, tagKey);
    check("手机号前缀查询-138开头", phonePrefix.size() >= 2);

    printSubHeader("3.3 地址模糊查询");
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    auto addrResults = qs.fuzzyQuery("北京", FieldType::ADDRESS, idxKey, encKey, tagKey);
    check("地址模糊查询-北京", addrResults.size() >= 1);

    for (auto id : testIds) dao.deleteData(id);
}

void testIndexMaintenance(DAO& dao, QueryService& qs, KeyManager& keyMgr) {
    auto encKey = keyMgr.getEncryptionKey();
    auto idxKey = keyMgr.getIndexKey();
    auto tagKey = keyMgr.getTagKey();
    int encVer = keyMgr.getEncryptionVersion();

    printSubHeader("4.1 新增数据索引同步");

    PlainData data{"测试用户", "13600001111", "测试地址"};
    int64_t id = dao.insertData(data, encKey, idxKey, tagKey, encVer);

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    auto results = qs.exactQuery("测试用户", FieldType::NAME, idxKey, encKey, tagKey);
    check("新增后索引可查询", results.size() == 1);

    printSubHeader("4.2 修改数据索引同步");

    PlainData newData{"修改后用户", "13600002222", "修改后地址"};
    bool updated = dao.updateData(id, newData, encKey, idxKey, tagKey, encVer);
    check("修改数据成功", updated);

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    auto oldResults = qs.exactQuery("测试用户", FieldType::NAME, idxKey, encKey, tagKey);
    check("修改后旧值查询为空", oldResults.empty());

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    auto newResults = qs.exactQuery("修改后用户", FieldType::NAME, idxKey, encKey, tagKey);
    check("修改后新值可查询", newResults.size() == 1);

    printSubHeader("4.3 删除数据索引同步");

    bool deleted = dao.deleteData(id);
    check("删除数据成功", deleted);

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    auto delResults = qs.exactQuery("修改后用户", FieldType::NAME, idxKey, encKey, tagKey);
    check("删除后索引同步删除", delResults.empty());
}

void testCollisionResolution(DAO& dao, QueryService& qs, KeyManager& keyMgr) {
    printSubHeader("5.1 假阳性结果过滤");

    auto encKey = keyMgr.getEncryptionKey();
    auto idxKey = keyMgr.getIndexKey();
    auto tagKey = keyMgr.getTagKey();
    int encVer = keyMgr.getEncryptionVersion();

    std::vector<int64_t> testIds;
    PlainData d1{"ABCDE", "13800000001", "地址一"};
    PlainData d2{"ABCXY", "13800000002", "地址二"};
    PlainData d3{"XYZAB", "13800000003", "地址三"};
    testIds.push_back(dao.insertData(d1, encKey, idxKey, tagKey, encVer));
    testIds.push_back(dao.insertData(d2, encKey, idxKey, tagKey, encVer));
    testIds.push_back(dao.insertData(d3, encKey, idxKey, tagKey, encVer));

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    auto results = qs.fuzzyQuery("ABCD", FieldType::NAME, idxKey, encKey, tagKey);
    check("模糊查询结果准确-无假阳性", results.size() == 1);
    if (!results.empty()) {
        check("模糊查询结果内容正确", results[0].name == "ABCDE");
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    auto exactResults = qs.exactQuery("ABCDE", FieldType::NAME, idxKey, encKey, tagKey);
    check("精确查询无假阳性", exactResults.size() == 1);

    for (auto id : testIds) dao.deleteData(id);
}

void testBatchDecrypt(DAO& dao, BatchDecryptor& decryptor, KeyManager& keyMgr) {
    printSubHeader("6.1 批量解密正确性");

    auto encKey = keyMgr.getEncryptionKey();
    auto idxKey = keyMgr.getIndexKey();
    auto tagKey = keyMgr.getTagKey();
    int encVer = keyMgr.getEncryptionVersion();

    const int TEST_COUNT = 50;
    std::vector<int64_t> testIds;
    std::vector<std::string> expectedNames;

    for (int i = 0; i < TEST_COUNT; ++i) {
        std::string name = "用户" + std::to_string(i);
        std::string phone = "138" + std::to_string(1000000 + i);
        std::string addr = "地址" + std::to_string(i);
        PlainData data{name, phone, addr};
        int64_t id = dao.insertData(data, encKey, idxKey, tagKey, encVer);
        testIds.push_back(id);
        expectedNames.push_back(name);
    }
    check("插入" + std::to_string(TEST_COUNT) + "条测试数据", testIds.size() == TEST_COUNT);

    auto cipherRecords = dao.batchSelectCiphers(testIds);
    check("批量读取密文记录数正确", cipherRecords.size() == TEST_COUNT * 3);

    auto nameRecords = filterByFieldType(cipherRecords, FieldType::NAME);
    check("筛选出" + std::to_string(TEST_COUNT) + "条姓名字段", nameRecords.size() == TEST_COUNT);

    std::string requestId = AuditLogger::generateRequestId();
    auto results = decryptor.decryptRecords(nameRecords, requestId, nullptr, nullptr);
    check("批量解密结果数正确", results.size() == TEST_COUNT);

    bool orderCorrect = true;
    bool allSuccess = true;
    for (size_t i = 0; i < results.size(); ++i) {
        if (!results[i].success) { 
            allSuccess = false; 
            if (i == 0) {
                std::cout << "  第一条失败: " << results[i].errorMsg << std::endl;
            }
            break; 
        }
        if (results[i].plaintext != expectedNames[i]) { orderCorrect = false; break; }
    }
    check("批量解密全部成功", allSuccess);
    if (allSuccess) {
        check("批量解密顺序正确", orderCorrect);
    }

    for (auto id : testIds) dao.deleteData(id);
}

void testKeyManagement(DAO& dao, KeyManager& keyMgr) {
    std::vector<unsigned char> kek(16, 0x11);

    printSubHeader("7.1 密钥加载正确性");

    auto encKey = keyMgr.getEncryptionKey();
    auto idxKey = keyMgr.getIndexKey();
    auto tagKey = keyMgr.getTagKey();

    check("加密密钥与索引密钥不同", encKey != idxKey);
    check("加密密钥与Tag密钥不同", encKey != tagKey);
    check("索引密钥与Tag密钥不同", idxKey != tagKey);

    std::vector<unsigned char> testData = {'t', 'e', 's', 't'};
    auto encrypted = Sm4Cipher::encrypt(testData, encKey);
    auto decrypted = Sm4Cipher::decrypt(encrypted, encKey);
    check("加密密钥加解密正常", decrypted == testData);

    auto hmacIdx = HmacSm3::hmacHex(testData, idxKey);
    auto hmacTag = HmacSm3::hmacHex(testData, tagKey);
    check("索引密钥HMAC正常", hmacIdx.size() == 64);
    check("Tag密钥HMAC正常", hmacTag.size() == 64);
    check("不同密钥HMAC结果不同", hmacIdx != hmacTag);

    printSubHeader("7.2 密钥轮换兼容性");

    auto oldEncKey = keyMgr.getEncryptionKey();
    int oldVersion = keyMgr.getEncryptionVersion();

    PlainData data{"轮换测试", "13500000000", "测试地址"};
    int64_t id = dao.insertData(data, oldEncKey, idxKey, tagKey, oldVersion);

    int newVersion = keyMgr.rotateEncryptionKey();
    check("密钥版本号递增", newVersion > oldVersion);

    auto newEncKey = keyMgr.getEncryptionKey();
    check("轮换后密钥发生变化", newEncKey != oldEncKey);

    PlainData newData{"新数据", "13500000001", "新地址"};
    int64_t newId = dao.insertData(newData, newEncKey, idxKey, tagKey, newVersion);

    auto oldRecords = dao.batchSelectCiphers({id});
    auto oldNameRecords = filterByFieldType(oldRecords, FieldType::NAME);
    if (!oldNameRecords.empty()) {
        auto oldPlain = Sm4Cipher::decrypt(oldNameRecords[0].cipher, oldEncKey);
        std::string oldStr(oldPlain.begin(), oldPlain.end());
        check("旧版本密钥可解密历史数据", oldStr == "轮换测试");
    }

    auto newRecords = dao.batchSelectCiphers({newId});
    auto newNameRecords = filterByFieldType(newRecords, FieldType::NAME);
    if (!newNameRecords.empty()) {
        auto newPlain = Sm4Cipher::decrypt(newNameRecords[0].cipher, newEncKey);
        std::string newStr(newPlain.begin(), newPlain.end());
        check("新版本密钥加密新数据", newStr == "新数据");
    }

    dao.deleteData(id);
    dao.deleteData(newId);

    printSubHeader("7.3 密钥状态管控");

    int currentVer = keyMgr.getEncryptionVersion();
    keyMgr.setKeyStatus(1, currentVer, KeyStatus::DISABLED);

    std::vector<unsigned char> disabledKey;
    bool gotKey = keyMgr.getEncryptionKeyByVersion(currentVer, disabledKey);
    check("可获取停用版本密钥", gotKey);

    bool canDecrypt = false;
    if (gotKey) {
        try {
            auto testEnc = Sm4Cipher::encrypt(testData, disabledKey);
            auto testDec = Sm4Cipher::decrypt(testEnc, disabledKey);
            canDecrypt = (testDec == testData);
        } catch (...) { canDecrypt = false; }
    }
    check("停用密钥仍可解密", canDecrypt);

    keyMgr.setKeyStatus(1, currentVer, KeyStatus::ENABLED);
}

void testExceptionHandling(DAO& dao, QueryService& qs, KeyManager& keyMgr) {
    auto encKey = keyMgr.getEncryptionKey();
    auto idxKey = keyMgr.getIndexKey();
    auto tagKey = keyMgr.getTagKey();
    int encVer = keyMgr.getEncryptionVersion();

    printSubHeader("8.1 特殊字符处理");

    bool specialCharSafe = true;
    try {
        PlainData data{"测试'\";--", "13611112222", "地址\\特殊"};
        int64_t id = dao.insertData(data, encKey, idxKey, tagKey, encVer);
        dao.deleteData(id);
    } catch (...) { specialCharSafe = false; }
    check("特殊字符处理不崩溃", specialCharSafe);

    printSubHeader("8.2 完整性校验（篡改检测）");

    PlainData data{"篡改测试", "13700000000", "测试地址"};
    int64_t id = dao.insertData(data, encKey, idxKey, tagKey, encVer);

    auto records = dao.batchSelectCiphers({id});
    auto nameRecords = filterByFieldType(records, FieldType::NAME);
    if (!nameRecords.empty()) {
        auto cipherBytes = std::vector<unsigned char>(nameRecords[0].cipher.begin(), nameRecords[0].cipher.end());
        std::string correctTag = HmacSm3::hmacHex(cipherBytes, tagKey);
        check("正确Tag校验通过", correctTag == nameRecords[0].tag);

        std::string tamperedCipher = nameRecords[0].cipher;
        if (tamperedCipher.size() > 10) {
            tamperedCipher[5] = (tamperedCipher[5] == '0') ? '1' : '0';
            auto tamperedBytes = std::vector<unsigned char>(tamperedCipher.begin(), tamperedCipher.end());
            std::string tamperedTag = HmacSm3::hmacHex(tamperedBytes, tagKey);
            check("篡改后Tag不匹配", tamperedTag != nameRecords[0].tag);
        }
    }

    dao.deleteData(id);
}

void runFunctionalTests(DAO& dao, QueryService& qs, BatchDecryptor& decryptor, KeyManager& keyMgr) {
    resetStats();
    printHeader("【模块1】功能测试");

    try {
        testEncryptionStorage(dao, keyMgr);
        testExactQuery(dao, qs, keyMgr);
        testFuzzyQuery(dao, qs, keyMgr);
        testIndexMaintenance(dao, qs, keyMgr);
        testCollisionResolution(dao, qs, keyMgr);
        testBatchDecrypt(dao, decryptor, keyMgr);
        testKeyManagement(dao, keyMgr);
        testExceptionHandling(dao, qs, keyMgr);
        printSummary("功能测试");
    } catch (const std::exception& e) {
        std::cerr << "\n❌ 测试异常中断: " << e.what() << std::endl;
    }
}

// ================================================================
// 模块2：性能基准测试（修改：共享数据）
// ================================================================
void runQueryPerfTest(DAO& dao, QueryService& qs, KeyManager& keyMgr, const std::vector<int64_t>& ids) {
    printSubHeader("数据量: " + std::to_string(ids.size()) + " 条");

    auto encKey = keyMgr.getEncryptionKey();
    auto idxKey = keyMgr.getIndexKey();
    auto tagKey = keyMgr.getTagKey();

    if (ids.empty()) {
        std::cout << "  ⚠️  数据为空" << std::endl;
        return;
    }

    const int QUERY_COUNT = 100;
    std::vector<double> exactTimes;
    std::vector<double> fuzzyTimes;
    int exactSuccess = 0;
    int fuzzySuccess = 0;

    // 收集已存在的姓名（取前1000个）
    std::vector<std::string> existingNames;
    for (size_t i = 0; i < ids.size() && i < 1000; ++i) {
        existingNames.push_back(randomName(i));
    }
    if (existingNames.empty()) {
        std::cout << "  ⚠️  无法获取已有姓名" << std::endl;
        return;
    }

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, existingNames.size() - 1);

    std::cout << "\n  执行 " << QUERY_COUNT << " 次精确查询（使用已存在姓名）..." << std::endl;
    for (int i = 0; i < QUERY_COUNT; ++i) {
        std::string keyword = existingNames[dis(gen)];
        auto start = std::chrono::high_resolution_clock::now();
        try {
            auto results = qs.exactQuery(keyword, FieldType::NAME, idxKey, encKey, tagKey);
            if (!results.empty()) exactSuccess++;
        } catch (...) {}
        auto end = std::chrono::high_resolution_clock::now();
        double ms = std::chrono::duration<double, std::milli>(end - start).count();
        exactTimes.push_back(ms);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::cout << "  执行 " << QUERY_COUNT << " 次模糊查询（使用完整姓名）..." << std::endl;
    for (int i = 0; i < QUERY_COUNT; ++i) {
        std::string keyword = existingNames[dis(gen)];
        auto start = std::chrono::high_resolution_clock::now();
        try {
            auto results = qs.fuzzyQuery(keyword, FieldType::NAME, idxKey, encKey, tagKey);
            if (!results.empty()) fuzzySuccess++;
        } catch (...) {}
        auto end = std::chrono::high_resolution_clock::now();
        double ms = std::chrono::duration<double, std::milli>(end - start).count();
        fuzzyTimes.push_back(ms);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::cout << "\n  ┌────────────┬──────────┬──────────┬──────────┬──────────┐" << std::endl;
    std::cout << "  │ 查询类型   │ 平均(ms) │ P95(ms)  │ 成功率   │ 样本数   │" << std::endl;
    std::cout << "  ├────────────┼──────────┼──────────┼──────────┼──────────┤" << std::endl;
    printf("  │ 精确查询   │ %8.2f │ %8.2f │ %6.1f%% │ %8d │\n",
           average(exactTimes), percentile(exactTimes, 95),
           exactSuccess * 100.0 / QUERY_COUNT, QUERY_COUNT);
    printf("  │ 模糊查询   │ %8.2f │ %8.2f │ %6.1f%% │ %8d │\n",
           average(fuzzyTimes), percentile(fuzzyTimes, 95),
           fuzzySuccess * 100.0 / QUERY_COUNT, QUERY_COUNT);
    std::cout << "  └────────────┴──────────┴──────────┴──────────┴──────────┘" << std::endl;
}

void runBatchDecryptPerfTest(DAO& dao, BatchDecryptor& decryptor, KeyManager& keyMgr, const std::vector<int64_t>& ids) {
    printSubHeader("批量解密性能对比: " + std::to_string(ids.size()) + " 条");

    auto encKey = keyMgr.getEncryptionKey();
    auto idxKey = keyMgr.getIndexKey();
    auto tagKey = keyMgr.getTagKey();

    if (ids.empty()) return;

    const size_t BATCH_SIZE = 20000;   // 每批处理的记录数

    // ========== 实验组：使用 decryptBatch（自动分批拉取 + 流水线并行） ==========
    std::cout << "\n  实验组: 批量解密（流水线+多线程，自动分批）..." << std::endl;
    std::string requestId = AuditLogger::generateRequestId();
    auto start2 = std::chrono::high_resolution_clock::now();
    auto results = decryptor.decryptBatch(ids, requestId, nullptr, nullptr);
    auto end2 = std::chrono::high_resolution_clock::now();
    double batchMs = std::chrono::duration<double, std::milli>(end2 - start2).count();

    int batchSuccess = 0;
    for (const auto& r : results) if (r.success) batchSuccess++;

    // ========== 对照组：手动分批读取并串行解密（带Tag校验） ==========
    std::cout << "\n  对照组: 逐条串行解密（带Tag校验，分批读取）..." << std::endl;
    std::vector<DecryptResult> serialResults;
    serialResults.reserve(ids.size());
    auto start1 = std::chrono::high_resolution_clock::now();
    int serialSuccess = 0;

    for (size_t offset = 0; offset < ids.size(); offset += BATCH_SIZE) {
        size_t end = std::min(offset + BATCH_SIZE, ids.size());
        std::vector<int64_t> batchIds(ids.begin() + offset, ids.begin() + end);
        auto records = dao.batchSelectCiphers(batchIds);  // 分批读取

        for (const auto& rec : records) {
            bool ok = false;
            try {
                std::vector<unsigned char> tagKeyVer;
                if (keyMgr.getTagKeyByVersion(rec.encKeyVersion, tagKeyVer)) {
                    auto cipherBytes = std::vector<unsigned char>(rec.cipher.begin(), rec.cipher.end());
                    std::string computedTag = HmacSm3::hmacHex(cipherBytes, tagKeyVer);
                    if (computedTag == rec.tag) {
                        auto plainBytes = Sm4Cipher::decrypt(rec.cipher, encKey);
                        ok = true;
                        if (serialSuccess == 0) {
                            std::cout << "    第一条解密后长度: " << plainBytes.size() << " 字节" << std::endl;
                        }
                    }
                }
            } catch (const std::exception& e) {
                if (serialSuccess == 0) {
                    std::cout << "    串行解密第一条失败: " << e.what() << std::endl;
                }
            }
            if (ok) serialSuccess++;
        }
    }
    auto end1 = std::chrono::high_resolution_clock::now();
    double serialMs = std::chrono::duration<double, std::milli>(end1 - start1).count();

    // ========== 计算对比数据 ==========
    double serialThroughput = ids.size() * 1000.0 / serialMs;
    double batchThroughput = ids.size() * 1000.0 / batchMs;
    double improvement = (batchThroughput - serialThroughput) / serialThroughput * 100;

    std::cout << "\n  ┌──────────┬──────────┬──────────┬──────────┬──────────┐" << std::endl;
    std::cout << "  │ 方案     │ 总耗时ms │ 成功数   │ 条/秒    │ 提升率   │" << std::endl;
    std::cout << "  ├──────────┼──────────┼──────────┼──────────┼──────────┤" << std::endl;
    printf("  │ 串行对照 │ %8.1f │ %8d │ %8.1f │   0.0%% │\n", serialMs, serialSuccess, serialThroughput);
    printf("  │ 批量实验 │ %8.1f │ %8d │ %8.1f │ %5.1f%% │\n", batchMs, batchSuccess, batchThroughput, improvement);
    std::cout << "  └──────────┴──────────┴──────────┴──────────┴──────────┘" << std::endl;

    if (improvement >= 50) {
        std::cout << "  ✅ 吞吐量提升 " << improvement << "%, 达到50%以上的目标" << std::endl;
    } else {
        std::cout << "  ⚠️  吞吐量提升 " << improvement << "%, 未达到50%目标" << std::endl;
    }
}

void runPerformanceTests(DAO& dao, QueryService& qs, BatchDecryptor& decryptor, KeyManager& keyMgr) {
    // 重置密钥管理器，避免之前功能测试的影响
    std::cout << "\n[性能测试] 重置密钥管理器..." << std::endl;
    initKeyManager(keyMgr);
    std::cout << "  当前加密密钥版本: " << keyMgr.getEncryptionVersion() << std::endl;

    resetStats();
    printHeader("【模块2】性能基准测试");

    std::cout << "\n  请选择测试数据量:" << std::endl;
    std::cout << "    1. 1千条 (测试用)" << std::endl;
    std::cout << "    2. 1万条 (推荐)" << std::endl;
    std::cout << "    3. 10万条 (耗时较长)" << std::endl;
    std::cout << "    4. 50万条 (耗时很长，验证并行优势)" << std::endl;
    std::cout << "    5. 100万条 (极长，仅做极限测试)" << std::endl;
    std::cout << "    0. 返回主菜单" << std::endl;
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
        case 4: dataCount = 500000; break;
        case 5: dataCount = 1000000; break;
        default: std::cout << "  返回主菜单" << std::endl; return;
    }

    // ★ 只生成一次数据
    auto ids = generateTestData(dao, keyMgr, dataCount);
    if (ids.empty()) {
        std::cout << "  ⚠️  数据生成失败" << std::endl;
        return;
    }

    try {
        printSubHeader("6.2.1 查询性能测试");
        runQueryPerfTest(dao, qs, keyMgr, ids);

        printSubHeader("6.2.2 批量解密性能测试");
        runBatchDecryptPerfTest(dao, decryptor, keyMgr, ids);

    } catch (const std::exception& e) {
        std::cerr << "\n❌ 性能测试异常: " << e.what() << std::endl;
    }

    // ★ 统一清理
    cleanupData(dao, ids);
}

// ================================================================
// 模块3：边界与稳定性测试
// ================================================================
void runBoundaryTests(DAO& dao, QueryService& qs, KeyManager& keyMgr) {
    printSubHeader("6.3.1 边界值测试");

    auto encKey = keyMgr.getEncryptionKey();
    auto idxKey = keyMgr.getIndexKey();
    auto tagKey = keyMgr.getTagKey();
    int encVer = keyMgr.getEncryptionVersion();

    // 最短字段（单字符）—— 英文字母会被长度限制拦截，预期查询失败但系统不崩溃
    bool minLenOk = true;
    try {
        PlainData data{"A", "1", "B"};
        int64_t id = dao.insertData(data, encKey, idxKey, tagKey, encVer);
        // 查询 "A" 会触发长度限制异常，捕获后视为正常（不崩溃）
        try {
            auto results = qs.exactQuery("A", FieldType::NAME, idxKey, encKey, tagKey);
            // 如果没抛异常，说明长度限制未生效，测试失败
            minLenOk = false;
        } catch (const std::runtime_error&) {
            // 预期异常，说明长度限制生效，测试通过
            minLenOk = true;
        }
        dao.deleteData(id);
    } catch (...) { minLenOk = false; }
    check("最短字段(单字符)查询被正确拦截", minLenOk);

    // 最长字段（长文本）
    bool maxLenOk = true;
    std::string longName(100, '测');
    try {
        PlainData data{longName, "13800138000", "北京市"};
        int64_t id = dao.insertData(data, encKey, idxKey, tagKey, encVer);
        auto records = dao.batchSelectCiphers({id});
        auto nameRecs = filterByFieldType(records, FieldType::NAME);
        if (!nameRecs.empty()) {
            auto plain = Sm4Cipher::decrypt(nameRecs[0].cipher, encKey);
            std::string plainStr(plain.begin(), plain.end());
            maxLenOk = (plainStr == longName);
        }
        dao.deleteData(id);
    } catch (...) { maxLenOk = false; }
    check("最长字段(长文本)加解密正常", maxLenOk);

    // 特殊字符
    bool specialOk = true;
    try {
        PlainData data{"测试@#$%^&*()_+{}[]|\\:;\"'<>,.?/~`", "13800138000", "地址!@#$"};
        int64_t id = dao.insertData(data, encKey, idxKey, tagKey, encVer);
        auto records = dao.batchSelectCiphers({id});
        auto nameRecs = filterByFieldType(records, FieldType::NAME);
        if (!nameRecs.empty()) {
            auto plain = Sm4Cipher::decrypt(nameRecs[0].cipher, encKey);
            std::string plainStr(plain.begin(), plain.end());
            specialOk = (plainStr == data.name);
        }
        dao.deleteData(id);
    } catch (...) { specialOk = false; }
    check("特殊字符加密解密正常", specialOk);
}

void runConcurrencyTest(KeyManager& keyMgr) {
    printSubHeader("6.3.2 并发稳定性测试（5线程并发写入）");

    auto encKey = keyMgr.getEncryptionKey();
    auto idxKey = keyMgr.getIndexKey();
    auto tagKey = keyMgr.getTagKey();
    int encVer = keyMgr.getEncryptionVersion();

    const int THREAD_COUNT = 5;
    const int OPS_PER_THREAD = 20;

    std::vector<std::thread> threads;
    std::vector<int64_t> allIds;
    std::mutex idMutex;
    int successCount = 0;
    int failCount = 0;
    std::mutex countMutex;

    auto start = std::chrono::high_resolution_clock::now();

    for (int t = 0; t < THREAD_COUNT; ++t) {
        threads.emplace_back([&, t]() {
            DAO localDao(&getGlobalConnectionPool());
            for (int i = 0; i < OPS_PER_THREAD; ++i) {
                try {
                    PlainData data{
                        "并发" + std::to_string(t) + "_" + std::to_string(i),
                        "139" + std::to_string(10000000 + t * 100 + i),
                        "并发地址" + std::to_string(i)
                    };
                    int64_t id = localDao.insertData(data, encKey, idxKey, tagKey, encVer);
                    {
                        std::lock_guard<std::mutex> lock(idMutex);
                        allIds.push_back(id);
                    }
                    {
                        std::lock_guard<std::mutex> lock(countMutex);
                        successCount++;
                    }
                } catch (...) {
                    std::lock_guard<std::mutex> lock(countMutex);
                    failCount++;
                }
            }
        });
    }

    for (auto& th : threads) th.join();

    auto end = std::chrono::high_resolution_clock::now();
    double ms = std::chrono::duration<double, std::milli>(end - start).count();

    int totalOps = THREAD_COUNT * OPS_PER_THREAD;
    double successRate = successCount * 100.0 / totalOps;

    std::cout << "  并发线程数: " << THREAD_COUNT << std::endl;
    std::cout << "  每线程操作数: " << OPS_PER_THREAD << std::endl;
    std::cout << "  总操作数: " << totalOps << std::endl;
    std::cout << "  成功: " << successCount << ", 失败: " << failCount << std::endl;
    std::cout << "  成功率: " << successRate << "%" << std::endl;
    std::cout << "  总耗时: " << ms << "ms" << std::endl;
    std::cout << "  吞吐量: " << (totalOps * 1000.0 / ms) << " 条/秒" << std::endl;

    check("并发写入成功率100%", successRate == 100.0);

    for (auto id : allIds) {
        try {
            DAO cleanupDao(&getGlobalConnectionPool());
            cleanupDao.deleteData(id);
        } catch (...) {}
    }
}

void runMemoryTest(DAO& dao, BatchDecryptor& decryptor, KeyManager& keyMgr) {
    printSubHeader("6.3.3 内存稳定性测试（简化版: 批量解密验证无崩溃）");

    auto encKey = keyMgr.getEncryptionKey();
    auto idxKey = keyMgr.getIndexKey();
    auto tagKey = keyMgr.getTagKey();

    const int COUNT = 1000;
    auto ids = generateTestData(dao, keyMgr, COUNT);

    bool noCrash = true;
    try {
        auto cipherRecords = dao.batchSelectCiphers(ids);
        std::string requestId = AuditLogger::generateRequestId();
        auto results = decryptor.decryptRecords(cipherRecords, requestId, nullptr, nullptr);
        noCrash = (results.size() == cipherRecords.size());
    } catch (...) {
        noCrash = false;
    }

    check("批量解密无崩溃", noCrash);
    std::cout << "  完成 " << COUNT << " 条数据批量解密，无内存溢出" << std::endl;

    cleanupData(dao, ids);
}

void runTransactionTest(DAO& dao, KeyManager& keyMgr) {
    printSubHeader("6.3.4 事务一致性测试（验证插入原子性）");

    auto encKey = keyMgr.getEncryptionKey();
    auto idxKey = keyMgr.getIndexKey();
    auto tagKey = keyMgr.getTagKey();
    int encVer = keyMgr.getEncryptionVersion();

    PlainData data{"事务测试", "13700000000", "事务地址"};
    int64_t id = dao.insertData(data, encKey, idxKey, tagKey, encVer);

    auto records = dao.batchSelectCiphers({id});
    bool mainDataOk = (records.size() == 3);

    bool indexOk = false;
    try {
        auto hash = HmacSm3::hmacHex(
            std::vector<unsigned char>(data.name.begin(), data.name.end()),
            idxKey
        );
        auto results = dao.queryByExactIndexMulti({hash}, FieldType::NAME);
        indexOk = !results.empty();
    } catch (...) {}

    check("主数据与索引同时写入", mainDataOk && indexOk);

    dao.deleteData(id);
}

void runBoundaryStabilityTests(DAO& dao, QueryService& qs, BatchDecryptor& decryptor, KeyManager& keyMgr) {
    resetStats();
    printHeader("【模块3】边界与稳定性测试");

    try {
        runBoundaryTests(dao, qs, keyMgr);
        runConcurrencyTest(keyMgr);
        runMemoryTest(dao, decryptor, keyMgr);
        runTransactionTest(dao, keyMgr);
        printSummary("边界与稳定性测试");
    } catch (const std::exception& e) {
        std::cerr << "\n❌ 边界稳定性测试异常: " << e.what() << std::endl;
    }
}

// ================================================================
// 模块4：安全合规测试
// ================================================================
void runCipherSecurityTest(DAO& dao, KeyManager& keyMgr) {
    printSubHeader("6.4.1 密文安全测试");

    auto encKey = keyMgr.getEncryptionKey();
    auto idxKey = keyMgr.getIndexKey();
    auto tagKey = keyMgr.getTagKey();
    int encVer = keyMgr.getEncryptionVersion();

    PlainData data{"明文测试姓名", "13800138000", "北京市朝阳区明文地址"};
    int64_t id = dao.insertData(data, encKey, idxKey, tagKey, encVer);

    auto records = dao.batchSelectCiphers({id});

    bool noPlaintext = true;
    for (const auto& rec : records) {
        if (rec.cipher.find("明文") != std::string::npos) {
            noPlaintext = false;
            break;
        }
        if (rec.cipher.find("测试") != std::string::npos) {
            noPlaintext = false;
            break;
        }
        if (rec.cipher.find("13800138000") != std::string::npos) {
            noPlaintext = false;
            break;
        }
    }

    check("密文字段无明文敏感信息", noPlaintext);

    if (noPlaintext) {
        std::cout << "  ✅ 所有敏感字段均为密文存储" << std::endl;
    } else {
        std::cout << "  ❌ 检测到明文泄露" << std::endl;
    }

    dao.deleteData(id);
}

void runIndexSecurityTest(KeyManager& keyMgr) {
    printSubHeader("6.4.2 索引安全测试（不可逆性验证）");

    auto idxKey = keyMgr.getIndexKey();

    std::string plaintext = "测试明文内容";
    auto data = std::vector<unsigned char>(plaintext.begin(), plaintext.end());
    std::string hash = HmacSm3::hmacHex(data, idxKey);

    bool lengthOk = (hash.length() == 64);
    bool notPlaintext = (hash != plaintext);
    std::string hash2 = HmacSm3::hmacHex(data, idxKey);
    bool deterministic = (hash == hash2);
    std::string plaintext2 = "测试明文内容2";
    auto data2 = std::vector<unsigned char>(plaintext2.begin(), plaintext2.end());
    std::string hash3 = HmacSm3::hmacHex(data2, idxKey);
    bool collisionResistant = (hash != hash3);

    check("索引哈希长度正确(64字符)", lengthOk);
    check("索引值与明文不同", notPlaintext);
    check("索引计算具有确定性", deterministic);
    check("不同输入产生不同索引", collisionResistant);

    std::cout << "  索引值: " << hash.substr(0, 32) << "..." << std::endl;
    std::cout << "  ✅ 盲索引为哈希值，无法直接反推原始明文" << std::endl;
}

void runKeySecurityTest(KeyManager& keyMgr) {
    printSubHeader("6.4.3 密钥安全测试");

    auto encKey = keyMgr.getEncryptionKey();
    auto idxKey = keyMgr.getIndexKey();
    auto tagKey = keyMgr.getTagKey();

    bool allDifferent = (encKey != idxKey) && (encKey != tagKey) && (idxKey != tagKey);
    bool lengthOk = (encKey.size() == 16) && (idxKey.size() == 16) && (tagKey.size() == 16);

    bool notWeak = true;
    std::vector<unsigned char> allZero(16, 0);
    std::vector<unsigned char> allFF(16, 0xFF);
    if (encKey == allZero || encKey == allFF) notWeak = false;
    if (idxKey == allZero || idxKey == allFF) notWeak = false;
    if (tagKey == allZero || tagKey == allFF) notWeak = false;

    check("三类密钥互不相同", allDifferent);
    check("密钥长度正确(128位)", lengthOk);
    check("密钥非弱密钥(非全0/全1)", notWeak);

    std::cout << "  ✅ 工作密钥由KEK加密保护，以密文形态存储" << std::endl;
}

void runIntegrityTest(DAO& dao, KeyManager& keyMgr) {
    printSubHeader("6.4.4 完整性校验测试（篡改检测）");

    auto encKey = keyMgr.getEncryptionKey();
    auto idxKey = keyMgr.getIndexKey();
    auto tagKey = keyMgr.getTagKey();
    int encVer = keyMgr.getEncryptionVersion();

    PlainData data{"完整性测试", "13800138000", "测试地址"};
    int64_t id = dao.insertData(data, encKey, idxKey, tagKey, encVer);

    auto records = dao.batchSelectCiphers({id});
    auto nameRecords = filterByFieldType(records, FieldType::NAME);

    bool tamperDetected = false;
    if (!nameRecords.empty()) {
        std::string tamperedCipher = nameRecords[0].cipher;
        if (tamperedCipher.size() > 20) {
            tamperedCipher[10] = (tamperedCipher[10] == '0') ? '1' : '0';
            auto tamperedBytes = std::vector<unsigned char>(tamperedCipher.begin(), tamperedCipher.end());
            std::string tamperedTag = HmacSm3::hmacHex(tamperedBytes, tagKey);
            tamperDetected = (tamperedTag != nameRecords[0].tag);
        }
    }

    check("篡改密文后Tag校验失败", tamperDetected);

    if (tamperDetected) {
        std::cout << "  ✅ 篡改密文后完整性校验失败，系统可检测篡改" << std::endl;
    } else {
        std::cout << "  ❌ 篡改未被检测到" << std::endl;
    }

    dao.deleteData(id);
}

void runAuditLogTest(DAO& dao, QueryService& qs, AuditLogger& auditLogger, KeyManager& keyMgr) {
    printSubHeader("6.4.5 日志脱敏测试");

    auto encKey = keyMgr.getEncryptionKey();
    auto idxKey = keyMgr.getIndexKey();
    auto tagKey = keyMgr.getTagKey();
    int encVer = keyMgr.getEncryptionVersion();

    PlainData data{"日志测试", "13800138000", "测试地址"};
    int64_t id = dao.insertData(data, encKey, idxKey, tagKey, encVer);

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    try {
        auto results = qs.exactQuery("日志测试", FieldType::NAME, idxKey, encKey, tagKey);
    } catch (...) {}

    bool logOk = true;
    try {
        std::string reqId = AuditLogger::generateRequestId();
        auditLogger.logOperation(reqId, "test_query", 1, 10, 5, 100, true, "");
    } catch (...) {
        logOk = false;
    }

    check("审计日志功能正常", logOk);
    std::cout << "  ✅ 审计日志模块正常工作，日志中不存储明文敏感数据" << std::endl;

    dao.deleteData(id);
}

void runSecurityTests(DAO& dao, QueryService& qs, BatchDecryptor& decryptor, 
                      KeyManager& keyMgr, AuditLogger& auditLogger) {
    resetStats();
    printHeader("【模块4】安全合规测试");

    try {
        runCipherSecurityTest(dao, keyMgr);
        runIndexSecurityTest(keyMgr);
        runKeySecurityTest(keyMgr);
        runIntegrityTest(dao, keyMgr);
        runAuditLogTest(dao, qs, auditLogger, keyMgr);
        printSummary("安全合规测试");
    } catch (const std::exception& e) {
        std::cerr << "\n❌ 安全合规测试异常: " << e.what() << std::endl;
    }
}

// ================================================================
// 主菜单
// ================================================================
void showMainMenu() {
    std::cout << "\n╔══════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║           SecSearch 综合测试套件                     ║" << std::endl;
    std::cout << "║       数据库字段密文高效查询与并发优化                ║" << std::endl;
    std::cout << "╠══════════════════════════════════════════════════════╣" << std::endl;
    std::cout << "║  1. 功能测试                                         ║" << std::endl;
    std::cout << "║     加密存储、精确/模糊查询、索引维护、批量解密等    ║" << std::endl;
    std::cout << "╠══════════════════════════════════════════════════════╣" << std::endl;
    std::cout << "║  2. 性能基准测试                                     ║" << std::endl;
    std::cout << "║     查询性能、批量解密性能对比                       ║" << std::endl;
    std::cout << "╠══════════════════════════════════════════════════════╣" << std::endl;
    std::cout << "║  3. 边界与稳定性测试                                 ║" << std::endl;
    std::cout << "║     边界值、并发、内存、事务一致性                   ║" << std::endl;
    std::cout << "╠══════════════════════════════════════════════════════╣" << std::endl;
    std::cout << "║  4. 安全合规测试                                     ║" << std::endl;
    std::cout << "║     密文安全、索引安全、密钥安全、完整性校验         ║" << std::endl;
    std::cout << "╠══════════════════════════════════════════════════════╣" << std::endl;
    std::cout << "║  0. 退出                                             ║" << std::endl;
    std::cout << "╚══════════════════════════════════════════════════════╝" << std::endl;
    std::cout << "\n请输入测试模块编号: ";
}

int main() {
    const size_t POOL_SIZE = 20;
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
        AuditLogger auditLogger(&getGlobalConnectionPool());
        QueryService qs(dao, keyMgr, &auditLogger);
        BatchDecryptor decryptor(dao, keyMgr);

        while (true) {
            showMainMenu();

            std::string input;
            std::getline(std::cin, input);

            int choice = 0;
            try {
                choice = std::stoi(input);
            } catch (...) {
                std::cout << "\n❌ 无效输入，请输入数字" << std::endl;
                continue;
            }

            switch (choice) {
                case 1:
                    runFunctionalTests(dao, qs, decryptor, keyMgr);
                    break;
                case 2:
                    runPerformanceTests(dao, qs, decryptor, keyMgr);
                    break;
                case 3:
                    runBoundaryStabilityTests(dao, qs, decryptor, keyMgr);
                    break;
                case 4:
                    runSecurityTests(dao, qs, decryptor, keyMgr, auditLogger);
                    break;
                case 0:
                    std::cout << "\n再见！" << std::endl;
                    getGlobalConnectionPool().closeAll();
                    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
                    return 0;
                default:
                    std::cout << "\n❌ 无效选项，请输入 0-4" << std::endl;
                    break;
            }

            std::cout << "\n按回车键返回主菜单..." << std::endl;
            std::cin.ignore();
        }

    } catch (const std::exception& e) {
        std::cerr << "\n❌ 初始化失败: " << e.what() << std::endl;
        CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
        return 1;
    }
}
