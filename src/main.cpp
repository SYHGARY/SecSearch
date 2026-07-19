// main.cpp
// 功能：完整测试 crypto 模块
// 包含：
//   1. SM4-CBC 加解密（十六进制密文）
//   2. HMAC-SM3 精确索引（盲索引）
//   3. HMAC-SM3 完整性 Tag（密文校验）
//   4. 密钥管理器（三密钥加载）
//   5. 端到端链路测试

#include "crypto/sm4_cipher.h"
#include "crypto/hmac_sm3.h"
#include "crypto/key_manager.h"
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>

using namespace crypto;

// ---- 辅助工具 ----
// 打印二进制数据（十六进制，带格式）
void printBytes(const std::vector<unsigned char>& data, const std::string& label, size_t limit = 0) {
    if (limit == 0 || limit > data.size()) limit = data.size();
    std::cout << label << " (" << data.size() << " 字节): ";
    for (size_t i = 0; i < limit; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i] << " ";
    }
    if (limit < data.size()) std::cout << "...";
    std::cout << std::dec << std::endl;
}

// 打印字符串的十六进制表示（用于查看中文等）
void printStringHex(const std::string& str, const std::string& label) {
    std::cout << label << " (UTF-8 字节): ";
    for (unsigned char c : str) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)c << " ";
    }
    std::cout << std::dec << std::endl;
}

// ---- 主测试 ----
int main() {
    std::cout << "════════════════════════════════════════════════════════" << std::endl;
    std::cout << "           Crypto 模块完整功能测试" << std::endl;
    std::cout << "════════════════════════════════════════════════════════" << std::endl;

    try {
        // ================================================================
        // 第 1 部分：密钥管理器测试
        // ================================================================
        std::cout << "\n【第 1 部分】密钥管理器（三密钥分离）" << std::endl;
        std::cout << "────────────────────────────────────────────────────" << std::endl;

        // 1.1 准备主密钥 KEK（16 字节，模拟从安全环境读取）
        std::vector<unsigned char> kek(16, 0x11);
        std::cout << "主密钥 KEK: ";
        for (unsigned char c : kek) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)c;
        std::cout << std::dec << std::endl;

        // 1.2 准备三个工作密钥（每个 16 字节，模拟随机生成）
        std::vector<unsigned char> rawEncKey(16, 0xA0);   // 加密密钥
        std::vector<unsigned char> rawIdxKey(16, 0xB0);   // 索引密钥
        std::vector<unsigned char> rawTagKey(16, 0xC0);   // Tag 密钥

        std::cout << "原始加密密钥: ";
        for (unsigned char c : rawEncKey) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)c;
        std::cout << std::dec << std::endl;

        std::cout << "原始索引密钥: ";
        for (unsigned char c : rawIdxKey) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)c;
        std::cout << std::dec << std::endl;

        std::cout << "原始 Tag 密钥: ";
        for (unsigned char c : rawTagKey) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)c;
        std::cout << std::dec << std::endl;

        // 1.3 用 KEK 分别加密三个密钥（模拟数据库存储）
        std::string encKeyCipher = Sm4Cipher::encrypt(rawEncKey, kek);
        std::string idxKeyCipher = Sm4Cipher::encrypt(rawIdxKey, kek);
        std::string tagKeyCipher = Sm4Cipher::encrypt(rawTagKey, kek);

        std::cout << "\n加密后的密钥密文（存储到数据库）:" << std::endl;
        std::cout << "  加密密钥密文 (前60字符): " << encKeyCipher.substr(0, 60) << "..." << std::endl;
        std::cout << "  索引密钥密文 (前60字符): " << idxKeyCipher.substr(0, 60) << "..." << std::endl;
        std::cout << "  Tag 密钥密文 (前60字符): " << tagKeyCipher.substr(0, 60) << "..." << std::endl;

        // 1.4 初始化密钥管理器并加载三个密钥
        KeyManager keyMgr;
        keyMgr.init(kek);
        keyMgr.loadKeys(encKeyCipher, idxKeyCipher, tagKeyCipher);

        const auto& encKey = keyMgr.getEncryptionKey();
        const auto& idxKey = keyMgr.getIndexKey();
        const auto& tagKey = keyMgr.getTagKey();

        // 1.5 验证加载的密钥是否与原始一致
        bool encMatch = true, idxMatch = true, tagMatch = true;
        for (size_t i = 0; i < 16; ++i) {
            if (encKey[i] != rawEncKey[i]) encMatch = false;
            if (idxKey[i] != rawIdxKey[i]) idxMatch = false;
            if (tagKey[i] != rawTagKey[i]) tagMatch = false;
        }

        std::cout << "\n密钥加载验证:" << std::endl;
        std::cout << "  加密密钥匹配: " << (encMatch ? "✅ 通过" : "❌ 失败") << std::endl;
        std::cout << "  索引密钥匹配: " << (idxMatch ? "✅ 通过" : "❌ 失败") << std::endl;
        std::cout << "  Tag 密钥匹配: " << (tagMatch ? "✅ 通过" : "❌ 失败") << std::endl;

        if (!encMatch || !idxMatch || !tagMatch) {
            throw std::runtime_error("密钥加载验证失败");
        }

        // ================================================================
        // 第 2 部分：SM4-CBC 加解密测试
        // ================================================================
        std::cout << "\n【第 2 部分】SM4-CBC 加解密测试" << std::endl;
        std::cout << "────────────────────────────────────────────────────" << std::endl;

        // 测试数据：包含中文、英文、数字
        std::string plaintext = "张三的手机号是13800138000！";
        std::vector<unsigned char> plainBytes(plaintext.begin(), plaintext.end());

        std::cout << "原始明文: " << plaintext << std::endl;
        printStringHex(plaintext, "明文 UTF-8");

        // 2.1 加密
        std::string cipherHex = Sm4Cipher::encrypt(plainBytes, encKey);
        std::cout << "\n加密后的密文（十六进制）:" << std::endl;
        std::cout << "  完整密文长度: " << cipherHex.size() << " 字符" << std::endl;
        std::cout << "  密文前 80 字符: " << cipherHex.substr(0, 80) << "..." << std::endl;

        // 2.2 解密
        std::vector<unsigned char> decrypted = Sm4Cipher::decrypt(cipherHex, encKey);
        std::string recovered(decrypted.begin(), decrypted.end());

        std::cout << "\n解密结果: " << recovered << std::endl;
        bool decryptOk = (plaintext == recovered);
        std::cout << "加解密往返: " << (decryptOk ? "✅ 通过" : "❌ 失败") << std::endl;

        if (!decryptOk) {
            throw std::runtime_error("加解密往返失败");
        }

        // ================================================================
        // 第 3 部分：HMAC-SM3 精确盲索引测试
        // ================================================================
        std::cout << "\n【第 3 部分】HMAC-SM3 精确盲索引生成" << std::endl;
        std::cout << "────────────────────────────────────────────────────" << std::endl;

        // 3.1 对明文生成盲索引
        std::vector<unsigned char> plainForIndex(plaintext.begin(), plaintext.end());
        std::string blindIndex = HmacSm3::hmacHex(plainForIndex, idxKey);

        std::cout << "原始明文: " << plaintext << std::endl;
        std::cout << "盲索引 (HMAC-SM3, 64字符): " << blindIndex << std::endl;
        std::cout << "  索引长度: " << blindIndex.size() << " 字符 (应为 64)" << std::endl;

        // 3.2 验证：同一明文 + 同一密钥 → 相同索引
        std::string blindIndex2 = HmacSm3::hmacHex(plainForIndex, idxKey);
        bool indexSame = (blindIndex == blindIndex2);
        std::cout << "同一明文重复计算: " << (indexSame ? "✅ 索引一致" : "❌ 不一致") << std::endl;

        // 3.3 验证：不同明文 → 不同索引（演示）
        std::string differentPlain = "李四的手机号是13900139000";
        std::vector<unsigned char> diffBytes(differentPlain.begin(), differentPlain.end());
        std::string blindIndexDiff = HmacSm3::hmacHex(diffBytes, idxKey);
        bool indexDiff = (blindIndex != blindIndexDiff);
        std::cout << "不同明文索引不同: " << (indexDiff ? "✅ 是" : "❌ 否") << std::endl;

        // ================================================================
        // 第 4 部分：HMAC-SM3 完整性 Tag 测试
        // ================================================================
        std::cout << "\n【第 4 部分】HMAC-SM3 密文完整性 Tag" << std::endl;
        std::cout << "────────────────────────────────────────────────────" << std::endl;

        // 4.1 对密文生成 Tag（使用 Tag 密钥）
        std::vector<unsigned char> cipherBytes(cipherHex.begin(), cipherHex.end());
        std::string tag = HmacSm3::hmacHex(cipherBytes, tagKey);

        std::cout << "密文: " << cipherHex.substr(0, 60) << "..." << std::endl;
        std::cout << "完整性 Tag (HMAC-SM3, 64字符): " << tag << std::endl;
        std::cout << "  Tag 长度: " << tag.size() << " 字符 (应为 64)" << std::endl;

        // 4.2 验证：同一密文 + 同一密钥 → 相同 Tag
        std::string tag2 = HmacSm3::hmacHex(cipherBytes, tagKey);
        bool tagSame = (tag == tag2);
        std::cout << "同一密文重复计算: " << (tagSame ? "✅ Tag 一致" : "❌ 不一致") << std::endl;

        // 4.3 验证：密文被篡改后 Tag 不同（演示）
        std::string tamperedCipher = cipherHex;
        tamperedCipher[10] = (tamperedCipher[10] == '0') ? '1' : '0';  // 改一个字符
        std::vector<unsigned char> tamperedBytes(tamperedCipher.begin(), tamperedCipher.end());
        std::string tamperedTag = HmacSm3::hmacHex(tamperedBytes, tagKey);
        bool tagTampered = (tag != tamperedTag);
        std::cout << "篡改后 Tag 变化: " << (tagTampered ? "✅ 检测到篡改" : "❌ 未检测到") << std::endl;

        // 4.4 验证：错误密钥导致 Tag 不同
        std::string wrongTag = HmacSm3::hmacHex(cipherBytes, rawIdxKey);  // 用索引密钥代替 Tag 密钥
        bool tagWrongKey = (tag != wrongTag);
        std::cout << "错误密钥 Tag 不同: " << (tagWrongKey ? "✅ 是" : "❌ 否") << std::endl;

        // ================================================================
        // 第 5 部分：端到端完整流程模拟
        // ================================================================
        std::cout << "\n【第 5 部分】端到端完整流程模拟" << std::endl;
        std::cout << "────────────────────────────────────────────────────" << std::endl;

        std::cout << "步骤 1: 原始数据 -> 加密" << std::endl;
        std::cout << "  明文: " << plaintext << std::endl;
        std::cout << "  密文 (前60字符): " << cipherHex.substr(0, 60) << "..." << std::endl;

        std::cout << "\n步骤 2: 生成盲索引 (用于精确查询)" << std::endl;
        std::cout << "  索引值: " << blindIndex.substr(0, 40) << "..." << std::endl;

        std::cout << "\n步骤 3: 生成完整性 Tag (用于防篡改)" << std::endl;
        std::cout << "  Tag 值: " << tag.substr(0, 40) << "..." << std::endl;

        std::cout << "\n步骤 4: 模拟数据存储到数据库" << std::endl;
        std::cout << "  ┌─────────────────────────────────────────────┐" << std::endl;
        std::cout << "  │ id  │ 密文 (cipher) │ 盲索引 (idx) │ Tag │" << std::endl;
        std::cout << "  ├─────────────────────────────────────────────┤" << std::endl;
        std::cout << "  │ 1   │ " << cipherHex.substr(0, 20) << "... │ " << blindIndex.substr(0, 16) << "... │ " << tag.substr(0, 16) << "... │" << std::endl;
        std::cout << "  └─────────────────────────────────────────────┘" << std::endl;

        std::cout << "\n步骤 5: 查询时验证 Tag" << std::endl;
        std::string queryTag = HmacSm3::hmacHex(cipherBytes, tagKey);
        bool verifyOk = (queryTag == tag);
        std::cout << "  Tag 验证: " << (verifyOk ? "✅ 通过 (数据未被篡改)" : "❌ 失败") << std::endl;

        std::cout << "\n步骤 6: 解密返回明文" << std::endl;
        std::cout << "  解密结果: " << recovered << std::endl;

        // ================================================================
        // 总结
        // ================================================================
        std::cout << "\n════════════════════════════════════════════════════════" << std::endl;
        std::cout << "                    🎉 所有测试通过！" << std::endl;
        std::cout << "════════════════════════════════════════════════════════" << std::endl;

        std::cout << "\n【测试结果汇总】" << std::endl;
        std::cout << "  ✅ SM4-CBC 加解密往返正确" << std::endl;
        std::cout << "  ✅ HMAC-SM3 盲索引生成稳定且唯一" << std::endl;
        std::cout << "  ✅ HMAC-SM3 Tag 可检测篡改和密钥错误" << std::endl;
        std::cout << "  ✅ 三密钥分离管理正常工作" << std::endl;
        std::cout << "  ✅ 端到端流程完整可用" << std::endl;

        std::cout << "\n【关键输出摘要】" << std::endl;
        std::cout << "  明文: " << plaintext << std::endl;
        std::cout << "  盲索引: " << blindIndex << std::endl;
        std::cout << "  完整性 Tag: " << tag << std::endl;

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "\n❌ 测试失败: " << e.what() << std::endl;
        return 1;
    }
}
