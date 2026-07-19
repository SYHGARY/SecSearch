// main.cpp
// 功能：对 crypto 模块进行完整的单元测试
// 包括 SM4 往返加解密、HMAC-SM3 正确性、密钥管理器加载流程

#include "crypto/sm4_cipher.h"
#include "crypto/hmac_sm3.h"
#include "crypto/key_manager.h"
#include "crypto/utils.h"
#include <iostream>
#include <gmssl/sm4.h>
#include <cstring>
#include <iomanip>
#include <vector>
#include <string>

using namespace crypto;

void testRawSm4() {
    std::cout << "\n=== 原始 GmSSL SM4-CBC 测试 ===" << std::endl;
    uint8_t key[16] = {0x2B,0x2B,0x2B,0x2B,0x2B,0x2B,0x2B,0x2B,
                       0x2B,0x2B,0x2B,0x2B,0x2B,0x2B,0x2B,0x2B};
    uint8_t iv[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                      0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
    const char* plain = "Hello GmSSL";
    size_t plainlen = strlen(plain);
    uint8_t cipher[100];
    size_t cipherlen = 0;
    uint8_t decrypted[100];
    size_t decryptedlen = 0;

    SM4_KEY sm4_key;
    sm4_set_encrypt_key(&sm4_key, key);
    int ret = sm4_cbc_padding_encrypt(&sm4_key, iv,
                                      (const uint8_t*)plain, plainlen,
                                      cipher, &cipherlen);
    if (ret != 1) {
        std::cerr << "加密失败" << std::endl;
        return;
    }
    std::cout << "加密成功，密文长度: " << cipherlen << std::endl;

    // 解密
    SM4_KEY sm4_dec_key;
    sm4_set_decrypt_key(&sm4_dec_key, key);
    ret = sm4_cbc_padding_decrypt(&sm4_dec_key, iv,
                                  cipher, cipherlen,
                                  decrypted, &decryptedlen);
    if (ret != 1) {
        std::cerr << "解密失败" << std::endl;
        return;
    }
    decrypted[decryptedlen] = '\0';
    std::cout << "解密结果: " << (char*)decrypted << std::endl;
    std::cout << "测试结果: " << (strcmp(plain, (char*)decrypted)==0 ? "✅ 通过" : "❌ 失败") << std::endl;
}

// 辅助函数：打印二进制数据为十六进制（用于调试）
void printHex(const std::vector<unsigned char>& data, const std::string& label) {
    std::cout << label << ": ";
    for (unsigned char c : data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    }
    std::cout << std::dec << std::endl;
}

// 测试1：SM4-CBC 加解密往返测试
bool testSM4EncryptDecrypt() {
    std::cout << "\n=== 测试 SM4-CBC 加解密往返 ===" << std::endl;

    // 构造一个 16 字节的固定密钥（实际环境应使用随机密钥）
    std::vector<unsigned char> key(16, 0x2B); // 0x2B2B2B...
    // 准备测试数据：包含中文、英文、特殊字符
    std::string plaintext = "张三的手机号是13800138000！";
    std::vector<unsigned char> plainBytes(plaintext.begin(), plaintext.end());

    try {
        // 加密
        std::string cipherBase64 = Sm4Cipher::encrypt(plainBytes, key);
        std::cout << "加密成功，密文长度: " << cipherBase64.size() << std::endl;
        std::cout << "密文(Base64前32字符): " << cipherBase64.substr(0, 32) << "..." << std::endl;

        // 解密
        std::vector<unsigned char> decrypted = Sm4Cipher::decrypt(cipherBase64, key);
        std::string recovered(decrypted.begin(), decrypted.end());

        // 验证是否与原文一致
        bool success = (plaintext == recovered);
        std::cout << "解密结果: " << recovered << std::endl;
        std::cout << "测试结果: " << (success ? "✅ 通过" : "❌ 失败") << std::endl;
        return success;
    } catch (const std::exception& e) {
        std::cerr << "❌ 异常: " << e.what() << std::endl;
        return false;
    }
}

// 测试2：HMAC-SM3 计算（验证输出长度和稳定性）
bool testHMAC() {
    std::cout << "\n=== 测试 HMAC-SM3 ===" << std::endl;

    std::vector<unsigned char> key(16, 0x5A);
    std::string data = "Hello, 国密!";
    std::vector<unsigned char> dataBytes(data.begin(), data.end());

    try {
        // 计算十六进制 HMAC
        std::string hexResult = HmacSm3::hmacHex(dataBytes, key);
        std::cout << "HMAC-SM3(Hex): " << hexResult << std::endl;
        std::cout << "输出长度: " << hexResult.size() << " (应为64)" << std::endl;

        // 计算原始二进制 HMAC
        std::vector<unsigned char> rawResult = HmacSm3::hmacRaw(dataBytes, key);
        std::cout << "原始长度: " << rawResult.size() << " (应为32)" << std::endl;

        bool success = (hexResult.size() == 64 && rawResult.size() == 32);
        std::cout << "测试结果: " << (success ? "✅ 通过" : "❌ 失败") << std::endl;
        return success;
    } catch (const std::exception& e) {
        std::cerr << "❌ 异常: " << e.what() << std::endl;
        return false;
    }
}

// 测试3：密钥管理器（模拟加载流程）
bool testKeyManager() {
    std::cout << "\n=== 测试密钥管理器 ===" << std::endl;

    try {
        // 1. 准备一个 16 字节的 KEK（主密钥）
        std::vector<unsigned char> kek(16, 0x11);

        // 2. 准备一个 32 字节的 DEK（前16字节加密密钥，后16字节索引密钥）
        std::vector<unsigned char> rawDEK(32);
        for (size_t i = 0; i < 32; ++i) rawDEK[i] = (unsigned char)(0xA0 + i);

        std::cout << "原始DEK(前16字节): ";
        for (size_t i = 0; i < 16; ++i) std::cout << std::hex << (int)rawDEK[i] << " ";
        std::cout << std::dec << std::endl;

        // 3. 用 KEK 加密 DEK（模拟数据库中存储的密文）
        std::string encryptedDEK = Sm4Cipher::encrypt(rawDEK, kek);
        std::cout << "加密后的DEK(Base64): " << encryptedDEK.substr(0, 40) << "..." << std::endl;

        // 4. 初始化密钥管理器
        KeyManager keyMgr;
        keyMgr.init(kek);

        // 5. 从"数据库"加载 DEK 密文
        keyMgr.loadKeysFromDB(encryptedDEK);

        // 6. 取出两个工作密钥
        auto encKey = keyMgr.getEncryptionKey();
        auto idxKey = keyMgr.getIndexKey();

        std::cout << "提取的加密密钥(前8字节): ";
        for (size_t i = 0; i < 8; ++i) std::cout << std::hex << (int)encKey[i] << " ";
        std::cout << std::dec << std::endl;

        std::cout << "提取的索引密钥(前8字节): ";
        for (size_t i = 0; i < 8; ++i) std::cout << std::hex << (int)idxKey[i] << " ";
        std::cout << std::dec << std::endl;

        // 7. 验证提取的密钥是否与原始 DEK 一致
        bool encMatch = true, idxMatch = true;
        for (size_t i = 0; i < 16; ++i) {
            if (encKey[i] != rawDEK[i]) encMatch = false;
            if (idxKey[i] != rawDEK[i + 16]) idxMatch = false;
        }

        bool success = encMatch && idxMatch;
        std::cout << "测试结果: " << (success ? "✅ 通过" : "❌ 失败") << std::endl;
        return success;
    } catch (const std::exception& e) {
        std::cerr << "❌ 异常: " << e.what() << std::endl;
        return false;
    }
}

// 主函数
int main() {

    testRawSm4();  // 测试原始 GmSSL SM4-CBC 接口

    std::cout << "========== Crypto 模块单元测试 ==========" << std::endl;

    bool allPassed = true;
    allPassed = testSM4EncryptDecrypt() && allPassed;
    allPassed = testHMAC() && allPassed;
    allPassed = testKeyManager() && allPassed;

    std::cout << "\n========== 总体测试结果 ==========" << std::endl;
    std::cout << (allPassed ? "🎉 所有测试通过！" : "😞 存在测试失败，请检查错误信息。") << std::endl;

    return allPassed ? 0 : 1;
}