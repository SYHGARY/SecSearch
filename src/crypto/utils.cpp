// utils.cpp
// 自实现 Base64 (RFC 4648) 和十六进制转换，以及密钥文件读取

#include "crypto/utils.h"
#include <stdexcept>
#include <fstream>
#include <cctype>
#include <algorithm>

namespace crypto {

// ---- Base64 ----
static const char* BASE64_ALPHABET =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

std::string base64Encode(const std::vector<unsigned char>& data) {
    std::string result;
    result.reserve(((data.size() + 2) / 3) * 4);

    size_t i = 0;
    unsigned char a, b, c;
    while (i < data.size()) {
        a = data[i++];
        b = (i < data.size()) ? data[i++] : 0;
        c = (i < data.size()) ? data[i++] : 0;

        unsigned char enc1 = (a >> 2) & 0x3F;
        unsigned char enc2 = ((a & 0x03) << 4) | ((b >> 4) & 0x0F);
        unsigned char enc3 = ((b & 0x0F) << 2) | ((c >> 6) & 0x03);
        unsigned char enc4 = c & 0x3F;

        result.push_back(BASE64_ALPHABET[enc1]);
        result.push_back(BASE64_ALPHABET[enc2]);
        result.push_back((i - 1) < data.size() ? BASE64_ALPHABET[enc3] : '=');
        result.push_back((i < data.size()) ? BASE64_ALPHABET[enc4] : '=');
    }
    return result;
}

static inline bool isBase64Char(unsigned char c) {
    return (c >= 'A' && c <= 'Z') ||
           (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') ||
           c == '+' || c == '/';
}

std::vector<unsigned char> base64Decode(const std::string& base64) {
    std::vector<unsigned char> result;
    result.reserve((base64.size() / 4) * 3);

    size_t i = 0;
    while (i < base64.size() && base64[i] != '=') {
        unsigned char enc[4];
        int count = 0;
        while (count < 4 && i < base64.size() && base64[i] != '=') {
            char c = base64[i++];
            if (!isBase64Char(c)) {
                throw std::runtime_error("Invalid Base64 character");
            }
            if (c >= 'A' && c <= 'Z')      enc[count] = c - 'A';
            else if (c >= 'a' && c <= 'z') enc[count] = c - 'a' + 26;
            else if (c >= '0' && c <= '9') enc[count] = c - '0' + 52;
            else if (c == '+')             enc[count] = 62;
            else if (c == '/')             enc[count] = 63;
            count++;
        }
        if (count < 2) break;

        unsigned char out1 = (enc[0] << 2) | (enc[1] >> 4);
        result.push_back(out1);

        if (count >= 3) {
            unsigned char out2 = ((enc[1] & 0x0F) << 4) | (enc[2] >> 2);
            result.push_back(out2);
        }
        if (count >= 4) {
            unsigned char out3 = ((enc[2] & 0x03) << 6) | enc[3];
            result.push_back(out3);
        }
    }
    return result;
}

// ---- 十六进制 ----
std::string binToHex(const unsigned char* data, size_t len) {
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(hex[data[i] >> 4]);
        out.push_back(hex[data[i] & 0x0F]);
    }
    return out;
}

std::vector<unsigned char> hexToBin(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        throw std::runtime_error("Invalid hex length");
    }
    std::vector<unsigned char> out(hex.size() / 2);
    auto val = [](char c) -> unsigned char {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        throw std::runtime_error("Invalid hex char");
    };
    for (size_t i = 0; i < hex.size(); i += 2) {
        out[i/2] = (val(hex[i]) << 4) | val(hex[i+1]);
    }
    return out;
}

// ---- ★ 从文件读取十六进制密钥 ----
std::vector<unsigned char> readKeyFromFile(const std::string& filepath) {
    // 1. 打开文件
    std::ifstream file(filepath);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open key file: " + filepath);
    }

    // 2. 读取所有内容（支持多行，忽略空白字符）
    std::string content;
    std::string line;
    while (std::getline(file, line)) {
        content += line;
    }
    file.close();

    // 3. 去掉所有空白字符（空格、换行、制表符）
    content.erase(std::remove_if(content.begin(), content.end(), ::isspace), content.end());

    // 4. 检查内容是否为空
    if (content.empty()) {
        throw std::runtime_error("Key file is empty: " + filepath);
    }

    // 5. 检查长度（16字节 = 32个十六进制字符）
    if (content.size() != 32) {
        throw std::runtime_error("Invalid key length in file: expected 32 hex characters (16 bytes), got " +
                                 std::to_string(content.size()));
    }

    // 6. 尝试转换为二进制
    try {
        auto keyBytes = hexToBin(content);
        if (keyBytes.size() != 16) {
            throw std::runtime_error("Decoded key length is not 16 bytes");
        }
        return keyBytes;
    } catch (const std::exception& e) {
        throw std::runtime_error("Invalid hex format in key file: " + std::string(e.what()));
    }
}

} // namespace crypto