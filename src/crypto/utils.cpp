// utils.cpp
// 实现 Base64 编解码（调用 GmSSL 的 base64_encode_block 和 base64_decode_block）
// 以及十六进制转换

#include "crypto/utils.h"
#include <gmssl/base64.h>   // GmSSL 提供的 Base64 底层接口
#include <stdexcept>

namespace crypto {

// Base64 编码实现
std::string base64Encode(const std::vector<unsigned char>& data) {
    if (data.empty()) return "";  // 空数据直接返回空串

    // 计算输出缓冲区大小（Base64 编码后长度约为原长的 4/3，+1 为安全）
    size_t outlen = ((data.size() + 2) / 3) * 4 + 1;
    std::vector<unsigned char> out(outlen);

    // 调用 GmSSL 的 base64_encode_block 进行编码
    // 返回值是实际编码后的字节数（不含 '\0'）
    int len = base64_encode_block(out.data(), data.data(), (int)data.size());
    if (len < 0) {
        throw std::runtime_error("base64_encode_block failed");
    }

    // 构造 std::string，只取前 len 个字符
    return std::string(reinterpret_cast<char*>(out.data()), len);
}

// Base64 解码实现
std::vector<unsigned char> base64Decode(const std::string& base64) {
    if (base64.empty()) return {};  // 空串返回空向量

    // 计算输出缓冲区大小（解码后长度不会超过原长的 3/4 + 1）
    size_t outlen = (base64.size() / 4) * 3 + 1;
    std::vector<unsigned char> out(outlen);

    // 调用 GmSSL 的 base64_decode_block，注意输入是 unsigned char*
    int len = base64_decode_block(out.data(),
                                  reinterpret_cast<const unsigned char*>(base64.c_str()),
                                  (int)base64.size());
    if (len < 0) {
        throw std::runtime_error("base64_decode_block failed");
    }

    // 根据实际长度调整输出向量大小
    out.resize(len);
    return out;
}

// 二进制数据转十六进制字符串（小写）
std::string binToHex(const unsigned char* data, size_t len) {
    static const char* hex = "0123456789abcdef";  // 十六进制字符表
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(hex[data[i] >> 4]);   // 高4位
        out.push_back(hex[data[i] & 0x0F]); // 低4位
    }
    return out;
}

// 十六进制字符串转二进制
std::vector<unsigned char> hexToBin(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        throw std::runtime_error("Invalid hex length");
    }

    std::vector<unsigned char> out(hex.size() / 2);
    // 将单个字符转换为数值
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

} // namespace crypto