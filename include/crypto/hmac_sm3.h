// hmac_sm3.h
// 基于 OpenHiTLS 的 HMAC-SM3 哈希

#pragma once

#include <string>
#include <vector>

namespace crypto {

class HmacSm3 {
public:
    // 计算 HMAC-SM3，返回十六进制（64字符）
    static std::string hmacHex(const std::vector<unsigned char>& data,
                               const std::vector<unsigned char>& key);

    // 计算 HMAC-SM3，返回原始二进制（32字节）
    static std::vector<unsigned char> hmacRaw(const std::vector<unsigned char>& data,
                                              const std::vector<unsigned char>& key);
};

} // namespace crypto