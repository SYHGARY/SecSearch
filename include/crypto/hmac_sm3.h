// hmac_sm3.h
// 功能：使用 HMAC-SM3 算法计算消息认证码，用于生成盲索引和完整性校验
// 输出支持原始二进制（32 字节）或十六进制字符串（64 字符）

#pragma once

#include <string>
#include <vector>

namespace crypto {

class HmacSm3 {
public:
    // 计算 HMAC-SM3，返回十六进制字符串（64 字符）
    static std::string hmacHex(const std::vector<unsigned char>& data,
                               const std::vector<unsigned char>& key);

    // 计算 HMAC-SM3，返回原始二进制（32 字节）
    static std::vector<unsigned char> hmacRaw(const std::vector<unsigned char>& data,
                                              const std::vector<unsigned char>& key);
};

} // namespace crypto