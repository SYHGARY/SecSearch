// hmac_sm3.cpp
// 实现 HMAC-SM3，利用 GmSSL 的 SM3_HMAC_CTX 系列函数

#include "crypto/hmac_sm3.h"
#include "crypto/utils.h"
#include <gmssl/sm3.h>      // SM3 及 HMAC-SM3 接口
#include <stdexcept>

namespace crypto {

// 返回原始二进制（32 字节）
std::vector<unsigned char> HmacSm3::hmacRaw(const std::vector<unsigned char>& data,
                                            const std::vector<unsigned char>& key) {
    SM3_HMAC_CTX ctx;          // GmSSL 定义的 HMAC 上下文
    sm3_hmac_init(&ctx, key.data(), key.size());   // 用密钥初始化
    sm3_hmac_update(&ctx, data.data(), data.size()); // 更新数据
    uint8_t mac[SM3_HMAC_SIZE];                    // 32 字节输出缓冲区
    sm3_hmac_finish(&ctx, mac);                    // 计算最终 HMAC
    return std::vector<unsigned char>(mac, mac + SM3_HMAC_SIZE);
}

// 返回十六进制字符串（64 字符）
std::string HmacSm3::hmacHex(const std::vector<unsigned char>& data,
                             const std::vector<unsigned char>& key) {
    auto raw = hmacRaw(data, key);
    return binToHex(raw.data(), raw.size());
}

} // namespace crypto