// hmac_sm3.cpp
// 基于 OpenHiTLS 的 HMAC-SM3 实现

#include "crypto/hmac_sm3.h"
#include "crypto/utils.h"

#include <hitls/crypto/crypt_eal_mac.h>
#include <hitls/crypto/crypt_algid.h>
#include <hitls/crypto/crypt_errno.h>

#include <stdexcept>

namespace crypto {

std::vector<unsigned char> HmacSm3::hmacRaw(const std::vector<unsigned char>& data,
                                            const std::vector<unsigned char>& key) {
    // 1. 创建 MAC 上下文（HMAC-SM3）
    CRYPT_EAL_MacCtx* ctx = CRYPT_EAL_MacNewCtx(CRYPT_MAC_HMAC_SM3);
    if (!ctx) {
        throw std::runtime_error("Failed to create HMAC-SM3 context");
    }

    // 2. 初始化（传入密钥）
    int32_t ret = CRYPT_EAL_MacInit(ctx, key.data(), (uint32_t)key.size());
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_MacFreeCtx(ctx);
        throw std::runtime_error("HMAC-SM3 init failed");
    }

    // 3. 更新数据
    ret = CRYPT_EAL_MacUpdate(ctx, data.data(), (uint32_t)data.size());
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_MacFreeCtx(ctx);
        throw std::runtime_error("HMAC-SM3 update failed");
    }

    // 4. 获取结果（HMAC-SM3 输出 32 字节）
    std::vector<unsigned char> mac(32);
    uint32_t macLen = 32;
    ret = CRYPT_EAL_MacFinal(ctx, mac.data(), &macLen);
    CRYPT_EAL_MacFreeCtx(ctx);

    if (ret != CRYPT_SUCCESS || macLen != 32) {
        throw std::runtime_error("HMAC-SM3 final failed");
    }

    return mac;
}

std::string HmacSm3::hmacHex(const std::vector<unsigned char>& data,
                             const std::vector<unsigned char>& key) {
    auto raw = hmacRaw(data, key);
    return binToHex(raw.data(), raw.size());
}

} // namespace crypto