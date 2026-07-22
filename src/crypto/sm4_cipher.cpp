// sm4_cipher.cpp
// 基于 OpenHiTLS 的 SM4-CBC 加解密实现

#include "crypto/sm4_cipher.h"
#include "crypto/utils.h"

#include <hitls/crypto/crypt_eal_cipher.h>
#include <hitls/crypto/crypt_eal_rand.h>
#include <hitls/crypto/crypt_eal_init.h>
#include <hitls/crypto/crypt_algid.h>
#include <hitls/crypto/crypt_errno.h>

#include <stdexcept>
#include <cstring>
#include <iostream>   // 临时调试，可删除

namespace crypto {

static void generateIV(uint8_t* iv, size_t len) {
    int32_t ret = CRYPT_EAL_Randbytes(iv, (uint32_t)len);
    if (ret != CRYPT_SUCCESS) {
        throw std::runtime_error("Failed to generate random IV");
    }
}

std::string Sm4Cipher::encrypt(const std::vector<unsigned char>& plaintext,
                               const std::vector<unsigned char>& key) {
    if (key.size() != KEY_LEN) {
        throw std::runtime_error("SM4 key must be 16 bytes");
    }

    uint8_t iv[IV_LEN];
    generateIV(iv, IV_LEN);

    CRYPT_EAL_CipherCtx* ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_SM4_CBC);
    if (!ctx) {
        throw std::runtime_error("Failed to create SM4 context");
    }

    // ★ 调整顺序：先初始化，再设置填充
    int32_t ret = CRYPT_EAL_CipherInit(ctx, key.data(), KEY_LEN,
                                       iv, IV_LEN, true);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_CipherFreeCtx(ctx);
        throw std::runtime_error("Init failed with code " + std::to_string(ret));
    }

    // ★ 在 Init 之后设置填充
    ret = CRYPT_EAL_CipherSetPadding(ctx, CRYPT_PADDING_PKCS7);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_CipherFreeCtx(ctx);
        throw std::runtime_error("SetPadding failed with code " + std::to_string(ret));
    }

    std::vector<unsigned char> cipher(plaintext.size() + 16);
    uint32_t outLen = (uint32_t)cipher.size();
    uint32_t totalLen = 0;

    ret = CRYPT_EAL_CipherUpdate(ctx, plaintext.data(), (uint32_t)plaintext.size(),
                                  cipher.data(), &outLen);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_CipherFreeCtx(ctx);
        throw std::runtime_error("Update failed with code " + std::to_string(ret));
    }
    totalLen += outLen;

    // ★ Final 前，设置 finalLen 为剩余空间
    uint32_t finalLen = (uint32_t)(cipher.size() - totalLen);
    ret = CRYPT_EAL_CipherFinal(ctx, cipher.data() + totalLen, &finalLen);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_CipherFreeCtx(ctx);
        throw std::runtime_error("Final failed with code " + std::to_string(ret));
    }
    totalLen += finalLen;
    cipher.resize(totalLen);

    CRYPT_EAL_CipherFreeCtx(ctx);

    std::vector<unsigned char> combined;
    combined.reserve(IV_LEN + cipher.size());
    combined.insert(combined.end(), iv, iv + IV_LEN);
    combined.insert(combined.end(), cipher.begin(), cipher.end());

    return binToHex(combined.data(), combined.size());
}

std::vector<unsigned char> Sm4Cipher::decrypt(const std::string& ciphertextHex,
                                              const std::vector<unsigned char>& key) {
    if (key.size() != KEY_LEN) {
        throw std::runtime_error("SM4 key must be 16 bytes");
    }

    auto combined = hexToBin(ciphertextHex);
    if (combined.size() < IV_LEN) {
        throw std::runtime_error("Ciphertext too short");
    }

    const uint8_t* iv = combined.data();
    const uint8_t* cipher = combined.data() + IV_LEN;
    size_t cipherLen = combined.size() - IV_LEN;

    if (cipherLen % 16 != 0) {
        throw std::runtime_error("Invalid ciphertext length (not multiple of 16)");
    }

    CRYPT_EAL_CipherCtx* ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_SM4_CBC);
    if (!ctx) {
        throw std::runtime_error("Failed to create SM4 context");
    }

    // ★ 先初始化，再设置填充
    int32_t ret = CRYPT_EAL_CipherInit(ctx, key.data(), KEY_LEN,
                                       iv, IV_LEN, false);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_CipherFreeCtx(ctx);
        throw std::runtime_error("Init failed with code " + std::to_string(ret));
    }

    ret = CRYPT_EAL_CipherSetPadding(ctx, CRYPT_PADDING_PKCS7);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_CipherFreeCtx(ctx);
        throw std::runtime_error("SetPadding failed with code " + std::to_string(ret));
    }

    std::vector<unsigned char> plaintext(cipherLen);
    uint32_t outLen = (uint32_t)plaintext.size();
    uint32_t totalLen = 0;

    ret = CRYPT_EAL_CipherUpdate(ctx, cipher, (uint32_t)cipherLen,
                                  plaintext.data(), &outLen);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_CipherFreeCtx(ctx);
        throw std::runtime_error("Update failed with code " + std::to_string(ret));
    }
    totalLen += outLen;

    uint32_t finalLen = (uint32_t)(plaintext.size() - totalLen);
    ret = CRYPT_EAL_CipherFinal(ctx, plaintext.data() + totalLen, &finalLen);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_CipherFreeCtx(ctx);
        throw std::runtime_error("Final failed with code " + std::to_string(ret));
    }
    totalLen += finalLen;
    plaintext.resize(totalLen);

    CRYPT_EAL_CipherFreeCtx(ctx);

    return plaintext;
}

} // namespace crypto