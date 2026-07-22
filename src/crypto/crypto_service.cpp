// crypto_service.cpp
// 实现统一加密服务

#include "crypto/crypto_service.h"
#include "crypto/sm4_cipher.h"
#include "crypto/hmac_sm3.h"

#include <stdexcept>

namespace crypto {

CryptoService::CryptoService(KeyManager& keyMgr) : keyMgr_(keyMgr) {}

CryptoService::EncryptResult CryptoService::encryptData(
    const std::vector<unsigned char>& plaintext) {

    auto keyInfo = keyMgr_.getEncryptionKeyInfo();
    if (keyInfo.status != KeyStatus::ENABLED) {
        throw std::runtime_error("Encryption key is not active");
    }

    auto result = Sm4Cipher::encrypt(plaintext, keyInfo.key);

    auto tagKeyInfo = keyMgr_.getTagKeyInfo();
    if (tagKeyInfo.status == KeyStatus::DESTROYED) {
        throw std::runtime_error("Tag key is destroyed");
    }

    auto cipherBytes = std::vector<unsigned char>(result.begin(), result.end());
    std::string tag = HmacSm3::hmacHex(cipherBytes, tagKeyInfo.key);

    EncryptResult finalResult;
    finalResult.cipher = result;
    finalResult.tag = tag;
    finalResult.keyVersion = keyInfo.version;
    return finalResult;
}

std::vector<unsigned char> CryptoService::decryptData(
    const std::string& cipher,
    const std::string& tag,
    int keyVersion) {

    auto tagKeyInfo = keyMgr_.getTagKeyInfo();
    if (tagKeyInfo.status == KeyStatus::DESTROYED) {
        throw std::runtime_error("Tag key is destroyed");
    }

    auto cipherBytes = std::vector<unsigned char>(cipher.begin(), cipher.end());
    std::string computedTag = HmacSm3::hmacHex(cipherBytes, tagKeyInfo.key);

    if (computedTag != tag) {
        throw std::runtime_error("Integrity check failed");
    }

    std::vector<unsigned char> encKey;
    if (!keyMgr_.getEncryptionKeyByVersion(keyVersion, encKey)) {
        throw std::runtime_error("Encryption key version not found");
    }

    return Sm4Cipher::decrypt(cipher, encKey);
}

std::string CryptoService::generateBlindIndex(
    const std::vector<unsigned char>& data) {

    auto keyInfo = keyMgr_.getIndexKeyInfo();
    if (keyInfo.status == KeyStatus::DESTROYED) {
        throw std::runtime_error("Index key is destroyed");
    }

    return HmacSm3::hmacHex(data, keyInfo.key);
}

bool CryptoService::verifyTag(const std::string& cipher,
                              const std::string& tag,
                              int keyVersion) {

    std::vector<unsigned char> tagKey;
    if (!keyMgr_.getTagKeyByVersion(keyVersion, tagKey)) {
        return false;
    }

    auto cipherBytes = std::vector<unsigned char>(cipher.begin(), cipher.end());
    std::string computedTag = HmacSm3::hmacHex(cipherBytes, tagKey);
    return computedTag == tag;
}

std::vector<unsigned char> CryptoService::decryptData(
    const std::string& cipher,
    const std::vector<unsigned char>& key) {
    return Sm4Cipher::decrypt(cipher, key);
}

} // namespace crypto