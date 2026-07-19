// key_manager.cpp

#include "crypto/key_manager.h"
#include "crypto/sm4_cipher.h"
#include <stdexcept>

namespace crypto {

void KeyManager::init(const std::vector<unsigned char>& kek) {
    if (kek.size() != 16) {
        throw std::runtime_error("KEK must be 16 bytes for SM4");
    }
    std::lock_guard<std::mutex> lock(mutex_);
    kek_ = kek;
}

void KeyManager::loadKeys(const std::string& encryptedEncKey,
                          const std::string& encryptedIdxKey,
                          const std::string& encryptedTagKey) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (kek_.empty()) {
        throw std::runtime_error("KeyManager not initialized with KEK");
    }

    dek_encryption_ = decryptDEK(encryptedEncKey);
    dek_index_      = decryptDEK(encryptedIdxKey);
    dek_tag_        = decryptDEK(encryptedTagKey);

    if (dek_encryption_.size() != 16 ||
        dek_index_.size()      != 16 ||
        dek_tag_.size()        != 16) {
        throw std::runtime_error("All keys must be 16 bytes");
    }
}

const std::vector<unsigned char>& KeyManager::getEncryptionKey() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (dek_encryption_.empty()) {
        throw std::runtime_error("Encryption key not loaded");
    }
    return dek_encryption_;
}

const std::vector<unsigned char>& KeyManager::getIndexKey() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (dek_index_.empty()) {
        throw std::runtime_error("Index key not loaded");
    }
    return dek_index_;
}

const std::vector<unsigned char>& KeyManager::getTagKey() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (dek_tag_.empty()) {
        throw std::runtime_error("Tag key not loaded");
    }
    return dek_tag_;
}

std::vector<unsigned char> KeyManager::decryptDEK(const std::string& cipherBase64) {
    return Sm4Cipher::decrypt(cipherBase64, kek_);
}

} // namespace crypto
