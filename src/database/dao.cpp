// dao.cpp
// 实现 DAO 的所有方法

#include "database/dao.h"
#include "database/transaction.h"
#include "crypto/sm4_cipher.h"
#include "crypto/hmac_sm3.h"
#include <sstream>
#include <set>
#include <cstring>

namespace database {

// ---- Bigram 分词 ----
std::vector<std::string> DAO::splitBigram(const std::string& text) {
    std::vector<std::string> tokens;
    if (text.empty()) return tokens;
    if (text.size() == 1) {
        tokens.push_back(text);
        return tokens;
    }
    for (size_t i = 0; i + 1 < text.size(); ++i) {
        tokens.push_back(text.substr(i, 2));
    }
    return tokens;
}

// ---- 辅助：将 token 列表转为 HMAC-SM3 哈希列表 ----
static std::vector<std::string> hashTokens(const std::vector<std::string>& tokens,
                                           const std::vector<unsigned char>& idxKey) {
    std::vector<std::string> hashes;
    hashes.reserve(tokens.size());
    for (const auto& t : tokens) {
        auto bytes = std::vector<unsigned char>(t.begin(), t.end());
        hashes.push_back(crypto::HmacSm3::hmacHex(bytes, idxKey));
    }
    return hashes;
}

// ---- 构造函数 ----
DAO::DAO(ConnectionPool* pool) : pool_(pool ? pool : &getGlobalConnectionPool()) {
    connGuard_ = pool_->getConnection();
}

// ---- 插入数据 ----
int64_t DAO::insertData(const PlainData& data,
                        const std::vector<unsigned char>& encKey,
                        const std::vector<unsigned char>& idxKey,
                        const std::vector<unsigned char>& tagKey,
                        int encKeyVersion) {

    auto nameBytes = std::vector<unsigned char>(data.name.begin(), data.name.end());
    auto phoneBytes = std::vector<unsigned char>(data.phone.begin(), data.phone.end());
    auto addrBytes = std::vector<unsigned char>(data.address.begin(), data.address.end());

    std::string nameCipher = crypto::Sm4Cipher::encrypt(nameBytes, encKey);
    std::string phoneCipher = crypto::Sm4Cipher::encrypt(phoneBytes, encKey);
    std::string addrCipher = crypto::Sm4Cipher::encrypt(addrBytes, encKey);

    std::string nameBlind = crypto::HmacSm3::hmacHex(nameBytes, idxKey);
    std::string phoneBlind = crypto::HmacSm3::hmacHex(phoneBytes, idxKey);
    std::string addrBlind = crypto::HmacSm3::hmacHex(addrBytes, idxKey);

    auto nameCipherBytes = std::vector<unsigned char>(nameCipher.begin(), nameCipher.end());
    auto phoneCipherBytes = std::vector<unsigned char>(phoneCipher.begin(), phoneCipher.end());
    auto addrCipherBytes = std::vector<unsigned char>(addrCipher.begin(), addrCipher.end());

    std::string nameTag = crypto::HmacSm3::hmacHex(nameCipherBytes, tagKey);
    std::string phoneTag = crypto::HmacSm3::hmacHex(phoneCipherBytes, tagKey);
    std::string addrTag = crypto::HmacSm3::hmacHex(addrCipherBytes, tagKey);

    int64_t dataId = insertMainTable(nameCipher, nameBlind, nameTag,
                                     phoneCipher, phoneBlind, phoneTag,
                                     addrCipher, addrBlind, addrTag,
                                     encKeyVersion);
    if (dataId <= 0) throw std::runtime_error("Insert main table failed");

    auto nameTokens = splitBigram(data.name);
    auto phoneTokens = splitBigram(data.phone);
    auto addrTokens = splitBigram(data.address);

    auto nameHashes = hashTokens(nameTokens, idxKey);
    auto phoneHashes = hashTokens(phoneTokens, idxKey);
    auto addrHashes = hashTokens(addrTokens, idxKey);

    MYSQL* conn = connGuard_->get();
    Transaction tx(conn);

    insertFuzzyIndex(dataId, FieldType::NAME, nameHashes);
    insertFuzzyIndex(dataId, FieldType::PHONE, phoneHashes);
    insertFuzzyIndex(dataId, FieldType::ADDRESS, addrHashes);

    tx.commit();
    return dataId;
}

// ---- 插入主表 ----
int64_t DAO::insertMainTable(const std::string& nameCipher, const std::string& nameBlind,
                             const std::string& nameTag,
                             const std::string& phoneCipher, const std::string& phoneBlind,
                             const std::string& phoneTag,
                             const std::string& addrCipher, const std::string& addrBlind,
                             const std::string& addrTag,
                             int encKeyVersion) {
    MYSQL* conn = connGuard_->get();

    const char* sql = R"(
        INSERT INTO sensitive_data
        (enc_key_version, name_cipher, name_blind_idx, name_tag,
         phone_cipher, phone_blind_idx, phone_tag,
         address_cipher, address_blind_idx, address_tag)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";

    MYSQL_STMT* stmt = mysql_stmt_init(conn);
    if (!stmt || mysql_stmt_prepare(stmt, sql, strlen(sql)) != 0) {
        if (stmt) mysql_stmt_close(stmt);
        throw std::runtime_error("Prepare insert main failed");
    }

    MYSQL_BIND bind[10];
    memset(bind, 0, sizeof(bind));

    #define SET_STRING_BIND(i, str) \
        bind[i].buffer_type = MYSQL_TYPE_STRING; \
        bind[i].buffer = (char*)str.c_str(); \
        bind[i].buffer_length = str.size(); \
        bind[i].is_null = 0

    bind[0].buffer_type = MYSQL_TYPE_LONG;
    bind[0].buffer = (char*)&encKeyVersion;
    bind[0].is_null = 0;

    SET_STRING_BIND(1, nameCipher);
    SET_STRING_BIND(2, nameBlind);
    SET_STRING_BIND(3, nameTag);
    SET_STRING_BIND(4, phoneCipher);
    SET_STRING_BIND(5, phoneBlind);
    SET_STRING_BIND(6, phoneTag);
    SET_STRING_BIND(7, addrCipher);
    SET_STRING_BIND(8, addrBlind);
    SET_STRING_BIND(9, addrTag);

    if (mysql_stmt_bind_param(stmt, bind) != 0 ||
        mysql_stmt_execute(stmt) != 0) {
        mysql_stmt_close(stmt);
        throw std::runtime_error(mysql_stmt_error(stmt));
    }

    int64_t insertId = mysql_stmt_insert_id(stmt);
    mysql_stmt_close(stmt);
    return insertId;
}

// ---- 插入倒排索引 ----
void DAO::insertFuzzyIndex(int64_t dataId, FieldType type,
                           const std::vector<std::string>& tokenHashes) {
    if (tokenHashes.empty()) return;
    MYSQL* conn = connGuard_->get();

    std::string sql = "INSERT IGNORE INTO fuzzy_inverted (token_hash, data_id, field_type) VALUES ";
    for (size_t i = 0; i < tokenHashes.size(); ++i) {
        if (i > 0) sql += ",";
        sql += "(?, ?, ?)";
    }

    MYSQL_STMT* stmt = mysql_stmt_init(conn);
    if (!stmt) throw std::runtime_error("mysql_stmt_init failed");

    if (mysql_stmt_prepare(stmt, sql.c_str(), sql.length()) != 0) {
        std::string err = mysql_stmt_error(stmt);
        mysql_stmt_close(stmt);
        throw std::runtime_error("Prepare batch insert fuzzy failed: " + err);
    }

    size_t paramCount = tokenHashes.size() * 3;
    std::vector<MYSQL_BIND> bind(paramCount);
    std::vector<std::string> hashValues = tokenHashes;
    std::vector<uint8_t> fieldTypes(tokenHashes.size(), static_cast<uint8_t>(type));

    for (size_t i = 0; i < tokenHashes.size(); ++i) {
        size_t base = i * 3;
        bind[base].buffer_type = MYSQL_TYPE_STRING;
        bind[base].buffer = (char*)hashValues[i].c_str();
        bind[base].buffer_length = hashValues[i].size();
        bind[base].is_null = 0;

        bind[base+1].buffer_type = MYSQL_TYPE_LONGLONG;
        bind[base+1].buffer = (char*)&dataId;
        bind[base+1].is_null = 0;

        bind[base+2].buffer_type = MYSQL_TYPE_TINY;
        bind[base+2].buffer = (char*)&fieldTypes[i];
        bind[base+2].is_null = 0;
    }

    if (mysql_stmt_bind_param(stmt, bind.data()) != 0) {
        std::string err = mysql_stmt_error(stmt);
        mysql_stmt_close(stmt);
        throw std::runtime_error("Bind param fuzzy failed: " + err);
    }

    if (mysql_stmt_execute(stmt) != 0) {
        std::string err = mysql_stmt_error(stmt);
        mysql_stmt_close(stmt);
        throw std::runtime_error("Execute fuzzy failed: " + err);
    }
    mysql_stmt_close(stmt);
}

// ---- 删除模糊索引 ----
void DAO::deleteFuzzyIndex(int64_t dataId) {
    MYSQL* conn = connGuard_->get();
    const char* sql = "DELETE FROM fuzzy_inverted WHERE data_id = ?";
    MYSQL_STMT* stmt = mysql_stmt_init(conn);
    if (!stmt || mysql_stmt_prepare(stmt, sql, strlen(sql)) != 0) {
        if (stmt) mysql_stmt_close(stmt);
        throw std::runtime_error("Prepare delete fuzzy failed");
    }
    MYSQL_BIND bind[1];
    memset(bind, 0, sizeof(bind));
    bind[0].buffer_type = MYSQL_TYPE_LONGLONG;
    bind[0].buffer = (char*)&dataId;
    bind[0].is_null = 0;

    if (mysql_stmt_bind_param(stmt, bind) != 0 ||
        mysql_stmt_execute(stmt) != 0) {
        mysql_stmt_close(stmt);
        throw std::runtime_error(mysql_stmt_error(stmt));
    }
    mysql_stmt_close(stmt);
}

// ---- ★ 多版本精确查询 ----
std::vector<int64_t> DAO::queryByExactIndexMulti(const std::vector<std::string>& blindHashes,
                                                 FieldType fieldType) {
    std::vector<int64_t> ids;
    if (blindHashes.empty()) return ids;

    MYSQL* conn = connGuard_->get();

    std::string column;
    switch (fieldType) {
        case FieldType::NAME:    column = "name_blind_idx"; break;
        case FieldType::PHONE:   column = "phone_blind_idx"; break;
        case FieldType::ADDRESS: column = "address_blind_idx"; break;
        default: throw std::runtime_error("Invalid field type");
    }

    std::string inPlaceholders;
    for (size_t i = 0; i < blindHashes.size(); ++i) {
        if (i > 0) inPlaceholders += ",";
        inPlaceholders += "?";
    }

    std::string sql = "SELECT id FROM sensitive_data WHERE " + column + " IN (" + inPlaceholders + ")";

    MYSQL_STMT* stmt = mysql_stmt_init(conn);
    if (!stmt || mysql_stmt_prepare(stmt, sql.c_str(), sql.length()) != 0) {
        if (stmt) mysql_stmt_close(stmt);
        throw std::runtime_error("Prepare multi exact query failed");
    }

    std::vector<MYSQL_BIND> bind(blindHashes.size());
    std::vector<std::string> hashCopies = blindHashes;
    for (size_t i = 0; i < blindHashes.size(); ++i) {
        bind[i].buffer_type = MYSQL_TYPE_STRING;
        bind[i].buffer = (char*)hashCopies[i].c_str();
        bind[i].buffer_length = hashCopies[i].size();
        bind[i].is_null = 0;
    }

    if (mysql_stmt_bind_param(stmt, bind.data()) != 0 ||
        mysql_stmt_execute(stmt) != 0) {
        mysql_stmt_close(stmt);
        throw std::runtime_error(mysql_stmt_error(stmt));
    }

    MYSQL_BIND out_bind[1];
    memset(out_bind, 0, sizeof(out_bind));
    int64_t id;
    out_bind[0].buffer_type = MYSQL_TYPE_LONGLONG;
    out_bind[0].buffer = &id;
    out_bind[0].is_null = 0;

    if (mysql_stmt_bind_result(stmt, out_bind) != 0) {
        mysql_stmt_close(stmt);
        throw std::runtime_error(mysql_stmt_error(stmt));
    }

    while (mysql_stmt_fetch(stmt) == 0) ids.push_back(id);
    mysql_stmt_close(stmt);
    return ids;
}

// ---- ★ 多版本模糊查询 ----
std::vector<int64_t> DAO::queryByFuzzyKeywordMulti(const std::vector<std::string>& tokenHashes,
                                                   FieldType fieldType) {
    std::vector<int64_t> ids;
    if (tokenHashes.empty()) return ids;

    MYSQL* conn = connGuard_->get();

    std::string inPlaceholders;
    for (size_t i = 0; i < tokenHashes.size(); ++i) {
        if (i > 0) inPlaceholders += ",";
        inPlaceholders += "?";
    }

    std::string sql = "SELECT data_id FROM fuzzy_inverted WHERE token_hash IN (" + inPlaceholders +
                      ") AND field_type = ? GROUP BY data_id HAVING COUNT(DISTINCT token_hash) = ?";

    MYSQL_STMT* stmt = mysql_stmt_init(conn);
    if (!stmt || mysql_stmt_prepare(stmt, sql.c_str(), sql.length()) != 0) {
        if (stmt) mysql_stmt_close(stmt);
        throw std::runtime_error("Prepare multi fuzzy query failed");
    }

    size_t paramCount = tokenHashes.size() + 2;
    std::vector<MYSQL_BIND> bind(paramCount);
    std::vector<std::string> hashCopies = tokenHashes;

    for (size_t i = 0; i < tokenHashes.size(); ++i) {
        bind[i].buffer_type = MYSQL_TYPE_STRING;
        bind[i].buffer = (char*)hashCopies[i].c_str();
        bind[i].buffer_length = hashCopies[i].size();
        bind[i].is_null = 0;
    }

    uint8_t ft = static_cast<uint8_t>(fieldType);
    size_t tokenCount = tokenHashes.size();
    bind[tokenHashes.size()].buffer_type = MYSQL_TYPE_TINY;
    bind[tokenHashes.size()].buffer = (char*)&ft;
    bind[tokenHashes.size()].is_null = 0;

    bind[tokenHashes.size() + 1].buffer_type = MYSQL_TYPE_LONGLONG;
    bind[tokenHashes.size() + 1].buffer = (char*)&tokenCount;
    bind[tokenHashes.size() + 1].is_null = 0;

    if (mysql_stmt_bind_param(stmt, bind.data()) != 0 ||
        mysql_stmt_execute(stmt) != 0) {
        mysql_stmt_close(stmt);
        throw std::runtime_error(mysql_stmt_error(stmt));
    }

    MYSQL_BIND out_bind[1];
    memset(out_bind, 0, sizeof(out_bind));
    int64_t dataId;
    out_bind[0].buffer_type = MYSQL_TYPE_LONGLONG;
    out_bind[0].buffer = &dataId;
    out_bind[0].is_null = 0;

    if (mysql_stmt_bind_result(stmt, out_bind) != 0) {
        mysql_stmt_close(stmt);
        throw std::runtime_error(mysql_stmt_error(stmt));
    }

    while (mysql_stmt_fetch(stmt) == 0) ids.push_back(dataId);
    mysql_stmt_close(stmt);
    return ids;
}

// ---- 单版本模糊查询 ----
std::vector<int64_t> DAO::queryByFuzzyKeyword(const std::string& keyword,
                                              FieldType fieldType,
                                              const std::vector<unsigned char>& idxKey) {
    auto tokens = splitBigram(keyword);
    if (tokens.empty()) return {};
    auto hashes = hashTokens(tokens, idxKey);
    return queryByFuzzyKeywordMulti(hashes, fieldType);
}

// ---- 批量读取密文 ----
std::vector<CipherRecord> DAO::batchSelectCiphers(const std::vector<int64_t>& ids) {
    std::vector<CipherRecord> records;
    if (ids.empty()) return records;

    MYSQL* conn = connGuard_->get();

    std::string sql = R"(
        SELECT id, enc_key_version, name_cipher, name_tag, phone_cipher, phone_tag,
               address_cipher, address_tag
        FROM sensitive_data WHERE id IN (?
    )";
    for (size_t i = 1; i < ids.size(); ++i) sql += ",?";
    sql += ")";

    MYSQL_STMT* stmt = mysql_stmt_init(conn);
    if (!stmt || mysql_stmt_prepare(stmt, sql.c_str(), sql.length()) != 0) {
        if (stmt) mysql_stmt_close(stmt);
        throw std::runtime_error("Prepare batch select failed");
    }

    std::vector<MYSQL_BIND> bind(ids.size());
    std::vector<int64_t> idCopies = ids;
    for (size_t i = 0; i < ids.size(); ++i) {
        bind[i].buffer_type = MYSQL_TYPE_LONGLONG;
        bind[i].buffer = (char*)&idCopies[i];
        bind[i].is_null = 0;
    }

    if (mysql_stmt_bind_param(stmt, bind.data()) != 0 ||
        mysql_stmt_execute(stmt) != 0) {
        mysql_stmt_close(stmt);
        throw std::runtime_error(mysql_stmt_error(stmt));
    }

    MYSQL_BIND out_bind[8];
    memset(out_bind, 0, sizeof(out_bind));

    int64_t id;
    int encKeyVersion;
    char nameCipher[4096], nameTag[65], phoneCipher[4096], phoneTag[65];
    char addrCipher[4096], addrTag[65];
    unsigned long nameCipherLen, nameTagLen, phoneCipherLen, phoneTagLen;
    unsigned long addrCipherLen, addrTagLen;
    bool isNull[8];

    out_bind[0].buffer_type = MYSQL_TYPE_LONGLONG;
    out_bind[0].buffer = &id;

    out_bind[1].buffer_type = MYSQL_TYPE_LONG;
    out_bind[1].buffer = &encKeyVersion;
    out_bind[1].is_null = &isNull[1];

    #define SET_STR_OUT(i, buf, len) \
        out_bind[i].buffer_type = MYSQL_TYPE_STRING; \
        out_bind[i].buffer = buf; \
        out_bind[i].buffer_length = sizeof(buf); \
        out_bind[i].length = &len; \
        out_bind[i].is_null = &isNull[i]

    SET_STR_OUT(2, nameCipher, nameCipherLen);
    SET_STR_OUT(3, nameTag, nameTagLen);
    SET_STR_OUT(4, phoneCipher, phoneCipherLen);
    SET_STR_OUT(5, phoneTag, phoneTagLen);
    SET_STR_OUT(6, addrCipher, addrCipherLen);
    SET_STR_OUT(7, addrTag, addrTagLen);

    if (mysql_stmt_bind_result(stmt, out_bind) != 0) {
        mysql_stmt_close(stmt);
        throw std::runtime_error(mysql_stmt_error(stmt));
    }

    while (mysql_stmt_fetch(stmt) == 0) {
        if (!isNull[2]) {
            records.push_back({id, std::string(nameCipher, nameCipherLen),
                               std::string(nameTag, nameTagLen),
                               FieldType::NAME, encKeyVersion});
        }
        if (!isNull[4]) {
            records.push_back({id, std::string(phoneCipher, phoneCipherLen),
                               std::string(phoneTag, phoneTagLen),
                               FieldType::PHONE, encKeyVersion});
        }
        if (!isNull[6]) {
            records.push_back({id, std::string(addrCipher, addrCipherLen),
                               std::string(addrTag, addrTagLen),
                               FieldType::ADDRESS, encKeyVersion});
        }
    }

    mysql_stmt_close(stmt);
    return records;
}

// ---- 更新数据 ----
bool DAO::updateData(int64_t id, const PlainData& newData,
                     const std::vector<unsigned char>& encKey,
                     const std::vector<unsigned char>& idxKey,
                     const std::vector<unsigned char>& tagKey,
                     int encKeyVersion) {
    MYSQL* conn = connGuard_->get();
    Transaction tx(conn);

    deleteFuzzyIndex(id);

    auto nameBytes = std::vector<unsigned char>(newData.name.begin(), newData.name.end());
    auto phoneBytes = std::vector<unsigned char>(newData.phone.begin(), newData.phone.end());
    auto addrBytes = std::vector<unsigned char>(newData.address.begin(), newData.address.end());

    std::string nameCipher = crypto::Sm4Cipher::encrypt(nameBytes, encKey);
    std::string phoneCipher = crypto::Sm4Cipher::encrypt(phoneBytes, encKey);
    std::string addrCipher = crypto::Sm4Cipher::encrypt(addrBytes, encKey);

    std::string nameBlind = crypto::HmacSm3::hmacHex(nameBytes, idxKey);
    std::string phoneBlind = crypto::HmacSm3::hmacHex(phoneBytes, idxKey);
    std::string addrBlind = crypto::HmacSm3::hmacHex(addrBytes, idxKey);

    auto nameCipherBytes = std::vector<unsigned char>(nameCipher.begin(), nameCipher.end());
    auto phoneCipherBytes = std::vector<unsigned char>(phoneCipher.begin(), phoneCipher.end());
    auto addrCipherBytes = std::vector<unsigned char>(addrCipher.begin(), addrCipher.end());

    std::string nameTag = crypto::HmacSm3::hmacHex(nameCipherBytes, tagKey);
    std::string phoneTag = crypto::HmacSm3::hmacHex(phoneCipherBytes, tagKey);
    std::string addrTag = crypto::HmacSm3::hmacHex(addrCipherBytes, tagKey);

    const char* sql = R"(
        UPDATE sensitive_data SET
            enc_key_version = ?,
            name_cipher = ?, name_blind_idx = ?, name_tag = ?,
            phone_cipher = ?, phone_blind_idx = ?, phone_tag = ?,
            address_cipher = ?, address_blind_idx = ?, address_tag = ?
        WHERE id = ?
    )";
    MYSQL_STMT* stmt = mysql_stmt_init(conn);
    if (!stmt || mysql_stmt_prepare(stmt, sql, strlen(sql)) != 0) {
        if (stmt) mysql_stmt_close(stmt);
        throw std::runtime_error("Prepare update failed");
    }

    MYSQL_BIND bind[11];
    memset(bind, 0, sizeof(bind));

    bind[0].buffer_type = MYSQL_TYPE_LONG;
    bind[0].buffer = (char*)&encKeyVersion;
    bind[0].is_null = 0;

    #define SET_STR_BIND(i, str) \
        bind[i].buffer_type = MYSQL_TYPE_STRING; \
        bind[i].buffer = (char*)str.c_str(); \
        bind[i].buffer_length = str.size(); \
        bind[i].is_null = 0

    SET_STR_BIND(1, nameCipher);
    SET_STR_BIND(2, nameBlind);
    SET_STR_BIND(3, nameTag);
    SET_STR_BIND(4, phoneCipher);
    SET_STR_BIND(5, phoneBlind);
    SET_STR_BIND(6, phoneTag);
    SET_STR_BIND(7, addrCipher);
    SET_STR_BIND(8, addrBlind);
    SET_STR_BIND(9, addrTag);

    bind[10].buffer_type = MYSQL_TYPE_LONGLONG;
    bind[10].buffer = (char*)&id;
    bind[10].is_null = 0;

    if (mysql_stmt_bind_param(stmt, bind) != 0 ||
        mysql_stmt_execute(stmt) != 0) {
        mysql_stmt_close(stmt);
        throw std::runtime_error(mysql_stmt_error(stmt));
    }
    mysql_stmt_close(stmt);

    auto nameTokens = splitBigram(newData.name);
    auto phoneTokens = splitBigram(newData.phone);
    auto addrTokens = splitBigram(newData.address);

    auto nameHashes = hashTokens(nameTokens, idxKey);
    auto phoneHashes = hashTokens(phoneTokens, idxKey);
    auto addrHashes = hashTokens(addrTokens, idxKey);

    insertFuzzyIndex(id, FieldType::NAME, nameHashes);
    insertFuzzyIndex(id, FieldType::PHONE, phoneHashes);
    insertFuzzyIndex(id, FieldType::ADDRESS, addrHashes);

    tx.commit();
    return true;
}

// ---- 删除数据 ----
bool DAO::deleteData(int64_t id) {
    MYSQL* conn = connGuard_->get();
    Transaction tx(conn);

    deleteFuzzyIndex(id);

    const char* sql = "DELETE FROM sensitive_data WHERE id = ?";
    MYSQL_STMT* stmt = mysql_stmt_init(conn);
    if (!stmt || mysql_stmt_prepare(stmt, sql, strlen(sql)) != 0) {
        if (stmt) mysql_stmt_close(stmt);
        throw std::runtime_error("Prepare delete failed");
    }
    MYSQL_BIND bind[1];
    memset(bind, 0, sizeof(bind));
    bind[0].buffer_type = MYSQL_TYPE_LONGLONG;
    bind[0].buffer = (char*)&id;
    bind[0].is_null = 0;

    if (mysql_stmt_bind_param(stmt, bind) != 0 ||
        mysql_stmt_execute(stmt) != 0) {
        mysql_stmt_close(stmt);
        throw std::runtime_error(mysql_stmt_error(stmt));
    }
    mysql_stmt_close(stmt);

    tx.commit();
    return true;

    
}

// ---- ★ 从 key_config 表加载所有密钥（密文形式） ----
std::vector<crypto::KeyInfo> DAO::loadAllKeysFromConfig(int keyType) const {
    std::vector<crypto::KeyInfo> keys;
    MYSQL* conn = connGuard_->get();

    const char* sql = "SELECT key_version, key_cipher, status FROM key_config WHERE key_type = ? ORDER BY key_version ASC";
    MYSQL_STMT* stmt = mysql_stmt_init(conn);
    if (!stmt) return keys;

    if (mysql_stmt_prepare(stmt, sql, strlen(sql)) != 0) {
        mysql_stmt_close(stmt);
        return keys;
    }

    MYSQL_BIND bind[1];
    memset(bind, 0, sizeof(bind));
    bind[0].buffer_type = MYSQL_TYPE_TINY;
    bind[0].buffer = (char*)&keyType;
    bind[0].is_null = 0;

    if (mysql_stmt_bind_param(stmt, bind) != 0 ||
        mysql_stmt_execute(stmt) != 0) {
        mysql_stmt_close(stmt);
        return keys;
    }

    MYSQL_BIND out_bind[3];
    memset(out_bind, 0, sizeof(out_bind));

    int version;
    char keyCipher[4096];
    int status;
    unsigned long keyCipherLen;

    out_bind[0].buffer_type = MYSQL_TYPE_LONG;
    out_bind[0].buffer = &version;
    out_bind[0].is_null = 0;

    out_bind[1].buffer_type = MYSQL_TYPE_STRING;
    out_bind[1].buffer = keyCipher;
    out_bind[1].buffer_length = sizeof(keyCipher);
    out_bind[1].length = &keyCipherLen;
    out_bind[1].is_null = 0;

    out_bind[2].buffer_type = MYSQL_TYPE_TINY;
    out_bind[2].buffer = &status;
    out_bind[2].is_null = 0;

    if (mysql_stmt_bind_result(stmt, out_bind) != 0) {
        mysql_stmt_close(stmt);
        return keys;
    }

    while (mysql_stmt_fetch(stmt) == 0) {
        crypto::KeyInfo info;
        info.version = version;
        info.status = static_cast<crypto::KeyStatus>(status);
        // 存储密文（调用者用 KEK 解密）
        info.key = std::vector<unsigned char>(keyCipher, keyCipher + keyCipherLen);
        keys.push_back(info);
    }

    mysql_stmt_close(stmt);
    return keys;
}

// ---- ★ 保存密钥到 key_config 表 ----
void DAO::saveKeyToConfig(int keyType, const std::vector<unsigned char>& key,
                          int version, crypto::KeyStatus status) {
    MYSQL* conn = connGuard_->get();
    Transaction tx(conn);

    const char* sql = R"(
        INSERT INTO key_config (key_type, key_cipher, key_version, status)
        VALUES (?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE key_cipher = ?, status = ?
    )";
    MYSQL_STMT* stmt = mysql_stmt_init(conn);
    if (!stmt || mysql_stmt_prepare(stmt, sql, strlen(sql)) != 0) {
        if (stmt) mysql_stmt_close(stmt);
        throw std::runtime_error("Prepare save key failed");
    }

    // ★ 密钥已由调用者加密，直接存储 Base64 或十六进制
    // 这里 key 已经是密文字节，转为字符串存储
    std::string keyStr(key.begin(), key.end());
    uint8_t statusByte = static_cast<uint8_t>(status);

    MYSQL_BIND bind[6];
    memset(bind, 0, sizeof(bind));

    bind[0].buffer_type = MYSQL_TYPE_TINY;
    bind[0].buffer = (char*)&keyType;
    bind[0].is_null = 0;

    bind[1].buffer_type = MYSQL_TYPE_STRING;
    bind[1].buffer = (char*)keyStr.c_str();
    bind[1].buffer_length = keyStr.size();
    bind[1].is_null = 0;

    bind[2].buffer_type = MYSQL_TYPE_LONG;
    bind[2].buffer = (char*)&version;
    bind[2].is_null = 0;

    bind[3].buffer_type = MYSQL_TYPE_TINY;
    bind[3].buffer = (char*)&statusByte;
    bind[3].is_null = 0;

    bind[4].buffer_type = MYSQL_TYPE_STRING;
    bind[4].buffer = (char*)keyStr.c_str();
    bind[4].buffer_length = keyStr.size();
    bind[4].is_null = 0;

    bind[5].buffer_type = MYSQL_TYPE_TINY;
    bind[5].buffer = (char*)&statusByte;
    bind[5].is_null = 0;

    if (mysql_stmt_bind_param(stmt, bind) != 0 ||
        mysql_stmt_execute(stmt) != 0) {
        mysql_stmt_close(stmt);
        throw std::runtime_error("Execute save key failed");
    }

    mysql_stmt_close(stmt);
    tx.commit();
}

// ---- ★ 更新密钥状态 ----
void DAO::updateKeyStatusInConfig(int keyType, int version, crypto::KeyStatus status) {
    MYSQL* conn = connGuard_->get();
    uint8_t statusByte = static_cast<uint8_t>(status);

    const char* sql = "UPDATE key_config SET status = ? WHERE key_type = ? AND key_version = ?";
    MYSQL_STMT* stmt = mysql_stmt_init(conn);
    if (!stmt || mysql_stmt_prepare(stmt, sql, strlen(sql)) != 0) {
        if (stmt) mysql_stmt_close(stmt);
        throw std::runtime_error("Prepare update key status failed");
    }

    MYSQL_BIND bind[3];
    memset(bind, 0, sizeof(bind));
    bind[0].buffer_type = MYSQL_TYPE_TINY;
    bind[0].buffer = (char*)&statusByte;
    bind[0].is_null = 0;
    bind[1].buffer_type = MYSQL_TYPE_TINY;
    bind[1].buffer = (char*)&keyType;
    bind[1].is_null = 0;
    bind[2].buffer_type = MYSQL_TYPE_LONG;
    bind[2].buffer = (char*)&version;
    bind[2].is_null = 0;

    if (mysql_stmt_bind_param(stmt, bind) != 0 ||
        mysql_stmt_execute(stmt) != 0) {
        mysql_stmt_close(stmt);
        throw std::runtime_error("Execute update key status failed");
    }
    mysql_stmt_close(stmt);
}

// ---- ★ 删除密钥 ----
void DAO::deleteKeyFromConfig(int keyType, int version) {
    MYSQL* conn = connGuard_->get();
    const char* sql = "DELETE FROM key_config WHERE key_type = ? AND key_version = ?";
    MYSQL_STMT* stmt = mysql_stmt_init(conn);
    if (!stmt || mysql_stmt_prepare(stmt, sql, strlen(sql)) != 0) {
        if (stmt) mysql_stmt_close(stmt);
        throw std::runtime_error("Prepare delete key failed");
    }

    MYSQL_BIND bind[2];
    memset(bind, 0, sizeof(bind));
    bind[0].buffer_type = MYSQL_TYPE_TINY;
    bind[0].buffer = (char*)&keyType;
    bind[0].is_null = 0;
    bind[1].buffer_type = MYSQL_TYPE_LONG;
    bind[1].buffer = (char*)&version;
    bind[1].is_null = 0;

    if (mysql_stmt_bind_param(stmt, bind) != 0 ||
        mysql_stmt_execute(stmt) != 0) {
        mysql_stmt_close(stmt);
        throw std::runtime_error("Execute delete key failed");
    }
    mysql_stmt_close(stmt);
}

} // namespace database