// dao.cpp
// 实现 DAO 的所有方法，与 crypto 模块配合完成加密存储和查询

#include "database/dao.h"
#include "database/transaction.h"
#include "crypto/sm4_cipher.h"
#include "crypto/hmac_sm3.h"
#include <sstream>
#include <set>
#include <cstring>

namespace database {

// ---- Bigram 分词（按字节滑动，适合中文/英文混合） ----
std::vector<std::string> DAO::splitBigram(const std::string& text) {
    std::vector<std::string> tokens;
    if (text.empty()) return tokens;
    // 对于长度为1的文本，单独作为一个 token
    if (text.size() == 1) {
        tokens.push_back(text);
        return tokens;
    }
    // 每两个连续字节作为一个 bigram
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
                        const std::vector<unsigned char>& tagKey) {
    // 1. 将明文字符串转为字节
    auto nameBytes = std::vector<unsigned char>(data.name.begin(), data.name.end());
    auto phoneBytes = std::vector<unsigned char>(data.phone.begin(), data.phone.end());
    auto addrBytes = std::vector<unsigned char>(data.address.begin(), data.address.end());

    // 2. SM4 加密 → 得到密文（十六进制字符串）
    std::string nameCipher = crypto::Sm4Cipher::encrypt(nameBytes, encKey);
    std::string phoneCipher = crypto::Sm4Cipher::encrypt(phoneBytes, encKey);
    std::string addrCipher = crypto::Sm4Cipher::encrypt(addrBytes, encKey);

    // 3. 生成精确盲索引（用 idxKey 对明文做 HMAC）
    std::string nameBlind = crypto::HmacSm3::hmacHex(nameBytes, idxKey);
    std::string phoneBlind = crypto::HmacSm3::hmacHex(phoneBytes, idxKey);
    std::string addrBlind = crypto::HmacSm3::hmacHex(addrBytes, idxKey);

    // 4. 生成完整性 Tag（用 tagKey 对密文做 HMAC）
    auto nameCipherBytes = std::vector<unsigned char>(nameCipher.begin(), nameCipher.end());
    auto phoneCipherBytes = std::vector<unsigned char>(phoneCipher.begin(), phoneCipher.end());
    auto addrCipherBytes = std::vector<unsigned char>(addrCipher.begin(), addrCipher.end());

    std::string nameTag = crypto::HmacSm3::hmacHex(nameCipherBytes, tagKey);
    std::string phoneTag = crypto::HmacSm3::hmacHex(phoneCipherBytes, tagKey);
    std::string addrTag = crypto::HmacSm3::hmacHex(addrCipherBytes, tagKey);

    // 5. 插入主表
    int64_t dataId = insertMainTable(nameCipher, nameBlind, nameTag,
                                     phoneCipher, phoneBlind, phoneTag,
                                     addrCipher, addrBlind, addrTag);
    if (dataId <= 0) {
        throw std::runtime_error("Insert main table failed");
    }

    // 6. 构建模糊索引（Bigram 分词 → HMAC-SM3 → 倒排表）
    // 注意：这里要使用 idxKey 来哈希 token，与盲索引共用同一把索引密钥
    auto nameTokens = splitBigram(data.name);
    auto phoneTokens = splitBigram(data.phone);
    auto addrTokens = splitBigram(data.address);

    auto nameHashes = hashTokens(nameTokens, idxKey);
    auto phoneHashes = hashTokens(phoneTokens, idxKey);
    auto addrHashes = hashTokens(addrTokens, idxKey);

    // 7. 在事务中插入倒排索引
    MYSQL* conn = connGuard_->get();
    Transaction tx(conn);

    insertFuzzyIndex(dataId, FieldType::NAME, nameHashes);
    insertFuzzyIndex(dataId, FieldType::PHONE, phoneHashes);
    insertFuzzyIndex(dataId, FieldType::ADDRESS, addrHashes);

    tx.commit();
    return dataId;
}

// ---- 插入主表（内部方法） ----
int64_t DAO::insertMainTable(const std::string& nameCipher, const std::string& nameBlind,
                             const std::string& nameTag,
                             const std::string& phoneCipher, const std::string& phoneBlind,
                             const std::string& phoneTag,
                             const std::string& addrCipher, const std::string& addrBlind,
                             const std::string& addrTag) {
    MYSQL* conn = connGuard_->get();
    const char* sql = R"(
        INSERT INTO sensitive_data
        (name_cipher, name_blind_idx, name_tag,
         phone_cipher, phone_blind_idx, phone_tag,
         address_cipher, address_blind_idx, address_tag)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";

    MYSQL_STMT* stmt = mysql_stmt_init(conn);
    if (!stmt || mysql_stmt_prepare(stmt, sql, strlen(sql)) != 0) {
        if (stmt) mysql_stmt_close(stmt);
        throw std::runtime_error("Prepare insert main failed");
    }

    MYSQL_BIND bind[9];
    memset(bind, 0, sizeof(bind));

    #define SET_STRING_BIND(i, str) \
        bind[i].buffer_type = MYSQL_TYPE_STRING; \
        bind[i].buffer = (char*)str.c_str(); \
        bind[i].buffer_length = str.size(); \
        bind[i].is_null = 0

    SET_STRING_BIND(0, nameCipher);
    SET_STRING_BIND(1, nameBlind);
    SET_STRING_BIND(2, nameTag);
    SET_STRING_BIND(3, phoneCipher);
    SET_STRING_BIND(4, phoneBlind);
    SET_STRING_BIND(5, phoneTag);
    SET_STRING_BIND(6, addrCipher);
    SET_STRING_BIND(7, addrBlind);
    SET_STRING_BIND(8, addrTag);

    if (mysql_stmt_bind_param(stmt, bind) != 0 ||
        mysql_stmt_execute(stmt) != 0) {
        mysql_stmt_close(stmt);
        throw std::runtime_error(mysql_stmt_error(stmt));
    }

    int64_t insertId = mysql_stmt_insert_id(stmt);
    mysql_stmt_close(stmt);
    return insertId;
}

// ---- 插入倒排索引（批量） ----
void DAO::insertFuzzyIndex(int64_t dataId, FieldType type,
                           const std::vector<std::string>& tokenHashes) {
    if (tokenHashes.empty()) return;
    MYSQL* conn = connGuard_->get();

    // 构造批量 INSERT 语句
    std::string sql = "INSERT IGNORE INTO fuzzy_inverted (token_hash, data_id, field_type) VALUES ";
    for (size_t i = 0; i < tokenHashes.size(); ++i) {
        if (i > 0) sql += ",";
        sql += "(?, ?, ?)";
    }

    MYSQL_STMT* stmt = mysql_stmt_init(conn);
    if (!stmt) {
        throw std::runtime_error("mysql_stmt_init failed");
    }

    // 检查 prepare，并在失败时打印具体 MySQL 错误
    if (mysql_stmt_prepare(stmt, sql.c_str(), sql.length()) != 0) {
        std::string err = mysql_stmt_error(stmt);  // 获取 MySQL 错误信息
        mysql_stmt_close(stmt);
        throw std::runtime_error("Prepare batch insert fuzzy failed: " + err);
    }

    size_t paramCount = tokenHashes.size() * 3;
    std::vector<MYSQL_BIND> bind(paramCount);
    std::vector<std::string> hashValues = tokenHashes; // 确保生命周期
    
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

        // ★ 使用 fieldTypes[i] 代替局部变量 ft
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

// ---- 删除全部模糊索引（按 data_id） ----
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

// ---- 精确查询 ----
std::vector<int64_t> DAO::queryByExactIndex(const std::string& blindHash,
                                            FieldType fieldType) {
    std::vector<int64_t> ids;
    MYSQL* conn = connGuard_->get();

    // 根据字段类型选择列名
    std::string column;
    switch (fieldType) {
        case FieldType::NAME:    column = "name_blind_idx"; break;
        case FieldType::PHONE:   column = "phone_blind_idx"; break;
        case FieldType::ADDRESS: column = "address_blind_idx"; break;
        default: throw std::runtime_error("Invalid field type");
    }

    std::string sql = "SELECT id FROM sensitive_data WHERE " + column + " = ?";
    MYSQL_STMT* stmt = mysql_stmt_init(conn);
    if (!stmt || mysql_stmt_prepare(stmt, sql.c_str(), sql.length()) != 0) {
        if (stmt) mysql_stmt_close(stmt);
        throw std::runtime_error("Prepare exact query failed");
    }

    MYSQL_BIND bind[1];
    memset(bind, 0, sizeof(bind));
    bind[0].buffer_type = MYSQL_TYPE_STRING;
    bind[0].buffer = (char*)blindHash.c_str();
    bind[0].buffer_length = blindHash.size();

    if (mysql_stmt_bind_param(stmt, bind) != 0 ||
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

    while (mysql_stmt_fetch(stmt) == 0) {
        ids.push_back(id);
    }
    mysql_stmt_close(stmt);
    return ids;
}

// ---- 模糊查询 ----
std::vector<int64_t> DAO::queryByFuzzyKeyword(const std::string& keyword,
                                              FieldType fieldType,
                                              const std::vector<unsigned char>& idxKey) {
    // 1. 对关键词做 Bigram 分词
    auto tokens = splitBigram(keyword);
    if (tokens.empty()) return {};

    // 2. 计算每个 token 的 HMAC-SM3 哈希
    auto hashes = hashTokens(tokens, idxKey);

    // 3. 查倒排表：必须同时匹配所有 token（取交集）
    // 使用 SQL: GROUP BY data_id HAVING COUNT(DISTINCT token_hash) = N
    MYSQL* conn = connGuard_->get();
    std::string sql = R"(
        SELECT data_id FROM fuzzy_inverted
        WHERE token_hash IN (?) AND field_type = ?
        GROUP BY data_id
        HAVING COUNT(DISTINCT token_hash) = ?
    )";

    // 简化处理：IN 子句动态生成
    std::string inPlaceholders;
    for (size_t i = 0; i < hashes.size(); ++i) {
        if (i > 0) inPlaceholders += ",";
        inPlaceholders += "?";
    }
    sql = "SELECT data_id FROM fuzzy_inverted WHERE token_hash IN (" + inPlaceholders +
          ") AND field_type = ? GROUP BY data_id HAVING COUNT(DISTINCT token_hash) = ?";

    MYSQL_STMT* stmt = mysql_stmt_init(conn);
    if (!stmt || mysql_stmt_prepare(stmt, sql.c_str(), sql.length()) != 0) {
        if (stmt) mysql_stmt_close(stmt);
        throw std::runtime_error("Prepare fuzzy query failed");
    }

    size_t paramCount = hashes.size() + 2;
    std::vector<MYSQL_BIND> bind(paramCount);
    std::vector<std::string> hashCopies = hashes;

    for (size_t i = 0; i < hashes.size(); ++i) {
        bind[i].buffer_type = MYSQL_TYPE_STRING;
        bind[i].buffer = (char*)hashCopies[i].c_str();
        bind[i].buffer_length = hashCopies[i].size();
        bind[i].is_null = 0;
    }

    uint8_t ft = static_cast<uint8_t>(fieldType);
    size_t tokenCount = hashes.size();

    bind[hashes.size()].buffer_type = MYSQL_TYPE_TINY;
    bind[hashes.size()].buffer = (char*)&ft;
    bind[hashes.size()].is_null = 0;

    bind[hashes.size() + 1].buffer_type = MYSQL_TYPE_LONGLONG;
    bind[hashes.size() + 1].buffer = (char*)&tokenCount;
    bind[hashes.size() + 1].is_null = 0;

    if (mysql_stmt_bind_param(stmt, bind.data()) != 0 ||
        mysql_stmt_execute(stmt) != 0) {
        mysql_stmt_close(stmt);
        throw std::runtime_error(mysql_stmt_error(stmt));
    }

    std::vector<int64_t> ids;
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

    while (mysql_stmt_fetch(stmt) == 0) {
        ids.push_back(dataId);
    }
    mysql_stmt_close(stmt);
    return ids;
}

// ---- 批量读取密文 ----
std::vector<CipherRecord> DAO::batchSelectCiphers(const std::vector<int64_t>& ids) {
    std::vector<CipherRecord> records;
    if (ids.empty()) return records;

    MYSQL* conn = connGuard_->get();

    // 构建 IN 子句
    std::string sql = R"(
        SELECT id, name_cipher, name_tag, phone_cipher, phone_tag,
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

    // 定义输出缓冲区
    MYSQL_BIND out_bind[7];
    memset(out_bind, 0, sizeof(out_bind));

    int64_t id;
    char nameCipher[4096], nameTag[65], phoneCipher[4096], phoneTag[65];
    char addrCipher[4096], addrTag[65];
    unsigned long nameCipherLen, nameTagLen, phoneCipherLen, phoneTagLen;
    unsigned long addrCipherLen, addrTagLen;
    bool isNull[7];

    out_bind[0].buffer_type = MYSQL_TYPE_LONGLONG;
    out_bind[0].buffer = &id;

    #define SET_STR_OUT(i, buf, len) \
        out_bind[i].buffer_type = MYSQL_TYPE_STRING; \
        out_bind[i].buffer = buf; \
        out_bind[i].buffer_length = sizeof(buf); \
        out_bind[i].length = &len; \
        out_bind[i].is_null = &isNull[i]

    SET_STR_OUT(1, nameCipher, nameCipherLen);
    SET_STR_OUT(2, nameTag, nameTagLen);
    SET_STR_OUT(3, phoneCipher, phoneCipherLen);
    SET_STR_OUT(4, phoneTag, phoneTagLen);
    SET_STR_OUT(5, addrCipher, addrCipherLen);
    SET_STR_OUT(6, addrTag, addrTagLen);

    if (mysql_stmt_bind_result(stmt, out_bind) != 0) {
        mysql_stmt_close(stmt);
        throw std::runtime_error(mysql_stmt_error(stmt));
    }

    // 逐行读取，每个字段分别作为一条 CipherRecord 返回
    while (mysql_stmt_fetch(stmt) == 0) {
        if (!isNull[1]) {
            records.push_back({id, std::string(nameCipher, nameCipherLen),
                               std::string(nameTag, nameTagLen), FieldType::NAME});
        }
        if (!isNull[3]) {
            records.push_back({id, std::string(phoneCipher, phoneCipherLen),
                               std::string(phoneTag, phoneTagLen), FieldType::PHONE});
        }
        if (!isNull[5]) {
            records.push_back({id, std::string(addrCipher, addrCipherLen),
                               std::string(addrTag, addrTagLen), FieldType::ADDRESS});
        }
    }

    mysql_stmt_close(stmt);
    return records;
}

// ---- 更新数据 ----
bool DAO::updateData(int64_t id, const PlainData& newData,
                     const std::vector<unsigned char>& encKey,
                     const std::vector<unsigned char>& idxKey,
                     const std::vector<unsigned char>& tagKey) {
    MYSQL* conn = connGuard_->get();
    Transaction tx(conn);

    // 1. 删除旧模糊索引
    deleteFuzzyIndex(id);

    // 2. 加密新数据
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

    // 3. 更新主表
    const char* sql = R"(
        UPDATE sensitive_data SET
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

    MYSQL_BIND bind[10];
    memset(bind, 0, sizeof(bind));

    #define SET_STR_BIND(i, str) \
        bind[i].buffer_type = MYSQL_TYPE_STRING; \
        bind[i].buffer = (char*)str.c_str(); \
        bind[i].buffer_length = str.size(); \
        bind[i].is_null = 0

    SET_STR_BIND(0, nameCipher);
    SET_STR_BIND(1, nameBlind);
    SET_STR_BIND(2, nameTag);
    SET_STR_BIND(3, phoneCipher);
    SET_STR_BIND(4, phoneBlind);
    SET_STR_BIND(5, phoneTag);
    SET_STR_BIND(6, addrCipher);
    SET_STR_BIND(7, addrBlind);
    SET_STR_BIND(8, addrTag);
    bind[9].buffer_type = MYSQL_TYPE_LONGLONG;
    bind[9].buffer = (char*)&id;
    bind[9].is_null = 0;

    if (mysql_stmt_bind_param(stmt, bind) != 0 ||
        mysql_stmt_execute(stmt) != 0) {
        mysql_stmt_close(stmt);
        throw std::runtime_error(mysql_stmt_error(stmt));
    }
    mysql_stmt_close(stmt);

    // 4. 插入新模糊索引
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

} // namespace database