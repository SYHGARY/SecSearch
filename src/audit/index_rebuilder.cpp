// audit/index_rebuilder.cpp
// 索引重建执行器实现

#include "audit/index_rebuilder.h"
#include "crypto/sm4_cipher.h"
#include "crypto/hmac_sm3.h"

#include <stdexcept>
#include <iostream>
#include <cstring>          
#include <algorithm>       

namespace rebuild {

IndexRebuilder::IndexRebuilder(database::DAO& dao, crypto::KeyManager& keyMgr)
    : dao_(dao), keyMgr_(keyMgr) {}

bool IndexRebuilder::rebuildOneRecord(const database::DAO::RebuildRawRecord& record,
                                      int fieldCode,
                                      const std::vector<unsigned char>& encKey,
                                      const std::vector<unsigned char>& idxKey,
                                      const std::vector<unsigned char>& tagKey,
                                      std::string& errorMsg) {
    try {
        // 1. 解密明文
        std::string plaintext;
        if (fieldCode == 1 && !record.nameCipher.empty()) {
            auto plainBytes = crypto::Sm4Cipher::decrypt(record.nameCipher, encKey);
            plaintext = std::string(plainBytes.begin(), plainBytes.end());
        } else if (fieldCode == 2 && !record.phoneCipher.empty()) {
            auto plainBytes = crypto::Sm4Cipher::decrypt(record.phoneCipher, encKey);
            plaintext = std::string(plainBytes.begin(), plainBytes.end());
        } else if (fieldCode == 3 && !record.addressCipher.empty()) {
            auto plainBytes = crypto::Sm4Cipher::decrypt(record.addressCipher, encKey);
            plaintext = std::string(plainBytes.begin(), plainBytes.end());
        } else {
            // 字段为空，跳过但视为成功
            return true;
        }

        auto plainBytes = std::vector<unsigned char>(plaintext.begin(), plaintext.end());

        // 2. 生成新的盲索引
        std::string newBlind = crypto::HmacSm3::hmacHex(plainBytes, idxKey);

        // 3. 生成新的模糊索引（Bigram 分词）
        auto tokens = database::DAO::splitBigram(plaintext);
        std::vector<std::string> newTokenHashes;
        for (const auto& token : tokens) {
            auto tokenBytes = std::vector<unsigned char>(token.begin(), token.end());
            newTokenHashes.push_back(crypto::HmacSm3::hmacHex(tokenBytes, idxKey));
        }

        // 4. 更新主表（只用更新 blind_idx 列）
        MYSQL* conn = dao_.getConnection();
        std::string column;
        switch (fieldCode) {
            case 1: column = "name_blind_idx"; break;
            case 2: column = "phone_blind_idx"; break;
            case 3: column = "address_blind_idx"; break;
            default: throw std::runtime_error("Invalid field code");
        }

        std::string sql = "UPDATE sensitive_data SET " + column + " = ? WHERE id = ?";
        MYSQL_STMT* stmt = mysql_stmt_init(conn);
        if (!stmt || mysql_stmt_prepare(stmt, sql.c_str(), sql.length()) != 0) {
            if (stmt) mysql_stmt_close(stmt);
            errorMsg = "Prepare update blind index failed";
            return false;
        }

        MYSQL_BIND bind[2];
        memset(bind, 0, sizeof(bind));
        bind[0].buffer_type = MYSQL_TYPE_STRING;
        bind[0].buffer = (char*)newBlind.c_str();
        bind[0].buffer_length = newBlind.size();
        bind[0].is_null = 0;
        bind[1].buffer_type = MYSQL_TYPE_LONGLONG;
        bind[1].buffer = (char*)&record.id;
        bind[1].is_null = 0;

        if (mysql_stmt_bind_param(stmt, bind) != 0 ||
            mysql_stmt_execute(stmt) != 0) {
            mysql_stmt_close(stmt);
            errorMsg = mysql_stmt_error(stmt);
            return false;
        }
        mysql_stmt_close(stmt);

        // 5. 更新模糊索引（先删除旧的，再插入新的）
        //    删除旧的模糊索引
        sql = "DELETE FROM fuzzy_inverted WHERE data_id = ? AND field_type = ?";
        stmt = mysql_stmt_init(conn);
        if (!stmt || mysql_stmt_prepare(stmt, sql.c_str(), sql.length()) != 0) {
            if (stmt) mysql_stmt_close(stmt);
            errorMsg = "Prepare delete fuzzy failed";
            return false;
        }
        uint8_t ft = static_cast<uint8_t>(fieldCode);
        MYSQL_BIND del_bind[2];
        memset(del_bind, 0, sizeof(del_bind));
        del_bind[0].buffer_type = MYSQL_TYPE_LONGLONG;
        del_bind[0].buffer = (char*)&record.id;
        del_bind[0].is_null = 0;
        del_bind[1].buffer_type = MYSQL_TYPE_TINY;
        del_bind[1].buffer = (char*)&ft;
        del_bind[1].is_null = 0;

        if (mysql_stmt_bind_param(stmt, del_bind) != 0 ||
            mysql_stmt_execute(stmt) != 0) {
            mysql_stmt_close(stmt);
            errorMsg = mysql_stmt_error(stmt);
            return false;
        }
        mysql_stmt_close(stmt);

        //    插入新的模糊索引
        if (!newTokenHashes.empty()) {
            std::string insertSql = "INSERT IGNORE INTO fuzzy_inverted (token_hash, data_id, field_type) VALUES ";
            for (size_t i = 0; i < newTokenHashes.size(); ++i) {
                if (i > 0) insertSql += ",";
                insertSql += "(?, ?, ?)";
            }

            stmt = mysql_stmt_init(conn);
            if (!stmt || mysql_stmt_prepare(stmt, insertSql.c_str(), insertSql.length()) != 0) {
                if (stmt) mysql_stmt_close(stmt);
                errorMsg = "Prepare insert fuzzy failed";
                return false;
            }

            std::vector<MYSQL_BIND> ins_bind(newTokenHashes.size() * 3);
            std::vector<uint8_t> fieldTypes(newTokenHashes.size(), ft);
            for (size_t i = 0; i < newTokenHashes.size(); ++i) {
                size_t base = i * 3;
                ins_bind[base].buffer_type = MYSQL_TYPE_STRING;
                ins_bind[base].buffer = (char*)newTokenHashes[i].c_str();
                ins_bind[base].buffer_length = newTokenHashes[i].size();
                ins_bind[base].is_null = 0;

                ins_bind[base + 1].buffer_type = MYSQL_TYPE_LONGLONG;
                ins_bind[base + 1].buffer = (char*)&record.id;
                ins_bind[base + 1].is_null = 0;

                ins_bind[base + 2].buffer_type = MYSQL_TYPE_TINY;
                ins_bind[base + 2].buffer = (char*)&fieldTypes[i];
                ins_bind[base + 2].is_null = 0;
            }

            if (mysql_stmt_bind_param(stmt, ins_bind.data()) != 0 ||
                mysql_stmt_execute(stmt) != 0) {
                mysql_stmt_close(stmt);
                errorMsg = mysql_stmt_error(stmt);
                return false;
            }
            mysql_stmt_close(stmt);
        }

        return true;

    } catch (const std::exception& e) {
        errorMsg = e.what();
        return false;
    }
}

int64_t IndexRebuilder::runTask(int64_t taskId, int batchSize,
                                std::function<void(const ProgressInfo&)> progressCb) {
    // 1. 获取任务信息
    auto task = dao_.getRebuildTaskStatus(taskId);
    if (task.status == 2) {
        // 已完成
        return task.successCount;
    }

    // 2. 标记任务为执行中
    dao_.updateRebuildTaskProgress(taskId, task.lastProcessedId, 
                                   task.successCount, task.failCount, 1); // status=1 执行中

    // 3. 获取当前密钥（使用最新启用的密钥重建索引）
    auto encKey = keyMgr_.getEncryptionKey();
    auto idxKey = keyMgr_.getIndexKey();
    auto tagKey = keyMgr_.getTagKey();

    // 4. 分批处理
    int64_t currentId = task.lastProcessedId > 0 ? task.lastProcessedId : task.startId - 1;
    int64_t endId = task.endId;
    int totalSuccess = task.successCount;
    int totalFail = task.failCount;

    ProgressInfo progress;
    progress.taskId = taskId;
    progress.total = endId - task.startId + 1;
    if (progress.total <= 0) progress.total = 1;

    while (currentId < endId) {
        // 分批获取
        int64_t batchStart = currentId + 1;
        int64_t batchEnd = std::min(batchStart + batchSize - 1, endId);

        auto records = dao_.getRecordsForRebuild(batchStart, batchEnd, batchSize);

        if (records.empty()) {
            currentId = batchEnd;
            continue;
        }

        // 处理本批次
        for (const auto& rec : records) {
            std::string errorMsg;
            bool ok = rebuildOneRecord(rec, task.fieldCode, encKey, idxKey, tagKey, errorMsg);
            if (ok) {
                totalSuccess++;
            } else {
                totalFail++;
                std::cerr << "⚠️ 重建记录 ID=" << rec.id << " 失败: " << errorMsg << std::endl;
            }
            currentId = rec.id;

            // 更新进度（每10条更新一次，减少数据库压力）
            if ((totalSuccess + totalFail) % 10 == 0) {
                dao_.updateRebuildTaskProgress(taskId, currentId, totalSuccess, totalFail, 1);
            }

            // 回调
            if (progressCb) {
                progress.processed = totalSuccess + totalFail;
                progress.successCount = totalSuccess;
                progress.failCount = totalFail;
                progress.currentId = std::to_string(currentId);
                progressCb(progress);
            }
        }

        // 批次结束后持久化进度
        dao_.updateRebuildTaskProgress(taskId, currentId, totalSuccess, totalFail, 1);
    }

    // 5. 标记任务完成（根据是否有失败决定状态）
    if (totalFail > 0) {
        // 有部分失败，标记为 3（失败），并记录错误信息
        MYSQL* conn = dao_.getConnection();
        std::string errMsg = "重建完成但有 " + std::to_string(totalFail) + " 条记录失败";
        const char* sql = "UPDATE index_rebuild_task SET status = 3, error_msg = ? WHERE id = ?";
        MYSQL_STMT* stmt = mysql_stmt_init(conn);
        if (stmt && mysql_stmt_prepare(stmt, sql, strlen(sql)) == 0) {
            MYSQL_BIND bind[2];
            memset(bind, 0, sizeof(bind));
            bind[0].buffer_type = MYSQL_TYPE_STRING;
            bind[0].buffer = (char*)errMsg.c_str();
            bind[0].buffer_length = errMsg.size();
            bind[0].is_null = 0;
            bind[1].buffer_type = MYSQL_TYPE_LONGLONG;
            bind[1].buffer = (char*)&taskId;
            bind[1].is_null = 0;
            mysql_stmt_bind_param(stmt, bind);
            mysql_stmt_execute(stmt);
            mysql_stmt_close(stmt);
        }
    } else {
        // 全部成功，标记为 2（已完成）
        dao_.updateRebuildTaskProgress(taskId, currentId, totalSuccess, totalFail, 2);
    }

    return totalSuccess;
}

int64_t IndexRebuilder::rebuildField(int fieldCode, int64_t startId, int64_t endId,
                                     int batchSize,
                                     std::function<void(const ProgressInfo&)> progressCb) {
    // 创建任务
    int64_t taskId = dao_.createRebuildTask(fieldCode, startId, endId);
    // 执行任务
    return runTask(taskId, batchSize, progressCb);
}

} // namespace rebuild