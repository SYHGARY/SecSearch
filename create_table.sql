-- create_table.sql：用于直接在MySQL中生成系统需要的管理表

-- 1. 创建数据库
CREATE DATABASE IF NOT EXISTS secsearch;

-- 2. 使用正确的数据库
USE secsearch;

-- 3. 创建主数据表
CREATE TABLE IF NOT EXISTS `sensitive_data` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT COMMENT '主键ID',
  `enc_key_version` int(11) NOT NULL DEFAULT 1 COMMENT '加密密钥版本号',
  `name_cipher` text NOT NULL COMMENT '姓名SM4密文',
  `name_blind_idx` char(64) NOT NULL COMMENT '姓名精确盲索引',
  `name_tag` char(64) NOT NULL COMMENT '姓名完整性Tag',
  `phone_cipher` text NOT NULL COMMENT '手机号SM4密文',
  `phone_blind_idx` char(64) NOT NULL COMMENT '手机号精确盲索引',
  `phone_tag` char(64) NOT NULL COMMENT '手机号完整性Tag',
  `address_cipher` text NOT NULL COMMENT '地址SM4密文',
  `address_blind_idx` char(64) NOT NULL COMMENT '地址精确盲索引',
  `address_tag` char(64) NOT NULL COMMENT '地址完整性Tag',
  `create_time` datetime DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `update_time` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  PRIMARY KEY (`id`),
  KEY `idx_name_blind` (`name_blind_idx`),
  KEY `idx_phone_blind` (`phone_blind_idx`),
  KEY `idx_address_blind` (`address_blind_idx`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='敏感数据主表';

-- 4. 创建模糊查询倒排索引表
CREATE TABLE IF NOT EXISTS `fuzzy_inverted` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT COMMENT '自增主键',
  `token_hash` char(64) NOT NULL COMMENT 'Bigram分词的HMAC-SM3盲哈希值（64字符）',
  `data_id` bigint(20) NOT NULL COMMENT '关联主数据表的ID',
  `field_type` tinyint(4) NOT NULL COMMENT '字段类型：1=姓名，2=手机号，3=地址',
  `create_time` datetime DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_token_data_field` (`token_hash`, `data_id`, `field_type`),
  KEY `idx_token_hash` (`token_hash`),
  KEY `idx_data_id` (`data_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='模糊查询倒排索引表';

-- 5. 创建密钥配置表（用于存储加密后的工作密钥）
CREATE TABLE IF NOT EXISTS `key_config` (
  `key_id` bigint(20) NOT NULL AUTO_INCREMENT COMMENT '密钥主键ID',
  `key_type` tinyint(4) NOT NULL COMMENT '密钥类型：1=加密密钥，2=盲索引密钥，3=完整性密钥',
  `key_cipher` text NOT NULL COMMENT '工作密钥密文（经主密钥KEK加密）',
  `key_version` int(11) NOT NULL COMMENT '密钥版本号',
  `status` tinyint(4) NOT NULL DEFAULT 1 COMMENT '密钥状态：1=启用，2=停用，3=销毁',
  `create_time` datetime DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `update_time` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  PRIMARY KEY (`key_id`),
  UNIQUE KEY `uk_type_version` (`key_type`, `key_version`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='密钥配置表';

-- 6. 审计日志表
CREATE TABLE IF NOT EXISTS audit_log (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    request_id VARCHAR(64) NOT NULL COMMENT '请求唯一标识',
    operator VARCHAR(64) DEFAULT 'system' COMMENT '操作者（可扩展）',
    operation VARCHAR(32) NOT NULL COMMENT '操作类型: INSERT/EXACT_QUERY/FUZZY_QUERY/UPDATE/DELETE/BATCH_DECRYPT',
    field_code TINYINT COMMENT '字段类型: 1-姓名 2-手机号 3-地址',
    candidate_count INT DEFAULT 0 COMMENT '候选记录数（查询时）',
    result_count INT DEFAULT 0 COMMENT '最终返回记录数',
    duration_ms INT DEFAULT 0 COMMENT '耗时（毫秒）',
    status TINYINT DEFAULT 1 COMMENT '1-成功 0-失败',
    error_msg VARCHAR(255) DEFAULT NULL COMMENT '错误信息（失败时）',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_request (request_id),
    INDEX idx_operation (operation),
    INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='审计日志表';

-- 7. 解密错误日志表
CREATE TABLE IF NOT EXISTS decrypt_error_log (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    request_id VARCHAR(64) NOT NULL COMMENT '关联的请求ID',
    record_id BIGINT NOT NULL COMMENT '数据主键ID',
    error_type VARCHAR(32) NOT NULL COMMENT '错误类型: TAG_MISMATCH/DECRYPT_FAILED/KEY_NOT_FOUND等',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_request (request_id),
    INDEX idx_record (record_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='批量解密失败记录表';
