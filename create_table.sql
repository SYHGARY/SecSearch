-- 1. 使用正确的数据库
USE secsearch;

-- 2. 创建模糊查询倒排索引表
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

-- 3. 创建主数据表
CREATE TABLE IF NOT EXISTS `sensitive_data` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT COMMENT '主键ID',
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