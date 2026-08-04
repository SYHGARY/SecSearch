# 🔐SecSearch - 数据库字段密文高效查询与并发优化系统

基于国密算法（SM4/SM3）的敏感字段加密存储与密文检索系统，支持密文精确匹配、模糊搜索及高吞吐批量解密。

## 功能特性

- **字段级加密**：SM4-CBC 加密 + HMAC-SM3 完整性校验，每条记录独立 IV
- **精确查询**：HMAC-SM3 盲索引 + B-Tree 加速，等值查询准确率 100%
- **模糊查询**：Bigram 分词 + 倒排索引，支持中缀匹配
- **批量解密优化**：生产者-消费者流水线 + OpenHiTLS 算法加速，吞吐量提升 50%+
- **密钥全生命周期管理**：三密钥分离（加密/索引/Tag）、多版本控制、平滑轮换、状态管控
- **安全审计**：全操作审计日志、解密错误追踪、查询频率/候选数限制防护
- **索引重建**：支持断点续跑的索引重建任务，用于密钥轮换后数据迁移
- **工程特性**：MySQL 连接池、事务支持、交互式 CLI、密钥持久化自动恢复

## 系统架构

```
应用层 (CLI) → 业务处理层 (增删改查/审计/索引重建) → 安全密码层 (SM4/HMAC/密钥管理) → 性能优化层 (批量/流水线) → 数据存储层 (MySQL)
```

密码学底座：**OpenHiTLS** (SM4 / SM3 / HMAC)

## 目录结构

```
SecSearch/
├── CMakeLists.txt              # CMake 构建配置
├── create_table.sql            # 数据库建表语句
├── include/
│   ├── crypto/                 # 加密模块 (sm4/hmac/key_manager/utils)
│   ├── database/               # 数据库模块 (连接池/DAO/事务)
│   ├── query/                  # 查询服务 (精确/模糊/批量解密)
│   ├── decrypt/                # 批量解密流水线
│   ├── audit/                  # 审计日志 & 索引重建
│   ├── hitls/                  # OpenHiTLS 头文件
│   ├── gmssl/                  # GmSSL 头文件
│   └── mysql/                  # MySQL 头文件
├── src/
│   ├── main.cpp                # 主程序入口 (交互式 CLI)
│   ├── SecSearch_test.cpp      # 全量测试文件
│   ├── SecSearch_SM4test/cpp   # SM4算法优化测试文件
│   ├── crypto/
│   ├── database/
│   ├── query/
│   ├── decrypt/
│   └── audit/
└── lib/                        # 第三方静态库 (OpenHiTLS + MySQL)
```

## 环境要求

| 依赖 | 版本要求 |
|------|----------|
| 系统 | Linux / WSL2 (Ubuntu 20.04+) |
| GCC | 10+ (C++20) |
| CMake | 3.16+ |
| MySQL | 8.0+ |
| OpenSSL | 1.1+ |

## 快速开始

### 1. 安装依赖

```bash
sudo apt update
sudo apt install -y build-essential cmake g++ libmysqlclient-dev \
    libssl-dev zlib1g-dev libzstd-dev
```

### 2. 编译

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

主体可执行文件输出至项目根目录：`./SecSearch`  
全量测试可执行文件输出至项目根目录：`./SecSearch_test`  
SM4算法性能测试可执行文件输出至项目根目录：`./SecSearch_SM4test`

### 3. 初始化数据库

```bash
mysql -u root -p < create_table.sql
```

> ⚠️ `create_table.sql` 末尾包含清空所有表的 TRUNCATE 语句，首次执行无影响，后续请勿在有数据的库中直接运行。

### 4. 生成主密钥 (KEK)

```bash
mkdir -p ~/.secsearch
openssl rand -hex 16 > ~/.secsearch/kek.key
chmod 600 ~/.secsearch/kek.key
```

> ⚠️ 密钥文件丢失将无法解密数据，请妥善保管。

KEK 搜索路径（按优先级）：
1. `/etc/secsearch/kek.key`
2. `/usr/local/etc/secsearch/kek.key`
3. `~/.secsearch/kek.key`
4. `./kek.key`
5. `./.kek.key`

### 5. 运行

```bash
./SecSearch
```

启动后按提示输入数据库连接信息即可进入交互式 CLI。

## 数据库表结构

| 表名 | 用途 |
|------|------|
| `sensitive_data` | 主数据表，存储 SM4 密文、盲索引、完整性 Tag |
| `fuzzy_inverted` | 模糊查询倒排索引表，Bigram 分词的 HMAC-SM3 盲哈希 |
| `key_config` | 密钥配置表，工作密钥经 KEK 加密后持久化 |
| `audit_log` | 审计日志表，记录所有操作及耗时 |
| `decrypt_error_log` | 解密错误记录表，追踪失败记录 |
| `index_rebuild_task` | 索引重建任务表，支持断点续跑 |

## 密码学设计

| 模块 | 算法 | 说明 |
|------|------|------|
| 字段加密 | SM4-CBC + PKCS7 | 128bit 密钥，每条记录独立 IV |
| 完整性校验 | HMAC-SM3 | 256bit Tag，解密前强制校验 |
| 精确索引 | HMAC-SM3 | 索引密钥独立，不可逆推明文 |
| 模糊索引 | Bigram + HMAC-SM3 | 分词后逐片段盲哈希，倒排存储 |

### 密钥体系

| 密钥类型 | 用途 | 轮换影响 |
|----------|------|----------|
| KEK 主密钥 | 加密保护工作密钥 | 需重新加密所有工作密钥 |
| 加密密钥 | 字段 SM4 加密 | 旧数据仍可用旧版本解密 |
| 索引密钥 | 盲索引生成 | 多版本自动匹配，历史数据可查 |
| Tag 密钥 | 完整性校验 | 旧 Tag 仍可验证 |

默认自动轮换周期：90 天

## License

本项目仅供学习研究使用。OpenHiTLS 库遵循其自身开源协议。


本项目仅供学习研究使用。OpenHiTLS 库遵循其自身开源协议。
