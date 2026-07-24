# SecSearch - 数据库密文检索系统

基于国密算法的**加密数据库全文检索系统**，采用 SM4-CBC 加密 + HMAC-SM3 完整性校验 + 盲索引方案，实现密文状态下的精确查询与模糊查询。支持密钥多版本管理、自动轮换、数据库持久化等企业级特性。

---

## ✨ 功能特性

### 核心功能
- **字段级加密存储**：姓名、电话、地址等敏感字段独立加密存储
- **密文精确查询**：基于盲索引的等值查询，无需解密即可定位记录
- **密文模糊查询**：支持 N-gram 分词的模糊匹配，密文状态下完成检索
- **完整性校验**：每条密文附带 HMAC-SM3 标签，防止篡改
- **密钥多版本管理**：加密密钥、索引密钥、标签密钥三套独立版本链
- **密钥自动轮换**：支持 90 天自动轮换策略，向前兼容历史数据
- **数据库持久化**：密钥版本与状态持久化到 MySQL，支持多实例部署

### 工程特性
- **连接池**：自研 MySQL 连接池，线程安全，支持 RAII 自动归还
- **事务支持**：数据库操作支持事务回滚
- **跨平台**：支持 Linux / WSL / Windows 编译
- **性能基准测试**：内置 benchmark 测试程序，量化加解密与查询性能

---

## 🏗️ 系统架构

```
┌─────────────────────────────────────────────────┐
│                  应用层 (main)                   │
│        交互式 CLI / 增删改查 / 密钥管理          │
├─────────────────────────────────────────────────┤
│  查询服务层       │       加密服务层             │
│  QueryService    │    CryptoService             │
│  精确/模糊查询    │    SM4 加密 / HMAC 校验      │
├──────────────────┴──────────────────────────────┤
│              数据访问层 (DAO)                    │
│         连接池 / 事务 / SQL 封装                 │
├─────────────────────────────────────────────────┤
│              密钥管理层                          │
│  KeyManager - 多版本 / 轮换 / 持久化             │
├─────────────────────────────────────────────────┤
│              密码学底座                          │
│  OpenHiTLS - SM4 / SM3 国密算法实现              │
└─────────────────────────────────────────────────┘
```

---

## 📁 目录结构

```
SecSearch-Linux/
├── include/                    # 头文件
│   ├── crypto/                 # 加密模块
│   │   ├── crypto_service.h    # 加密服务统一入口
│   │   ├── key_manager.h       # 密钥管理器
│   │   ├── sm4_cipher.h        # SM4 加密封装
│   │   ├── hmac_sm3.h          # HMAC-SM3 封装
│   │   └── utils.h             # 工具函数
│   ├── database/               # 数据库模块
│   │   ├── connection_pool.h   # 连接池
│   │   ├── dao.h               # 数据访问对象
│   │   └── transaction.h       # 事务
│   ├── query/                  # 查询模块
│   │   └── query_service.h     # 查询服务
│   ├── hitls/                  # OpenHiTLS 头文件
│   └── mysql/                  # MySQL 头文件
├── src/                        # 源文件
│   ├── main.cpp                # 主程序入口
│   ├── crypto/                 # 加密模块实现
│   ├── database/               # 数据库模块实现
│   ├── query/                  # 查询模块实现
│   └── tests/                  # 测试程序
│       └── benchmark_test.cpp  # 性能基准测试
├── lib/                        # 第三方静态库
│   ├── libhitls_crypto.a
│   ├── libhitls_bsl.a
│   └── libmysqlclient.a
└── CMakeLists.txt              # CMake 构建配置

```

---

## 🔧 环境要求

| 依赖 | 版本要求 | 说明 |
|------|----------|------|
| 操作系统 | Linux / WSL (Ubuntu 20.04+) | Windows 需使用 WSL |
| GCC | 10+ | 支持 C++20 |
| CMake | 3.16+ | 构建工具 |
| MySQL | 5.7+ / 8.0+ | 数据库服务端 |
| OpenSSL | 1.1+ | MySQL 客户端依赖 |
| ZLIB | 1.2+ | MySQL 客户端依赖 |
| ZSTD | 1.4+ | MySQL 客户端依赖 |
| OpenHiTLS | - | 已随项目提供静态库 |

---

## 📦 依赖安装

### Ubuntu / Debian / WSL

```bash
# 更新软件源
sudo apt update

# 安装编译工具链
sudo apt install -y build-essential cmake g++ make

# 安装 MySQL 客户端开发库
sudo apt install -y libmysqlclient-dev

# 安装加密与压缩库
sudo apt install -y libssl-dev zlib1g-dev libzstd-dev

# 验证安装
g++ --version    # 需 >= 10
cmake --version  # 需 >= 3.16
```

### CentOS / RHEL

```bash
sudo yum groupinstall "Development Tools"
sudo yum install cmake mysql-devel openssl-devel zlib-devel libzstd-devel
```

---

## 🗄️ 数据库初始化

### 1. 创建数据库

```sql
source SecSearch/create_table.sql;
```
---

## 🚀 编译构建

### 方式一：CMake 构建（推荐）

```bash
# 进入项目目录
cd SecSearch-Linux

# 创建构建目录
mkdir build && cd build

# 配置项目
cmake .. -DCMAKE_BUILD_TYPE=Release

# 编译（-j 后接 CPU 核心数）
make -j$(nproc)
```

编译成功后，项目根目录会生成两个可执行文件：
- `SecSearch` - 主程序（交互式命令行）
- `benchmark_test` - 性能基准测试

**构建选项：**
```bash
# Debug 模式（含调试符号，无优化）
cmake .. -DCMAKE_BUILD_TYPE=Debug

# Release 模式（O2 优化）
cmake .. -DCMAKE_BUILD_TYPE=Release
```

### 方式二：VS Code 编译

1. 在 WSL 环境中用 VS Code 打开项目
2. 按 `Ctrl+Shift+B`，选择 **SecSearch: g++ 编译全部**
3. 编译产物输出到项目根目录

### 方式三：直接 g++ 编译

```bash
g++ -std=c++20 -O2 -Wall \
    src/main.cpp \
    src/crypto/*.cpp \
    src/database/*.cpp \
    src/query/*.cpp \
    -I include \
    -L lib \
    -lhitls_crypto -lhitls_bsl -lmysqlclient \
    -lssl -lcrypto -lzstd -lz -lpthread -ldl \
    -o SecSearch
```

---

## ⚙️ 配置说明

### 数据库连接配置

在 `src/main.cpp` 中修改数据库连接参数：

```cpp
// 数据库配置
const std::string DB_HOST = "127.0.0.1";
const std::string DB_USER = "root";
const std::string DB_PASS = "your_password";
const std::string DB_NAME = "secsearch";
const unsigned int DB_PORT = 3306;
const size_t POOL_SIZE = 10;  // 连接池大小
```

### 密钥轮换配置

```cpp
const int AUTO_ROTATE_DAYS = 90;        // 自动轮换周期（天）
const std::string ROTATE_TIME_FILE = ".key_rotate_time";  // 轮换时间记录文件
```

### 主密钥配置

程序启动时会要求输入主密钥（Master Key），用于加密保护数据密钥。主密钥派生自用户输入的密码，**请妥善保管，丢失将无法解密数据**。

---

## 🔐 密码学设计

### 加密方案
- **算法**：SM4-CBC 模式，PKCS7 填充
- **密钥长度**：128 bit
- **IV**：每条记录独立随机生成，附在密文前

### 完整性保护
- **算法**：HMAC-SM3
- **标签长度**：256 bit（64 字符十六进制）
- **作用**：防止密文被篡改，解密前强制校验

### 盲索引方案
- **精确查询**：对明文直接计算 HMAC 作为索引值
- **模糊查询**：N-gram 分词后分别计算 HMAC，多标签匹配
- **安全性**：索引密钥独立于加密密钥，无法从索引反推明文

### 密钥体系
| 密钥类型 | 用途 | 轮换影响 |
|----------|------|----------|
| 主密钥 Master Key | 保护数据密钥 | 需解密重加密所有密钥 |
| 加密密钥 Enc Key | 字段数据加密 | 旧数据仍可用旧版本解密 |
| 索引密钥 Idx Key | 盲索引生成 | 需重建所有盲索引 |
| 标签密钥 Tag Key | HMAC 完整性校验 | 需重新计算所有标签 |

---

## 📄 License

本项目仅供学习研究使用。OpenHiTLS 库遵循其自身开源协议。

---

## 🤝 相关参考

- [OpenHiTLS 官方文档](https://gitee.com/openhitls/openhitls)
