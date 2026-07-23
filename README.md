# 🔐 SecSearch in Linux

基于国密算法（SM4/SM3）的敏感字段加密存储与密文检索系统，支持精确匹配与模糊搜索。

## ✨ 核心特性

- **国密加密**：基于 OpenHiTLS 实现 SM4-CBC 加密，SM3 哈希
- **三密钥分离**：加密密钥、索引密钥、完整性校验密钥独立管理
- **盲索引精确查询**：基于 HMAC-SM3 的盲索引，支持高效等值查询
- **Bigram 倒排模糊查询**：支持中文/数字中缀模糊匹配
- **密钥版本管理**：支持密钥平滑轮换，历史数据自动匹配对应版本
- **完整性校验**：密文 Tag 防篡改
- **交互式命令行**：友好的 CLI 菜单，支持增删改查

## 🛠 技术栈

- C++20
- OpenHiTLS（国密算法库）
- MySQL 8.0
- CMake

## 🚀 快速开始

### 环境要求

- GCC 9+ / Clang 11+
- CMake 3.16+
- MySQL 8.0+
- OpenSSL（MySQL 依赖）


### 编译

```bash
git clone https://github.com/SYHGARY/SecSearch.git
cd SecSearch
mkdir build && cd build
cmake ..
make -j
```

### 创建MySQL数据库与表单

```sql
source SecSearch/create_table.sql;
```
