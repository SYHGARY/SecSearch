// utils.h
// 功能：提供 Base64 编解码、十六进制字符串与二进制互转等基础工具
// 依赖：GmSSL 的 base64.h

#pragma once

#include <string>
#include <vector>

namespace crypto {

// Base64 编码：将二进制数据转换为 Base64 字符串
std::string base64Encode(const std::vector<unsigned char>& data);

// Base64 解码：将 Base64 字符串还原为二进制数据
std::vector<unsigned char> base64Decode(const std::string& base64);

// 二进制转十六进制字符串（小写）
std::string binToHex(const unsigned char* data, size_t len);

// 十六进制字符串转二进制（支持大小写）
std::vector<unsigned char> hexToBin(const std::string& hex);

} // namespace crypto