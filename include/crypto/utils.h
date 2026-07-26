// utils.h
// 功能：Base64 编解码、十六进制转换、密钥文件读取

#pragma once

#include <string>
#include <vector>

namespace crypto {

// ---- Base64 编解码 ----
std::string base64Encode(const std::vector<unsigned char>& data);
std::vector<unsigned char> base64Decode(const std::string& base64);

// ---- 十六进制转换 ----
std::string binToHex(const unsigned char* data, size_t len);
std::vector<unsigned char> hexToBin(const std::string& hex);

// ---- ★ 从文件读取十六进制密钥 ----
// 参数：文件路径
// 返回：16 字节密钥
// 异常：文件不存在、内容格式错误、长度不正确时抛出 std::runtime_error
std::vector<unsigned char> readKeyFromFile(const std::string& filepath);

} // namespace crypto