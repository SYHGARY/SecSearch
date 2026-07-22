// utils.h
// 功能：Base64 编解码、十六进制转换

#pragma once

#include <string>
#include <vector>

namespace crypto {

// Base64 编码
std::string base64Encode(const std::vector<unsigned char>& data);

// Base64 解码
std::vector<unsigned char> base64Decode(const std::string& base64);

// 二进制转十六进制（小写）
std::string binToHex(const unsigned char* data, size_t len);

// 十六进制转二进制
std::vector<unsigned char> hexToBin(const std::string& hex);

} // namespace crypto