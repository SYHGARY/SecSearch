cmake_minimum_required(VERSION 3.16)
project(SecSearch VERSION 1.0.0 LANGUAGES CXX)

# ---- C++ 标准 ----
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---- 构建类型（默认 Debug） ----
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

# ---- 编译选项 ----
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -Wall -Wextra")
set(CMAKE_CXX_FLAGS_RELEASE "-O2 -Wall -DNDEBUG")

# ---- 可执行文件输出到项目根目录 ----
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR})

# ========== 依赖库查找 ==========

# 1. MySQL
find_path(MYSQL_INCLUDE_DIR
    NAMES mysql/mysql.h
    PATHS /usr/include /usr/local/include
)
find_library(MYSQL_LIBRARY
    NAMES mysqlclient mysql
    PATHS /usr/lib /usr/lib/x86_64-linux-gnu /usr/local/lib
)

# 2. OpenSSL (MySQL 依赖)
find_package(OpenSSL REQUIRED)

# 3. ZLIB (MySQL 依赖)
find_package(ZLIB REQUIRED)

# 4. ZSTD (MySQL 依赖)
find_library(ZSTD_LIBRARY
    NAMES zstd
    PATHS /usr/lib /usr/lib/x86_64-linux-gnu
)

# 5. boundscheck (OpenHiTLS 依赖，可选)
find_library(BOUNDSCHECK_LIBRARY
    NAMES boundscheck
    PATHS ${CMAKE_SOURCE_DIR}/lib
)

# 6. OpenHiTLS
find_path(HITLS_INCLUDE_DIR
    NAMES hitls/crypto/crypt_eal_cipher.h
    PATHS ${CMAKE_SOURCE_DIR}/include /usr/local/include /usr/include
)

find_library(HITLS_CRYPTO_LIBRARY
    NAMES hitls_crypto
    PATHS ${CMAKE_SOURCE_DIR}/lib /usr/local/lib /usr/lib
)

find_library(HITLS_BSL_LIBRARY
    NAMES hitls_bsl
    PATHS ${CMAKE_SOURCE_DIR}/lib /usr/local/lib /usr/lib
)

# ========== 公共源码库（避免重复编译） ==========
set(COMMON_SRC
    src/crypto/utils.cpp
    src/crypto/sm4_cipher.cpp
    src/crypto/sm3_hash.cpp
    src/crypto/key_manager.cpp
    src/crypto/crypto_service.cpp
    src/database/connection_pool.cpp
    src/database/transaction.cpp
    src/database/dao.cpp
    src/query/query_service.cpp
    src/decrypt/batch_decryptor.cpp
)

add_library(secsearch_common OBJECT ${COMMON_SRC})

target_include_directories(secsearch_common PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${MYSQL_INCLUDE_DIR}
    ${HITLS_INCLUDE_DIR}
)

# ========== 主程序 ==========
add_executable(SecSearch src/main.cpp)

target_link_libraries(SecSearch
    secsearch_common
    ${HITLS_CRYPTO_LIBRARY}
    ${HITLS_BSL_LIBRARY}
    ${BOUNDSCHECK_LIBRARY}
    ${MYSQL_LIBRARY}
    OpenSSL::SSL
    OpenSSL::Crypto
    ZLIB::ZLIB
    ${ZSTD_LIBRARY}
    pthread
    dl
)

# ========== 性能测试程序 ==========
add_executable(benchmark_test src/tests/benchmark_test.cpp)

target_link_libraries(benchmark_test
    secsearch_common
    ${HITLS_CRYPTO_LIBRARY}
    ${HITLS_BSL_LIBRARY}
    ${BOUNDSCHECK_LIBRARY}
    ${MYSQL_LIBRARY}
    OpenSSL::SSL
    OpenSSL::Crypto
    ZLIB::ZLIB
    ${ZSTD_LIBRARY}
    pthread
    dl
)

# ========== 配置检查与提示 ==========
if(NOT BOUNDSCHECK_LIBRARY)
    message(WARNING "boundscheck library not found. If you see undefined references to __security_check_cookie or memcpy_s, please install libboundscheck.")
endif()

if(NOT HITLS_CRYPTO_LIBRARY OR NOT HITLS_BSL_LIBRARY)
    message(FATAL_ERROR "OpenHiTLS libraries not found. Please check HITLS_CRYPTO_LIBRARY and HITLS_BSL_LIBRARY paths.")
endif()

# ========== 打印配置摘要 ==========
message(STATUS "===== SecSearch Build Configuration =====")
message(STATUS "Build type:    ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ standard:  ${CMAKE_CXX_STANDARD}")
message(STATUS "MySQL include: ${MYSQL_INCLUDE_DIR}")
message(STATUS "MySQL library: ${MYSQL_LIBRARY}")
message(STATUS "OpenHiTLS inc: ${HITLS_INCLUDE_DIR}")
message(STATUS "OpenHiTLS crypto: ${HITLS_CRYPTO_LIBRARY}")
message(STATUS "OpenHiTLS bsl:    ${HITLS_BSL_LIBRARY}")
message(STATUS "========================================")
