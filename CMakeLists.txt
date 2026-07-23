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

# ---- 设置可执行文件输出目录 ----
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/SecSearch)

# ---- 查找依赖库 ----

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
    PATHS
        ${CMAKE_SOURCE_DIR}/lib
        /home/songyihang/openhitls/platform/Secure_C/build
        /home/songyihang/libboundscheck/build
)

# 6. OpenHiTLS
find_path(HITLS_INCLUDE_DIR
    NAMES hitls/crypt_eal_cipher.h
    PATHS
        ${CMAKE_SOURCE_DIR}/hits
        /usr/local/include
        /usr/include
)

find_library(HITLS_CRYPTO_LIBRARY
    NAMES hitls_crypto
    PATHS
        ${CMAKE_SOURCE_DIR}/lib
        /usr/local/lib
        /usr/lib
)

find_library(HITLS_BSL_LIBRARY
    NAMES hitls_bsl
    PATHS
        ${CMAKE_SOURCE_DIR}/lib
        /usr/local/lib
        /usr/lib
)

# ---- 包含目录 ----
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/hits
    ${MYSQL_INCLUDE_DIR}
    ${HITLS_INCLUDE_DIR}
)

# ---- 收集源文件 ----
set(SRC_FILES
    src/main.cpp
    src/crypto/utils.cpp
    src/crypto/sm4_cipher.cpp
    src/crypto/sm3_hash.cpp
    src/crypto/key_manager.cpp
    src/crypto/crypto_service.cpp
    src/database/connection_pool.cpp
    src/database/transaction.cpp
    src/database/dao.cpp
    src/query/query_service.cpp
)

# ---- 生成可执行文件 ----
add_executable(SecSearch ${SRC_FILES})

# ---- 链接库 ----
target_link_libraries(SecSearch
    ${HITLS_CRYPTO_LIBRARY}
    ${HITLS_BSL_LIBRARY}
    ${BOUNDSCHECK_LIBRARY}
    ${MYSQL_LIBRARY}
    ${OPENSSL_LIBRARIES}
    ${ZLIB_LIBRARIES}
    ${ZSTD_LIBRARY}
    pthread
    dl
)

# ---- 如果找不到 boundscheck，给出提示但不中断 ----
if(NOT BOUNDSCHECK_LIBRARY)
    message(WARNING "boundscheck library not found. If you see undefined references to __security_check_cookie or memcpy_s, please install libboundscheck.")
endif()

# ---- 如果找不到 OpenHiTLS，报错 ----
if(NOT HITLS_CRYPTO_LIBRARY OR NOT HITLS_BSL_LIBRARY)
    message(FATAL_ERROR "OpenHiTLS libraries not found. Please check HITLS_CRYPTO_LIBRARY and HITLS_BSL_LIBRARY paths.")
endif()

# ---- 打印配置信息 ----
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "MySQL include: ${MYSQL_INCLUDE_DIR}")
message(STATUS "MySQL library: ${MYSQL_LIBRARY}")
message(STATUS "OpenHiTLS include: ${HITLS_INCLUDE_DIR}")
message(STATUS "OpenHiTLS crypto: ${HITLS_CRYPTO_LIBRARY}")
message(STATUS "OpenHiTLS bsl: ${HITLS_BSL_LIBRARY}")
