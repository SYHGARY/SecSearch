cmake_minimum_required(VERSION 3.16)
project(SecSearch VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -Wall -Wextra")
set(CMAKE_CXX_FLAGS_RELEASE "-O2 -Wall -DNDEBUG")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR})

# ============================================================
# 依赖库查找（优先使用项目内 lib/ 和 include/）
# ============================================================

# ---- MySQL ----
find_path(MYSQL_INCLUDE_DIR NAMES mysql/mysql.h
    PATHS /usr/include /usr/local/include
)
find_library(MYSQL_LIBRARY NAMES mysqlclient mysql
    PATHS /usr/lib /usr/lib/x86_64-linux-gnu /usr/local/lib
)

# ---- OpenSSL ----
find_package(OpenSSL REQUIRED)

# ---- ZLIB ----
find_package(ZLIB REQUIRED)

# ---- ZSTD ----
find_library(ZSTD_LIBRARY NAMES zstd
    PATHS /usr/lib /usr/lib/x86_64-linux-gnu
)

# ---- boundscheck（可选） ----
find_library(BOUNDSCHECK_LIBRARY NAMES boundscheck
    PATHS ${CMAKE_SOURCE_DIR}/lib
          /usr/local/lib /usr/lib
)
if(BOUNDSCHECK_LIBRARY AND BOUNDSCHECK_LIBRARY MATCHES "-NOTFOUND$")
    set(BOUNDSCHECK_LIBRARY "")
endif()

# ---- ★ OpenHiTLS（优先项目内 lib/） ----
find_path(HITLS_INCLUDE_DIR NAMES hitls/crypto/crypt_eal_cipher.h
    PATHS ${CMAKE_SOURCE_DIR}/include
          /usr/local/include /usr/include
)
find_library(HITLS_CRYPTO_LIBRARY NAMES hitls_crypto
    PATHS ${CMAKE_SOURCE_DIR}/lib
          /usr/local/lib /usr/lib
)
find_library(HITLS_BSL_LIBRARY NAMES hitls_bsl
    PATHS ${CMAKE_SOURCE_DIR}/lib
          /usr/local/lib /usr/lib
)

# ---- ★ GmSSL（可选，用于 SecSearch_SM4test，优先项目内） ----
find_path(GMSSL_INCLUDE_DIR NAMES gmssl/sm4.h
    PATHS ${CMAKE_SOURCE_DIR}/include
          /usr/local/gmssl/include
          /usr/local/include /usr/include
)
find_library(GMSSL_LIBRARY NAMES gmssl
    PATHS ${CMAKE_SOURCE_DIR}/lib
          /usr/local/gmssl/lib
          /usr/local/lib /usr/lib
)
if(GMSSL_INCLUDE_DIR AND GMSSL_LIBRARY)
    message(STATUS "GmSSL found: ${GMSSL_INCLUDE_DIR}")
else()
    message(WARNING "GmSSL not found. SecSearch_SM4test will not be built.")
endif()

# ============================================================
# 公共源码库
# ============================================================
set(COMMON_SRC
    src/crypto/utils.cpp
    src/crypto/sm4_cipher.cpp
    src/crypto/sm3_hash.cpp
    src/crypto/key_manager.cpp
    src/database/connection_pool.cpp
    src/database/transaction.cpp
    src/database/dao.cpp
    src/query/query_service.cpp
    src/decrypt/batch_decryptor.cpp
    src/audit/audit_logger.cpp
    src/audit/index_rebuilder.cpp
)
add_library(secsearch_common OBJECT ${COMMON_SRC})
target_include_directories(secsearch_common PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${MYSQL_INCLUDE_DIR}
    ${HITLS_INCLUDE_DIR}
)

# ============================================================
# 链接库列表
# ============================================================
set(LINK_LIBS
    ${HITLS_CRYPTO_LIBRARY}
    ${HITLS_BSL_LIBRARY}
    ${MYSQL_LIBRARY}
    OpenSSL::SSL
    OpenSSL::Crypto
    ZLIB::ZLIB
    ${ZSTD_LIBRARY}
    pthread
    dl
)
if(BOUNDSCHECK_LIBRARY)
    list(APPEND LINK_LIBS ${BOUNDSCHECK_LIBRARY})
endif()

# ============================================================
# 主程序
# ============================================================
add_executable(SecSearch src/main.cpp)
target_link_libraries(SecSearch secsearch_common ${LINK_LIBS})

# ============================================================
# 测试程序
# ============================================================
add_executable(SecSearch_test src/SecSearch_test.cpp)
target_link_libraries(SecSearch_test secsearch_common ${LINK_LIBS})

# ============================================================
# ★ OpenHiTLS vs GmSSL 性能对比测试
# ============================================================
if(GMSSL_INCLUDE_DIR AND GMSSL_LIBRARY)
    add_executable(SecSearch_SM4test src/SecSearch_SM4test.cpp)
    target_include_directories(SecSearch_SM4test PRIVATE
        ${GMSSL_INCLUDE_DIR}
        ${HITLS_INCLUDE_DIR}
    )
    target_link_libraries(SecSearch_SM4test
        ${HITLS_CRYPTO_LIBRARY}
        ${HITLS_BSL_LIBRARY}
        ${GMSSL_LIBRARY}
        pthread
        dl
    )
    if(BOUNDSCHECK_LIBRARY)
        target_link_libraries(SecSearch_SM4test ${BOUNDSCHECK_LIBRARY})
    endif()

    # ★ GmSSL串行 vs OpenHiTLS流水线 解密+HMAC校验 性能对比（使用MySQL）
    add_executable(SecSearch_PerfCompare src/SecSearch_PerfCompare.cpp)
    target_include_directories(SecSearch_PerfCompare PRIVATE
        ${GMSSL_INCLUDE_DIR}
        ${HITLS_INCLUDE_DIR}
        ${CMAKE_SOURCE_DIR}/include
        ${MYSQL_INCLUDE_DIR}
    )
    target_link_libraries(SecSearch_PerfCompare
        secsearch_common
        ${HITLS_CRYPTO_LIBRARY}
        ${HITLS_BSL_LIBRARY}
        ${GMSSL_LIBRARY}
        ${MYSQL_LIBRARY}
        OpenSSL::SSL
        OpenSSL::Crypto
        ZLIB::ZLIB
        ${ZSTD_LIBRARY}
        pthread
        dl
    )
    if(BOUNDSCHECK_LIBRARY)
        target_link_libraries(SecSearch_PerfCompare ${BOUNDSCHECK_LIBRARY})
    endif()
endif()

# ============================================================
# 配置检查
# ============================================================
if(NOT BOUNDSCHECK_LIBRARY)
    message(WARNING "boundscheck library not found. If you see undefined references to __security_check_cookie or memcpy_s, please install libboundscheck.")
endif()
if(NOT HITLS_CRYPTO_LIBRARY OR NOT HITLS_BSL_LIBRARY)
    message(FATAL_ERROR "OpenHiTLS libraries not found.")
endif()

message(STATUS "===== SecSearch Build Configuration =====")
message(STATUS "Build type:    ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ standard:  ${CMAKE_CXX_STANDARD}")
message(STATUS "MySQL include: ${MYSQL_INCLUDE_DIR}")
message(STATUS "MySQL library: ${MYSQL_LIBRARY}")
message(STATUS "OpenHiTLS inc: ${HITLS_INCLUDE_DIR}")
message(STATUS "OpenHiTLS crypto: ${HITLS_CRYPTO_LIBRARY}")
message(STATUS "OpenHiTLS bsl:    ${HITLS_BSL_LIBRARY}")
if(GMSSL_INCLUDE_DIR)
    message(STATUS "GmSSL include: ${GMSSL_INCLUDE_DIR}")
    message(STATUS "GmSSL library: ${GMSSL_LIBRARY}")
endif()
message(STATUS "========================================")
