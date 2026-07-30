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

# ---- 依赖查找 ----
find_path(MYSQL_INCLUDE_DIR NAMES mysql/mysql.h PATHS /usr/include /usr/local/include)
find_library(MYSQL_LIBRARY NAMES mysqlclient mysql PATHS /usr/lib /usr/lib/x86_64-linux-gnu /usr/local/lib)

find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)
find_library(ZSTD_LIBRARY NAMES zstd PATHS /usr/lib /usr/lib/x86_64-linux-gnu)

find_library(BOUNDSCHECK_LIBRARY NAMES boundscheck PATHS ${CMAKE_SOURCE_DIR}/lib)
# ★ 关键修正：如果未找到，置空，避免链接时引用无效路径
if(BOUNDSCHECK_LIBRARY AND BOUNDSCHECK_LIBRARY MATCHES "-NOTFOUND$")
    set(BOUNDSCHECK_LIBRARY "")
endif()

find_path(HITLS_INCLUDE_DIR NAMES hitls/crypto/crypt_eal_cipher.h PATHS ${CMAKE_SOURCE_DIR}/include /usr/local/include /usr/include)
find_library(HITLS_CRYPTO_LIBRARY NAMES hitls_crypto PATHS ${CMAKE_SOURCE_DIR}/lib /usr/local/lib /usr/lib)
find_library(HITLS_BSL_LIBRARY NAMES hitls_bsl PATHS ${CMAKE_SOURCE_DIR}/lib /usr/local/lib /usr/lib)

# ---- 公共源码 ----
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

# ---- 主程序 ----
add_executable(SecSearch src/main.cpp)

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

target_link_libraries(SecSearch secsearch_common ${LINK_LIBS})

# ---- 测试程序 ----
add_executable(SecSearch_test src/secsearch_test.cpp)
target_link_libraries(SecSearch_test secsearch_common ${LINK_LIBS})

# ---- 配置检查 ----
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
message(STATUS "========================================")
