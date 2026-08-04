// benchmark_sm4.cpp
// OpenHiTLS vs GmSSL SM4-CBC 性能对比测试

#include <iostream>
#include <chrono>
#include <vector>
#include <iomanip>
#include <cstring>

// OpenHiTLS
#include <hitls/crypto/crypt_eal_cipher.h>
#include <hitls/crypto/crypt_eal_rand.h>
#include <hitls/crypto/crypt_eal_init.h>

// GmSSL
#include <gmssl/sm4.h>

using namespace std;

const int DATA_SIZE = 1024;        // 1KB (必须是16的倍数)
const int TOTAL_OPS = 100000;      // 总操作次数
const int WARMUP_OPS = 1000;       // 预热次数

// ---- OpenHiTLS 测试 ----
double benchmarkOpenHiTLS() {
    unsigned char key[16], iv[16];
    CRYPT_EAL_Randbytes(key, 16);
    CRYPT_EAL_Randbytes(iv, 16);

    vector<unsigned char> plaintext(DATA_SIZE, 'A');
    vector<unsigned char> ciphertext(DATA_SIZE + 16);

    // 预热
    for (int i = 0; i < WARMUP_OPS; i++) {
        CRYPT_EAL_CipherCtx* ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_SM4_CBC);
        CRYPT_EAL_CipherInit(ctx, key, 16, iv, 16, true);
        uint32_t outLen = DATA_SIZE + 16;
        CRYPT_EAL_CipherUpdate(ctx, plaintext.data(), DATA_SIZE, ciphertext.data(), &outLen);
        CRYPT_EAL_CipherFinal(ctx, ciphertext.data() + outLen, &outLen);
        CRYPT_EAL_CipherFreeCtx(ctx);
    }

    auto start = chrono::high_resolution_clock::now();
    for (int i = 0; i < TOTAL_OPS; i++) {
        CRYPT_EAL_CipherCtx* ctx = CRYPT_EAL_CipherNewCtx(CRYPT_CIPHER_SM4_CBC);
        CRYPT_EAL_CipherInit(ctx, key, 16, iv, 16, true);
        uint32_t outLen = DATA_SIZE + 16;
        CRYPT_EAL_CipherUpdate(ctx, plaintext.data(), DATA_SIZE, ciphertext.data(), &outLen);
        CRYPT_EAL_CipherFinal(ctx, ciphertext.data() + outLen, &outLen);
        CRYPT_EAL_CipherFreeCtx(ctx);
    }
    auto end = chrono::high_resolution_clock::now();
    double ms = chrono::duration<double, milli>(end - start).count();
    double throughput = (TOTAL_OPS * DATA_SIZE) / (ms / 1000.0) / 1024 / 1024;
    cout << "    OpenHiTLS: " << fixed << setprecision(2) << ms << " ms, "
         << setprecision(2) << throughput << " MB/s" << endl;
    return ms;
}

// ---- GmSSL 测试 ----
double benchmarkGmSSL() {
    SM4_KEY sm4_key;
    unsigned char key[16], iv[16];

    // 用固定值初始化（避免随机数生成依赖）
    memset(key, 0x01, 16);
    memset(iv, 0x02, 16);
    sm4_set_encrypt_key(&sm4_key, key);

    vector<unsigned char> plaintext(DATA_SIZE, 'A');
    vector<unsigned char> ciphertext(DATA_SIZE);

    // 预热
    for (int i = 0; i < WARMUP_OPS; i++) {
        uint8_t iv_copy[16];
        memcpy(iv_copy, iv, 16);
        sm4_cbc_encrypt_blocks(&sm4_key, iv_copy,
            plaintext.data(), DATA_SIZE / 16, ciphertext.data());
    }

    auto start = chrono::high_resolution_clock::now();
    for (int i = 0; i < TOTAL_OPS; i++) {
        uint8_t iv_copy[16];
        memcpy(iv_copy, iv, 16);
        sm4_cbc_encrypt_blocks(&sm4_key, iv_copy,
            plaintext.data(), DATA_SIZE / 16, ciphertext.data());
    }
    auto end = chrono::high_resolution_clock::now();
    double ms = chrono::duration<double, milli>(end - start).count();
    double throughput = (TOTAL_OPS * DATA_SIZE) / (ms / 1000.0) / 1024 / 1024;
    cout << "    GmSSL: " << fixed << setprecision(2) << ms << " ms, "
         << setprecision(2) << throughput << " MB/s" << endl;
    return ms;
}

int main() {
    CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);

    cout << "\n╔════════════════════════════════════════════════════════════╗" << endl;
    cout << "║        SM4-CBC 性能对比: OpenHiTLS vs GmSSL                ║" << endl;
    cout << "║  数据块: " << DATA_SIZE << " 字节, 操作次数: " << TOTAL_OPS << " (预热 " << WARMUP_OPS << " 次)" << endl;
    cout << "╚════════════════════════════════════════════════════════════╝" << endl;

    // 跑3轮取平均
    double hitls_sum = 0, gmssl_sum = 0;
    for (int round = 0; round < 3; round++) {
        cout << "\n📊 第 " << round + 1 << " 轮:" << endl;
        gmssl_sum += benchmarkGmSSL();
        hitls_sum += benchmarkOpenHiTLS();
    }

    double hitls_avg = hitls_sum / 3;
    double gmssl_avg = gmssl_sum / 3;
    double improvement = (gmssl_avg - hitls_avg) / gmssl_avg * 100;

    cout << "\n════════════════════════════════════════════════════════════" << endl;
    cout << "📈 平均结果:" << endl;
    cout << "   GmSSL 平均:    " << fixed << setprecision(2) << gmssl_avg << " ms" << endl;
    cout << "   OpenHiTLS 平均: " << setprecision(2) << hitls_avg << " ms" << endl;
    cout << "   提升:          +" << setprecision(2) << improvement << "%" << endl;
    cout << "════════════════════════════════════════════════════════════" << endl;

    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_ALL);
    return 0;
}