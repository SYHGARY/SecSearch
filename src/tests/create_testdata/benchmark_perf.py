"""
SecSearch 性能基准测试脚本
===========================
验证三大性能指标:
  1. 千条数据精确查询平均时延 < 100ms
  2. 千条数据模糊搜索平均时延 < 500ms
  3. 万条数据批量解密吞吐量较串行提升 > 50%

使用方式:
    # 完整性能测试
    python create_testdata/benchmark_perf.py

    # 仅测试精确查询
    python create_testdata/benchmark_perf.py --test exact

    # 指定测试样本数
    python create_testdata/benchmark_perf.py --samples 100

    # 批量解密并发线程数
    python create_testdata/benchmark_perf.py --decrypt-threads 8
"""

import os
import sys
import time
import random
import argparse
import importlib.util
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# 依赖检测
_PYMYSQL_OK = importlib.util.find_spec("pymysql") is not None
_GMSSL_OK = importlib.util.find_spec("gmssl") is not None

if not _PYMYSQL_OK or not _GMSSL_OK:
    missing = []
    if not _PYMYSQL_OK:
        missing.append("pymysql")
    if not _GMSSL_OK:
        missing.append("gmssl")
    print("缺少依赖: " + ", ".join(missing))
    print("请先运行: pip install " + " ".join(missing))
    sys.exit(1)

import pymysql
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT
from gmssl import sm3, func

# ============================================================
# 配置
# ============================================================
DB_CONFIG = {
    "host": "127.0.0.1",
    "port": 3306,
    "user": "root",
    "password": "Lwc20041125",
    "database": "secsearch",
    "charset": "utf8mb4",
}

RAW_ENC_KEY = bytes([0xA0] * 16)
RAW_IDX_KEY = bytes([0xB0] * 16)
RAW_TAG_KEY = bytes([0xC0] * 16)

_SM3_BLOCK_SIZE = 64

_ID_RANGE_FILE = os.path.join(os.path.dirname(__file__), ".benchmark_id_range")


# ============================================================
# 工具函数
# ============================================================
def _sm3_hash_bytes(data: bytes) -> bytes:
    return bytes.fromhex(sm3.sm3_hash(func.bytes_to_list(data)))


def hmac_sm3_hex(data: bytes, key: bytes) -> str:
    """HMAC-SM3，手动实现，与 C++ GmSSL 输出一致"""
    if len(key) > _SM3_BLOCK_SIZE:
        key = _sm3_hash_bytes(key)
    key_padded = key + b'\x00' * (_SM3_BLOCK_SIZE - len(key))
    ipad = bytes(b ^ 0x36 for b in key_padded)
    opad = bytes(b ^ 0x5c for b in key_padded)
    inner = _sm3_hash_bytes(ipad + data)
    return sm3.sm3_hash(func.bytes_to_list(opad + inner))


def sm4_decrypt(cipher_hex: str, key: bytes) -> bytes:
    data = bytes.fromhex(cipher_hex)
    iv, ciphertext = data[:16], data[16:]
    sm4 = CryptSM4()
    sm4.set_key(key, SM4_DECRYPT)
    padded = sm4.crypt_cbc(iv, ciphertext)
    return padded[:-padded[-1]]


def split_bigram_raw(text: str) -> list:
    tb = text.encode("utf-8")
    if len(tb) == 0:
        return []
    if len(tb) == 1:
        return [tb]
    return [tb[i:i + 2] for i in range(len(tb) - 1)]


def get_connection():
    return pymysql.connect(**DB_CONFIG)


def get_test_id_range():
    """获取测试数据 ID 范围，读不到则返回 None"""
    if not os.path.exists(_ID_RANGE_FILE):
        return None
    try:
        with open(_ID_RANGE_FILE, "r") as f:
            line = f.read().strip()
            parts = line.split(",")
            return int(parts[0]), int(parts[1])
    except Exception:
        return None


# ============================================================
# 1. 精确查询性能测试
# ============================================================
def benchmark_exact_query(samples: int = 100) -> dict:
    """精确查询（盲索引等值匹配）时延测试"""
    conn = get_connection()
    cursor = conn.cursor()

    id_range = get_test_id_range()
    if id_range:
        s, e = id_range
        cursor.execute(
            "SELECT name_blind_idx FROM sensitive_data "
            "WHERE id BETWEEN %s AND %s ORDER BY RAND() LIMIT %s",
            (s, e, samples)
        )
    else:
        cursor.execute(
            "SELECT name_blind_idx FROM sensitive_data "
            "ORDER BY RAND() LIMIT %s",
            (samples,)
        )
    rows = cursor.fetchall()

    if not rows:
        cursor.close()
        conn.close()
        return {"error": "无测试数据，请先运行 benchmark_data.py 注入数据"}

    actual_samples = min(samples, len(rows))

    # 预热
    cursor.execute(
        "SELECT id, name_cipher FROM sensitive_data WHERE name_blind_idx = %s LIMIT 1",
        (rows[0][0],)
    )
    cursor.fetchone()

    # 正式测试
    latencies = []
    for i in range(actual_samples):
        blind_idx = rows[i % len(rows)][0]
        t0 = time.perf_counter()
        cursor.execute(
            "SELECT id, name_cipher FROM sensitive_data WHERE name_blind_idx = %s LIMIT 1",
            (blind_idx,)
        )
        cursor.fetchone()
        latencies.append((time.perf_counter() - t0) * 1000)

    cursor.close()
    conn.close()

    latencies.sort()
    n = len(latencies)
    avg = sum(latencies) / n

    return {
        "test": "精确查询 (盲索引等值匹配)",
        "samples": n,
        "avg_ms": round(avg, 2),
        "p50_ms": round(latencies[n // 2], 2),
        "p95_ms": round(latencies[int(n * 0.95)], 2),
        "p99_ms": round(latencies[int(n * 0.99)], 2),
        "min_ms": round(latencies[0], 2),
        "max_ms": round(latencies[-1], 2),
        "target_ms": 100,
        "pass": avg < 100,
    }


# ============================================================
# 2. 模糊查询性能测试
# ============================================================
def benchmark_fuzzy_query(samples: int = 50) -> dict:
    """模糊查询（Bigram 倒排索引交集）时延测试"""
    keywords = [
        "张", "李", "王", "北京", "上海", "138", "朝阳", "海淀",
        "南山", "天河", "科技", "人民", "大道", "小区", "花园",
    ]

    conn = get_connection()
    cursor = conn.cursor()

    # 预热
    kw = keywords[0]
    tokens = split_bigram_raw(kw)
    hashes = [hmac_sm3_hex(t, RAW_IDX_KEY) for t in tokens]
    ph = ",".join(["%s"] * len(hashes))
    sql = (f"SELECT data_id FROM fuzzy_inverted "
           f"WHERE token_hash IN ({ph}) AND field_type = 1 "
           f"GROUP BY data_id HAVING COUNT(DISTINCT token_hash) = %s LIMIT 100")
    cursor.execute(sql, hashes + [len(hashes)])
    cursor.fetchall()

    # 正式测试
    latencies = []
    match_counts = []

    for i in range(samples):
        kw = random.choice(keywords)
        tokens = split_bigram_raw(kw)
        hashes = [hmac_sm3_hex(t, RAW_IDX_KEY) for t in tokens]
        ph = ",".join(["%s"] * len(hashes))
        sql = (f"SELECT data_id FROM fuzzy_inverted "
               f"WHERE token_hash IN ({ph}) AND field_type = 1 "
               f"GROUP BY data_id HAVING COUNT(DISTINCT token_hash) = %s LIMIT 500")

        t0 = time.perf_counter()
        cursor.execute(sql, hashes + [len(hashes)])
        rows = cursor.fetchall()
        latencies.append((time.perf_counter() - t0) * 1000)
        match_counts.append(len(rows))

    cursor.close()
    conn.close()

    latencies.sort()
    n = len(latencies)
    avg = sum(latencies) / n

    return {
        "test": "模糊查询 (Bigram 倒排索引交集)",
        "samples": n,
        "avg_ms": round(avg, 2),
        "p50_ms": round(latencies[n // 2], 2),
        "p95_ms": round(latencies[int(n * 0.95)], 2),
        "min_ms": round(latencies[0], 2),
        "max_ms": round(latencies[-1], 2),
        "avg_matches": round(sum(match_counts) / n, 1),
        "target_ms": 500,
        "pass": avg < 500,
    }


# ============================================================
# 3. 批量解密吞吐量测试
# ============================================================
def benchmark_batch_decrypt(batch_size: int = 10000, threads: int = 8) -> dict:
    """批量解密：串行 vs 并发吞吐量对比"""
    conn = get_connection()
    cursor = conn.cursor()

    id_range = get_test_id_range()
    if id_range:
        s, e = id_range
        cursor.execute(
            "SELECT name_cipher FROM sensitive_data "
            "WHERE id BETWEEN %s AND %s LIMIT %s",
            (s, e, batch_size)
        )
    else:
        cursor.execute(
            "SELECT name_cipher FROM sensitive_data LIMIT %s",
            (batch_size,)
        )
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    if not rows:
        return {"error": "无测试数据，请先运行 benchmark_data.py"}

    actual_size = len(rows)
    cipher_list = [r[0] for r in rows]

    # 串行解密
    t0 = time.perf_counter()
    for c in cipher_list:
        sm4_decrypt(c, RAW_ENC_KEY)
    serial_time = time.perf_counter() - t0
    serial_throughput = actual_size / serial_time

    # 并发解密
    def decrypt_worker(chunk):
        for c in chunk:
            sm4_decrypt(c, RAW_ENC_KEY)
        return len(chunk)

    chunk_size = (actual_size + threads - 1) // threads
    chunks = [cipher_list[i:i + chunk_size] for i in range(0, actual_size, chunk_size)]

    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(decrypt_worker, chunk) for chunk in chunks]
        for f in as_completed(futures):
            f.result()
    parallel_time = time.perf_counter() - t0
    parallel_throughput = actual_size / parallel_time

    improvement = ((parallel_throughput - serial_throughput) / serial_throughput) * 100

    return {
        "test": "批量解密吞吐量",
        "batch_size": actual_size,
        "threads": threads,
        "serial_time_s": round(serial_time, 3),
        "serial_throughput": round(serial_throughput, 1),
        "parallel_time_s": round(parallel_time, 3),
        "parallel_throughput": round(parallel_throughput, 1),
        "improvement_pct": round(improvement, 1),
        "target_pct": 50,
        "pass": improvement >= 50,
    }


# ============================================================
# 4. 并发写入一致性测试
# ============================================================
def benchmark_concurrent_consistency(num_threads: int = 8, per_thread: int = 100) -> dict:
    """多线程并发写入，验证数据一致性"""
    # 动态导入生成函数
    sys.path.insert(0, os.path.dirname(__file__))
    from benchmark_data import generate_batch, encrypt_record, get_max_id, save_id_range

    total = num_threads * per_thread
    all_records = generate_batch(total)
    chunks = [all_records[i * per_thread:(i + 1) * per_thread] for i in range(num_threads)]

    conn0 = get_connection()
    start_id = get_max_id(conn0) + 1
    conn0.close()

    errors = []
    lock = threading.Lock()

    def insert_worker(wid, recs):
        conn = get_connection()
        cursor = conn.cursor()
        try:
            insert_main = """
                INSERT INTO sensitive_data
                (name_cipher, name_blind_idx, name_tag,
                 phone_cipher, phone_blind_idx, phone_tag,
                 address_cipher, address_blind_idx, address_tag)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            insert_fuzzy = (
                "INSERT IGNORE INTO fuzzy_inverted (token_hash, data_id, field_type) "
                "VALUES (%s, %s, %s)"
            )
            for rec in recs:
                enc = encrypt_record(rec)
                cursor.execute(insert_main, (
                    enc["nc"], enc["nb"], enc["nt"],
                    enc["pc"], enc["pb"], enc["pt"],
                    enc["ac"], enc["ab"], enc["at"],
                ))
                did = cursor.lastrowid
                fv = []
                for t in enc["ntokens"]:
                    fv.append((t, did, 1))
                for t in enc["ptokens"]:
                    fv.append((t, did, 2))
                for t in enc["atokens"]:
                    fv.append((t, did, 3))
                if fv:
                    cursor.executemany(insert_fuzzy, fv)
            conn.commit()
        except Exception as e:
            conn.rollback()
            with lock:
                errors.append(f"线程{wid}: {e}")
        finally:
            cursor.close()
            conn.close()

    t0 = time.time()
    threads = []
    for idx, chunk in enumerate(chunks):
        t = threading.Thread(target=insert_worker, args=(idx, chunk))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    elapsed = time.time() - t0

    # 验证
    conn = get_connection()
    cursor = conn.cursor()
    end_id = get_max_id(conn)

    cursor.execute(
        "SELECT COUNT(*) FROM sensitive_data WHERE id >= %s", (start_id,)
    )
    actual_count = cursor.fetchone()[0]

    cursor.execute(
        "SELECT name_cipher, name_tag, phone_cipher, phone_tag, address_cipher, address_tag "
        "FROM sensitive_data WHERE id >= %s LIMIT 20", (start_id,)
    )
    samples = cursor.fetchall()
    name_tag_ok = phone_tag_ok = addr_tag_ok = 0
    for nc, nt, pc, pt, ac, at in samples:
        if hmac_sm3_hex(nc.encode("utf-8"), RAW_TAG_KEY) == nt:
            name_tag_ok += 1
        if hmac_sm3_hex(pc.encode("utf-8"), RAW_TAG_KEY) == pt:
            phone_tag_ok += 1
        if hmac_sm3_hex(ac.encode("utf-8"), RAW_TAG_KEY) == at:
            addr_tag_ok += 1
    all_tag_ok = (name_tag_ok == len(samples) and
                  phone_tag_ok == len(samples) and
                  addr_tag_ok == len(samples))

    # 清理
    cursor.execute(
        "DELETE FROM fuzzy_inverted WHERE data_id >= %s", (start_id,)
    )
    cursor.execute("DELETE FROM sensitive_data WHERE id >= %s", (start_id,))
    conn.commit()
    cursor.close()
    conn.close()

    return {
        "test": "并发写入一致性",
        "threads": num_threads,
        "expected": total,
        "actual": actual_count,
        "elapsed_s": round(elapsed, 2),
        "tag_verify_name": f"{name_tag_ok}/{len(samples)}",
        "tag_verify_phone": f"{phone_tag_ok}/{len(samples)}",
        "tag_verify_address": f"{addr_tag_ok}/{len(samples)}",
        "errors": errors,
        "pass": actual_count == total and len(errors) == 0 and all_tag_ok,
    }


# ============================================================
# 结果打印
# ============================================================
def print_result(result: dict):
    if "error" in result:
        print(f"  失败: {result['error']}")
        return

    name = result.get("test", "未知测试")
    passed = result.get("pass")
    status = "通过" if passed else "未达标" if passed is not None else "-"
    print(f"\n【{name}】 {status}")
    print("  " + "-" * 50)

    key_map = {
        "samples": "样本数",
        "avg_ms": "平均时延",
        "p50_ms": "P50 时延",
        "p95_ms": "P95 时延",
        "p99_ms": "P99 时延",
        "min_ms": "最小时延",
        "max_ms": "最大时延",
        "target_ms": "目标值",
        "avg_matches": "平均匹配数",
        "batch_size": "批次大小",
        "threads": "线程数",
        "serial_time_s": "串行耗时(s)",
        "serial_throughput": "串行吞吐(条/s)",
        "parallel_time_s": "并发耗时(s)",
        "parallel_throughput": "并发吞吐(条/s)",
        "improvement_pct": "吞吐量提升",
        "target_pct": "目标提升",
        "expected": "期望记录数",
        "actual": "实际记录数",
        "elapsed_s": "总耗时(s)",
        "tag_verify_name": "姓名Tag校验",
        "tag_verify_phone": "手机Tag校验",
        "tag_verify_address": "地址Tag校验",
        "errors": "错误数",
    }

    for k, v in result.items():
        if k in ("test", "pass"):
            continue
        label = key_map.get(k, k)

        if k == "target_ms":
            print(f"  {label:<18}: < {v} ms")
        elif k == "target_pct":
            print(f"  {label:<18}: >= {v}%")
        elif "ms" in k:
            print(f"  {label:<18}: {v} ms")
        elif k == "improvement_pct":
            mark = "达标" if v >= result.get("target_pct", 0) else "未达标"
            print(f"  {label:<18}: {v}% ({mark})")
        elif k == "errors":
            if v:
                print(f"  {label:<18}: {len(v)} 个错误")
                for e in v:
                    print(f"    - {e}")
            else:
                print(f"  {label:<18}: 0")
        else:
            print(f"  {label:<18}: {v}")


# ============================================================
# 主入口
# ============================================================
def main():
    parser = argparse.ArgumentParser(description="SecSearch 性能基准测试")
    parser.add_argument("--test", choices=["all", "exact", "fuzzy", "decrypt", "concurrency"],
                        default="all", help="运行指定测试 (默认 all)")
    parser.add_argument("--samples", type=int, default=100, help="查询测试样本数 (默认 100)")
    parser.add_argument("--decrypt-batch", type=int, default=10000, help="批量解密条数 (默认 10000)")
    parser.add_argument("--decrypt-threads", type=int, default=8, help="批量解密线程数 (默认 8)")
    parser.add_argument("--conc-threads", type=int, default=8, help="并发测试线程数 (默认 8)")
    parser.add_argument("--conc-per-thread", type=int, default=100, help="每线程写入数 (默认 100)")
    args = parser.parse_args()

    print("=" * 60)
    print("  SecSearch 性能基准测试")
    print("=" * 60)

    id_range = get_test_id_range()
    if id_range:
        print(f"  测试数据 ID 范围: {id_range[0]} ~ {id_range[1]}")
    print()

    results = []

    if args.test in ("all", "exact"):
        print("运行精确查询性能测试...")
        r = benchmark_exact_query(samples=args.samples)
        print_result(r)
        results.append(r)
        print()

    if args.test in ("all", "fuzzy"):
        print("运行模糊查询性能测试...")
        r = benchmark_fuzzy_query(samples=max(args.samples // 2, 20))
        print_result(r)
        results.append(r)
        print()

    if args.test in ("all", "decrypt"):
        print("运行批量解密吞吐量测试...")
        r = benchmark_batch_decrypt(
            batch_size=args.decrypt_batch,
            threads=args.decrypt_threads
        )
        print_result(r)
        results.append(r)
        print()

    if args.test in ("all", "concurrency"):
        print("运行并发写入一致性测试...")
        r = benchmark_concurrent_consistency(
            num_threads=args.conc_threads,
            per_thread=args.conc_per_thread
        )
        print_result(r)
        results.append(r)
        print()

    # 汇总
    print("=" * 60)
    print("  测试汇总")
    print("=" * 60)

    passed = 0
    total = 0
    for r in results:
        if "error" in r:
            continue
        total += 1
        if r.get("pass"):
            passed += 1
        name = r.get("test", "?")
        status = "通过" if r.get("pass") else "未达标"
        print(f"  [{status}] {name}")

    print()
    print(f"  通过: {passed}/{total}")
    print()
    print("  性能目标:")
    print("    精确查询平均时延 < 100ms")
    print("    模糊搜索平均时延 < 500ms")
    print("    批量解密吞吐量较串行提升 > 50%")
    print("    并发场景无数据一致性问题")
    print()


if __name__ == "__main__":
    main()
