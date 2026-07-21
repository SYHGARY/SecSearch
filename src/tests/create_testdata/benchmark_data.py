"""
SecSearch 批量数据注入脚本
===========================
用于生成千条 / 万条测试数据，验证性能指标与并发一致性

性能目标:
  - 千条数据: 精确查询 < 100ms, 模糊查询 < 500ms
  - 万条数据: 批量解密吞吐量较串行提升 50%+
  - 并发场景: 无数据一致性问题

使用方式:
    # 注入 1000 条测试数据
    python tests/benchmark_data.py --count 1000

    # 注入 10000 条测试数据
    python tests/benchmark_data.py --count 10000

    # 并发插入验证一致性
    python tests/benchmark_data.py --count 5000 --concurrency 8

    # 插入后校验完整性
    python tests/benchmark_data.py --count 1000 --verify

    # 一键清理本次注入的测试数据
    python tests/benchmark_data.py --only-clear

依赖:
    pip install gmssl pymysql
"""

import os
import sys
import time
import random
import string
import argparse
import importlib.util
import threading
from datetime import datetime

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
    "autocommit": False,
}

# 三密钥（与 C++ 测试保持一致）
KEK = bytes([0x11] * 16)
RAW_ENC_KEY = bytes([0xA0] * 16)
RAW_IDX_KEY = bytes([0xB0] * 16)
RAW_TAG_KEY = bytes([0xC0] * 16)

# SM3 块大小（字节），HMAC 需要
_SM3_BLOCK_SIZE = 64

# 记录本次测试 ID 范围的文件（同目录下）
_ID_RANGE_FILE = os.path.join(os.path.dirname(__file__), ".benchmark_id_range")

# 数据生成素材
SURNAMES = list("赵钱孙李周吴郑王冯陈褚卫蒋沈韩杨朱秦尤许何吕施张孔曹严华金魏陶姜")
GIVEN_NAMES = [
    "伟", "芳", "娜", "敏", "静", "丽", "强", "磊", "军", "洋",
    "勇", "艳", "杰", "娟", "涛", "明", "超", "秀英", "霞", "平",
    "思远", "雨萱", "梓涵", "浩然", "子轩", "欣怡", "俊熙",
]
CITIES = ["北京市", "上海市", "广州市", "深圳市", "杭州市", "南京市", "武汉市", "成都市",
          "西安市", "重庆市", "天津市", "苏州市", "长沙市", "郑州市", "青岛市", "大连市"]
DISTRICTS = ["朝阳区", "海淀区", "浦东新区", "南山区", "福田区", "天河区", "越秀区", "西湖区",
             "鼓楼区", "武昌区", "洪山区", "锦江区", "武侯区", "雁塔区", "江北区", "和平区"]
STREETS = ["中关村大街", "长安街", "南京路", "解放路", "人民路", "建设路", "和平路", "中山路",
           "科技大道", "创业路", "学府路", "长江路", "黄河路", "珠江路", "文化路", "体育路"]


# ============================================================
# 加密工具函数
# ============================================================
def _sm3_hash_bytes(data: bytes) -> bytes:
    """SM3 哈希，返回 bytes"""
    return bytes.fromhex(sm3.sm3_hash(func.bytes_to_list(data)))


def hmac_sm3_hex(data: bytes, key: bytes) -> str:
    """
    HMAC-SM3，返回 64 字符十六进制字符串
    基于 HMAC 标准算法 (RFC 2104) 手动实现
    与 C++ 端 GmSSL 库的 HMAC-SM3 输出完全一致
    """
    if len(key) > _SM3_BLOCK_SIZE:
        key = _sm3_hash_bytes(key)
    key_padded = key + b'\x00' * (_SM3_BLOCK_SIZE - len(key))
    ipad = bytes(b ^ 0x36 for b in key_padded)
    opad = bytes(b ^ 0x5c for b in key_padded)
    inner = _sm3_hash_bytes(ipad + data)
    return sm3.sm3_hash(func.bytes_to_list(opad + inner))


def sm4_encrypt(plaintext: bytes, key: bytes) -> str:
    """SM4-CBC 加密，返回 hex 字符串（IV + 密文）"""
    iv = os.urandom(16)
    sm4 = CryptSM4()
    sm4.set_key(key, SM4_ENCRYPT)
    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad_len] * pad_len)
    ciphertext = sm4.crypt_cbc(iv, padded)
    return (iv + ciphertext).hex()


def sm4_decrypt(cipher_hex: str, key: bytes) -> bytes:
    """SM4-CBC 解密"""
    data = bytes.fromhex(cipher_hex)
    iv, ciphertext = data[:16], data[16:]
    sm4 = CryptSM4()
    sm4.set_key(key, SM4_DECRYPT)
    padded = sm4.crypt_cbc(iv, ciphertext)
    return padded[:-padded[-1]]


def split_bigram_raw(text: str) -> list:
    """Bigram 分词（按字节滑动，与 C++ 一致）"""
    tb = text.encode("utf-8")
    if len(tb) == 0:
        return []
    if len(tb) == 1:
        return [tb]
    return [tb[i:i + 2] for i in range(len(tb) - 1)]


# ============================================================
# ID 范围记录（用于识别和清理测试数据）
# ============================================================
def save_id_range(start_id: int, end_id: int):
    """保存本次测试数据的 ID 范围到文件"""
    with open(_ID_RANGE_FILE, "w") as f:
        f.write(f"{start_id},{end_id}\n")


def load_id_range():
    """读取上次测试数据的 ID 范围，返回 (start, end) 或 None"""
    if not os.path.exists(_ID_RANGE_FILE):
        return None
    try:
        with open(_ID_RANGE_FILE, "r") as f:
            line = f.read().strip()
            parts = line.split(",")
            return int(parts[0]), int(parts[1])
    except Exception:
        return None


def get_max_id(conn) -> int:
    cursor = conn.cursor()
    cursor.execute("SELECT COALESCE(MAX(id), 0) FROM sensitive_data")
    mid = cursor.fetchone()[0]
    cursor.close()
    return mid


# ============================================================
# 数据生成器
# ============================================================
def generate_phone() -> str:
    prefixes = ["130", "131", "132", "133", "135", "136", "137", "138", "139",
                "150", "151", "152", "153", "155", "156", "157", "158", "159",
                "180", "181", "182", "183", "185", "186", "187", "188", "189"]
    return random.choice(prefixes) + "".join(random.choices(string.digits, k=8))


def generate_name() -> str:
    return random.choice(SURNAMES) + random.choice(GIVEN_NAMES)


def generate_address() -> str:
    return (f"{random.choice(CITIES)}{random.choice(DISTRICTS)}"
            f"{random.choice(STREETS)}{random.randint(1, 999)}号")


def generate_batch(count: int) -> list:
    records = []
    used = set()
    for _ in range(count):
        while True:
            phone = generate_phone()
            if phone not in used:
                used.add(phone)
                break
        records.append({
            "name": generate_name(),
            "phone": phone,
            "address": generate_address(),
        })
    return records


# ============================================================
# 数据库操作
# ============================================================
def get_connection():
    return pymysql.connect(**DB_CONFIG)


def encrypt_record(rec: dict) -> dict:
    """加密一条记录，返回所有写入字段"""
    nb = rec["name"].encode("utf-8")
    pb = rec["phone"].encode("utf-8")
    ab = rec["address"].encode("utf-8")

    nc = sm4_encrypt(nb, RAW_ENC_KEY)
    pc = sm4_encrypt(pb, RAW_ENC_KEY)
    ac = sm4_encrypt(ab, RAW_ENC_KEY)

    nb_idx = hmac_sm3_hex(nb, RAW_IDX_KEY)
    pb_idx = hmac_sm3_hex(pb, RAW_IDX_KEY)
    ab_idx = hmac_sm3_hex(ab, RAW_IDX_KEY)

    nt = hmac_sm3_hex(nc.encode("utf-8"), RAW_TAG_KEY)
    pt = hmac_sm3_hex(pc.encode("utf-8"), RAW_TAG_KEY)
    at = hmac_sm3_hex(ac.encode("utf-8"), RAW_TAG_KEY)

    ntokens = [hmac_sm3_hex(t, RAW_IDX_KEY) for t in split_bigram_raw(rec["name"])]
    ptokens = [hmac_sm3_hex(t, RAW_IDX_KEY) for t in split_bigram_raw(rec["phone"])]
    atokens = [hmac_sm3_hex(t, RAW_IDX_KEY) for t in split_bigram_raw(rec["address"])]

    return {
        "nc": nc, "nb": nb_idx, "nt": nt,
        "pc": pc, "pb": pb_idx, "pt": pt,
        "ac": ac, "ab": ab_idx, "at": at,
        "ntokens": ntokens, "ptokens": ptokens, "atokens": atokens,
    }


def clear_by_id_range(conn, start_id: int, end_id: int):
    """按 ID 范围清理测试数据"""
    cursor = conn.cursor()
    cursor.execute(
        "DELETE FROM fuzzy_inverted WHERE data_id BETWEEN %s AND %s",
        (start_id, end_id)
    )
    fuzzy_del = cursor.rowcount
    cursor.execute(
        "DELETE FROM sensitive_data WHERE id BETWEEN %s AND %s",
        (start_id, end_id)
    )
    main_del = cursor.rowcount
    conn.commit()
    cursor.close()
    return main_del, fuzzy_del


# ============================================================
# 主流程
# ============================================================
def main():
    parser = argparse.ArgumentParser(description="SecSearch 批量数据注入脚本")
    parser.add_argument("--count", type=int, default=10000, help="注入条数 (默认 10000)")
    parser.add_argument("--concurrency", type=int, default=1, help="并发线程数 (默认 1)")
    parser.add_argument("--verify", action="store_true", help="插入后校验完整性")
    parser.add_argument("--clear", action="store_true", help="先清理上次测试数据")
    parser.add_argument("--only-clear", action="store_true", help="仅清理上次测试数据，不插入")
    parser.add_argument("--batch-size", type=int, default=100, help="每批大小 (默认 100)")
    args = parser.parse_args()

    # 一键清理模式
    if args.only_clear:
        id_range = load_id_range()
        if not id_range:
            print("没有找到上次测试数据的记录，无法清理。")
            print("（请先运行过一次注入脚本，或手动 TRUNCATE 表）")
            return

        start_id, end_id = id_range
        print("=" * 60)
        print("  SecSearch 测试数据清理")
        print("=" * 60)
        print(f"  ID 范围: {start_id} ~ {end_id}")

        conn = get_connection()
        md, fd = clear_by_id_range(conn, start_id, end_id)
        conn.close()

        print(f"\n  已清理主表数据: {md} 条")
        print(f"  已清理倒排索引: {fd} 条")
        print("\n" + "=" * 60)

        # 清理记录文件
        if os.path.exists(_ID_RANGE_FILE):
            os.remove(_ID_RANGE_FILE)
        return

    print("=" * 60)
    print("  SecSearch 基准数据注入工具")
    print("=" * 60)
    print(f"  目标数据量: {args.count:,} 条")
    print(f"  并发线程数: {args.concurrency}")
    print(f"  开始时间  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 60)

    conn = get_connection()

    # 清理旧数据
    if args.clear:
        id_range = load_id_range()
        if id_range:
            print("\n[1/5] 清理上次测试数据...")
            s, e = id_range
            md, fd = clear_by_id_range(conn, s, e)
            print(f"  已清理主表 {md} 条, 倒排表 {fd} 条")
        else:
            print("\n[1/5] 无历史测试数据记录，跳过清理")

    # 记录起始 ID
    start_id = get_max_id(conn) + 1
    print(f"\n  本次起始 ID: {start_id}")

    # 生成数据
    print(f"\n[2/5] 生成 {args.count:,} 条测试数据...")
    t0 = time.time()
    records = generate_batch(args.count)
    gen_time = time.time() - t0
    print(f"  完成, 耗时 {gen_time:.2f}s")
    print(f"  示例: {records[0]['name']} / {records[0]['phone']}")

    # 插入数据
    print(f"\n[3/5] 插入数据 ({args.concurrency} 线程)...")
    t0 = time.time()
    inserted = 0

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

    cursor = conn.cursor()
    for i in range(0, len(records), args.batch_size):
        batch = records[i:i + args.batch_size]
        try:
            for rec in batch:
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

                inserted += 1
                if inserted % 1000 == 0:
                    el = time.time() - t0
                    rate = inserted / el if el > 0 else 0
                    print(f"  已插入 {inserted:,} / {args.count:,} ({rate:.0f} 条/s)")

            conn.commit()
        except Exception as e:
            conn.rollback()
            print(f"  批次 {i // args.batch_size} 失败: {e}")
            raise

    cursor.close()
    insert_time = time.time() - t0
    end_id = get_max_id(conn)

    # 保存 ID 范围
    save_id_range(start_id, end_id)

    print(f"\n  插入完成: {inserted:,} 条")
    print(f"  ID 范围  : {start_id} ~ {end_id}")
    print(f"  总耗时  : {insert_time:.2f}s")
    print(f"  平均速率: {inserted / insert_time:.1f} 条/秒")

    # 校验
    if args.verify:
        print("\n[4/5] 数据完整性校验...")
        cur = conn.cursor()
        cur.execute(
            "SELECT COUNT(*) FROM sensitive_data WHERE id BETWEEN %s AND %s",
            (start_id, end_id)
        )
        cnt = cur.fetchone()[0]

        cur.execute(
            "SELECT name_cipher, name_tag FROM sensitive_data "
            "WHERE id BETWEEN %s AND %s LIMIT 10",
            (start_id, end_id)
        )
        samples = cur.fetchall()
        tag_ok = sum(
            1 for c, t in samples
            if hmac_sm3_hex(c.encode("utf-8"), RAW_TAG_KEY) == t
        )
        cur.close()

        print(f"  主表记录数: {cnt}")
        print(f"  Tag 校验  : {tag_ok}/{len(samples)} 通过")

    # 统计
    print("\n[5/5] 索引规模统计...")
    cur = conn.cursor()
    cur.execute(
        "SELECT COUNT(*) FROM sensitive_data WHERE id BETWEEN %s AND %s",
        (start_id, end_id)
    )
    mc = cur.fetchone()[0]
    cur.execute(
        "SELECT COUNT(*) FROM fuzzy_inverted WHERE data_id BETWEEN %s AND %s",
        (start_id, end_id)
    )
    fc = cur.fetchone()[0]
    cur.close()
    conn.close()

    print(f"  主表记录  : {mc:,}")
    print(f"  倒排条目  : {fc:,}")

    print("\n" + "=" * 60)
    print(f"  完成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    print("\n下一步运行性能测试:")
    print("  python tests/benchmark_perf.py")
    print("\n清理本次测试数据:")
    print("  python tests/benchmark_data.py --only-clear")


if __name__ == "__main__":
    main()
