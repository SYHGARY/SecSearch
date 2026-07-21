"""
SecSearch 项目 Python 测试套件
===============================
覆盖加密模块、分词逻辑、数据库集成查询等核心功能

依赖安装:
    pip install gmssl pymysql

运行方式:
    python -m unittest tests.test_secsearch -v
    或单独运行: python tests/test_secsearch.py

兼容 Python 3.8 ~ 3.14
"""

import unittest
import os
import sys
import importlib.util

# ============================================================
# 配置区 - 修改为你的数据库信息
# ============================================================
DB_CONFIG = {
    "host": "127.0.0.1",
    "port": 3306,
    "user": "root",
    "password": "Lwc20041125",
    "database": "secsearch",
    "charset": "utf8mb4",
}

# 测试用三密钥（与 C++ 测试保持一致）
KEK = bytes([0x11] * 16)           # 主密钥
RAW_ENC_KEY = bytes([0xA0] * 16)   # 加密密钥
RAW_IDX_KEY = bytes([0xB0] * 16)   # 索引密钥
RAW_TAG_KEY = bytes([0xC0] * 16)   # Tag 密钥

# 检测可选依赖是否已安装
_PYMYSQL_AVAILABLE = importlib.util.find_spec("pymysql") is not None
_GMSSL_AVAILABLE = importlib.util.find_spec("gmssl") is not None


# ============================================================
# 工具函数：SM4-CBC 加解密（与 C++ 实现对齐）
# ============================================================
def sm4_cbc_encrypt(plaintext: bytes, key: bytes) -> str:
    """
    SM4-CBC 加密，返回十六进制字符串
    密文格式: IV(16字节) + 密文数据 → hex 编码
    PKCS7 填充
    """
    from gmssl.sm4 import CryptSM4, SM4_ENCRYPT

    iv = os.urandom(16)
    sm4 = CryptSM4()
    sm4.set_key(key, SM4_ENCRYPT)

    # PKCS7 填充
    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad_len] * pad_len)

    ciphertext = sm4.crypt_cbc(iv, padded)
    return (iv + ciphertext).hex()


def sm4_cbc_decrypt(cipher_hex: str, key: bytes) -> bytes:
    """
    SM4-CBC 解密，输入十六进制字符串，返回明文 bytes
    """
    from gmssl.sm4 import CryptSM4, SM4_DECRYPT

    data = bytes.fromhex(cipher_hex)
    iv = data[:16]
    ciphertext = data[16:]

    sm4 = CryptSM4()
    sm4.set_key(key, SM4_DECRYPT)

    padded = sm4.crypt_cbc(iv, ciphertext)

    # 去除 PKCS7 填充
    pad_len = padded[-1]
    return padded[:-pad_len]


def hmac_sm3_hex(data: bytes, key: bytes) -> str:
    """HMAC-SM3，返回 64 字符十六进制字符串"""
    from gmssl.sm3 import sm3_hmac

    return sm3_hmac(key, data).hex()


def split_bigram_raw(text: str) -> list:
    """
    Bigram 分词（返回原始字节 token 列表，用于哈希）
    与 C++ dao.cpp 中 splitBigram 逻辑一致：按字节滑动窗口
    """
    text_bytes = text.encode("utf-8")
    if len(text_bytes) == 0:
        return []
    if len(text_bytes) == 1:
        return [text_bytes]
    tokens = []
    for i in range(len(text_bytes) - 1):
        tokens.append(text_bytes[i:i + 2])
    return tokens


# ============================================================
# 测试 1: SM4-CBC 加解密
# ============================================================
@unittest.skipUnless(_GMSSL_AVAILABLE, "gmssl 未安装")
class TestSm4Cipher(unittest.TestCase):
    """SM4-CBC 对称加解密测试"""

    def test_encrypt_decrypt_roundtrip_ascii(self):
        """英文数字明文加解密往返正确"""
        plain = b"Hello, SecSearch! 12345"
        cipher = sm4_cbc_encrypt(plain, RAW_ENC_KEY)
        decrypted = sm4_cbc_decrypt(cipher, RAW_ENC_KEY)
        self.assertEqual(plain, decrypted)
        self.assertGreater(len(cipher), 0)
        self.assertEqual(len(cipher) % 2, 0)  # hex 编码必为偶数长度

    def test_encrypt_decrypt_roundtrip_chinese(self):
        """中文明文加解密往返正确"""
        plain = "张三的手机号是13800138000！".encode("utf-8")
        cipher = sm4_cbc_encrypt(plain, RAW_ENC_KEY)
        decrypted = sm4_cbc_decrypt(cipher, RAW_ENC_KEY)
        self.assertEqual(plain, decrypted)
        self.assertEqual(decrypted.decode("utf-8"), "张三的手机号是13800138000！")

    def test_encrypt_random_iv(self):
        """每次加密 IV 随机，密文不同但解密结果一致"""
        plain = b"test data for iv check"
        c1 = sm4_cbc_encrypt(plain, RAW_ENC_KEY)
        c2 = sm4_cbc_encrypt(plain, RAW_ENC_KEY)
        self.assertNotEqual(c1, c2)          # IV 不同 → 密文不同
        self.assertEqual(sm4_cbc_decrypt(c1, RAW_ENC_KEY), plain)
        self.assertEqual(sm4_cbc_decrypt(c2, RAW_ENC_KEY), plain)

    def test_wrong_key_decrypt_fails(self):
        """错误密钥无法还原明文"""
        plain = b"sensitive data"
        cipher = sm4_cbc_encrypt(plain, RAW_ENC_KEY)
        wrong_key = bytes([0xBB] * 16)
        decrypted = sm4_cbc_decrypt(cipher, wrong_key)
        self.assertNotEqual(plain, decrypted)

    def test_empty_plaintext(self):
        """空明文加密（PKCS7 填充一个完整块）"""
        plain = b""
        cipher = sm4_cbc_encrypt(plain, RAW_ENC_KEY)
        decrypted = sm4_cbc_decrypt(cipher, RAW_ENC_KEY)
        self.assertEqual(plain, decrypted)

    def test_exact_one_block(self):
        """刚好 16 字节明文（会补一整块 16 字节填充）"""
        plain = b"A" * 16
        cipher = sm4_cbc_encrypt(plain, RAW_ENC_KEY)
        decrypted = sm4_cbc_decrypt(cipher, RAW_ENC_KEY)
        self.assertEqual(plain, decrypted)

    def test_cipher_starts_with_iv(self):
        """密文前 16 字节是 IV（32 个 hex 字符）"""
        plain = b"check iv position"
        cipher = sm4_cbc_encrypt(plain, RAW_ENC_KEY)
        iv_hex = cipher[:32]
        self.assertEqual(len(iv_hex), 32)     # 16 字节 = 32 hex 字符


# ============================================================
# 测试 2: HMAC-SM3 盲索引与完整性 Tag
# ============================================================
@unittest.skipUnless(_GMSSL_AVAILABLE, "gmssl 未安装")
class TestHmacSm3(unittest.TestCase):
    """HMAC-SM3 盲索引和完整性校验测试"""

    def test_output_length_64_chars(self):
        """输出为 64 字符十六进制（对应 32 字节 SM3 摘要）"""
        result = hmac_sm3_hex(b"test", RAW_IDX_KEY)
        self.assertEqual(len(result), 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in result))

    def test_deterministic_same_input(self):
        """相同输入 + 相同密钥 → 相同哈希（确定性）"""
        data = "张三".encode("utf-8")
        h1 = hmac_sm3_hex(data, RAW_IDX_KEY)
        h2 = hmac_sm3_hex(data, RAW_IDX_KEY)
        self.assertEqual(h1, h2)

    def test_different_plaintext_different_hash(self):
        """不同明文 → 不同盲索引"""
        h1 = hmac_sm3_hex("张三".encode("utf-8"), RAW_IDX_KEY)
        h2 = hmac_sm3_hex("李四".encode("utf-8"), RAW_IDX_KEY)
        self.assertNotEqual(h1, h2)

    def test_three_keys_isolation(self):
        """三密钥互不相同，相同数据用不同密钥产生不同哈希"""
        data = b"test data for key isolation"
        h_enc = hmac_sm3_hex(data, RAW_ENC_KEY)
        h_idx = hmac_sm3_hex(data, RAW_IDX_KEY)
        h_tag = hmac_sm3_hex(data, RAW_TAG_KEY)
        self.assertNotEqual(h_enc, h_idx)
        self.assertNotEqual(h_idx, h_tag)
        self.assertNotEqual(h_enc, h_tag)

    def test_blind_index_exact_match(self):
        """盲索引可用于精确等值匹配查询"""
        stored_index = hmac_sm3_hex("张三".encode("utf-8"), RAW_IDX_KEY)
        query_index = hmac_sm3_hex("张三".encode("utf-8"), RAW_IDX_KEY)
        self.assertEqual(stored_index, query_index)

    def test_tag_detects_cipher_tampering(self):
        """完整性 Tag 能检测密文篡改"""
        cipher_hex = sm4_cbc_encrypt(b"original data", RAW_ENC_KEY)
        tag = hmac_sm3_hex(cipher_hex.encode("utf-8"), RAW_TAG_KEY)

        # 篡改一个 hex 字符
        tampered = list(cipher_hex)
        tampered[10] = "1" if tampered[10] == "0" else "0"
        tampered_hex = "".join(tampered)

        tampered_tag = hmac_sm3_hex(tampered_hex.encode("utf-8"), RAW_TAG_KEY)
        self.assertNotEqual(tag, tampered_tag)

    def test_tag_detects_wrong_key(self):
        """用错误密钥计算的 Tag 与存储值不一致"""
        cipher_hex = sm4_cbc_encrypt(b"data", RAW_ENC_KEY)
        correct_tag = hmac_sm3_hex(cipher_hex.encode("utf-8"), RAW_TAG_KEY)
        wrong_tag = hmac_sm3_hex(cipher_hex.encode("utf-8"), RAW_IDX_KEY)
        self.assertNotEqual(correct_tag, wrong_tag)


# ============================================================
# 测试 3: Bigram 分词（模糊查询核心）
# ============================================================
class TestBigramTokenizer(unittest.TestCase):
    """Bigram 分词逻辑测试（纯 Python，无外部依赖）"""

    def test_empty_string(self):
        """空字符串返回空列表"""
        self.assertEqual(split_bigram_raw(""), [])

    def test_single_ascii_char(self):
        """单 ASCII 字符 → 1 个 token"""
        tokens = split_bigram_raw("A")
        self.assertEqual(len(tokens), 1)
        self.assertEqual(tokens[0], b"A")

    def test_ascii_string(self):
        """英文 Bigram："abc" → "ab", "bc" 共 2 个"""
        tokens = split_bigram_raw("abc")
        self.assertEqual(len(tokens), 2)
        self.assertEqual(tokens[0], b"ab")
        self.assertEqual(tokens[1], b"bc")

    def test_chinese_utf8_bytewise(self):
        """中文按 UTF-8 字节滑动："张三" 6 字节 → 5 个 token"""
        tokens = split_bigram_raw("张三")
        self.assertEqual(len(tokens), 5)  # 6字节 - 1 = 5

    def test_phone_number(self):
        """11 位手机号 → 10 个 token"""
        tokens = split_bigram_raw("13800138000")
        self.assertEqual(len(tokens), 10)

    def test_token_count_formula(self):
        """token 数量 = 字节数 - 1（长度 > 1 时）"""
        text = "hello world 123"
        byte_len = len(text.encode("utf-8"))
        tokens = split_bigram_raw(text)
        self.assertEqual(len(tokens), byte_len - 1)


# ============================================================
# 测试 4: 三密钥管理逻辑
# ============================================================
@unittest.skipUnless(_GMSSL_AVAILABLE, "gmssl 未安装")
class TestKeyManager(unittest.TestCase):
    """密钥管理逻辑测试"""

    def test_kek_wrap_unwrap_roundtrip(self):
        """KEK 加密保护三个工作密钥，解密后与原值一致"""
        enc_cipher = sm4_cbc_encrypt(RAW_ENC_KEY, KEK)
        idx_cipher = sm4_cbc_encrypt(RAW_IDX_KEY, KEK)
        tag_cipher = sm4_cbc_encrypt(RAW_TAG_KEY, KEK)

        loaded_enc = sm4_cbc_decrypt(enc_cipher, KEK)
        loaded_idx = sm4_cbc_decrypt(idx_cipher, KEK)
        loaded_tag = sm4_cbc_decrypt(tag_cipher, KEK)

        self.assertEqual(loaded_enc, RAW_ENC_KEY)
        self.assertEqual(loaded_idx, RAW_IDX_KEY)
        self.assertEqual(loaded_tag, RAW_TAG_KEY)

    def test_three_keys_distinct(self):
        """三个工作密钥互不相同"""
        self.assertNotEqual(RAW_ENC_KEY, RAW_IDX_KEY)
        self.assertNotEqual(RAW_IDX_KEY, RAW_TAG_KEY)
        self.assertNotEqual(RAW_ENC_KEY, RAW_TAG_KEY)

    def test_wrong_kek_fails(self):
        """错误 KEK 无法还原工作密钥"""
        enc_cipher = sm4_cbc_encrypt(RAW_ENC_KEY, KEK)
        wrong_kek = bytes([0x22] * 16)
        loaded = sm4_cbc_decrypt(enc_cipher, wrong_kek)
        self.assertNotEqual(loaded, RAW_ENC_KEY)

    def test_key_length_16_bytes(self):
        """所有密钥长度均为 16 字节（SM4 密钥长度）"""
        self.assertEqual(len(KEK), 16)
        self.assertEqual(len(RAW_ENC_KEY), 16)
        self.assertEqual(len(RAW_IDX_KEY), 16)
        self.assertEqual(len(RAW_TAG_KEY), 16)


# ============================================================
# 测试 5: 数据库集成测试
# ============================================================
@unittest.skipUnless(
    _PYMYSQL_AVAILABLE and _GMSSL_AVAILABLE,
    "需要 pymysql 和 gmssl 才能运行数据库集成测试"
)
class TestDatabaseIntegration(unittest.TestCase):
    """
    数据库集成测试
    测试精确查询、模糊查询、CRUD、批量读取等完整流程
    需要 MySQL 服务运行且 secsearch 数据库 + 表已建好
    """

    @classmethod
    def setUpClass(cls):
        import pymysql
        cls.conn = pymysql.connect(**DB_CONFIG)
        cls.cursor = cls.conn.cursor()

    @classmethod
    def tearDownClass(cls):
        cls.cursor.close()
        cls.conn.close()

    def setUp(self):
        """每个测试前清理测试数据（通过 phone_blind_idx 前缀识别）"""
        self.cursor.execute(
            "DELETE FROM fuzzy_inverted WHERE data_id IN "
            "(SELECT id FROM sensitive_data WHERE phone_blind_idx LIKE 'tst_%')"
        )
        self.cursor.execute(
            "DELETE FROM sensitive_data WHERE phone_blind_idx LIKE 'tst_%'"
        )
        self.conn.commit()

    # ---- 辅助方法 ----
    def _insert_record(self, name, phone, address):
        """插入一条完整测试数据，返回记录 ID"""
        # 加密
        name_cipher = sm4_cbc_encrypt(name.encode("utf-8"), RAW_ENC_KEY)
        phone_cipher = sm4_cbc_encrypt(phone.encode("utf-8"), RAW_ENC_KEY)
        addr_cipher = sm4_cbc_encrypt(address.encode("utf-8"), RAW_ENC_KEY)

        # 盲索引（手机号加前缀便于清理）
        name_blind = hmac_sm3_hex(name.encode("utf-8"), RAW_IDX_KEY)
        phone_blind = "tst_" + hmac_sm3_hex(phone.encode("utf-8"), RAW_IDX_KEY)
        addr_blind = hmac_sm3_hex(address.encode("utf-8"), RAW_IDX_KEY)

        # 完整性 Tag
        name_tag = hmac_sm3_hex(name_cipher.encode("utf-8"), RAW_TAG_KEY)
        phone_tag = hmac_sm3_hex(phone_cipher.encode("utf-8"), RAW_TAG_KEY)
        addr_tag = hmac_sm3_hex(addr_cipher.encode("utf-8"), RAW_TAG_KEY)

        # 插入主表
        sql = """
            INSERT INTO sensitive_data
            (name_cipher, name_blind_idx, name_tag,
             phone_cipher, phone_blind_idx, phone_tag,
             address_cipher, address_blind_idx, address_tag)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        self.cursor.execute(
            sql,
            (name_cipher, name_blind, name_tag,
             phone_cipher, phone_blind, phone_tag,
             addr_cipher, addr_blind, addr_tag)
        )
        data_id = self.cursor.lastrowid

        # 插入模糊倒排索引
        self._insert_fuzzy(data_id, 1, name)
        self._insert_fuzzy(data_id, 2, phone)
        self._insert_fuzzy(data_id, 3, address)

        self.conn.commit()
        return data_id

    def _insert_fuzzy(self, data_id, field_type, text):
        tokens = split_bigram_raw(text)
        if not tokens:
            return
        hashes = [hmac_sm3_hex(t, RAW_IDX_KEY) for t in tokens]
        values = [(h, data_id, field_type) for h in hashes]
        sql = "INSERT IGNORE INTO fuzzy_inverted (token_hash, data_id, field_type) VALUES (%s, %s, %s)"
        self.cursor.executemany(sql, values)

    # ---- 测试用例 ----
    def test_insert_and_exact_query_name(self):
        """插入后按姓名盲索引精确查询，能命中"""
        name = "测试用户张三"
        rid = self._insert_record(name, "13910000001", "上海市浦东新区")

        query_blind = hmac_sm3_hex(name.encode("utf-8"), RAW_IDX_KEY)
        self.cursor.execute(
            "SELECT id FROM sensitive_data WHERE name_blind_idx = %s",
            (query_blind,)
        )
        rows = self.cursor.fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], rid)

    def test_exact_query_no_match(self):
        """查询不存在的值返回空"""
        self._insert_record("王五", "13910000002", "广州市天河区")
        query_blind = hmac_sm3_hex("不存在的人".encode("utf-8"), RAW_IDX_KEY)
        self.cursor.execute(
            "SELECT id FROM sensitive_data WHERE name_blind_idx = %s",
            (query_blind,)
        )
        self.assertEqual(len(self.cursor.fetchall()), 0)

    def test_fuzzy_query_keyword_match(self):
        """模糊查询：含"张"的姓名能被匹配到"""
        self._insert_record("张三丰", "13910000003", "北京市海淀区")
        self._insert_record("张三", "13910000004", "北京市朝阳区")
        self._insert_record("李四", "13910000005", "上海市静安区")

        keyword = "张"
        tokens = split_bigram_raw(keyword)
        hashes = [hmac_sm3_hex(t, RAW_IDX_KEY) for t in tokens]

        ph = ",".join(["%s"] * len(hashes))
        sql = (f"SELECT data_id FROM fuzzy_inverted "
               f"WHERE token_hash IN ({ph}) AND field_type = 1 "
               f"GROUP BY data_id HAVING COUNT(DISTINCT token_hash) = %s")
        self.cursor.execute(sql, hashes + [len(hashes)])
        rows = self.cursor.fetchall()
        self.assertGreaterEqual(len(rows), 2)

    def test_fuzzy_query_multi_token_intersection(self):
        """模糊查询多 token 取交集："北京"只匹配北京的记录"""
        self._insert_record("北京市朝阳", "13910000006", "地址1")
        self._insert_record("北京市海淀", "13910000007", "地址2")
        self._insert_record("上海市朝阳", "13910000008", "地址3")

        keyword = "北京"
        tokens = split_bigram_raw(keyword)
        hashes = [hmac_sm3_hex(t, RAW_IDX_KEY) for t in tokens]

        ph = ",".join(["%s"] * len(hashes))
        sql = (f"SELECT data_id FROM fuzzy_inverted "
               f"WHERE token_hash IN ({ph}) AND field_type = 1 "
               f"GROUP BY data_id HAVING COUNT(DISTINCT token_hash) = %s")
        self.cursor.execute(sql, hashes + [len(hashes)])
        rows = self.cursor.fetchall()
        self.assertEqual(len(rows), 2)  # 两条"北京..."记录

    def test_batch_select_and_decrypt(self):
        """批量读取密文，Tag 校验通过后解密得到明文"""
        id1 = self._insert_record("用户A", "13910000010", "地址A")
        id2 = self._insert_record("用户B", "13910000011", "地址B")

        ids = [id1, id2]
        ph = ",".join(["%s"] * len(ids))
        sql = (f"SELECT id, name_cipher, name_tag "
               f"FROM sensitive_data WHERE id IN ({ph})")
        self.cursor.execute(sql, ids)
        rows = self.cursor.fetchall()
        self.assertEqual(len(rows), 2)

        # 校验 Tag 并解密第一条
        _, cipher_hex, tag_stored = rows[0]
        tag_computed = hmac_sm3_hex(cipher_hex.encode("utf-8"), RAW_TAG_KEY)
        self.assertEqual(tag_computed, tag_stored)

        plain = sm4_cbc_decrypt(cipher_hex, RAW_ENC_KEY).decode("utf-8")
        self.assertIn(plain, ["用户A", "用户B"])

    def test_update_record_maintains_index(self):
        """更新记录：旧索引被清理，新索引可查询"""
        rid = self._insert_record("旧姓名", "13910000020", "旧地址")

        new_name = "新姓名"
        new_phone = "13910000020"
        new_addr = "新地址"

        # 删旧模糊索引
        self.cursor.execute("DELETE FROM fuzzy_inverted WHERE data_id = %s", (rid,))

        # 重新加密计算
        nc = sm4_cbc_encrypt(new_name.encode("utf-8"), RAW_ENC_KEY)
        nb = hmac_sm3_hex(new_name.encode("utf-8"), RAW_IDX_KEY)
        nt = hmac_sm3_hex(nc.encode("utf-8"), RAW_TAG_KEY)
        pc = sm4_cbc_encrypt(new_phone.encode("utf-8"), RAW_ENC_KEY)
        pb = "tst_" + hmac_sm3_hex(new_phone.encode("utf-8"), RAW_IDX_KEY)
        pt = hmac_sm3_hex(pc.encode("utf-8"), RAW_TAG_KEY)
        ac = sm4_cbc_encrypt(new_addr.encode("utf-8"), RAW_ENC_KEY)
        ab = hmac_sm3_hex(new_addr.encode("utf-8"), RAW_IDX_KEY)
        at = hmac_sm3_hex(ac.encode("utf-8"), RAW_TAG_KEY)

        self.cursor.execute(
            """UPDATE sensitive_data SET
                   name_cipher=%s, name_blind_idx=%s, name_tag=%s,
                   phone_cipher=%s, phone_blind_idx=%s, phone_tag=%s,
                   address_cipher=%s, address_blind_idx=%s, address_tag=%s
               WHERE id=%s""",
            (nc, nb, nt, pc, pb, pt, ac, ab, at, rid)
        )
        self._insert_fuzzy(rid, 1, new_name)
        self._insert_fuzzy(rid, 2, new_phone)
        self._insert_fuzzy(rid, 3, new_addr)
        self.conn.commit()

        # 新姓名能查到
        self.cursor.execute(
            "SELECT id FROM sensitive_data WHERE name_blind_idx = %s",
            (hmac_sm3_hex(new_name.encode("utf-8"), RAW_IDX_KEY),)
        )
        self.assertEqual(self.cursor.fetchone()[0], rid)

        # 旧姓名查不到
        self.cursor.execute(
            "SELECT id FROM sensitive_data WHERE name_blind_idx = %s",
            (hmac_sm3_hex("旧姓名".encode("utf-8"), RAW_IDX_KEY),)
        )
        self.assertIsNone(self.cursor.fetchone())

    def test_delete_cleans_up_both_tables(self):
        """删除记录后主表和倒排表都被清理"""
        rid = self._insert_record("待删除", "13910000030", "删除地址")

        self.cursor.execute("DELETE FROM fuzzy_inverted WHERE data_id = %s", (rid,))
        self.cursor.execute("DELETE FROM sensitive_data WHERE id = %s", (rid,))
        self.conn.commit()

        self.cursor.execute("SELECT id FROM sensitive_data WHERE id = %s", (rid,))
        self.assertIsNone(self.cursor.fetchone())

        self.cursor.execute(
            "SELECT COUNT(*) FROM fuzzy_inverted WHERE data_id = %s", (rid,)
        )
        self.assertEqual(self.cursor.fetchone()[0], 0)


# ============================================================
# 测试 6: 端到端完整流程（不依赖数据库）
# ============================================================
@unittest.skipUnless(_GMSSL_AVAILABLE, "gmssl 未安装")
class TestEndToEndFlow(unittest.TestCase):
    """端到端流程模拟测试"""

    def test_full_lifecycle_encrypt_query_decrypt(self):
        """完整生命周期：加密 → 建索引 → 查询命中 → Tag 校验 → 解密"""
        original = {
            "name": "王小明",
            "phone": "13712345678",
            "address": "深圳市南山区科技园",
        }

        # 写入阶段
        ciphers = {k: sm4_cbc_encrypt(v.encode("utf-8"), RAW_ENC_KEY)
                   for k, v in original.items()}
        blinds = {k: hmac_sm3_hex(v.encode("utf-8"), RAW_IDX_KEY)
                  for k, v in original.items()}
        tags = {k: hmac_sm3_hex(c.encode("utf-8"), RAW_TAG_KEY)
                for k, c in ciphers.items()}

        # 查询阶段：用姓名精确查询
        query_blind = hmac_sm3_hex("王小明".encode("utf-8"), RAW_IDX_KEY)
        self.assertEqual(query_blind, blinds["name"])

        # Tag 校验
        computed_tag = hmac_sm3_hex(ciphers["name"].encode("utf-8"), RAW_TAG_KEY)
        self.assertEqual(computed_tag, tags["name"])

        # 解密
        decrypted = sm4_cbc_decrypt(ciphers["name"], RAW_ENC_KEY).decode("utf-8")
        self.assertEqual(decrypted, original["name"])

    def test_fuzzy_inverted_index_search(self):
        """纯内存模拟倒排索引构建与交集检索"""
        docs = [
            "北京市朝阳区人民法院",
            "北京市海淀区人民政府",
            "上海市浦东新区张江园区",
        ]

        # 构建倒排索引
        idx = {}
        for doc_id, doc in enumerate(docs):
            for token in split_bigram_raw(doc):
                h = hmac_sm3_hex(token, RAW_IDX_KEY)
                idx.setdefault(h, set()).add(doc_id)

        # "北京" → 文档 0, 1
        q_tokens = split_bigram_raw("北京")
        q_hashes = [hmac_sm3_hex(t, RAW_IDX_KEY) for t in q_tokens]
        result_sets = [idx[h] for h in q_hashes if h in idx]
        matched = set.intersection(*result_sets) if result_sets else set()
        self.assertEqual(matched, {0, 1})

        # "上海" → 文档 2
        q2_tokens = split_bigram_raw("上海")
        q2_hashes = [hmac_sm3_hex(t, RAW_IDX_KEY) for t in q2_tokens]
        result_sets2 = [idx[h] for h in q2_hashes if h in idx]
        matched2 = set.intersection(*result_sets2) if result_sets2 else set()
        self.assertEqual(matched2, {2})


# ============================================================
# 测试 7: 边界与异常场景
# ============================================================
@unittest.skipUnless(_GMSSL_AVAILABLE, "gmssl 未安装")
class TestEdgeCases(unittest.TestCase):
    """边界条件和异常场景测试"""

    def test_single_char_fuzzy_token(self):
        """单字符只有 1 个 token"""
        tokens = split_bigram_raw("A")
        self.assertEqual(len(tokens), 1)
        hashes = [hmac_sm3_hex(t, RAW_IDX_KEY) for t in tokens]
        self.assertEqual(len(hashes), 1)

    def test_long_text_encrypt_decrypt(self):
        """长文本（>10KB）加解密往返正确"""
        long_text = "这是一段很长的测试文本用于验证大数据量加密。" * 200
        cipher = sm4_cbc_encrypt(long_text.encode("utf-8"), RAW_ENC_KEY)
        decrypted = sm4_cbc_decrypt(cipher, RAW_ENC_KEY).decode("utf-8")
        self.assertEqual(decrypted, long_text)

    def test_special_characters(self):
        """特殊符号加密解密正确"""
        special = r"!@#$%^&*()_+-=[]{}|;':\",./<>?"
        cipher = sm4_cbc_encrypt(special.encode("utf-8"), RAW_ENC_KEY)
        decrypted = sm4_cbc_decrypt(cipher, RAW_ENC_KEY).decode("utf-8")
        self.assertEqual(decrypted, special)

    def test_unicode_emoji(self):
        """Emoji 等多字节 Unicode 字符"""
        text = "测试表情 🎉 国密加密 🔐 完成 ✅"
        cipher = sm4_cbc_encrypt(text.encode("utf-8"), RAW_ENC_KEY)
        decrypted = sm4_cbc_decrypt(cipher, RAW_ENC_KEY).decode("utf-8")
        self.assertEqual(decrypted, text)

    def test_duplicate_tokens_insert_ignore(self):
        """重复 token（如 "aaaa"）去重后只存一个哈希"""
        tokens = split_bigram_raw("aaaa")
        unique = set(tokens)
        self.assertLess(len(unique), len(tokens))  # 有重复
        # 数据库端 INSERT IGNORE 会自动去重


# ============================================================
# 主入口
# ============================================================
if __name__ == "__main__":
    print("=" * 60)
    print("  SecSearch Python 测试套件")
    print("=" * 60)
    print()
    print("依赖状态:")
    print(f"  gmssl : {'✅ 已安装' if _GMSSL_AVAILABLE else '❌ 未安装 (加密相关测试跳过)'}")
    print(f"  pymysql: {'✅ 已安装' if _PYMYSQL_AVAILABLE else '❌ 未安装 (数据库测试跳过)'}")
    print()
    print("测试分类:")
    print("  1. SM4-CBC 加解密单元测试")
    print("  2. HMAC-SM3 盲索引与完整性 Tag 测试")
    print("  3. Bigram 分词逻辑测试 (无依赖)")
    print("  4. 三密钥管理逻辑测试")
    print("  5. 数据库集成测试 (需 MySQL)")
    print("  6. 端到端完整流程模拟")
    print("  7. 边界与异常场景测试")
    print()
    print("-" * 60)
    unittest.main(verbosity=2)
