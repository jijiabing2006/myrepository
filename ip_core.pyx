# -*- coding: utf-8 -*-
"""
=============================================================================
  ip_core —— 客户侧安全核心（防破解关键模块）
=============================================================================
  本模块集中存放所有【安全敏感 / 防破解核心】逻辑，随交付以编译后的
  原生二进制扩展 .pyd 形式发布（用 py2pydso + Cython 编译，源码不交付）。

  纳入本模块的内容（均属“拿到即可绕开/窃取数据”的关键）：
    1. AES 数据库/更新包加解密密钥（XOR 混淆内嵌，运行期还原）
    2. RSA 公钥 + license.key 签名与有效期校验
    3. 整库加密 ip_data.db.enc 的解密/加密、临时明文生命周期管理
    4. 加密更新包 update_package.zip.enc 的解密解包
    5. IP 点分 <-> 32 位无符号整数转换
    6. 单 IP 归属查询（对解密临时库执行区间匹配）

  设计目标：攻击者即使拿到 .pyd 与全部明文 .py，也无法在缺少本模块
  二进制的前提下还原 AES 密钥 / 绕开 License 校验 / 解密 .enc 库。
  由于本模块编译为原生 C 扩展并剥离符号、混淆内嵌字节，
  反编译还原密钥的逻辑成本远高于收益，达成“难以破解”的工程目标。

  ---------- 边界说明 ----------
  ip_core 是【无状态、纯逻辑】模块：不做 HTTP、不读写配置文件、
  不负责导出 SQL 的编排。它只把“密钥 / 验签 / 库解密 / 查询”这些
  原子能力暴露给上层薄壳（ip_tool / http_api / export_sql）。

  密钥更换：外网侧重跑 gen_license.py --keygen 并重生成 license.key，
  再以相同方式更新本模块内的 XOR 混淆字节与 RSA 公钥后重新编译。
=============================================================================
"""
import base64
import io
import json
import os
import tempfile
import zipfile
from contextlib import contextmanager
from datetime import date

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

# ---------------------------------------------------------------------------
# 1) 区分密钥与验签用的 RSA 公钥（随 exe 发布，编译后不落明文）
# ---------------------------------------------------------------------------
RSA_PUBLIC_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz6U1bsTzXadhjXb4ekeA
Ohnsced+2wYj5AwEQmxMpKnZK2xTh8tCvoJjc7nfdlcI3IdsX6lo29XbE6PIh9MG
a9W+pXM8nJ/zcg2fPczBji2ILWW0kAMFK5XVdBJMR33dWjc0tv1Wrp7HkvuIs+Tp
1jfNj2bJzSR/aUi+pA1E+I3lT6jSyeaQsyNpbtDcLqwYX380VvJ0RbM/t7cvU44g
r1zZAAM2cnTVVo2z3LkGk5/2jfoRmr3wrTtDCyBDgk735uPm0xew3qKAzEHRRnMh
i7AxFLhm+ie6e5OqriI/SsBIWzyO+ouSMBg4sYc/C/wCkB4KuzPmQetrXcgzYigt
TwIDAQAB
-----END PUBLIC KEY-----"""

# AES 密钥（base64 文本）逐字节异或 0x5A 后的字节串 —— 编译后不落明文
_AES_XOR = b'";-3\x11k2\x02 j\x0b\x00\x10(+\x08?\x1c\x18q \x021\x192\x1dnl\t0/\x1ec=l0\x13\x0e9\x18=h\x03g'


def get_aes_key() -> bytes:
    """运行期还原 AES-256 密钥（异或还原 -> base64 解码）。"""
    b64 = bytes(b ^ 0x5A for b in _AES_XOR).decode()
    return base64.b64decode(b64)


# ---------------------------------------------------------------------------
# 2) license.key 校验（RSA 签名 + 有效期）
# ---------------------------------------------------------------------------
def _canonical(customer: str, issued_at: str, expires_at: str) -> str:
    return json.dumps(
        {"customer": customer, "issued_at": issued_at, "expires_at": expires_at},
        sort_keys=True, ensure_ascii=False, separators=(",", ":"),
    )


def check_license(path: str = "license.key", pub_pem: str = RSA_PUBLIC_PEM):
    """
    校验授权证书。返回 (ok: bool, msg: str)。
    校验：文件存在、JSON 可解析、RSA 签名有效、未过期。
    """
    if not os.path.exists(path):
        return False, f"缺少授权文件 {path}（请与 exe 放在同一目录）"
    try:
        with open(path, "r", encoding="utf-8") as f:
            lic = json.load(f)
        customer = lic["customer"]
        issued_at = lic["issued_at"]
        expires_at = lic["expires_at"]
        sig_b64 = lic["seal"]
    except (KeyError, json.JSONDecodeError) as e:
        return False, f"授权文件格式错误: {e}"

    try:
        pub = RSA.import_key(pub_pem)
        payload = _canonical(customer, issued_at, expires_at)
        h = SHA256.new(payload.encode("utf-8"))
        pkcs1_15.new(pub).verify(h, base64.b64decode(sig_b64))
    except (ValueError, TypeError) as e:
        return False, "授权签名校验失败，证书可能被篡改"

    try:
        expires = date.fromisoformat(expires_at)
    except ValueError:
        return False, f"有效期格式错误: {expires_at}"
    if expires < date.today():
        return False, f"授权已过期（{expires_at}），请联系我方续期"
    return True, f"授权有效  客户={customer}  有效期至 {expires_at}"


# ---------------------------------------------------------------------------
# 3) 整库加密 ip_data.db.enc（AES-GCM）
# ---------------------------------------------------------------------------
DB_MAGIC = b"IPDB"
DB_NONCE_LEN = 12
DB_TAG_LEN = 16
DB_FILE_NAME = "ip_data.db"
DB_ENC_FILE_NAME = "ip_data.db.enc"


def db_enc_path(base_dir: str) -> str:
    return os.path.join(base_dir, DB_ENC_FILE_NAME)


def db_plain_path(base_dir: str) -> str:
    return os.path.join(base_dir, DB_FILE_NAME)


def encrypt_blob(key: bytes, data: bytes) -> bytes:
    """AES-GCM 加密 -> MAGIC + nonce + tag + 密文。"""
    nonce = os.urandom(DB_NONCE_LEN)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(data)
    return DB_MAGIC + nonce + tag + ct


def decrypt_blob(key: bytes, blob: bytes) -> bytes:
    """解密 -> 明文。magic 不符或密钥错误抛 ValueError。"""
    if not blob.startswith(DB_MAGIC):
        raise ValueError("不是合法的加密库文件（magic 不匹配）")
    if len(blob) < len(DB_MAGIC) + DB_NONCE_LEN + DB_TAG_LEN:
        raise ValueError("加密库文件长度不完整")
    nonce = blob[len(DB_MAGIC):len(DB_MAGIC) + DB_NONCE_LEN]
    tag = blob[len(DB_MAGIC) + DB_NONCE_LEN:len(DB_MAGIC) + DB_NONCE_LEN + DB_TAG_LEN]
    ct = blob[len(DB_MAGIC) + DB_NONCE_LEN + DB_TAG_LEN:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)


def encrypt_file(key: bytes, src_path: str, dst_path: str) -> None:
    """明文文件 -> 加密写入 dst（原子替换）。"""
    with open(src_path, "rb") as f:
        blob = encrypt_blob(key, f.read())
    dst_dir = os.path.dirname(os.path.abspath(dst_path))
    fd, tmp = tempfile.mkstemp(prefix="ipdb_enc_", suffix=".tmp", dir=dst_dir)
    os.close(fd)
    try:
        with open(tmp, "wb") as f:
            f.write(blob)
        os.replace(tmp, dst_path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def decrypt_file(key: bytes, src_path: str, dst_path: str) -> None:
    """加密库文件 -> 明文临时文件。"""
    with open(src_path, "rb") as f:
        blob = f.read()
    data = decrypt_blob(key, blob)
    with open(dst_path, "wb") as f:
        f.write(data)


def migrate_if_needed(base_dir: str, key: bytes) -> None:
    """旧版明文 ip_data.db -> 加密 .enc 的一次性迁移。"""
    plain, enc = db_plain_path(base_dir), db_enc_path(base_dir)
    if os.path.exists(plain):
        if not os.path.exists(enc):
            encrypt_file(key, plain, enc)
        os.remove(plain)


@contextmanager
def open_db(base_dir: str, key: bytes, writable: bool = False):
    """解密 .enc 到系统临时明文，yield 临时路径；结束清理。"""
    migrate_if_needed(base_dir, key)
    enc = db_enc_path(base_dir)
    if not os.path.exists(enc) and not writable:
        raise FileNotFoundError("本地数据库不存在，请先执行「1 更新本地IP数据库」")
    fd, tmp = tempfile.mkstemp(prefix="ipdb_", suffix=".db")
    os.close(fd)
    try:
        if os.path.exists(enc):
            decrypt_file(key, enc, tmp)
        yield tmp
        if writable:
            encrypt_file(key, tmp, enc)
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# 4) 加密更新包 update_package.zip.enc 的解密解包（AES-GCM）
# ---------------------------------------------------------------------------
PKG_MAGIC = b"IPPK"
PKG_NONCE_LEN = 12
PKG_TAG_LEN = 16


def decrypt_package(key: bytes, blob: bytes) -> bytes:
    """解密更新包 -> zip 字节流。格式不符或密钥错误抛异常。"""
    if not blob.startswith(PKG_MAGIC):
        raise ValueError("不是合法的加密包（magic 不匹配）")
    if len(blob) < len(PKG_MAGIC) + PKG_NONCE_LEN + PKG_TAG_LEN:
        raise ValueError("加密包长度不完整")
    nonce = blob[len(PKG_MAGIC):len(PKG_MAGIC) + PKG_NONCE_LEN]
    tag = blob[len(PKG_MAGIC) + PKG_NONCE_LEN:len(PKG_MAGIC) + PKG_NONCE_LEN + PKG_TAG_LEN]
    ct = blob[len(PKG_MAGIC) + PKG_NONCE_LEN + PKG_TAG_LEN:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)


def read_sql_from_pkg(key: bytes, blob: bytes) -> str:
    """解密并解包，返回 update.sql 文本（全程内存，不落盘）。"""
    zip_bytes = decrypt_package(key, blob)
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        names = z.namelist()
        if "update.sql" not in names:
            raise ValueError(f"包内缺少 update.sql（实际内容: {names}）")
        return z.read("update.sql").decode("utf-8")


# ---------------------------------------------------------------------------
# 5) IP 转换
# ---------------------------------------------------------------------------
def ip_to_int32(ip: str) -> int:
    """IPv4 点分十进制 -> 32 位无符号整数。含 IPv6 抛 ValueError。"""
    ip = ip.strip()
    if ":" in ip:
        raise ValueError(f"当前仅支持 IPv4 查询: {ip}")
    parts = ip.split(".")
    if len(parts) != 4:
        raise ValueError(f"非法 IP 地址: {ip}")
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        raise ValueError(f"非法 IP 地址: {ip}") from None
    if any(n < 0 or n > 255 for n in nums):
        raise ValueError(f"非法 IP 地址: {ip}")
    return (nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]


def int_to_ip(n: int) -> str:
    """32 位无符号整数 -> IPv4 点分十进制。"""
    return ".".join(str((n >> s) & 0xFF) for s in (24, 16, 8, 0))


# ---------------------------------------------------------------------------
# 6) 单 IP 归属查询（对解密后的临时库执行区间匹配）
#    —— 该函数不涉及明文库落盘，仅对调用方提供的临时路径做只读查询
# ---------------------------------------------------------------------------
def query_geo(db_plain_path: str, ip_int: int):
    """
    在解密后的临时 SQLite 库上做区间归属查询。
    返回命中 dict 或 None；库不存在/未命中返回 None。
    """
    if not os.path.exists(db_plain_path):
        return None
    import sqlite3
    conn = sqlite3.connect(db_plain_path)
    try:
        row = conn.execute(
            "SELECT IP_START_NUMBER, IP_END_NUMBER, COUNTRY, COUNTRYCODE, "
            "COUNTRYCN, REGIONNAMECN, CITYCN FROM ip_address "
            "WHERE IP_START_NUMBER <= ? AND IP_END_NUMBER >= ? "
            "ORDER BY IP_START_NUMBER DESC LIMIT 1",
            (ip_int, ip_int),
        ).fetchone()
        if not row:
            return None
        return {
            "ip_start_num": row[0], "ip_end_num": row[1],
            "country": row[2] or "-", "country_code": row[3] or "-",
            "country_cn": row[4] or "-", "region": row[5] or "-",
            "city": row[6] or "-",
        }
    finally:
        conn.close()
