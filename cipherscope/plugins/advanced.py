"""高级编码/结构化插件: Unicode 转义 / HTML 实体 / Quoted-Printable / Punycode /
Zlib / Gzip / JWT 解析(含 HS256 弱密钥爆破) / ISO-8859-1 乱码修复。

设计原则: 全部为"确定性解码"(结构验证即可信), 关键场景标记 verified 短路,
不依赖统计评分背书——例如 JWT 三段 base64url + header JSON 结构即确定性结果。
"""
from __future__ import annotations

import base64
import binascii
import codecs
import gzip
import hashlib
import hmac
import html
import json
import quopri
import re
import zlib
from typing import Iterator

from cipherscope.core.plugin import Candidate

# ---------------------------------------------------- Unicode 转义

_UNICODE_ESC_RE = re.compile(r"(?:\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8})")


class UnicodeEscapePlugin:
    """Unicode 转义序列解码: \\u4f60\\u597d -> 你好 (也处理 \\U00004f60)。
    CTF 高频题型(中文 flag 的 Unicode 表示)。"""

    name = "unicode-escape"
    category = "codec"

    def match(self, ct: bytes) -> float:
        try:
            text = ct.decode("utf-8")
        except UnicodeDecodeError:
            return 0.0
        hits = _UNICODE_ESC_RE.findall(text)
        if len(hits) >= 2:
            return 0.9
        if len(hits) == 1 and len(ct) < 40:
            return 0.7
        return 0.0

    def attack(self, ct: bytes) -> Iterator[Candidate]:
        text = ct.decode("utf-8", errors="ignore")

        def repl(m: re.Match) -> str:
            h = m.group(0)[2:]
            return chr(int(h, 16))

        pt = _UNICODE_ESC_RE.sub(repl, text)
        yield Candidate(plaintext=pt.encode(), method="unicode-escape-decode", chain=["unicode"])


# ---------------------------------------------------- HTML 实体

_HTML_ENTITY_RE = re.compile(r"&#x?[0-9a-fA-F]+;|&[a-zA-Z]+;")


class HtmlEntityPlugin:
    """HTML 实体解码: &#x4f60;&#x597d; -> 你好; &amp;lt; 等命名实体。"""

    name = "html-entity"
    category = "codec"

    def match(self, ct: bytes) -> float:
        try:
            text = ct.decode("utf-8")
        except UnicodeDecodeError:
            return 0.0
        hits = _HTML_ENTITY_RE.findall(text)
        if len(hits) >= 2:
            return 0.9
        if len(hits) == 1 and text.startswith("&#"):
            return 0.6
        return 0.0

    def attack(self, ct: bytes) -> Iterator[Candidate]:
        text = ct.decode("utf-8", errors="ignore")
        yield Candidate(plaintext=html.unescape(text).encode(), method="html-entity-decode", chain=["html-entity"])


# ---------------------------------------------------- Quoted-Printable

_QP_RE = re.compile(r"=[0-9a-fA-F]{2}")


class QuotedPrintablePlugin:
    """Quoted-Printable (RFC 2045): =E4=BD=A0 -> 你好。MIME 文本编码, CTF 偶见。"""

    name = "quoted-printable"
    category = "codec"

    def match(self, ct: bytes) -> float:
        try:
            text = ct.decode("ascii")
        except UnicodeDecodeError:
            return 0.0
        hits = _QP_RE.findall(text)
        if len(hits) >= 3:
            return 0.85
        return 0.0

    def attack(self, ct: bytes) -> Iterator[Candidate]:
        text = ct.decode("ascii", errors="ignore")
        try:
            pt = quopri.decodestring(text.encode("ascii"))
        except (binascii.Error, ValueError):
            return
        yield Candidate(plaintext=pt, method="quoted-printable-decode", chain=["qp"])


# ---------------------------------------------------- Punycode

class PunycodePlugin:
    """Punycode 解码: xn--fiq228c -> 中文。国际域名编码, CTF 中文题偶见。"""

    name = "punycode"
    category = "codec"

    def match(self, ct: bytes) -> float:
        try:
            text = ct.decode("ascii").strip().lower()
        except UnicodeDecodeError:
            return 0.0
        return 0.95 if "xn--" in text else 0.0

    def attack(self, ct: bytes) -> Iterator[Candidate]:
        text = ct.decode("ascii", errors="ignore").strip()
        try:
            out = []
            for label in text.split("."):
                if label.startswith("xn--"):
                    raw = label[4:]
                    if not raw:
                        return
                    out.append(codecs.decode(raw.encode("ascii"), "punycode"))
                else:
                    out.append(label)
            pt = ".".join(out).encode()
        except (UnicodeDecodeError, ValueError, IndexError):
            return
        yield Candidate(plaintext=pt, method="punycode-decode", chain=["punycode"])


# ---------------------------------------------------- Zlib 解压

_ZLIB_MAGIC = {(0x78, 0x9C), (0x78, 0xDA), (0x78, 0x01), (0x78, 0x5E), (0x78, 0x9F)}


class ZlibPlugin:
    """zlib 压缩数据解压: 识别 0x78 开头 magic 并 zlib.decompress。
    产物为原始字节(文本/图片), CTF 压缩数据题常见。"""

    name = "zlib"
    category = "codec"

    def match(self, ct: bytes) -> float:
        if len(ct) < 4:
            return 0.0
        if (ct[0], ct[1]) not in _ZLIB_MAGIC:
            return 0.0
        try:
            zlib.decompress(ct)
            return 0.95
        except zlib.error:
            return 0.0

    def attack(self, ct: bytes) -> Iterator[Candidate]:
        try:
            pt = zlib.decompress(ct)
        except zlib.error:
            return
        yield Candidate(plaintext=pt, method="zlib-decompress", chain=["zlib"])


# ---------------------------------------------------- Gzip 解压

class GzipPlugin:
    """gzip 数据解压: 识别 1f 8b magic 并 gzip.decompress。"""

    name = "gzip"
    category = "codec"

    def match(self, ct: bytes) -> float:
        if len(ct) < 10 or ct[:2] != b"\x1f\x8b":
            return 0.0
        try:
            gzip.decompress(ct)
            return 0.95
        except (OSError, EOFError):
            return 0.0

    def attack(self, ct: bytes) -> Iterator[Candidate]:
        try:
            pt = gzip.decompress(ct)
        except (OSError, EOFError):
            return
        yield Candidate(plaintext=pt, method="gzip-decompress", chain=["gzip"])


# ---------------------------------------------------- JWT 解析

_JWT_SECRETS = (
    "secret secretkey key admin password 123456 12345678 qwerty "
    "flag ctf crypto cipher token jwt none nssctf buu "
    "supersecret letmein iloveyou abc123 root passw0rd"
).split()


class JwtPlugin:
    """JWT 解析: 三段 base64url(header.payload.signature)。结构验证即确定性结果:
    header 必须是合法 JSON。同时尝试 HS256 弱密钥爆破(内置常见密钥表)。"""

    name = "jwt"
    category = "codec"

    def match(self, ct: bytes) -> float:
        try:
            text = ct.decode("ascii").strip()
        except UnicodeDecodeError:
            return 0.0
        parts = text.split(".")
        if len(parts) != 3 or not all(parts):
            return 0.0
        try:
            header = json.loads(_b64url_decode(parts[0]))
        except Exception:
            return 0.0
        return 0.95 if isinstance(header, dict) and "alg" in header else 0.0

    def attack(self, ct: bytes) -> Iterator[Candidate]:
        text = ct.decode("ascii", errors="ignore").strip()
        parts = text.split(".")
        if len(parts) != 3:
            return
        try:
            header = json.loads(_b64url_decode(parts[0]))
            payload_b = _b64url_decode(parts[1])
            payload = json.loads(payload_b)
        except Exception:
            return
        # 解析结果: 确定性, verified 短路(绕过统计评分——JSON 不属于自然语言)
        display = json.dumps({"header": header, "payload": payload}, ensure_ascii=False, indent=2)
        yield Candidate(
            plaintext=display.encode(),
            method=f"jwt-parse(alg={header.get('alg', '?')})",
            chain=["jwt:parse"],
            verified=True,
        )
        # HS256 弱密钥爆破: 签名验证通过即确定性命中
        if str(header.get("alg", "")).upper() == "HS256":
            msg = f"{parts[0]}.{parts[1]}".encode()
            sig = parts[2]
            for secret in _JWT_SECRETS:
                expect = base64.urlsafe_b64encode(
                    hmac.new(secret.encode(), msg, hashlib.sha256).digest()
                ).rstrip(b"=").decode()
                if expect == sig:
                    yield Candidate(
                        plaintext=json.dumps(
                            {"header": header, "payload": payload, "secret": secret},
                            ensure_ascii=False, indent=2,
                        ).encode(),
                        method=f"jwt-hs256-crack(secret='{secret}')",
                        chain=["jwt:hs256"],
                        verified=True,
                    )
                    return


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


# ---------------------------------------------------- ISO-8859-1 乱码修复

class Latin1ToUtf8Plugin:
    """ISO-8859-1 乱码修复: UTF-8 字节被误按 latin1 解码后, 其 UTF-8 编码再次
    被工具读取 -> 还原原始字节再按 UTF-8 重解码。如 "ä½ å¥½" -> "你好"。
    经典 mojibake 链: 你好 -> E4BDA0... -> latin1 误读 -> ä½ å¥½ -> UTF-8 存盘。"""

    name = "latin1-to-utf8"
    category = "codec"

    def match(self, ct: bytes) -> float:
        try:
            text = ct.decode("utf-8")          # 乱码字符文本
            raw = text.encode("latin1")        # 还原原始字节
            fixed = raw.decode("utf-8")        # 真实明文
        except (UnicodeDecodeError, UnicodeEncodeError):
            return 0.0
        if fixed == text:
            return 0.0
        # 修复产物含 CJK 或基本可打印 -> 可疑乱码
        if any("\u4e00" <= ch <= "\u9fff" for ch in fixed):
            return 0.8
        if sum(32 <= ord(ch) <= 126 for ch in fixed) / max(len(fixed), 1) > 0.9:
            return 0.6
        return 0.0

    def attack(self, ct: bytes) -> Iterator[Candidate]:
        try:
            text = ct.decode("utf-8")
            raw = text.encode("latin1")
            fixed = raw.decode("utf-8")
        except (UnicodeDecodeError, UnicodeEncodeError):
            return
        yield Candidate(plaintext=fixed.encode(), method="latin1-mojibake-fix", chain=["latin1"])


ALL_ADVANCED = [
    UnicodeEscapePlugin(), HtmlEntityPlugin(), QuotedPrintablePlugin(),
    PunycodePlugin(), ZlibPlugin(), GzipPlugin(), JwtPlugin(),
    Latin1ToUtf8Plugin(),
]
