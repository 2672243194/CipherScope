"""补充编码类插件: uuencode / OOK! / base91 / 猪圈密码。

普适性盲测驱动: CTF 高频但初版未覆盖的编码题型。
"""
from __future__ import annotations

import binascii
import re
from typing import Iterator

from cipherscope.core.plugin import Candidate

# ------------------------------------------------------------ uuencode

class UUEncodePlugin:
    """uuencode (RFC 1421): 每 45 字节编码为 60 字符, 特征为行首长度字符
    (32+字节数) 与字符集 [ !-` ](空格~反引号)。"""

    name = "uuencode"
    category = "codec"

    def match(self, ct: bytes) -> float:
        try:
            text = ct.decode("ascii").strip()
        except UnicodeDecodeError:
            return 0.0
        lines = text.splitlines()
        if not lines:
            return 0.0
        if lines[0].startswith("begin ") or lines[-1].startswith("end"):
            return 0.95
        body_lines = [l for l in lines if not l.startswith(("begin", "end"))]
        body = "".join(body_lines)
        if len(body) >= 8 and re.fullmatch(r"[ !-`]+", body):
            # 裸 uu 内容校验: 行首字符 ASCII-32 = 该行字节数, 恒 <= 行编码长度。
            # 防止全大写普通文本(如 ROT13 密文 URYYB JBEYQ)被误判为 uu 编码
            # 而跳过古典攻击——真实 bug: 大写 ROT13 解不出。
            valid = True
            for l in body_lines:
                if l and ord(l[0]) - 32 > len(l):
                    valid = False
                    break
            return 0.6 if valid else 0.15
        return 0.0

    def attack(self, ct: bytes) -> Iterator[Candidate]:
        text = ct.decode("ascii", errors="ignore").strip()
        if "begin " in text:
            text = text.split("begin ", 1)[1].split("\n", 1)[-1]
        if text.endswith("end"):
            text = text.rsplit("end", 1)[0]
        try:
            pt = binascii.a2b_uu(text)
        except (binascii.Error, ValueError):
            return
        yield Candidate(plaintext=pt, method="uu-decode", chain=["uuencode"])


# ------------------------------------------------------------ OOK!

_OOK_TO_BF = {
    "Ook. Ook?": ">", "Ook? Ook.": "<",
    "Ook. Ook.": "+", "Ook! Ook!": "-",
    "Ook! Ook.": ".", "Ook. Ook!": ",",
    "Ook! Ook?": "[", "Ook? Ook!": "]",
}


class OOKPlugin:
    """Ook! 语言: Brainfuck 的 8 指令用 Ook 对表达。翻译后复用 BF 解释器。"""

    name = "ook"
    category = "codec"

    def match(self, ct: bytes) -> float:
        try:
            text = ct.decode("ascii")
        except UnicodeDecodeError:
            return 0.0
        tokens = re.findall(r"Ook[.!?]\s+Ook[.!?]", text)
        return 0.95 if len(tokens) >= 6 else 0.0

    def attack(self, ct: bytes) -> Iterator[Candidate]:
        from cipherscope.plugins.codecs import BrainfuckPlugin
        text = ct.decode("ascii", errors="ignore")
        tokens = re.findall(r"Ook[.!?]\s+Ook[.!?]", text)
        code = []
        for t in tokens:
            bf = _OOK_TO_BF.get(t.strip())
            if bf is None:
                return
            code.append(bf)
        pt = BrainfuckPlugin._run("".join(code))
        if pt:
            yield Candidate(plaintext=pt, method="ook-interp", chain=["ook"])


# ------------------------------------------------------------ base91

_B91_ALPHABET = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    "!#$%&()*+,./:;<=>?@[]^_`{|}~\""
)


class Base91Plugin:
    """basE91: 91 字符字母表, 每 13 个 base91 字符编码 13~14 字节。
    手写解码 (basE91 标准算法)。"""

    name = "base91"
    category = "codec"

    def match(self, ct: bytes) -> float:
        try:
            text = ct.decode("ascii").strip()
        except UnicodeDecodeError:
            return 0.0
        if len(text) < 6 or not all(c in _B91_ALPHABET for c in text):
            return 0.0
        # base91 字符集与 base64 重叠大, 排除明显 base64 (padding/长度%4)
        if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", text) and len(text) % 4 == 0:
            return 0.1
        return 0.4

    @staticmethod
    def _decode(s: str) -> bytes:
        v, b, n = -1, 0, 0
        out = bytearray()
        for ch in s:
            c = _B91_ALPHABET.index(ch)
            if v < 0:
                v = c
            else:
                v += c * 91
                b |= v << n
                n += 13 if (v & 8191) > 88 else 14
                while n > 7:
                    out.append(b & 255)
                    b >>= 8
                    n -= 8
                v = -1
        if v != -1:
            out.append((b | (v << n)) & 255)
        return bytes(out)

    def attack(self, ct: bytes) -> Iterator[Candidate]:
        try:
            s = ct.decode("ascii").strip()
        except UnicodeDecodeError:
            return
        try:
            pt = self._decode(s)
        except Exception:
            return
        yield Candidate(plaintext=pt, method="base91-decode", chain=["base91"])


# ------------------------------------------------------------ 猪圈密码

# 经典猪圈网格映射 (28 字符): 2x3 网格 + X 标记; 用 unicode 近似符号表
_PIGPEN_MAP = {
    "⌐": "a", "¬": "b", "½": "c", "¼": "d", "¾": "e", "⅓": "f",  # 常规网格
    "⌠": "g", "⌡": "h", "≡": "i", "≌": "j", "≤": "k", "≥": "l",
    "⌐⌐": "m", "¬¬": "n", "½½": "o", "¼¼": "p", "¾¾": "q", "⅓⅓": "r",  # X 标记
    "⌠⌠": "s", "⌡⌡": "t", "≢": "u", "≭": "v", "∠": "w", "∡": "x",
    "◠": "y", "◡": "z",
}


class PigpenPlugin:
    """猪圈密码 (查表): 密文符号映射回字母。CTF 中常以图片/unicode 呈现,
    此处支持常见 unicode 猪圈符号; 图片形态需人工辅助。"""

    name = "pigpen"
    category = "codec"

    def match(self, ct: bytes) -> float:
        try:
            text = ct.decode("utf-8")
        except UnicodeDecodeError:
            return 0.0
        chars = [c for c in text if not c.isspace()]
        if not chars:
            return 0.0
        matched = sum(1 for c in chars if c in _PIGPEN_MAP)
        return 0.8 if matched == len(chars) and len(chars) >= 3 else 0.0

    def attack(self, ct: bytes) -> Iterator[Candidate]:
        text = ct.decode("utf-8", errors="ignore")
        chars = [c for c in text if not c.isspace()]
        if any(c not in _PIGPEN_MAP for c in chars):
            return
        pt = "".join(_PIGPEN_MAP[c] for c in chars).encode()
        yield Candidate(plaintext=pt, method="pigpen-decode", chain=["pigpen"])


ALL_EXTRA_CODECS = [UUEncodePlugin(), OOKPlugin(), Base91Plugin(), PigpenPlugin()]
