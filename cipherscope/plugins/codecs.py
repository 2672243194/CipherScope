"""编码链插件组 (codecs) —— base 系 / url / hex / 二进制 / 摩斯 / Brainfuck / 培根。

每个编码一个轻量插件: match() 用字符集/长度等强特征快速判定,
attack() 产出唯一解码结果(编码无密钥, 至多培根双变体)。
评分与是否继续深挖由管道统一决定, 插件本身不做明文质量判断。
"""
from __future__ import annotations

import base64
import binascii
import re
from typing import Iterator
from urllib.parse import unquote_to_bytes

from cipherscope.core.plugin import Candidate

# ------------------------------------------------------------ 摩斯码表
MORSE_TABLE = {
    ".-": "a", "-...": "b", "-.-.": "c", "-..": "d", ".": "e", "..-.": "f",
    "--.": "g", "....": "h", "..": "i", ".---": "j", "-.-": "k", ".-..": "l",
    "--": "m", "-.": "n", "---": "o", ".--.": "p", "--.-": "q", ".-.": "r",
    "...": "s", "-": "t", "..-": "u", "...-": "v", ".--": "w", "-..-": "x",
    "-.--": "y", "--..": "z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9", "/": " ",
    # 扩展符号(CTF 摩斯题常见): 完整编码 flag{...} 等。键为符号串, 值为字符。
    "-.--.-": "{", ".-..-.": "}", "..--.-": "_", "-.-.--": "!",
    "..--..": "?", ".-.-.-": ".", "--..--": ",", "---...": ":", "-...-": "=",
}


def _compact(ct: bytes) -> str:
    return re.sub(rb"\s+", b"", ct).decode("ascii", errors="ignore")


class Base64Plugin:
    name = "base64"
    category = "codec"

    # 常见图片/文件魔数 (用于 base64 解码产物识别)
    _MAGIC = {
        b"\x89PNG\r\n\x1a\n": "PNG 图片",
        b"\xff\xd8\xff": "JPEG 图片",
        b"GIF87a": "GIF 图片", b"GIF89a": "GIF 图片",
        b"BM": "BMP 图片",
        b"PK\x03\x04": "ZIP 压缩包",
        b"%PDF": "PDF 文档",
        b"\x1f\x8b": "GZIP 压缩数据",
    }

    def match(self, ct: bytes) -> float:
        # data:image/xxx;base64, 前缀: 图片 base64, 直接高置信
        try:
            head = ct.decode("ascii", errors="ignore")
        except Exception:
            head = ""
        if head.startswith("data:") and ";base64," in head:
            return 0.98
        c = _compact(ct)
        if len(c) < 8 or len(c) % 4 != 0 or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", c):
            return 0.0
        # hash 长度(32/40/56/64/96/128)的全 hex 串: hex 字符集 ⊂ base64,
        # 但长度特征强烈指向哈希——base64 解码只会得到乱码并污染管道
        if len(c) in (32, 40, 56, 64, 96, 128) and re.fullmatch(r"[0-9a-fA-F]+", c):
            return 0.0
        # 0x 前缀的纯 hex 串: 是 hex 不是 base64——否则 0x 开头密文被 base64
        # 误解码出乱码入队, 再被 xor-crib 硬凑出假 flag (真实 bug)
        if re.fullmatch(r"0[xX][0-9a-fA-F]+", c):
            return 0.0
        return 0.85 if len(set(c)) >= 8 else 0.2

    def attack(self, ct: bytes) -> Iterator[Candidate]:
        try:
            head = ct.decode("ascii", errors="ignore")
        except Exception:
            head = ""
        if head.startswith("data:") and ";base64," in head:
            c = head.split(";base64,", 1)[1]
        else:
            c = _compact(ct)
        try:
            pt = base64.b64decode(c, validate=True)
        except (binascii.Error, ValueError):
            return
        # 识别解码产物的文件类型 (图片 base64 题)
        kind = ""
        for magic, label in self._MAGIC.items():
            if pt.startswith(magic):
                kind = label
                break
        method = f"base64-decode{'(→' + kind + ')' if kind else ''}"
        yield Candidate(plaintext=pt, method=method, chain=["base64"])


class Base32Plugin:
    name = "base32"
    category = "codec"

    def match(self, ct: bytes) -> float:
        c = _compact(ct)
        if len(c) < 8 or len(c) % 8 != 0 or not re.fullmatch(r"[A-Z2-7]+=*", c):
            return 0.0
        return 0.8

    def attack(self, ct: bytes) -> Iterator[Candidate]:
        try:
            pt = base64.b32decode(_compact(ct))
        except (binascii.Error, ValueError):
            return
        yield Candidate(plaintext=pt, method="base32-decode", chain=["base32"])


class Base16Plugin:
    """hex 即 base16。哈希长度(32/40/64/128)的 hex 串不解码——那是哈希不是编码,
    由 hash 插件处理; 这里仅在解码产物可打印时产出。"""

    name = "hex"
    category = "codec"

    def match(self, ct: bytes) -> float:
        c = _compact(ct)
        c = re.sub(r"0[xX]", "", c)   # 去所有 0x 前缀(支持 0x66 0x6c 混合书写)
        if len(c) < 4 or len(c) % 2 != 0 or not re.fullmatch(r"[0-9A-Fa-f]+", c):
            return 0.0
        return 0.85

    def attack(self, ct: bytes) -> Iterator[Candidate]:
        c = _compact(ct)
        c = re.sub(r"0[xX]", "", c)
        if len(c) in (32, 40, 56, 64, 96, 128):
            # 疑似哈希长度: 仅当解码产物几乎全部可打印才是真 hex 编码
            # (如 28 字节文本的 56 位 hex), 否则是哈希乱码让给 hash 插件
            try:
                pt = bytes.fromhex(c)
            except ValueError:
                return
            printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in pt)
            if printable / max(len(pt), 1) < 0.9:
                return
            yield Candidate(plaintext=pt, method="hex-decode", chain=["hex"])
            return
        try:
            pt = bytes.fromhex(c)
        except ValueError:
            return
        yield Candidate(plaintext=pt, method="hex-decode", chain=["hex"])


class Base85Plugin:
    name = "base85"
    category = "codec"

    def match(self, ct: bytes) -> float:
        c = _compact(ct)
        # Python b85 尾部处理使输出长度不一定是 5 的倍数; 字符集需含
        # `{|}~` 等 (ASCII 33~126 子集), 不能用 [!-u](仅到 117) 判定。
        # 且必须至少含一个 base64 字符集外的符号——b85 字符集包含 base64,
        # 否则纯 base64 串会被误匹配, 其"乱解"产物会挤掉 base64 真解。
        if len(c) < 8 or not re.fullmatch(r"[0-9A-Za-z!#$%&()*+\-;<=>?@^_`{|}~]+", c):
            return 0.0
        # 必须含至少一个 base64 字符集外且非 +/= 的符号(真实 b85 输出必含)
        if not re.search(r"[!#$%&()*\-;<>?@^_`{|}~]", c):
            return 0.0
        if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", c) and len(c) % 4 == 0:
            return 0.1  # 更像 base64
        return 0.5

    def attack(self, ct: bytes) -> Iterator[Candidate]:
        try:
            pt = base64.b85decode(_compact(ct))
        except (binascii.Error, ValueError):
            return
        yield Candidate(plaintext=pt, method="base85-decode", chain=["base85"])


class UrlEncodePlugin:
    name = "url-encode"
    category = "codec"

    def match(self, ct: bytes) -> float:
        try:
            text = ct.decode("ascii")
        except UnicodeDecodeError:
            return 0.0
        return 0.85 if re.search(r"%[0-9A-Fa-f]{2}", text) else 0.0

    def attack(self, ct: bytes) -> Iterator[Candidate]:
        try:
            pt = unquote_to_bytes(ct.decode("ascii"))
        except Exception:
            return
        yield Candidate(plaintext=pt, method="url-decode", chain=["url"])


class BinaryAsciiPlugin:
    name = "binary-ascii"
    category = "codec"

    def match(self, ct: bytes) -> float:
        c = _compact(ct)
        if len(c) < 16 or len(c) % 8 != 0 or not re.fullmatch(r"[01]+", c):
            return 0.0
        return 0.9

    def attack(self, ct: bytes) -> Iterator[Candidate]:
        c = _compact(ct)
        try:
            pt = bytes(int(c[i:i + 8], 2) for i in range(0, len(c), 8))
        except ValueError:
            return
        yield Candidate(plaintext=pt, method="binary-ascii-decode", chain=["binary"])


class MorsePlugin:
    name = "morse"
    category = "codec"

    def match(self, ct: bytes) -> float:
        try:
            text = ct.decode("ascii").strip()
        except UnicodeDecodeError:
            return 0.0
        if re.fullmatch(r"[.\- /]+", text) and "." in text and "-" in text:
            return 0.95
        return 0.0

    def attack(self, ct: bytes) -> Iterator[Candidate]:
        text = ct.decode("ascii", errors="ignore").strip()
        words = re.split(r"\s{2,}|\n", text)
        out_words = []
        for word in words:
            syms = word.split()
            if any(s not in MORSE_TABLE for s in syms):
                return  # 存在未知符号, 不是本表能解的摩斯
            out_words.append("".join(MORSE_TABLE[s] for s in syms))
        pt = " ".join(out_words).encode()
        yield Candidate(plaintext=pt, method="morse-decode", chain=["morse"])


class BrainfuckPlugin:
    name = "brainfuck"
    category = "codec"

    def match(self, ct: bytes) -> float:
        try:
            text = ct.decode("ascii")
        except UnicodeDecodeError:
            return 0.0
        if re.fullmatch(r"[\[\]<>+\-.,\s]+", text) and "[" in text:
            return 0.95
        return 0.0

    @staticmethod
    def _run(code: str, limit: int = 200_000) -> bytes:
        tape = [0] * 30_000
        ptr = out_pos = 0
        out = bytearray()
        jumps: dict[int, int] = {}
        stack: list[int] = []
        for i, ch in enumerate(code):
            if ch == "[":
                stack.append(i)
            elif ch == "]":
                j = stack.pop()
                jumps[i] = j
                jumps[j] = i
        steps = 0
        while out_pos < len(code) and steps < limit:
            ch = code[out_pos]
            steps += 1
            if ch == ">":
                ptr += 1
            elif ch == "<":
                ptr -= 1
            elif ch == "+":
                tape[ptr] = (tape[ptr] + 1) % 256
            elif ch == "-":
                tape[ptr] = (tape[ptr] - 1) % 256
            elif ch == ".":
                out.append(tape[ptr])
            elif ch == "[" and tape[ptr] == 0:
                out_pos = jumps[out_pos]
            elif ch == "]" and tape[ptr] != 0:
                out_pos = jumps[out_pos]
            out_pos += 1
        return bytes(out)

    def attack(self, ct: bytes) -> Iterator[Candidate]:
        code = re.sub(r"\s", "", ct.decode("ascii", errors="ignore"))
        try:
            pt = self._run(code)
        except Exception:
            return
        if pt:
            yield Candidate(plaintext=pt, method="brainfuck-interp", chain=["brainfuck"])


class BaconPlugin:
    """培根密码: 二元符号 5 位一组, 24 字母表(I/J, U/V 合并)与 26 字母表两变体。"""

    name = "bacon"
    category = "codec"

    def match(self, ct: bytes) -> float:
        c = _compact(ct)
        if len(c) < 10 or len(c) % 5 != 0 or not re.fullmatch(r"[A-Za-z]+", c):
            return 0.0
        return 0.8 if len(set(c.lower())) <= 2 else 0.0

    @staticmethod
    def _decode_groups(bits: list[int], alphabet24: bool) -> str:
        out = []
        for i in range(0, len(bits), 5):
            v = 0
            for b in bits[i:i + 5]:
                v = v * 2 + b
            if alphabet24:
                # 24 字母表: 无 j/u
                alpha = "abcdefghiklmnopqrstwxyz"
                if v >= len(alpha):
                    return ""
                out.append(alpha[v])
            else:
                if v >= 26:
                    return ""
                out.append(chr(ord("a") + v))
        return "".join(out)

    def attack(self, ct: bytes) -> Iterator[Candidate]:
        c = _compact(ct).lower()
        chars = sorted(set(c))
        bits = [0 if ch == chars[0] else 1 for ch in c]
        for variant, is24 in (("bacon-24", True), ("bacon-26", False)):
            text = self._decode_groups(bits, is24)
            if text:
                yield Candidate(plaintext=text.encode(), method=variant, chain=[variant])


class AsciiCodePlugin:
    """ASCII 码序列: "102 108 97 103" / "102,108,97" / "66 6c 61 67"(hex) /
    "141 142 143"(八进制, 0-7 数字)。CTF 高频送分题, 初版缺失, 普适性盲测暴露后补充。"""

    name = "ascii-codes"
    category = "codec"

    def match(self, ct: bytes) -> float:
        try:
            text = ct.decode("ascii").strip()
        except UnicodeDecodeError:
            return 0.0
        parts = re.split(r"[\s,;]+", text)
        if len(parts) < 3:
            return 0.0
        hexish = all(re.fullmatch(r"0?[0-9A-Fa-f]{1,2}", p) for p in parts)
        decish = all(re.fullmatch(r"\d{1,3}", p) for p in parts)
        octish = all(re.fullmatch(r"[0-7]{1,3}", p) for p in parts)
        if hexish and decish:
            return 0.6   # 两种解释都可能
        if decish and all(0 <= int(p) <= 255 for p in parts):
            return 0.85
        if hexish:
            return 0.7
        if octish and any(p.startswith("0") and len(p) >= 2 for p in parts):
            return 0.6   # 带前导 0 的八进制串(如 0141)特征更强
        return 0.0

    def attack(self, ct: bytes) -> Iterator[Candidate]:
        try:
            text = ct.decode("ascii").strip()
        except UnicodeDecodeError:
            return
        parts = re.split(r"[\s,;]+", text)
        for base, label in ((16, "hex"), (10, "dec"), (8, "oct")):
            try:
                vals = [int(p, base) for p in parts]
            except ValueError:
                continue
            if all(0 <= v <= 255 for v in vals):
                yield Candidate(plaintext=bytes(vals), method=f"ascii-codes({label})", chain=[f"ascii:{label}"])


# Bitcoin base58 字母表 (不含 0OIl 易混淆字符)
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


class Base58Plugin:
    """base58 编码 (比特币风格)。标准库无实现, 手写编解码。"""

    name = "base58"
    category = "codec"

    def match(self, ct: bytes) -> float:
        try:
            text = ct.decode("ascii").strip()
        except UnicodeDecodeError:
            return 0.0
        if len(text) < 6 or not all(c in _B58_ALPHABET for c in text):
            return 0.0
        return 0.4   # 字符集宽, 与 base64 有重叠, 中低置信

    @staticmethod
    def _decode(s: str) -> bytes:
        n = 0
        for ch in s:
            n = n * 58 + _B58_ALPHABET.index(ch)
        return n.to_bytes((n.bit_length() + 7) // 8, "big")

    def attack(self, ct: bytes) -> Iterator[Candidate]:
        try:
            s = ct.decode("ascii").strip()
        except UnicodeDecodeError:
            return
        try:
            pt = self._decode(s)
        except Exception:
            return
        yield Candidate(plaintext=pt, method="base58-decode", chain=["base58"])


ALL_CODECS = [
    Base64Plugin(), Base32Plugin(), Base16Plugin(), Base85Plugin(),
    UrlEncodePlugin(), BinaryAsciiPlugin(), MorsePlugin(),
    BrainfuckPlugin(), BaconPlugin(), AsciiCodePlugin(), Base58Plugin(),
]
