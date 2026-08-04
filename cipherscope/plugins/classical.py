"""古典密码攻击插件组 (classical)。

设计要点:
- 所有变换只作用于字母, 保留原文大小写位置与非字母字符;
- attack() 惰性产出全部密钥候选(凯撒 26 / 仿射 312 / 栅栏 ~10),
  由评分引擎统一排序——插件不预判明文质量;
- 维吉尼亚: Kasiski 候选钥长 + 按列卡方最小定逐位密钥, 产出 top-3。
"""
from __future__ import annotations

import re
import string
from typing import Iterator

from cipherscope.core.detector import kasiski_key_lengths
from cipherscope.core.plugin import Candidate
from cipherscope.core.scorer import ENGLISH_FREQ

_A2Z = string.ascii_lowercase


def _letters_only(text: str) -> str:
    return "".join(c for c in text.lower() if c in _A2Z)


def _apply_to_letters(text: str, func) -> bytes:
    """对字母应用 func(lower_char)->lower_char, 保留大小写与非字母。"""
    out = []
    for ch in text:
        if ch.lower() in _A2Z:
            new = func(ch.lower())
            out.append(new.upper() if ch.isupper() else new)
        else:
            out.append(ch)
    return "".join(out).encode()


def _column_chi2_best_shift(column: str) -> int:
    """对一列字母, 返回使解密后卡方最小的凯撒移位数(即该列密钥字母序号)。"""
    n = len(column)
    if n == 0:
        return 0
    best_shift, best_chi2 = 0, float("inf")
    for shift in range(26):
        counts = [0] * 26
        for c in column:
            counts[(_A2Z.index(c) - shift) % 26] += 1
        chi2 = sum(
            (counts[i] / n - ENGLISH_FREQ[_A2Z[i]]) ** 2 / ENGLISH_FREQ[_A2Z[i]]
            for i in range(26)
        )
        if chi2 < best_chi2:
            best_chi2, best_shift = chi2, shift
    return best_shift


class CaesarPlugin:
    name = "caesar"
    category = "classical"

    def match(self, ct: bytes) -> float:
        letters = _letters_only(ct.decode("ascii", errors="ignore"))
        if len(letters) >= 8:
            return 0.3   # 泛化候选, 低置信穷举
        # 短密文(字母<8)但含 flag 花括号结构: 也是凯撒题常见形态
        # (如 Synt{5pq1004q}), 低于 8 字母阈值会漏判——给低置信使其进入调度
        if len(letters) >= 4 and b"{" in ct and b"}" in ct:
            return 0.2
        return 0.0

    def attack(self, ct: bytes) -> Iterator[Candidate]:
        try:
            text = ct.decode("ascii")
        except UnicodeDecodeError:
            return
        for shift in range(1, 26):
            pt = _apply_to_letters(text, lambda c, s=shift: _A2Z[(_A2Z.index(c) - s) % 26])
            yield Candidate(plaintext=pt, method=f"caesar(shift={shift})", chain=[f"caesar:{shift}"])


class AtbashPlugin:
    name = "atbash"
    category = "classical"

    def match(self, ct: bytes) -> float:
        letters = _letters_only(ct.decode("ascii", errors="ignore"))
        return 0.15 if len(letters) >= 8 else 0.0

    def attack(self, ct: bytes) -> Iterator[Candidate]:
        try:
            text = ct.decode("ascii")
        except UnicodeDecodeError:
            return
        pt = _apply_to_letters(text, lambda c: _A2Z[25 - _A2Z.index(c)])
        yield Candidate(plaintext=pt, method="atbash", chain=["atbash"])


class AffinePlugin:
    """仿射密码: E(x)=(ax+b) mod 26, a 与 26 互素, 共 12×26=312 候选。"""

    name = "affine"
    category = "classical"
    _COPRIMES = (1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25)

    def match(self, ct: bytes) -> float:
        letters = _letters_only(ct.decode("ascii", errors="ignore"))
        return 0.15 if len(letters) >= 8 else 0.0

    @staticmethod
    def _modinv(a: int) -> int:
        return pow(a, -1, 26)

    def attack(self, ct: bytes) -> Iterator[Candidate]:
        try:
            text = ct.decode("ascii")
        except UnicodeDecodeError:
            return
        for a in self._COPRIMES:
            a_inv = self._modinv(a)
            for b in range(26):
                pt = _apply_to_letters(
                    text, lambda c, ai=a_inv, bb=b: _A2Z[(ai * (_A2Z.index(c) - bb)) % 26]
                )
                yield Candidate(plaintext=pt, method=f"affine(a={a},b={b})", chain=[f"affine:{a}:{b}"])


class VigenerePlugin:
    """维吉尼亚: Kasiski 候选钥长 -> 按列卡方最小定逐位密钥。"""

    name = "vigenere"
    category = "classical"

    def match(self, ct: bytes) -> float:
        letters = _letters_only(ct.decode("ascii", errors="ignore"))
        return 0.55 if len(letters) >= 30 else 0.0

    def attack(self, ct: bytes) -> Iterator[Candidate]:
        try:
            text = ct.decode("ascii")
        except UnicodeDecodeError:
            return
        letters = _letters_only(text)
        key_lengths = kasiski_key_lengths(letters, top=3)
        for k in (2, 3, 4, 5, 6, 7, 8):       # 兜底: Kasiski 未命中时穷举小钥长
            if k not in key_lengths:
                key_lengths.append(k)
        for klen in key_lengths[:6]:
            columns = [letters[i::klen] for i in range(klen)]
            key = "".join(_A2Z[_column_chi2_best_shift(col)] for col in columns)
            pt = self._decrypt(text, key)
            yield Candidate(
                plaintext=pt,
                method=f"vigenere(key='{key}', kasiski={klen})",
                chain=[f"vigenere:{key}"],
            )

    @staticmethod
    def _decrypt(text: str, key: str) -> bytes:
        key_idx = [_A2Z.index(c) for c in key]
        state = {"i": 0}

        def dec(c: str) -> str:
            shift = key_idx[state["i"] % len(key_idx)]
            state["i"] += 1
            return _A2Z[(_A2Z.index(c) - shift) % 26]

        return _apply_to_letters(text, dec)


class RailFencePlugin:
    """栅栏密码(zigzag): 栏数穷举 2~10。"""

    name = "railfence"
    category = "classical"

    def match(self, ct: bytes) -> float:
        letters = _letters_only(ct.decode("ascii", errors="ignore"))
        return 0.2 if len(letters) >= 12 else 0.0

    def attack(self, ct: bytes) -> Iterator[Candidate]:
        try:
            text = ct.decode("ascii").strip()
        except UnicodeDecodeError:
            return
        n = len(text)
        for rails in range(2, min(11, n // 2 + 1)):
            pt = self._decrypt(text, rails)
            yield Candidate(plaintext=pt, method=f"railfence(rails={rails})", chain=[f"railfence:{rails}"])

    @staticmethod
    def _decrypt(ct: str, rails: int) -> bytes:
        # 先算出每个位置在 zigzag 中属于哪一栏
        pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
        rail_of_pos = [pattern[i % len(pattern)] for i in range(len(ct))]
        # 各栏字符数 -> 切分密文
        counts = [rail_of_pos.count(r) for r in range(rails)]
        segments: list[str] = []
        idx = 0
        for c in counts:
            segments.append(ct[idx:idx + c])
            idx += c
        # 按位置顺序从各栏取字符
        ptr = [0] * rails
        out = []
        for r in rail_of_pos:
            out.append(segments[r][ptr[r]])
            ptr[r] += 1
        return "".join(out).encode()


class KeyboardShiftPlugin:
    """键盘邻键位移: 明文按密文键左/右一格(常见整活题)。
    使用行内循环映射(双射)避免边界字符歧义: p 右移回到 q;
    解密为纯逆位移, 边界字符无歧义。"""

    name = "keyboard-shift"
    category = "classical"
    _ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm")

    def match(self, ct: bytes) -> float:
        try:
            text = ct.decode("ascii")
        except UnicodeDecodeError:
            return 0.0
        letters = _letters_only(text)
        return 0.1 if len(letters) >= 8 else 0.0

    def _shift_map(self, direction: int) -> dict[str, str]:
        """direction=-1 解"加密右移"(密文各字符向左移回); direction=+1 解"加密左移"。
        循环位移下加密可逆, 边界字符无歧义。"""
        table: dict[str, str] = {}
        for row in self._ROWS:
            for i, ch in enumerate(row):
                table[ch] = row[(i + direction) % len(row)]
        return table

    def attack(self, ct: bytes) -> Iterator[Candidate]:
        try:
            text = ct.decode("ascii")
        except UnicodeDecodeError:
            return
        for direction, label in ((-1, "right-shift-dec"), (1, "left-shift-dec")):
            table = self._shift_map(direction)
            pt = _apply_to_letters(text, lambda c, t=table: t.get(c, c))
            yield Candidate(plaintext=pt, method=f"keyboard-shift({label})", chain=[f"kbd:{label}"])


class CloudShadowPlugin:
    """云影密码: 明文按字母序号(1~26)拆为 0-2-4-8 的和(如 3=2+1), 数字以 0 分隔。
    解密: 按 0 分组求和转字母; 非数字字符(如 flag 花括号/下划线)原样保留。
    国内 CTF 高频题型。"""

    name = "cloud-shadow"
    category = "classical"

    def match(self, ct: bytes) -> float:
        try:
            text = ct.decode("ascii").strip()
        except UnicodeDecodeError:
            return 0.0
        # 数字位为 1/2/4/8, 0 是字母分隔符; 出现 3/5/6/7/9 即排除
        if any(c.isdigit() and c not in "01248" for c in text):
            return 0.0
        groups = re.findall(r"[1248]+", text)
        if len(groups) < 3:
            return 0.0
        return 0.8

    def attack(self, ct: bytes) -> Iterator[Candidate]:
        text = ct.decode("ascii", errors="ignore").strip()
        out = []
        buf = 0
        pending = False
        for ch in text:
            if ch in "1248":
                buf += int(ch)
                pending = True
            else:
                if pending:
                    if buf < 1 or buf > 26:
                        return
                    out.append(chr(ord("a") + buf - 1))
                    buf, pending = 0, False
                if ch != "0":   # 0 是分隔符, 丢弃; 其余非数字字符原样保留
                    out.append(ch)
        if pending:
            if buf < 1 or buf > 26:
                return
            out.append(chr(ord("a") + buf - 1))
        yield Candidate(plaintext="".join(out).encode(), method="cloud-shadow-decode", chain=["cloud"])


class Rot47Plugin:
    """ROT47: 可打印 ASCII(33~126) 循环位移 47。对数字/符号/字母混合文本有效,
    而 ROT13 只影响字母——ROT47 是整活题常用变体。"""

    name = "rot47"
    category = "classical"

    def match(self, ct: bytes) -> float:
        try:
            text = ct.decode("ascii")
        except UnicodeDecodeError:
            return 0.0
        if not text:
            return 0.0
        printable = sum(33 <= ord(c) <= 126 for c in text)
        if printable / len(text) < 0.9:
            return 0.0
        # 纯字母文本更像 ROT13/凯撒, ROT47 特征弱, 仅当含数字符号时给候选
        letters = sum(c.isalpha() for c in text)
        return 0.25 if letters / len(text) < 0.9 else 0.05

    def attack(self, ct: bytes) -> Iterator[Candidate]:
        try:
            text = ct.decode("ascii")
        except UnicodeDecodeError:
            return
        pt = "".join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c
                     for c in text).encode()
        yield Candidate(plaintext=pt, method="rot47", chain=["rot47"])


class SimpleRailFencePlugin:
    """分栏式栅栏(非 zigzag): 明文按顺序均分 n 栏后按栏拼接。
    与 RailFencePlugin 的 W 型 zigzag 不同, 是 CTF 中常见混淆点。"""

    name = "railfence-simple"
    category = "classical"

    def match(self, ct: bytes) -> float:
        try:
            text = ct.decode("ascii").strip()
        except UnicodeDecodeError:
            return 0.0
        return 0.15 if len(text) >= 10 else 0.0

    def attack(self, ct: bytes) -> Iterator[Candidate]:
        try:
            text = ct.decode("ascii").strip()
        except UnicodeDecodeError:
            return
        n = len(text)
        for rails in range(2, min(9, n // 2 + 1)):
            base, extra = divmod(n, rails)
            # 各栏长度: 前 extra 栏 base+1, 其余 base
            seg_len = [base + (1 if i < extra else 0) for i in range(rails)]
            segments = []
            idx = 0
            for sl in seg_len:
                segments.append(text[idx:idx + sl])
                idx += sl
            ptr = [0] * rails
            out = []
            for i in range(n):
                r = i % rails
                out.append(segments[r][ptr[r]])
                ptr[r] += 1
            yield Candidate(plaintext="".join(out).encode(),
                            method=f"railfence-simple(rails={rails})", chain=[f"rfs:{rails}"])


class VariantCaesarPlugin:
    """变异凯撒: 对每个字符按 ASCII 码加/减递增位移 (起点 k, 每次 ±1)。
    经典题 (BUUCTF afZ_r9VYfScOeO_UL^RWUc): a+5=f, f+6=l, Z+7=a...
    与普通凯撒(只移字母)不同, 变异凯撒作用于全部可打印 ASCII,
    必须逐字节处理, 不能复用 _apply_to_letters。加减两个方向都尝试。"""

    name = "variant-caesar"
    category = "classical"

    def match(self, ct: bytes) -> float:
        if len(ct) < 8:
            return 0.0
        # 强特征: 存在递增位移起点(加减两向)使前 5 字节解出 "flag{"
        for sign in (1, -1):
            for start in range(26):
                if bytes((b + sign * (start + i)) % 256 for i, b in enumerate(ct[:5])) == b"flag{":
                    return 0.95
        # 弱特征: 某起点(加减两向)解出全可打印 ASCII
        for sign in (1, -1):
            for start in range(26):
                if all(32 <= (b + sign * (start + i)) % 256 <= 126 for i, b in enumerate(ct)):
                    return 0.35
        return 0.0

    def attack(self, ct: bytes) -> Iterator[Candidate]:
        for sign, label in ((1, "dec(+inc)"), (-1, "dec(-inc)")):
            for start in range(26):
                pt = bytes((b + sign * (start + i)) % 256 for i, b in enumerate(ct))
                yield Candidate(
                    plaintext=pt,
                    method=f"variant-caesar(start={start},{label})",
                    chain=[f"varCaesar:{start}:{sign}"],
                )


ALL_CLASSICAL = [
    CaesarPlugin(), AtbashPlugin(), AffinePlugin(),
    VigenerePlugin(), RailFencePlugin(), KeyboardShiftPlugin(),
    CloudShadowPlugin(), Rot47Plugin(), SimpleRailFencePlugin(),
    VariantCaesarPlugin(),
]
