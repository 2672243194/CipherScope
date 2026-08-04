"""XOR 分析插件组。

- XorSinglePlugin: 单字节 256 穷举, 内部用评分引擎预排序后产出 top-5
  (XOR 候选量大, 插件内预筛避免淹没调度器);
- XorMultiPlugin: 重复密钥 XOR, 归一化汉明距离定钥长 -> 按列单字节
  频率分析定钥 (Cryptopals Set 1 标准方法);
- XorKnownPlaintextPlugin: 利用 flag{ 等已知前缀异或反推密钥片段,
  能直接定钥(单字节)或验证密钥周期(多字节)时产出。
"""
from __future__ import annotations

import string
from typing import Iterator

from cipherscope.core.plugin import Candidate
from cipherscope.core.scorer import ScoringEngine

_PRINTABLE = set(bytes(string.printable, "ascii"))


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    klen = len(key)
    return bytes(b ^ key[i % klen] for i, b in enumerate(data))


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(b in _PRINTABLE for b in data) / len(data)


def _hamming(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def _column_mode(column: bytes) -> int:
    """列中出现频率最高的字节。"""
    return max(set(column), key=column.count)


class XorSinglePlugin:
    name = "xor-single"
    category = "xor"

    def __init__(self) -> None:
        self._scorer = ScoringEngine()

    def match(self, ct: bytes) -> float:
        if len(ct) < 6:
            return 0.0
        ratio = _printable_ratio(ct)
        if ratio >= 0.95:
            # 全可打印时仅当字母占比异常低才可能是 XOR(见 detector 同逻辑)
            letters = sum(chr(b) in string.ascii_letters for b in ct)
            return 0.4 if letters / len(ct) < 0.65 else 0.05
        return 0.5

    def attack(self, ct: bytes) -> Iterator[Candidate]:
        scored = []
        for k in range(256):
            pt = bytes(b ^ k for b in ct)
            r = self._scorer.score(pt)
            scored.append((r.score, k, pt))
        scored.sort(reverse=True)
        for score, k, pt in scored[:5]:
            yield Candidate(plaintext=pt, method=f"xor-single(key=0x{k:02x})", chain=[f"xor1:{k:02x}"])


class XorMultiPlugin:
    name = "xor-multi"
    category = "xor"
    _MAX_KEYLEN = 16

    def __init__(self) -> None:
        self._scorer = ScoringEngine()

    def match(self, ct: bytes) -> float:
        if len(ct) < 40:
            return 0.0
        return 0.3 if _printable_ratio(ct) < 0.95 else 0.1

    def _guess_keylen(self, ct: bytes, top: int = 3) -> list[int]:
        """空格启发法定密钥长度: 对每个候选 klen 按列取 mode 字节^0x20 恢复
        密钥并解码, 用"解出文本的可打印比例"打分——真实密钥长度解出的是
        英文(几乎全可打印), 错误长度解出乱码(可打印率低)。
        汉明距离在重复文本(FILLER 句式)上不可靠, 空格启发法直接验证更鲁棒。"""
        scored = []
        for klen in range(2, self._MAX_KEYLEN + 1):
            if len(ct) < klen * 3:
                continue   # 样本不足
            key = bytes(
                _column_mode(ct[i::klen]) ^ 0x20 for i in range(klen)
            )
            pt = _xor_bytes(ct, key)
            printable = _printable_ratio(pt)
            if printable < 0.7:
                continue   # 明显乱码, 不参与候选
            scored.append((printable, klen))
        scored.sort(key=lambda x: x[0], reverse=True)
        result = [klen for _, klen in scored[:top]]
        # 兜底: 一个都没达到 0.7 时退回汉明距离(兼容非英文明文)
        if not result:
            return self._hamming_guess(ct)[:top]
        return result

    def _hamming_guess(self, ct: bytes) -> list[int]:
        """汉明距离兜底: 密钥长度处块间距离显著最小。"""
        scored = []
        for klen in range(2, self._MAX_KEYLEN + 1):
            blocks = [ct[i:i + klen] for i in range(0, len(ct) - klen + 1, klen)]
            if len(blocks) < 2:
                continue
            pairs = [(blocks[i], blocks[j])
                     for i in range(len(blocks) - 1)
                     for j in range(i + 1, len(blocks))]
            if len(pairs) > 30:
                step = len(pairs) / 30
                pairs = [pairs[int(i * step)] for i in range(30)]
            dists = [_hamming(a, b) / klen for a, b in pairs]
            scored.append((sum(dists) / len(dists), klen))
        scored.sort()
        return [klen for _, klen in scored[:3]]

    @staticmethod
    def _best_key_byte(column: bytes, scorer: ScoringEngine) -> int:
        best_score, best_k = -1.0, 0
        for k in range(256):
            pt = bytes(b ^ k for b in column)
            r = scorer.score(pt)
            if r.score > best_score:
                best_score, best_k = r.score, k
        return best_k

    def attack(self, ct: bytes) -> Iterator[Candidate]:
        """多字节 XOR: _guess_keylen 定候选密钥长度(空格启发可打印打分),
        每列在 top-3 频次字节^0x20 中按评分引擎选最优密钥字节——
        对含特殊字符的密钥(如 k3y!)也能恢复, 比单 mode^0x20 更鲁棒。"""
        scored = []
        for klen in self._guess_keylen(ct):
            key = self._recover_key(ct, klen, self._scorer)
            pt = _xor_bytes(ct, key)
            r = self._scorer.score(pt)
            scored.append((r.score, klen, key, pt))
        scored.sort(reverse=True)
        for score, klen, key, pt in scored[:2]:
            yield Candidate(
                plaintext=pt,
                method=f"xor-multi(key={key!r}, keylen={klen}, space-heuristic)",
                chain=[f"xorN:{key.hex()}"],
            )

    @staticmethod
    def _mode(column: bytes) -> int:
        if not column:
            return 0
        return max(set(column), key=column.count)

    @classmethod
    def _recover_key(cls, ct: bytes, klen: int, scorer: ScoringEngine) -> bytes:
        """每列用英文频率分析恢复密钥字节: 正确密钥解出该列为**以字母为主**
        (明文该列), 错误密钥解出乱码/均匀分布。先按"字母占比 >=60%"过滤
        候选, 再对字母做英文频率 chi2 评分——短列(20+ 字节)上比 ngram
        评分可靠得多, 含数字/特殊字符的密钥列也能恢复。"""
        from cipherscope.core.scorer import ENGLISH_FREQ

        key = bytearray()
        for i in range(klen):
            col = ct[i::klen]
            if not col:
                key.append(0)
                continue
            best_k, best_chi2 = 0, 1e9
            for k in range(256):
                pt = bytes(b ^ k for b in col)
                letters = [b | 0x20 for b in pt
                           if 65 <= b <= 90 or 97 <= b <= 122]
                if len(letters) < len(pt) * 0.6:
                    continue   # 非字母为主, 不可能是正确密钥
                freq = [0] * 26
                for ch in letters:
                    freq[ch - 97] += 1
                total = len(letters)
                chi2 = sum(
                    (freq[i] / total - ENGLISH_FREQ[chr(97 + i)]) ** 2
                    / ENGLISH_FREQ[chr(97 + i)]
                    for i in range(26)
                )
                if chi2 < best_chi2:
                    best_chi2, best_k = chi2, k
            key.append(_pick_case(col, best_k))
        return bytes(key)


def _pick_case(col: bytes, k: int) -> int:
    """方向校正: 频率分析不区分大小写, 密钥 k 与 k^0x20 解出列分别对应
    小写/大写(或空格/NUL)。英文明文小写为主——选小写占比高的方向;
    无字母列(如空格列)按可打印率选择。"""
    def _lower_ratio(key: int) -> float:
        pt = bytes(b ^ key for b in col)
        letters = sum(65 <= b <= 90 or 97 <= b <= 122 for b in pt)
        if letters == 0:
            return -1.0
        lower = sum(97 <= b <= 122 for b in pt)
        return lower / letters

    k1, k2 = k, k ^ 0x20
    r1, r2 = _lower_ratio(k1), _lower_ratio(k2)
    if r1 >= 0 and r2 >= 0:
        return k1 if r1 >= r2 else k2
    # 无字母列: 选解出可打印字符多的方向(空格^0x20=NUL 不可打印)
    def _printable(key: int) -> int:
        return sum(32 <= b < 127 for b in bytes(b ^ key for b in col))
    return k1 if _printable(k1) >= _printable(k2) else k2


class XorKnownPlaintextPlugin:
    """已知明文攻击: 用已知前缀(如 flag{)异或密文头部反推密钥。"""

    name = "xor-known-plaintext"
    category = "xor"

    def __init__(self, cribs: tuple[bytes, ...] = (b"flag{", b"ctf{", b"NSSCTF{")) -> None:
        self._cribs = cribs

    def match(self, ct: bytes) -> float:
        return 0.2 if len(ct) >= 8 else 0.0

    def attack(self, ct: bytes) -> Iterator[Candidate]:
        for crib in self._cribs:
            if len(ct) < len(crib):
                continue
            key_fragment = bytes(a ^ b for a, b in zip(ct[: len(crib)], crib))
            # 单字节密钥: fragment 全部相同
            if len(set(key_fragment)) == 1:
                pt = bytes(b ^ key_fragment[0] for b in ct)
                yield Candidate(
                    plaintext=pt,
                    method=f"xor-crib('{crib.decode()}' -> single key 0x{key_fragment[0]:02x})",
                    chain=[f"xor1crib:{key_fragment[0]:02x}"],
                )
            # 周期密钥: fragment 存在短周期(2~8)
            for period in range(2, min(9, len(key_fragment))):
                if all(key_fragment[i] == key_fragment[i % period] for i in range(len(key_fragment))):
                    key = key_fragment[:period]
                    pt = _xor_bytes(ct, key)
                    yield Candidate(
                        plaintext=pt,
                        method=f"xor-crib('{crib.decode()}' -> key={key!r})",
                        chain=[f"xorNcrib:{key.hex()}"],
                    )
                    break


ALL_XOR = [XorSinglePlugin(), XorMultiPlugin(), XorKnownPlaintextPlugin()]
