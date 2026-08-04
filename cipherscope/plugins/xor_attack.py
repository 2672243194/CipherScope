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
        """归一化汉明距离: 密钥长度处距离显著最小。
        实现要点: 每个候选 klen 用全部完整块两两比较(而非固定前缀),
        采样上限 30 对保证不同 klen 间比较公平且代价可控。"""
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
        return [klen for _, klen in scored[:top]]

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
        """空格启发法: 英文明文里空格(0x20)频率最高, 密文每列中最常见的
        字节即为 空格^key_byte, 故 key_byte = mode(列) ^ 0x20。
        对 2~16 全部候选密钥长度做恢复+解码+评分, 产出分数最高的 2 个。
        (汉明距离法对重复性强的文本区分度不足, 空格启发法实测更鲁棒)"""
        scored = []
        for klen in range(2, self._MAX_KEYLEN + 1):
            key = bytes(self._mode(ct[i::klen]) ^ 0x20 for i in range(klen))
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
