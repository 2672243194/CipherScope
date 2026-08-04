"""哈希识别与字典爆破插件 —— 碰撞类题目的自动解决方案。

流程: 识别到 hash 长度 hex (32/40/56/64/96/128) -> 自动启用字典爆破。
支持变体 (CTF 常见碰撞题型):
  - 直接哈希: md5(x) / sha1(x) / sha256(x)
  - 双哈希:   md5(md5(x))  (同 32 hex, 自动尝试)
  - 带盐:     md5(salt + x) / md5(x + salt)  (需 --salt 指定)
  - 反向 MD5: md5(reverse(x)) 命中后自动还原
内置字典 (cipherscope/data/): weak_passwords / ctf_words / common_flags,
可通过 --wordlist 注入外部字典。大规模爆破建议 hashcat。
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Callable, Iterator

from cipherscope.core.plugin import Candidate

HASH_BY_HEXLEN = {
    32: "md5", 40: "sha1", 56: "sha224", 64: "sha256", 96: "sha384", 128: "sha512",
}

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_DICT_FILES = ("weak_passwords.txt", "ctf_words.txt", "common_flags.txt")
# dictionaries/ 目录下自动加载的行数上限: 万级字典默认加载(耗时 <1s),
# 百万级字典(如 xato-1m)需 --wordlist 显式加载, 否则每次求解都做百万次哈希
_AUTO_DICT_MAX_LINES = 20000


def _load_builtin_dicts() -> list[str]:
    words: list[str] = []
    for name in _DICT_FILES:
        p = _DATA_DIR / name
        if p.is_file():
            words.extend(line.strip() for line in p.read_text(encoding="utf-8", errors="ignore")
                         .splitlines() if line.strip())
    # dictionaries/ 目录: 仅自动加载小文件
    ddir = _DATA_DIR / "dictionaries"
    if ddir.is_dir():
        for p in sorted(ddir.glob("*.txt")):
            lines = [line.strip() for line in p.read_text(encoding="utf-8", errors="ignore")
                     .splitlines() if line.strip()]
            if len(lines) <= _AUTO_DICT_MAX_LINES:
                words.extend(lines)
    # 去重保序
    return list(dict.fromkeys(words))


class HashPlugin:
    name = "hash-dict"
    category = "hash"

    def __init__(self, extra_words: list[str] | None = None, salt: bytes | None = None) -> None:
        self._words = _load_builtin_dicts()
        if extra_words:
            self._words.extend(extra_words)
        self._words = list(dict.fromkeys(self._words))
        self._salt = salt

    def match(self, ct: bytes) -> float:
        c = re.sub(rb"\s+", b"", ct)
        if re.fullmatch(rb"[0-9a-fA-F]+", c) and len(c) in HASH_BY_HEXLEN:
            return 0.9
        return 0.0

    # ------------------------------------------------------------ 变体生成
    def _variants(self, word: bytes, algo: str) -> Iterator[tuple[bytes, bytes, str]]:
        """产出 (待哈希候选, 还原明文, 变体描述)。algo 为当前 hex 长度对应的主算法。"""
        if algo == "md5":
            # md5 长度(32 hex): 直接 / 大小写变体 / 双 md5 / 带盐 / 反向
            yield word, word, "md5"
            yield word[::-1], word, "md5-reverse"   # 反向命中 -> 还原正序
            if word.isalpha() or word[:1].isalpha():
                yield word.capitalize(), word.capitalize(), "md5(capitalize)"
                yield word.upper(), word.upper(), "md5(upper)"
            yield hashlib.md5(word).digest(), word, "md5(md5(x))"
            if self._salt:
                yield self._salt + word, word, f"md5(salt+x,salt={self._salt!r})"
                yield word + self._salt, word, f"md5(x+salt,salt={self._salt!r})"
        else:
            # sha 系: 直接 / 反向 / 大小写
            yield word, word, algo
            yield word[::-1], word, f"{algo}-reverse"
            if word.isalpha() or word[:1].isalpha():
                yield word.capitalize(), word.capitalize(), f"{algo}(capitalize)"
                yield word.upper(), word.upper(), f"{algo}(upper)"
            if self._salt:
                yield self._salt + word, word, f"{algo}(salt+x)"
                yield word + self._salt, word, f"{algo}(x+salt)"

    # ------------------------------------------------------------ 主攻击
    def attack(self, ct: bytes) -> Iterator[Candidate]:
        hexstr = re.sub(rb"\s+", b"", ct).decode().lower()
        algo = HASH_BY_HEXLEN[len(hexstr)]
        for word in self._words:
            w = word.encode()
            for candidate, plain, desc in self._variants(w, algo):
                digest = hashlib.new(algo, candidate).hexdigest()
                if digest == hexstr:
                    yield Candidate(
                        plaintext=plain,   # 还原后的实际明文
                        method=f"{desc}-dict-crack(word='{plain.decode()}')",
                        chain=[f"{algo}:{desc}"],
                        verified=True,   # 摘要比对是确定性结果, 不依赖统计评分
                    )
                    return


ALL_HASH = [HashPlugin()]
