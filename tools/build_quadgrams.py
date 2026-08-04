"""从英文语料构建 quadgram 频率表 (data/quadgrams.json)。

用法:
    python tools/build_quadgrams.py corpus.txt [more.txt ...]

语料来源建议: 公开版权英文文本 (Project Gutenberg 等), 数据量越大越好
(参考实现通常使用数百万词)。输出为 {quadgram: log10(probability)} 的 JSON,
评分引擎加载后替代内置精简兜底表, 可显著改善对"接近英文但非标准文本"
(如夹杂 flag 的句子)的区分度。
"""
from __future__ import annotations

import json
import math
import string
import sys
from collections import Counter
from pathlib import Path

OUTPUT = Path(__file__).resolve().parent.parent / "cipherscope" / "data" / "quadgrams.json"


def build(corpus_paths: list[str]) -> None:
    counts: Counter[str] = Counter()
    for path in corpus_paths:
        text = Path(path).read_text(encoding="utf-8", errors="ignore").lower()
        letters = "".join(c for c in text if c in string.ascii_lowercase)
        counts.update(letters[i:i + 4] for i in range(len(letters) - 3))

    total = sum(counts.values())
    if total == 0:
        raise SystemExit("语料中没有有效英文字母")
    table = {q: math.log10(c / total) for q, c in counts.items()}

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(table), encoding="utf-8")
    print(f"已写入 {OUTPUT}: {len(table)} 组 quadgram, 总样本 {total}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    build(sys.argv[1:])
