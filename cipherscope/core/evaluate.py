"""真题语料库评测 —— 通过率是项目最核心的可量化指标。

读取 corpus.yaml, 逐题执行完整管道求解, 输出"平台 × 密码类型"
二维通过率报表。每题独立预算, 单题失败不影响整体。
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from rich.console import Console
from rich.table import Table

from cipherscope.core.pipeline import Pipeline
from cipherscope.plugins import build_default_registry

DEFAULT_CORPUS = Path(__file__).resolve().parent.parent.parent / "tests" / "ctf_corpus" / "corpus.yaml"
PER_ITEM_DEPTH = 8


@dataclass
class EvalItem:
    id: str
    platform: str
    category: str
    passed: bool
    elapsed: float
    attempts: int = 0
    chain: list[str] = field(default_factory=list)
    note: str = ""


def run_eval(corpus_path: Path | None = None, verbose: bool = True) -> tuple[int, int]:
    console = Console()
    path = corpus_path or DEFAULT_CORPUS
    items = yaml.safe_load(path.read_text(encoding="utf-8"))
    pipeline = Pipeline(build_default_registry())

    results: list[EvalItem] = []
    for item in items:
        expected = item["expected_flag"].lower()
        encoding = item.get("ciphertext_encoding", "plain")
        data = item["ciphertext"].encode("latin1" if encoding == "latin1" else "utf-8")
        start = time.perf_counter()
        try:
            r = pipeline.solve(data, max_depth=PER_ITEM_DEPTH)
            passed = r.found and expected in r.plaintext.decode("utf-8", errors="ignore").lower()
            results.append(EvalItem(
                id=item["id"], platform=item.get("platform", item.get("source", "?")),
                category=item["category"], passed=passed,
                elapsed=time.perf_counter() - start, attempts=r.attempts,
                chain=r.chain if passed else [],
            ))
        except Exception as exc:  # 单题异常不阻塞整体评测
            results.append(EvalItem(
                id=item["id"], platform=item.get("platform", "?"), category=item["category"],
                passed=False, elapsed=time.perf_counter() - start, note=f"error: {exc}",
            ))
        if verbose:
            r = results[-1]
            mark = "[green]PASS[/green]" if r.passed else "[red]FAIL[/red]"
            console.print(f"{mark} {r.id:<24} {r.elapsed:5.1f}s  {' -> '.join(r.chain) if r.chain else r.note}")

    passed = sum(r.passed for r in results)
    total = len(results)

    # 二维报表: 平台 × 类型
    table = Table(title=f"CipherScope Eval — {passed}/{total} ({passed / total:.0%})")
    table.add_column("Platform")
    table.add_column("Category")
    table.add_column("Pass", justify="right")
    table.add_column("Total", justify="right")
    table.add_column("Rate", justify="right")
    cells: dict[tuple[str, str], list[int]] = {}
    for r in results:
        cell = cells.setdefault((r.platform, r.category.split("/")[0]), [0, 0])
        cell[0] += r.passed
        cell[1] += 1
    for (platform, category), (p, t) in sorted(cells.items()):
        table.add_row(platform, category, str(p), str(t), f"{p / t:.0%}")
    console.print(table)
    return passed, total
