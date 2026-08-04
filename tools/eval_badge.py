# -*- coding: utf-8 -*-
"""CI 徽章数据生成器: 运行语料评测 + 盲测, 输出 shields.io endpoint JSON。

由 .github/workflows/eval-badge.yml 在 GitHub Actions 中调用:
  python tools/eval_badge.py
产物: badge/eval-results.json / badge/blind-results.json
shields.io 动态徽章: https://img.shields.io/endpoint?url=<gh-pages 上的 json>
"""
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def _write_badge(path: str, label: str, message: str, color: str) -> None:
    data = {"schemaVersion": 1, "label": label, "message": message, "color": color}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)
    print(f"badge: {label} -> {message} ({color})")


def main() -> int:
    os.makedirs(os.path.join(ROOT, "badge"), exist_ok=True)

    # 1) 语料评测: (passed, total)
    try:
        from cipherscope.core.evaluate import run_eval

        passed, total = run_eval(verbose=False)
        color = "brightgreen" if passed == total else "yellow"
        _write_badge(
            os.path.join(ROOT, "badge", "eval-results.json"),
            "eval",
            f"{passed}/{total} ({passed / max(total, 1):.0%})",
            color,
        )
    except Exception as exc:  # noqa: BLE001 —— CI 容错, 徽章显示失败不影响流程
        print(f"eval failed: {exc}")
        _write_badge(os.path.join(ROOT, "badge", "eval-results.json"),
                     "eval", "error", "red")
        return 1

    # 2) 盲测: PASS 计数
    try:
        out = subprocess.run(
            [sys.executable, os.path.join(ROOT, "tools", "blind_test.py")],
            capture_output=True, text=True, timeout=1200, cwd=ROOT,
        ).stdout
        # blind_test 输出行格式: "{name:<22} PASS|FAIL chain=..."
        marks = [l for l in out.splitlines()
                 if re.search(r"\b(PASS|FAIL)\b", l)]
        p = sum(1 for m in marks if " PASS " in m or m.strip().endswith("PASS"))
        t = len(marks)
        color = "brightgreen" if p == t and t > 0 else "yellow"
        _write_badge(
            os.path.join(ROOT, "badge", "blind-results.json"),
            "blind tests",
            f"{p}/{t}",
            color,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"blind failed: {exc}")
        _write_badge(os.path.join(ROOT, "badge", "blind-results.json"),
                     "blind tests", "error", "red")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
