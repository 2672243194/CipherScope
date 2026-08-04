"""PyInstaller 打包脚本 —— 生成 CLI 与 Web 两个单文件 exe (v0.3 发布物)。

用法:
    pip install pyinstaller
    python tools/build_exe.py all        # CLI + Web 两个 exe
    python tools/build_exe.py cli        # 仅 CLI
    python tools/build_exe.py web        # 仅 Web

产物输出到 dist/:
    CipherScope-CLI-v0.1.0.exe   # 命令行版: cipherscope auto "..."
    CipherScope-Web-v0.1.0.exe   # Web 版: 双击启动本地服务并自动打开浏览器

说明:
- Web 版入口为 cipherscope.web.launcher(见下), 启动后自动 open 浏览器;
- PyInstaller 需 --collect-all cipherscope 收集静态文件(data/quadgrams.json 等);
- 打包体积主要来自 Python 运行时, 单文件约 20-40MB, 属正常。
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSION = "0.1.0"


def build_cli() -> None:
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile", "--clean",
        "--name", f"CipherScope-CLI-v{VERSION}",
        "--collect-all", "cipherscope",
        "--hidden-import", "cipherscope.plugins.codecs",
        "--hidden-import", "cipherscope.plugins.classical",
        "--hidden-import", "cipherscope.plugins.xor_attack",
        "--hidden-import", "cipherscope.plugins.hash_attack",
        "--hidden-import", "cipherscope.plugins.rsa_attack",
        str(ROOT / "cipherscope" / "cli.py"),
    ]
    print(">>", " ".join(cmd))
    subprocess.run(cmd, cwd=ROOT, check=True)


def build_web() -> None:
    # Web 入口脚本: 启动 uvicorn 并自动打开浏览器
    launcher = ROOT / "tools" / "_web_launcher.py"
    launcher.write_text(
        "import threading, webbrowser\n"
        "import uvicorn\n"
        "from cipherscope.web.app import app\n"
        "threading.Timer(1.2, lambda: webbrowser.open('http://127.0.0.1:8080')).start()\n"
        "uvicorn.run(app, host='127.0.0.1', port=8080, log_level='warning')\n",
        encoding="utf-8",
    )
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile", "--clean", "--windowed",   # --windowed: 不弹控制台窗口
        "--name", f"CipherScope-Web-v{VERSION}",
        "--collect-all", "cipherscope",
        "--hidden-import", "uvicorn.logging",
        "--hidden-import", "uvicorn.loops.auto",
        "--hidden-import", "uvicorn.protocols.http.auto",
        "--hidden-import", "uvicorn.protocols.websockets.auto",
        "--hidden-import", "uvicorn.lifespan.on",
        str(launcher),
    ]
    print(">>", " ".join(cmd))
    subprocess.run(cmd, cwd=ROOT, check=True)
    launcher.unlink()


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "all"
    if target in ("all", "cli"):
        build_cli()
    if target in ("all", "web"):
        build_web()
    print("打包完成, 产物在 dist/ 目录")
