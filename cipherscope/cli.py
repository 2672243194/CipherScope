"""CipherScope 命令行入口 (typer)。

v0.1 当前可用: detect / score
auto 与 attack 将在攻击插件(codecs/classical/xor)就绪后接入调度器。
"""
from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from cipherscope import __version__
from cipherscope.core.detector import DetectionEngine
from cipherscope.core.scorer import ScoringEngine, Verdict

app = typer.Typer(
    name="cipherscope",
    help="CTF 密码学自动化解题工具: 识别 -> 攻击 -> 评分 -> flag。",
    add_completion=False,
)
console = Console()


def _read_input(text: str | None, file: Path | None) -> bytes:
    if file is not None:
        return file.read_bytes()
    if text is not None:
        return text.encode("utf-8")
    raise typer.BadParameter("必须提供 TEXT 或 --file 之一")


@app.command()
def detect(
    text: str | None = typer.Argument(None, help="待识别的密文"),
    file: Path | None = typer.Option(None, "--file", "-f", help="从文件读取密文"),
) -> None:
    """识别密文类型, 输出置信度排序的候选列表。"""
    data = _read_input(text, file)
    detections = DetectionEngine().detect(data)
    if not detections:
        console.print("[yellow]未能识别: 无匹配特征 (样本可能过短)[/yellow]")
        raise typer.Exit(1)
    table = Table(title="Detection Results")
    table.add_column("Type", style="cyan")
    table.add_column("Confidence", justify="right")
    table.add_column("Detail")
    for d in detections:
        table.add_row(d.type, f"{d.confidence:.2f}", d.detail)
    console.print(table)


@app.command()
def score(
    text: str | None = typer.Argument(None, help="待评分的候选明文"),
    file: Path | None = typer.Option(None, "--file", "-f", help="从文件读取"),
    flag_prefix: str | None = typer.Option(None, "--flag-prefix", help="自定义 flag 前缀"),
) -> None:
    """对一段文本做明文质量评分 (调试评分引擎用)。"""
    data = _read_input(text, file)
    engine = ScoringEngine(flag_prefixes=(flag_prefix.lower(),) if flag_prefix else ())
    if flag_prefix is None:
        engine = ScoringEngine()
    result = engine.score(data)
    style = {"success": "green", "promising": "yellow", "reject": "red"}[result.verdict.value]
    console.print(f"score=[bold {style}]{result.score:.1f}[/] verdict=[{style}]{result.verdict.value}[/]")
    if result.flag_hit:
        console.print(f"flag prefix hit: {result.flag_prefix}")
    console.print({k: round(v, 2) for k, v in result.detail.items()})


@app.command()
def auto(
    text: str | None = typer.Argument(None, help="密文"),
    file: Path | None = typer.Option(None, "--file", "-f", help="从文件读取密文"),
    max_depth: int = typer.Option(10, "--max-depth", help="嵌套搜索最大层数"),
    flag_prefix: str | None = typer.Option(None, "--flag-prefix", help="自定义 flag 前缀"),
    prefer: str | None = typer.Option(None, "--prefer", help="优先尝试的攻击类型, 逗号分隔(如 caesar,vigenere), 提高其调度权重"),
    wordlist: Path | None = typer.Option(None, "--wordlist", "-w", help="哈希爆破外部字典文件(每行一词, 自动尝试正序/反转/双哈希等变体)"),
    salt: str | None = typer.Option(None, "--salt", help="带盐哈希的盐(尝试 md5(salt+x) 与 md5(x+salt))"),
    show_alternatives: bool = typer.Option(False, "--alternatives", "-a", help="同时展示其他可能答案"),
) -> None:
    """全自动求解: 识别 -> 攻击 -> 评分 -> 嵌套深挖, 直到命中 flag。
    成功后输出求解步骤(识别/攻击/验证), 供编写 writeup。
    可用 --prefer 手动指定优先攻击类型; --wordlist 注入哈希爆破字典;
    --salt 指定带盐哈希的盐。"""
    from cipherscope.core.pipeline import Pipeline
    from cipherscope.plugins import build_default_registry

    data = _read_input(text, file)
    scorer = ScoringEngine(flag_prefixes=(flag_prefix.lower(),)) if flag_prefix else ScoringEngine()
    extra_words = None
    if wordlist:
        extra_words = [
            line.strip() for line in wordlist.read_text(encoding="utf-8", errors="ignore")
            .splitlines() if line.strip()
        ]
        console.print(f"[dim]已加载字典 {len(extra_words)} 词: {wordlist}[/dim]")
    pipeline = Pipeline(
        build_default_registry(extra_words, salt.encode() if salt else None), scorer
    )
    prefer_set = {t.strip().lower() for t in prefer.split(",")} if prefer else None
    result = pipeline.solve(data, max_depth=max_depth, prefer=prefer_set)

    if not result.found:
        console.print(f"[red]未找到 flag[/red] (已尝试 {result.attempts} 次评分, 可尝试 --max-depth 加深或检查题型是否覆盖)")
        raise typer.Exit(1)
    console.print(f"[bold green]FOUND[/bold green] score={result.score:.1f} depth={result.depth} attempts={result.attempts}")
    console.print(f"[cyan]chain:[/cyan] {' -> '.join(result.chain)}")
    console.print(f"[cyan]method:[/cyan] {result.method}")
    console.print("[cyan]plaintext:[/cyan]")
    console.print(result.plaintext.decode("utf-8", errors="replace"))

    if result.steps:
        console.print("\n[bold cyan]== 求解步骤 (writeup) ==[/bold cyan]")
        for s in result.steps:
            detail = f"  [dim]({s.detail})[/dim]" if s.detail else ""
            console.print(f"  [{s.stage}] {s.description}{detail}")

    if show_alternatives and result.alternatives:
        console.print(f"\n[bold yellow]== 其他可能答案 ({len(result.alternatives)}) ==[/bold yellow]")
        for pt, method, score in result.alternatives:
            console.print(f"  [yellow]{method}[/yellow] score={score:.1f}")
            console.print(f"    {pt.decode('utf-8', errors='replace')}")


@app.command()
def evaluate(
    corpus: Path | None = typer.Option(None, "--corpus", help="语料库路径, 默认 tests/ctf_corpus/corpus.yaml"),
) -> None:
    """跑真题语料库, 输出分类通过率报表。"""
    from cipherscope.core.evaluate import run_eval
    run_eval(corpus)


@app.command()
def rsa(
    n: int | None = typer.Option(None, "-n", help="模数"),
    e: int | None = typer.Option(None, "-e", help="公钥指数"),
    c: int | None = typer.Option(None, "-c", help="密文"),
    e2: int | None = typer.Option(None, "--e2", help="共模攻击: 第二个公钥指数"),
    c2: int | None = typer.Option(None, "--c2", help="共模攻击: 第二份密文"),
    ns: str | None = typer.Option(None, "--ns", help="公约数/广播攻击: 逗号分隔的多组模数"),
    cs: str | None = typer.Option(None, "--cs", help="低指数广播攻击: 逗号分隔的多组密文(与 --ns 对齐, 需 -e)"),
    p: int | None = typer.Option(None, "-p", help="已知素数 p (配合 -q -e 求 d; -q -e -c 解明文)"),
    q: int | None = typer.Option(None, "-q", help="已知素数 q (配合 -p -e 求 d; -p -e -c 解明文)"),
    dp: int | None = typer.Option(None, "--dp", help="dp 泄露攻击: 已知 dp (配合 -n -e -c)"),
) -> None:
    """RSA 攻击: 小n分解 / 低指数 / 共模 / 维纳 / 公约数 / 广播 /
    费马 / Pollard p-1 / dp泄露 / p,q,e求d / p,q,e,c解明文。"""
    from cipherscope.plugins import rsa_attack as R

    # dp 泄露攻击 (dp, n, e, c)
    if dp is not None:
        if n is None or e is None or c is None:
            raise typer.BadParameter("--dp 攻击需要 -n -e -c")
        pt = R.dp_leak(dp, n, e, c)
        if pt is None:
            console.print("[red]dp 泄露攻击失败[/red] (dp 与 n/e/c 不匹配?)")
            raise typer.Exit(1)
        console.print(f"[green]dp 泄露攻击成功[/green] m = {pt!r}")
        return

    # 低指数广播攻击 (e 相同, 多组 n/c)
    if cs is not None:
        if e is None or ns is None:
            raise typer.BadParameter("广播攻击需要 -e --ns --cs")
        ns_list = [int(x) for x in ns.split(",")]
        cs_list = [int(x) for x in cs.split(",")]
        if len(ns_list) != len(cs_list) or len(ns_list) < e:
            raise typer.BadParameter("--ns 与 --cs 数量需一致且 >= e")
        pt = R.hastad_broadcast(e, ns_list, cs_list)
        if pt is None:
            console.print("[red]广播攻击失败[/red] (m^e 超过 ∏n_i 或 n_i 不两两互素?)")
            raise typer.Exit(1)
        console.print(f"[green]低指数广播攻击成功 (e={e})[/green] m = {pt!r}")
        return

    # 已知 p/q/e/c 解明文 (babyRSA); p/q/e 求 d (提交 flag)
    if p is not None or q is not None:
        if p is None or q is None or e is None:
            raise typer.BadParameter("-p -q -e 三个参数需同时提供")
        if c is not None:
            pt = R.solve_plaintext(p, q, e, c)
            if pt is None:
                console.print("[red]gcd(e, φ(n)) ≠ 1, 非合法 RSA 公钥[/red]")
                raise typer.Exit(1)
            console.print(f"[green]p,q,e,c 直接解密成功[/green] m = {pt!r}")
            return
        d = R.solve_d(p, q, e)
        if d is None:
            console.print("[red]gcd(e, φ(n)) ≠ 1, 非合法 RSA 公钥[/red]")
            raise typer.Exit(1)
        phi = (p - 1) * (q - 1)
        console.print(f"[green]φ(n) = {phi}[/green]")
        console.print(f"[green]d = {d}[/green]  (flag 内容)")
        console.print(f"[dim]n = p*q = {p * q}[/dim]")
        return

    if ns:
        moduli = [int(x) for x in ns.split(",")]
        hits = R.gcd_shared(moduli)
        if not hits:
            console.print("[red]公约数攻击: 无命中[/red]")
            raise typer.Exit(1)
        for i, j, p in hits:
            console.print(f"[green]n[{i}] 与 n[{j}] 共享因子 p={p}[/green]")
        return

    if n is None:
        raise typer.BadParameter("必须提供 -n (或使用 --ns)")

    # 共模攻击
    if e2 is not None and c2 is not None and e is not None and c is not None:
        pt = R.common_modulus(n, e, c, e2, c2)
        if pt:
            console.print(f"[green]共模攻击成功[/green] m = {pt!r}")
            return
        console.print("[yellow]共模攻击失败 (gcd(e1,e2)≠1?)[/yellow]")

    if e is None or c is None:
        raise typer.BadParameter("单组攻击需要 -n -e -c")

    # 低加密指数
    pt = R.low_exponent(e, c, n)
    if pt:
        console.print(f"[green]低加密指数攻击成功 (e={e})[/green] m = {pt!r}")
        return

    # 维纳攻击
    d = R.wiener(e, n)
    if d is not None:
        m = pow(c, d, n)
        console.print(f"[green]维纳攻击成功[/green] d = {d}")
        console.print(f"m = {R.int_to_bytes(m)!r}")
        return

    # 小 n 分解 -> 费马 -> Pollard p-1 (依次尝试)
    pq = R.small_n_factor(n)
    if pq is None:
        pq = R.fermat_factor(n)
        if pq:
            console.print(f"[green]费马分解成功 (p≈q)[/green] p={pq[0]} q={pq[1]}")
    if pq is None:
        f = R.pollard_p1(n)
        if f:
            pq = (f, n // f)
            console.print(f"[green]Pollard p-1 分解成功[/green] p={pq[0]} q={pq[1]}")
    if pq:
        pt = R.decrypt_with_factor(c, n, pq[0], e)
        if pt is None:
            console.print("[yellow]但 e 与 φ(n) 不互素, 非合法 RSA 公钥, 无法解密[/yellow]")
            raise typer.Exit(1)
        console.print(f"m = {pt!r}")
        return

    console.print("[red]所有 RSA 攻击均未命中[/red] (n 过大无法本地分解, 建议查 factordb.com)")
    raise typer.Exit(1)


@app.command()
def web(
    host: str = typer.Option("127.0.0.1", "--host", help="监听地址"),
    port: int = typer.Option(8080, "--port", "-p", help="监听端口(被占用时自动 +1)"),
    no_browser: bool = typer.Option(False, "--no-browser", help="不自动打开浏览器"),
) -> None:
    """启动 Web 可视化版 (FastAPI + 单页前端)。端口被占用时自动递增选择。"""
    import socket
    import threading
    import webbrowser

    import uvicorn
    from cipherscope.web.app import app as web_app

    # 端口检测: 被占用则自动递增, 避免 bind 失败 (winerror 10048)
    final_port = port
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((host, final_port))
                break
            except OSError:
                final_port += 1
    if final_port != port:
        console.print(f"[yellow]端口 {port} 已被占用, 自动切换至 {final_port}[/yellow]")

    if not no_browser:
        threading.Timer(1.2, lambda: webbrowser.open(f"http://{host}:{final_port}")).start()
    console.print(f"[green]CipherScope Web 已启动[/green] http://{host}:{final_port}  (Ctrl+C 退出)")
    uvicorn.run(web_app, host=host, port=final_port, log_level="warning")


@app.command()
def version() -> None:
    """显示版本号。"""
    console.print(f"CipherScope v{__version__}")


if __name__ == "__main__":
    app()
