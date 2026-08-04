"""CipherScope Web 可视化版 (v0.3) —— FastAPI + 单页前端。

打包 exe 时, PyInstaller 将本模块与静态文件打入单文件,
双击启动本地服务并自动打开浏览器。
"""
from __future__ import annotations

import binascii
import zlib
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from cipherscope.core.pipeline import Pipeline
from cipherscope.core.scorer import ScoringEngine
from cipherscope.plugins import build_default_registry

_STATIC_DIR = Path(__file__).resolve().parent / "static"


class SolveRequest(BaseModel):
    text: str
    max_depth: int = 10
    flag_prefix: str | None = None
    prefer: str | None = None   # 优先攻击类型, 逗号分隔
    exclude: list[str] = []     # 屏蔽的明文(答案不对时继续寻找)


class ToolRequest(BaseModel):
    tool: str
    text: str
    direction: str = "decode"


class RsaRequest(BaseModel):
    """RSA 表单式求解器: 所有参数可选, 填了哪些就算哪些。"""
    p: int | None = None
    q: int | None = None
    e: int | None = None
    c: int | None = None
    n: int | None = None
    dp: int | None = None
    e2: int | None = None
    c2: int | None = None
    ns: str | None = None   # 广播攻击: 逗号分隔的多组模数
    cs: str | None = None   # 广播攻击: 逗号分隔的多组密文


def _m_lines(m: bytes) -> list[str]:
    """格式化明文 m 的全部表示: bytes/text/decimal/hex。"""
    try:
        text = m.decode("utf-8")
        readable = all(c.isprintable() for c in text)
    except UnicodeDecodeError:
        readable = False
    lines = [f"m(bytes) = {m!r}"]
    if readable:
        lines.append(f"m(text)  = {text!r}")
    else:
        lines.append("m(text)  = (非可读文本——flag 通常为下方的十进制或 hex 值)")
    lines.append(f"m(decimal) = {int.from_bytes(m, 'big')}")
    lines.append(f"m(hex)     = {m.hex()}")
    return lines


def _rsa_solve(req: RsaRequest) -> dict:
    """自动匹配 RSA 题型: 用已填参数尝试所有适用的攻击, 返回全部成功结果。
    每个结果含攻击名与推导出的参数/值, 未填参数不影响其他题型。"""
    from cipherscope.plugins import rsa_attack as R
    results: list[dict] = []

    def add(attack: str, lines: list[str]) -> None:
        results.append({"attack": attack, "lines": lines})

    # 1) p,q,e -> d (填 p/q/e 即算)
    if req.p and req.q and req.e:
        d = R.solve_d(req.p, req.q, req.e)
        if d is not None:
            add("p,q,e → d", [f"φ(n) = {(req.p - 1) * (req.q - 1)}", f"d = {d}", f"n = {req.p * req.q}"])
        else:
            add("p,q,e → d", ["gcd(e, φ(n)) ≠ 1, 非合法 RSA 公钥"])

    # 2) p,q,e,c -> m (解密明文)
    if req.p and req.q and req.e and req.c is not None:
        m = R.solve_plaintext(req.p, req.q, req.e, req.c)
        if m is not None:
            add("p,q,e,c → m (直接解密)", _m_lines(m))

    # 3) dp,n,e,c -> m (dp 泄露)
    if req.dp is not None and req.n and req.e and req.c is not None:
        m = R.dp_leak(req.dp, req.n, req.e, req.c)
        if m is not None:
            add("dp 泄露 → m", _m_lines(m))
        else:
            add("dp 泄露", ["dp 与 n/e/c 不匹配, 攻击失败"])

    # 4) e,ns,cs -> m (低指数广播)
    if req.e and req.ns and req.cs:
        try:
            ns_list = [int(x) for x in req.ns.split(",")]
            cs_list = [int(x) for x in req.cs.split(",")]
        except ValueError:
            add("低指数广播", ["ns/cs 包含非整数, 请用逗号分隔的纯数字"])
            ns_list = cs_list = []
        if ns_list and len(ns_list) == len(cs_list) and len(ns_list) >= req.e:
            m = R.hastad_broadcast(req.e, ns_list, cs_list)
            if m is not None:
                add(f"低指数广播(e={req.e}) → m", _m_lines(m))
            else:
                add("低指数广播", ["m^e 超过 ∏n_i 或 n_i 不两两互素, 攻击失败"])

    # 5) 共模攻击: n,e,c + e2,c2
    if req.n and req.e and req.c is not None and req.e2 and req.c2 is not None:
        m = R.common_modulus(req.n, req.e, req.c, req.e2, req.c2)
        if m is not None:
            add("共模攻击 → m", _m_lines(m))
        else:
            add("共模攻击", ["gcd(e1,e2) ≠ 1, 攻击失败"])

    # 6) n,e,c 单组攻击链: 低指数 / 维纳 / 分解(小n→费马→Pollard)
    if req.n and req.e and req.c is not None:
        # 低加密指数
        m = R.low_exponent(req.e, req.c, req.n)
        if m is not None:
            add(f"低加密指数(e={req.e}) → m", _m_lines(m))
        # 维纳
        d = R.wiener(req.e, req.n)
        if d is not None:
            add("维纳攻击 → d", [f"d = {d}"])
            m = pow(req.c, d, req.n)
            add("维纳攻击 → m", _m_lines(R.int_to_bytes(m)))
        # 分解链
        pq = R.small_n_factor(req.n) or R.fermat_factor(req.n) or (lambda f: (f, req.n // f) if f else None)(R.pollard_p1(req.n))
        if pq:
            p, q = pq
            method = "小模数分解" if R.small_n_factor(req.n) else ("费马分解" if R.fermat_factor(req.n) else "Pollard p-1")
            d = R.solve_d(p, q, req.e)
            if d is not None:
                m = pow(req.c, d, req.n)
                add(f"{method} → m", [f"p = {p}", f"q = {q}", f"φ(n) = {(p - 1) * (q - 1)}", f"d = {d}"] + _m_lines(R.int_to_bytes(m)))
            else:
                add(method, ["e 与 φ(n) 不互素, 无法解密"])

    return {"results": results}


def create_app() -> FastAPI:
    app = FastAPI(title="CipherScope", description="CTF 密码学自动化解题工具")

    @app.get("/")
    def index():
        return FileResponse(_STATIC_DIR / "index.html")

    @app.get("/api/tools")
    def tools_list() -> JSONResponse:
        """手动工具箱操作清单 (含分组, 供前端 optgroup 渲染)。"""
        from cipherscope.web.tools import TOOLS, TOOL_CATEGORIES
        return JSONResponse([
            {"key": k, "name": name, "support": support,
             "category": TOOL_CATEGORIES.get(k, "其他")}
            for k, (name, support, _h) in TOOLS.items()
        ])

    @app.post("/api/tool")
    def tool(req: ToolRequest) -> JSONResponse:
        """手动编码/解码工具箱: 显式指定操作的确定性单步转换。"""
        from cipherscope.web.tools import run_tool
        if not req.text:
            return JSONResponse({"error": "输入不能为空"}, status_code=400)
        try:
            result = run_tool(req.tool, req.text.encode("utf-8"), req.direction)
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        except (binascii.Error, UnicodeDecodeError, UnicodeEncodeError, zlib.error) as exc:
            return JSONResponse({"error": f"执行失败: {exc}"}, status_code=400)
        except Exception as exc:
            return JSONResponse({"error": f"执行失败: {type(exc).__name__}: {exc}"}, status_code=400)
        return JSONResponse(result)

    @app.post("/api/rsa")
    def rsa_solve(req: RsaRequest) -> JSONResponse:
        """RSA 表单式求解器: 填了哪些参数就算哪些, 自动匹配题型。"""
        try:
            result = _rsa_solve(req)
        except Exception as exc:  # 兜底: 任何参数解析/计算异常都返回友好错误而非 500
            return JSONResponse({"error": f"参数解析失败: {exc}"}, status_code=400)
        if not result["results"]:
            return JSONResponse({"error": "未匹配到任何 RSA 题型——请至少提供一组有效参数(如 p,q,e 或 n,e,c 或 dp,n,e,c 等)"}, status_code=400)
        return JSONResponse(result)

    @app.post("/api/solve")
    def solve(req: SolveRequest) -> JSONResponse:
        if not req.text.strip():
            return JSONResponse({"error": "密文不能为空"}, status_code=400)
        prefixes = None
        if req.flag_prefix:
            prefixes = tuple(p.strip().lower() for p in req.flag_prefix.split(",") if p.strip())
        scorer = ScoringEngine(flag_prefixes=prefixes) if prefixes else ScoringEngine()
        pipeline = Pipeline(build_default_registry(), scorer)
        result = pipeline.solve(
            req.text.encode("utf-8"),
            max_depth=req.max_depth,
            prefer={t.strip().lower() for t in req.prefer.split(",")} if req.prefer else None,
            exclude={e.encode("utf-8") for e in req.exclude if e},
        )
        return JSONResponse({
            "found": result.found,
            "plaintext": result.plaintext.decode("utf-8", errors="replace") if result.found else "",
            "chain": result.chain,
            "method": result.method,
            "score": round(result.score, 1) if result.found else None,
            "depth": result.depth,
            "attempts": result.attempts,
            "steps": [
                {"stage": s.stage, "description": s.description, "detail": s.detail}
                for s in result.steps
            ],
            "alternatives": [
                {
                    "plaintext": pt.decode("utf-8", errors="replace"),
                    "method": method,
                    "score": round(score, 1),
                }
                for pt, method, score in result.alternatives
            ],
        })

    app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")
    return app


app = create_app()
