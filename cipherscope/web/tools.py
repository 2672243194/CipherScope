"""手动编码/解码工具箱 (CyberChef 式单步操作) —— /api/tool 端点后端逻辑。

与自动求解(pipeline)互补: 自动求解是"识别->攻击->评分"全链路;
工具箱是用户显式指定操作的确定性单步转换, 支持编码与解码双向。
每个操作: (name, category, 可逆方向, 处理器)。处理器统一签名:
    fn(data: bytes, direction: str) -> bytes
direction: "encode" | "decode" (不适用方向时返回原样并在 UI 标注)。
"""
from __future__ import annotations

import base64
import binascii
import codecs
import gzip
import hashlib
import html
import json
import quopri
import re
import urllib.parse
import zlib

# ------------------------------------------------------------ 基础工具

_MORSE_ENC = {
    "a": ".-", "b": "-...", "c": "-.-.", "d": "-..", "e": ".", "f": "..-.",
    "g": "--.", "h": "....", "i": "..", "j": ".---", "k": "-.-", "l": ".-..",
    "m": "--", "n": "-.", "o": "---", "p": ".--.", "q": "--.-", "r": ".-.",
    "s": "...", "t": "-", "u": "..-", "v": "...-", "w": ".--", "x": "-..-",
    "y": "-.--", "z": "--..", "0": "-----", "1": ".----", "2": "..---",
    "3": "...--", "4": "....-", "5": ".....", "6": "-....", "7": "--...",
    "8": "---..", "9": "----.", ".": ".-.-.-", ",": "--..--", "?": "..--..",
    "!": "-.-.--", ":": "---...", ";": "-.-.-.", "(": "-.--.", ")": "-.--.-",
    "'": ".----.", "-": "-....-", "_": "..--.-", '"': ".-..-.", "/": "-..-.",
    "+": ".-.-.", "=": "-...-", "@": ".--.-.", " ": "/",
}
_MORSE_DEC = {v: k for k, v in _MORSE_ENC.items()}

_B58_ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58_ALPHA[r] + out
    pad = 0
    for b in data:
        if b == 0:
            pad += 1
        else:
            break
    return "1" * pad + out


def _b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 58 + _B58_ALPHA.index(ch)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = 0
    for ch in s:
        if ch == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + raw


def _b91decode(s: str) -> bytes:
    """basE91 解码 (标准算法)。"""
    b = 0
    n = 0
    out = bytearray()
    for ch in s:
        if ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\"":
            continue
        v = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\"".index(ch)
        if n == 0:
            b, n = v, 1
        else:
            b |= v << n
            n = 0
            if b & 1:
                out.append((b >> 1) & 0xFF)
                b >>= 8
            else:
                out.append(b & 0xFF)
                b >>= 8
    if n:
        out.append((b >> 1) & 0xFF)
    return bytes(out)


def _b91encode(data: bytes) -> str:
    """basE91 编码 (标准算法)。"""
    out = []
    b, n = 0, 0
    for byte in data:
        b |= byte << n
        n += 8
        if n > 13:
            v = b & 8191
            if v > 88:
                b >>= 13
                n -= 13
            else:
                v = b & 16383
                b >>= 14
                n -= 14
            out.append(_B91_ALPHA[v % 91])
            out.append(_B91_ALPHA[v // 91])
    if n:
        out.append(_B91_ALPHA[b % 91])
        if n > 7 or b > 90:
            out.append(_B91_ALPHA[b // 91])
    return "".join(out)


_B91_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\""


def _unicode_escape_enc(data: bytes) -> str:
    return "".join(
        f"\\u{ord(c):04x}" if ord(c) > 0x7F else c
        for c in data.decode("utf-8", errors="replace")
    )


_UNICODE_ESC_RE = re.compile(r"(?:\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8})")


def _unicode_escape_dec(data: bytes) -> bytes:
    def repl(m: re.Match) -> str:
        return chr(int(m.group(0)[2:], 16))

    return _UNICODE_ESC_RE.sub(repl, data.decode("utf-8", errors="ignore")).encode()


def _ascii_ord(data: bytes) -> str:
    return " ".join(str(b) for b in data)


def _ascii_chr(data: bytes) -> bytes:
    nums = re.findall(r"\d+", data.decode("ascii", errors="ignore"))
    return bytes(int(n) for n in nums if 0 <= int(n) <= 255)


def _hex_ord(data: bytes) -> str:
    return " ".join(f"{b:02x}" for b in data)


def _hex_chr(data: bytes) -> bytes:
    return bytes.fromhex(re.sub(r"[\s,]", "", data.decode("ascii", errors="ignore")))


def _binary_ord(data: bytes) -> str:
    return " ".join(f"{b:08b}" for b in data)


def _binary_chr(data: bytes) -> bytes:
    bits = re.sub(r"[\s,]", "", data.decode("ascii", errors="ignore"))
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) - 7, 8))


def _rot13(data: bytes) -> bytes:
    return codecs.encode(data.decode("utf-8", errors="replace"), "rot13").encode()


def _reverse(data: bytes) -> bytes:
    return data[::-1]


def _swapcase(data: bytes) -> bytes:
    return data.decode("utf-8", errors="replace").swapcase().encode()


def _morse_enc(data: bytes) -> bytes:
    text = data.decode("utf-8", errors="replace").lower()
    words = text.split()
    return "   ".join(" ".join(_MORSE_ENC.get(c, "") for c in w if c in _MORSE_ENC) for w in words).encode()


def _morse_dec(data: bytes) -> bytes:
    text = data.decode("ascii", errors="ignore")
    out = []
    for word in re.split(r"\s{2,}", text.strip()):
        out.append("".join(_MORSE_DEC.get(sym, "") for sym in word.split()))
    return " ".join(out).encode()


def _puny_enc(data: bytes) -> bytes:
    text = data.decode("utf-8", errors="replace")
    return ".".join(
        "xn--" + codecs.encode(label, "punycode").decode("ascii") if not label.isascii() else label
        for label in text.split(".")
    ).encode()


def _puny_dec(data: bytes) -> bytes:
    text = data.decode("ascii", errors="ignore")
    out = []
    for label in text.split("."):
        if label.startswith("xn--"):
            out.append(codecs.decode(label[4:].encode(), "punycode"))
        else:
            out.append(label)
    return ".".join(out).encode()


def _jwt_parse(data: bytes, direction: str = "decode") -> bytes:
    parts = data.decode("ascii", errors="ignore").strip().split(".")
    if len(parts) != 3:
        raise ValueError("JWT 需为 header.payload.signature 三段")
    pad = lambda s: s + "=" * (-len(s) % 4)   # noqa: E731
    try:
        header = json.loads(base64.urlsafe_b64decode(pad(parts[0])))
        payload = json.loads(base64.urlsafe_b64decode(pad(parts[1])))
    except Exception as exc:
        raise ValueError(f"JWT 解析失败: {exc}") from exc
    return json.dumps({"header": header, "payload": payload}, ensure_ascii=False, indent=2).encode()


def _baseconv(data: bytes, direction: str = "encode") -> bytes:
    """进制转换: 输入一个整数(支持 0x/0b/0o 前缀), 输出 2/8/10/16 进制对照。"""
    s = data.decode("ascii", errors="ignore").strip()
    try:
        n = int(s, 0) if re.match(r"^0[xob]", s) else int(s)
    except ValueError as exc:
        raise ValueError("请输入十进制整数(或带 0x/0o/0b 前缀)") from exc
    return (
        f"decimal : {n}\n"
        f"hex     : 0x{n:x}\n"
        f"octal   : 0o{n:o}\n"
        f"binary  : 0b{n:b}\n"
        f"char    : {chr(n) if 0 <= n <= 0x10FFFF else '(超出范围)'}"
    ).encode()


def _oct_ord(data: bytes) -> str:
    return " ".join(f"{b:03o}" for b in data)


def _oct_chr(data: bytes) -> bytes:
    nums = re.findall(r"[0-7]+", data.decode("ascii", errors="ignore"))
    return bytes(int(n, 8) for n in nums if int(n, 8) <= 255)


def _num2text(data: bytes, direction: str = "decode") -> bytes:
    """进制 ↔ 文本 双向工具。

    decode (进制→文本): 输入一串 2/8/10/16 进制数, 自动尝试四种进制, 输出
    可打印率最高的前几个解释; 数字 >255 时额外尝试 Unicode 码点十进制解释
    (如 20320 22909 -> 你好)。单个数字无法消歧, 全部列出。
    encode (文本→进制): 输入文本, 输出各进制的数值序列与 Unicode 码点。"""
    s = data.decode("utf-8", errors="ignore").strip()
    if direction == "encode":
        return _num2text_enc(s)
    tokens = re.split(r"[\s,;]+", s)
    if not tokens or not any(t for t in tokens):
        raise ValueError("请输入至少一个数字(空格或逗号分隔)")
    results = []
    for base, label in ((2, "binary"), (8, "octal"), (10, "decimal"), (16, "hex")):
        try:
            vals = [int(t, base) for t in tokens]
        except ValueError:
            continue
        if not all(0 <= v <= 255 for v in vals):
            continue
        out = bytes(vals)
        if len(vals) >= 2:
            printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in out) / max(len(out), 1)
        else:
            printable = 0.0   # 单个数无交叉验证, 不参与排序(全部列出)
        results.append((printable, label, out))
    # Unicode 码点十进制: 数字可 >255 (如 20320 -> 你)
    try:
        cp_vals = [int(t, 10) for t in tokens]
        if all(0 <= v <= 0x10FFFF for v in cp_vals):
            cp_out = "".join(chr(v) for v in cp_vals)
            if any(v > 255 for v in cp_vals) or len(set(cp_out)) == len(cp_out) or all(c.isprintable() for c in cp_out):
                printable = sum(c.isprintable() for c in cp_out) / max(len(cp_out), 1)
                results.append((printable, "unicode-cp", cp_out.encode("utf-8")))
    except ValueError:
        pass
    if not results:
        raise ValueError("无法按 2/8/10/16 进制或 Unicode 码点解析")
    results.sort(key=lambda x: x[0], reverse=True)
    lines = [f"[{label}] {out.decode('utf-8', 'replace')}" for _, label, out in results[:4]]
    if len(tokens) == 1:
        lines.append("(单个数字无法确定进制, 以上为全部可能解释)")
    return "\n".join(lines).encode()


def _num2text_enc(text: str) -> bytes:
    """文本 -> 各进制数值序列 + Unicode 码点。"""
    lines = []
    hex_vals = " ".join(f"{ord(c):02x}" for c in text)
    dec_vals = " ".join(str(ord(c)) for c in text)
    oct_vals = " ".join(f"{ord(c):03o}" for c in text)
    bin_vals = " ".join(f"{ord(c):08b}" for c in text)
    lines.append(f"[hex]      {hex_vals}")
    lines.append(f"[decimal]  {dec_vals}")
    lines.append(f"[octal]    {oct_vals}")
    lines.append(f"[binary]   {bin_vals}")
    if any(ord(c) > 255 for c in text):
        lines.append(f"[unicode码点] {dec_vals}")
    return "\n".join(lines).encode()


def _maybe_hex_bytes(data: bytes) -> bytes:
    """zlib/gzip 解压输入约定: 二进制数据经 JSON 无法直接传递, 若输入文本
    是合法 hex(全 hex 字符 + 偶数长度), 先按 hex 解码为原始字节再解压。"""
    s = data.decode("ascii", errors="ignore").strip()
    if len(s) >= 2 and len(s) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", s):
        return bytes.fromhex(s)
    return data


# ------------------------------------------------------------ 执行入口


def run_tool(tool: str, data: bytes, direction: str) -> dict:
    """执行单个工具操作。返回 {ok, output(文本), binary(是否二进制输出)}。"""
    if tool not in TOOLS:
        raise ValueError(f"未知工具: {tool}")
    name, support, handler = TOOLS[tool]
    if direction not in ("encode", "decode"):
        raise ValueError("direction 必须为 encode/decode")
    if support != "both" and support != direction:
        raise ValueError(f"{name} 仅支持 {support} 方向")
    result = handler(data, direction)
    if not isinstance(result, bytes):
        raise TypeError(f"{name} 返回类型错误")
    # 二进制输出检测: 不可打印字节占比高
    printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in result)
    binary = printable / max(len(result), 1) < 0.8
    text = result.decode("utf-8", errors="replace")
    return {"ok": True, "output": text, "binary": binary, "name": name}


def _caesar_decode(data: bytes, direction: str = "decode") -> bytes:
    """凯撒穷举: 对纯字母文本尝试全部 25 种位移, 输出候选列表。"""
    text = data.decode("utf-8", errors="ignore")
    out = []
    for shift in range(1, 26):
        res = []
        for ch in text:
            if "a" <= ch <= "z":
                res.append(chr(ord("a") + (ord(ch) - ord("a") + shift) % 26))
            elif "A" <= ch <= "Z":
                res.append(chr(ord("A") + (ord(ch) - ord("A") + shift) % 26))
            else:
                res.append(ch)
        out.append(f"[shift +{shift:>2}] {''.join(res)}")
    return "\n".join(out).encode()


def _hash_compute(data: bytes, direction: str = "encode") -> bytes:
    """哈希计算: 输入文本, 输出 MD5/SHA1/SHA224/SHA256/SHA384/SHA512。"""
    lines = []
    for algo in ("md5", "sha1", "sha224", "sha256", "sha384", "sha512"):
        h = hashlib.new(algo, data)
        lines.append(f"{algo.upper():<8} {h.hexdigest()}")
    return "\n".join(lines).encode()


# ------------------------------------------------------------ 操作表
# 定义在所有 helper 之后(模块执行顺序: 表引用函数须先有定义)。
# key -> (显示名, 支持方向, handler(data, direction) -> bytes)
TOOLS: dict[str, tuple[str, str, object]] = {
    # ---------------- Base 编码
    "b64": ("Base64", "both", lambda d, k: base64.b64encode(d) if k == "encode" else base64.b64decode(d, validate=True)),
    "b32": ("Base32", "both", lambda d, k: base64.b32encode(d) if k == "encode" else base64.b32decode(d, casefold=True)),
    "b16": ("Hex (支持空格分隔)", "both", lambda d, k: d.hex().encode() if k == "encode" else _hex_flex(d)),
    "b85": ("Base85", "both", lambda d, k: base64.a85encode(d) if k == "encode" else base64.a85decode(d)),
    "b58": ("Base58", "both", lambda d, k: _b58encode(d).encode() if k == "encode" else _b58decode(d.decode("ascii", errors="ignore"))),
    "b91": ("Base91", "both", lambda d, k: _b91encode(d).encode() if k == "encode" else _b91decode(d.decode("ascii", errors="ignore"))),
    # ---------------- 文本编码
    "url": ("URL 编码", "both", lambda d, k: urllib.parse.quote_from_bytes(d).encode() if k == "encode" else urllib.parse.unquote_to_bytes(d.decode("ascii", errors="ignore"))),
    "uni": ("Unicode 转义 \\uXXXX", "both", lambda d, k: _unicode_escape_enc(d).encode() if k == "encode" else _unicode_escape_dec(d)),
    "html": ("HTML 实体", "both", lambda d, k: html.escape(d.decode("utf-8", errors="replace")).encode() if k == "encode" else html.unescape(d.decode("utf-8", errors="ignore")).encode()),
    "qp": ("Quoted-Printable", "both", lambda d, k: quopri.encodestring(d) if k == "encode" else quopri.decodestring(d)),
    "puny": ("Punycode (域名)", "both", lambda d, k: _puny_enc(d) if k == "encode" else _puny_dec(d)),
    "morse": ("摩斯电码", "both", lambda d, k: _morse_enc(d) if k == "encode" else _morse_dec(d)),
    "rot13": ("ROT13", "both", lambda d, k: _rot13(d) if k == "encode" else _rot13(d)),
    "reverse": ("反转字符串", "encode", lambda d, k: _reverse(d)),
    "swapcase": ("大小写互换", "encode", lambda d, k: _swapcase(d)),
    # ---------------- 古典密码
    "caesar": ("凯撒穷举(25位移)", "decode", _caesar_decode),
    # ---------------- 进制转换
    "num2text": ("进制↔文本(2/8/10/16+Unicode码点)", "both", _num2text),
    "baseconv": ("进制转换(输入整数)", "encode", _baseconv),
    # ---------------- 压缩/结构化
    "zlib": ("Zlib 压缩/解压(解压支持hex)", "both", lambda d, k: zlib.compress(d) if k == "encode" else zlib.decompress(_maybe_hex_bytes(d))),
    "gzip": ("Gzip 压缩/解压(解压支持hex)", "both", lambda d, k: gzip.compress(d) if k == "encode" else gzip.decompress(_maybe_hex_bytes(d))),
    "jwt": ("JWT 解析", "decode", _jwt_parse),
    # ---------------- 哈希
    "hash": ("哈希计算(MD5/SHA系)", "encode", _hash_compute),
}

# 工具分组 (前端 optgroup 渲染)
TOOL_CATEGORIES: dict[str, str] = {
    "b64": "Base 编码", "b32": "Base 编码", "b16": "Base 编码",
    "b85": "Base 编码", "b58": "Base 编码", "b91": "Base 编码",
    "url": "文本编码", "uni": "文本编码", "html": "文本编码",
    "qp": "文本编码", "puny": "文本编码", "morse": "文本编码",
    "rot13": "文本编码", "reverse": "文本编码", "swapcase": "文本编码",
    "caesar": "古典密码",
    "num2text": "进制转换", "baseconv": "进制转换",
    "zlib": "压缩与结构化", "gzip": "压缩与结构化", "jwt": "压缩与结构化",
    "hash": "哈希",
}


def _hex_flex(data: bytes) -> bytes:
    """Hex 解码, 兼容空格/逗号/0x 前缀分隔。"""
    s = data.decode("ascii", errors="ignore").strip()
    s = re.sub(r"[\s,;]+", "", s)
    s = s.replace("0x", "").replace("0X", "")
    return bytes.fromhex(s)
