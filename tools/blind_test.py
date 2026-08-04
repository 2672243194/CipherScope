"""普适性盲测：非语料内、模拟真实赛题形态的随机用例。"""
import base64
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cipherscope.plugins import build_default_registry
from cipherscope.core.pipeline import Pipeline

p = Pipeline(build_default_registry())
cases = []

# 1. 短文本凯撒(无 FILLER 提示, 纯 flag)
text = "flag{sh0rt_caesar}"
cases.append(("短文本凯撒(无提示)", "".join(
    chr((ord(c) - 97 + 3) % 26 + 97) if "a" <= c <= "z" else c for c in text
).encode(), text))

# 2. rot13 (凯撒 13) —— 注意 ROT13('flag')='synt'
cases.append(("ROT13", b"synt{ebg13_grfg}", "flag{rot13_test}"))

# 3. 中文 flag + base64
pt3 = "flag{zhongwen_ceshi}".encode()
cases.append(("中文flag+base64", base64.b64encode(pt3), pt3.decode()))

# 4. 纯栅栏(无提示词)
rf = "flag{r4ilfence_alone}"
pat = [0, 1, 2, 1]
fence = [[], [], []]
for i, ch in enumerate(rf):
    fence[pat[i % 4]].append(ch)
cases.append(("纯栅栏3栏", "".join("".join(r) for r in fence).encode(), rf))

# 5. 空格分隔十进制 ASCII (无插件覆盖)
dec = " ".join(str(b) for b in b"flag{dec_ascii_test}")
cases.append(("十进制ASCII序列", dec.encode(), "flag{dec_ascii_test}"))

# 6. 短单字节 XOR (30字节内)
plain6 = b"flag{x0r_sh0rt}"
cases.append(("短单字节XOR", bytes(b ^ 0x5A for b in plain6), plain6.decode()))

# 7. 双层混合: hex -> rot13
pt7 = "flag{mixed_r13_hex}"
r13 = "".join(chr((ord(c) - 97 + 13) % 26 + 97) if "a" <= c <= "z" else c for c in pt7)
cases.append(("hex套ROT13", r13.encode().hex().encode(), pt7))

# 8. base58 (手写实现, 比特币字母表)
def b58encode(data: bytes) -> str:
    alpha = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(data, "big")
    out = []
    while n > 0:
        n, r = divmod(n, 58)
        out.append(alpha[r])
    return "".join(reversed(out))

pt8 = "flag{b58_supported}"
cases.append(("base58编码", b58encode(pt8.encode()).encode(), pt8))

# 9. 云影密码: 字母序号拆 1-2-4-8 和(可重复), 数字位直接拼接, 字母间 0 分隔
def cloud_enc(text: str) -> str:
    parts = []
    for c in text.lower():
        if "a" <= c <= "z":
            v = ord(c) - 96
            digs = []
            for d in (8, 4, 2, 1):
                while v >= d:
                    digs.append(str(d))
                    v -= d
            parts.append("".join(digs))
        else:
            parts.append(c)
    return "0".join(parts)

pt9 = "flag{cloud_shadow}"
cases.append(("云影密码", cloud_enc(pt9).encode(), pt9))

# 10. uuencode
import binascii
pt10 = "flag{uuencode_works}"
cases.append(("uuencode", binascii.b2a_uu(pt10.encode()).decode().encode(), pt10))

# 11. OOK!: BF 程序输出 flag{ook_works} 后翻译成 Ook
def bf_print(text: str) -> str:
    return "".join("+" * v + "." + "-" * v for v in (ord(c) for c in text))

BF_PROG = bf_print("flag{ook_works}")
_OOK = {
    ">": "Ook. Ook? ", "<": "Ook? Ook. ", "+": "Ook. Ook. ", "-": "Ook! Ook! ",
    ".": "Ook! Ook. ", ",": "Ook. Ook! ", "[": "Ook! Ook? ", "]": "Ook? Ook! ",
}
ook_ct = "".join(_OOK[c] for c in BF_PROG).encode()
cases.append(("OOK!解释器", ook_ct, "flag{ook_works}"))

# 12. ROT47
def rot47(s: str) -> str:
    return "".join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in s)

pt12 = "flag{rot47_mix3d}"
cases.append(("ROT47", rot47(pt12).encode(), pt12))

# 13. 分栏式栅栏(非 zigzag)
pt13 = "flag{simple_railfence}"
def simple_rf_enc(text: str, rails: int) -> str:
    segs = [[] for _ in range(rails)]
    for i, ch in enumerate(text):
        segs[i % rails].append(ch)
    return "".join("".join(s) for s in segs)

cases.append(("分栏式栅栏3栏", simple_rf_enc(pt13, 3).encode(), pt13))

# 14. ROT13 + UUID 风格(用户真实反馈用例): synt{...} -> flag{...}
cases.append(("ROT13+UUID(用户反馈)", b"synt{5pq1004q-86n5-46q8-o720-oro5on0417r1}",
              "flag{5cd1004d-86a5-46d8-b720-beb5ba0417e1}"))

# 15. 变异凯撒(用户真实反馈, BUUCTF 经典题): 递增位移逐字节
cases.append(("变异凯撒(用户反馈)", b"afZ_r9VYfScOeO_UL^RWUc", "flag{Caesar_variation}"))

# 16~19. 哈希碰撞题型(双哈希/反向/flag变体/带盐)
import hashlib
cases.append(("双md5碰撞", hashlib.md5(hashlib.md5(b"password").digest()).hexdigest().encode(), "password"))
cases.append(("反向md5碰撞", hashlib.md5(b"flag{hello}"[::-1]).hexdigest().encode(), "flag{hello}"))
cases.append(("flag变体md5", hashlib.md5(b"flag{crypto}").hexdigest().encode(), "flag{crypto}"))
cases.append(("sha1碰撞", hashlib.sha1(b"admin").hexdigest().encode(), "admin"))
cases.append(("带盐md5", hashlib.md5(b"key" + b"secret").hexdigest().encode(), "secret"))

# 21. 简单摩斯密码(用户真实反馈): .. .-.. --- ...- . -.-- --- ..- -> iloveyou
cases.append(("摩斯密码(用户反馈)", b".. .-.. --- ...- . -.-- --- ..-", "iloveyou"))

# 22~26. 高级编码题型 (Unicode 转义 / QP / Zlib / JWT / Latin1 乱码)
import gzip as _gzip, zlib as _zlib, json as _json, hmac as _hmac, hashlib as _hashlib, base64 as _b64
cases.append(("unicode转义", r"\u4f60\u597d\uff0c\u4e16\u754c".encode(), "你好，世界"))
cases.append(("quoted-printable", "=E4=BD=A0=E5=A5=BD".encode(), "你好"))
cases.append(("zlib压缩", _zlib.compress(b"compressed flag{zlib_blind}"), "flag{zlib_blind}"))
_jh = _b64.urlsafe_b64encode(_json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode()).rstrip(b"=").decode()
_jb = _b64.urlsafe_b64encode(_json.dumps({"user": "admin", "flag": "flag{jwt_blind}"}, separators=(",", ":")).encode()).rstrip(b"=").decode()
_js = _b64.urlsafe_b64encode(_hmac.new(b"secret", f"{_jh}.{_jb}".encode(), _hashlib.sha256).digest()).rstrip(b"=").decode()
cases.append(("jwt解析", f"{_jh}.{_jb}.{_js}".encode(), "flag{jwt_blind}"))
cases.append(("latin1乱码", "ä½\u00a0å¥½".encode("utf-8"), "你好"))

# 27. 八进制 ASCII 序列
cases.append(("八进制ASCII", "150 145 154 154 157".encode(), "hello"))

# 28. 输入鲁棒性系列 (第二十四轮实测固化)
cases.append(("b64首尾空格", b"  aGVsbG8gZmxhZ3t1aV90ZXN0fQ==  ", "flag{ui_test}"))
cases.append(("b64中间空格", b"aGVsbG8g ZmxhZ3t1aV90ZXN0 fQ==", "flag{ui_test}"))
cases.append(("b64长串换行", b"aGVsbG8gZmxh\nZ3t1aV90ZXN0fQ==", "flag{ui_test}"))
cases.append(("hex全大写", b"666C61677B4845585F55507D", "flag{HEX_UP}"))
cases.append(("hex 0x前缀", b"0x666c61677b30785f7072656669787d", "flag{0x_prefix}"))
cases.append(("hex空格分隔", b"66 6c 61 67", "flag"))
cases.append(("md5全大写", b"E00CF25AD42683B3DF678C61F42C6BDA", "admin1"))
cases.append(("URL标点", b"hello%20world%21", "hello world!"))
cases.append(("ROT13大写密文", b"URYYB JBEYQ", "HELLO WORLD"))
cases.append(("凯撒短密文花括号", b"Synt{5pq1004q}", "Flag{5cd1004d}"))

# 29. 空格机制场景 (第二十六轮: 空格有意义的编码不被过滤)
import binascii as _b64_uu
import base64 as _b64_mod
cases.append(("摩斯双空格分隔单词", b".... ..   .-.. --- ...- .   -.-- --- ..-", "hi love you"))
cases.append(("摩斯斜杠分隔单词", b".... .. / .-.. --- ...- . / -.-- --- ..-", "hi love you"))
cases.append(("uuencode含空格字符", _b64_uu.b2a_uu(b"the flag is here").decode().rstrip().encode(), "the flag is here"))
_b64_long = b"The quick brown fox jumps over the lazy dog. " * 3
_b64_w = _b64_mod.b64encode(_b64_long).decode()
_b64_wrapped = "\n".join(_b64_w[i:i+76] for i in range(0, len(_b64_w), 76)).encode()
cases.append(("base64 76字符换行", _b64_wrapped, "The quick brown fox"))
cases.append(("培根A/B流", b"AABABABABAAAAAAAABBA", "flag"))
cases.append(("hex 0x+空格混合", b"0x66 0x6c 0x61 0x67", "flag"))

print(f"{'用例':<24} {'结果':<7} 说明")
print("-" * 70)
for name, ct, expected in cases:
    # 带盐用例需要带 salt 的 pipeline
    solver = p
    if name == "带盐md5":
        solver = Pipeline(build_default_registry(salt=b"key"))
    r = solver.solve(ct, max_depth=8)
    ok = r.found and expected in r.plaintext.decode("utf-8", "ignore")
    chain = "->".join(r.chain) if r.found else "-"
    print(f"{name:<22} {'PASS' if ok else 'FAIL':<7} chain={chain}")
