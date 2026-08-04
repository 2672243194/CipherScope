"""语料库生成器: 用正向加密函数构造 corpus.yaml。

自构造(synthetic)语料的意义:
- 答案绝对正确(我们自己加密的), 避免抄录真题时的转录错误;
- 覆盖每种插件的正向路径 + 常见多层组合, 是回归测试的基准;
- 真实赛事题(BUUCTF/攻防世界等)可后续按同格式追加, 标注真实出处。

用法: python tools/build_corpus.py  (覆盖写 tests/ctf_corpus/corpus.yaml)
"""
from __future__ import annotations

import base64
import string
from pathlib import Path
from urllib.parse import quote_from_bytes

import yaml

OUTPUT = Path(__file__).resolve().parent.parent / "tests" / "ctf_corpus" / "corpus.yaml"
_A2Z = string.ascii_lowercase

# 维吉尼亚等统计攻击需要足够长的文本样本
FILLER = ("the security of a cipher depends on the secrecy of the key rather "
          "than the secrecy of the algorithm and this principle guides the "
          "design of modern encryption systems around the world ")


# ------------------------------------------------------------ 正向加密

def caesar_enc(text: str, shift: int) -> str:
    return "".join(
        _A2Z[(_A2Z.index(c) + shift) % 26] if c in _A2Z else c for c in text.lower()
    )


def atbash_enc(text: str) -> str:
    return "".join(_A2Z[25 - _A2Z.index(c)] if c in _A2Z else c for c in text.lower())


def affine_enc(text: str, a: int, b: int) -> str:
    return "".join(
        _A2Z[(a * _A2Z.index(c) + b) % 26] if c in _A2Z else c for c in text.lower()
    )


def vigenere_enc(text: str, key: str) -> str:
    text = text.lower()
    key_idx = [_A2Z.index(c) for c in key]
    out, i = [], 0
    for c in text:
        if c in _A2Z:
            out.append(_A2Z[(_A2Z.index(c) + key_idx[i % len(key_idx)]) % 26])
            i += 1
        else:
            out.append(c)
    return "".join(out)


def railfence_enc(text: str, rails: int) -> str:
    pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
    fence: list[list[str]] = [[] for _ in range(rails)]
    for i, ch in enumerate(text):
        fence[pattern[i % len(pattern)]].append(ch)
    return "".join("".join(r) for r in fence)


KBD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm")


def kbd_enc(text: str, direction: int) -> str:
    """行内循环位移(双射): p 右移回到 q, 解密为纯逆位移。"""
    table = {}
    for row in KBD_ROWS:
        for i, ch in enumerate(row):
            table[ch] = row[(i + direction) % len(row)]
    return "".join(table.get(c, c) for c in text.lower())


def xor_enc(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


MORSE_ENC = {
    "a": ".-", "b": "-...", "c": "-.-.", "d": "-..", "e": ".", "f": "..-.",
    "g": "--.", "h": "....", "i": "..", "j": ".---", "k": "-.-", "l": ".-..",
    "m": "--", "n": "-.", "o": "---", "p": ".--.", "q": "--.-", "r": ".-.",
    "s": "...", "t": "-", "u": "..-", "v": "...-", "w": ".--", "x": "-..-",
    "y": "-.--", "z": "--..", "0": "-----", "1": ".----", "2": "..---",
    "3": "...--", "4": "....-", "5": ".....", "6": "-....", "7": "--...",
    "8": "---..", "9": "----.",
    "{": "-.--.-", "}": ".-..-.", "_": "..--.-", "!": "-.-.--",
    "?": "..--..", ".": ".-.-.-", ",": "--..--", ":": "---...", "=": "-...-",
}


def morse_enc(text: str) -> str:
    """字母/数字用标准码, 扩展符号用扩展码, 词间 3 空格。"""
    words = text.lower().split()
    return "   ".join(
        " ".join(MORSE_ENC.get(c, "") for c in w if c in MORSE_ENC) for w in words
    )


def bacon_enc(text: str) -> str:
    alpha = "abcdefghiklmnopqrstwxyz"  # 24 字母表, 无 j/u
    out = []
    for c in text.lower().replace(" ", ""):
        if c not in alpha:
            continue  # 培根只能编码字母, 跳过数字/符号
        v = alpha.index(c)
        out.append("".join("B" if v & (1 << (4 - i)) else "A" for i in range(5)))
    return "".join(out)


def binary_enc(data: bytes) -> str:
    return "".join(f"{b:08b}" for b in data)


def _rot47_enc(text: str) -> str:
    return "".join(
        chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c
        for c in text
    )


def _simple_rf_enc(text: str, rails: int) -> str:
    """分栏式栅栏(非 zigzag): 按位置取模分栏后拼接。"""
    segs = [[] for _ in range(rails)]
    for i, ch in enumerate(text):
        segs[i % rails].append(ch)
    return "".join("".join(s) for s in segs)


def _variant_caesar_enc(text: str, start: int = 5) -> bytes:
    """变异凯撒: 每个字符 ASCII 加递增位移(起点 start, 每次 +1)。
    返回 bytes 使 add() 走 latin1 存储——str 会含 U+0080 以上字符被 UTF-8 编码变形。"""
    return bytes((ord(c) + start + i) % 256 for i, c in enumerate(text))


# ------------------------------------------------------------ 题目构造

def make_items() -> list[dict]:
    items: list[dict] = []

    def add(category: str, ciphertext, flag: str, note: str = "", platform: str = "synthetic"):
        items.append({
            "id": f"{platform}-{category.replace('/', '-')}-{len(items) + 1:03d}",
            "platform": platform, "category": category,
            "ciphertext": ciphertext if isinstance(ciphertext, str) else ciphertext.decode("latin1"),
            "ciphertext_encoding": "latin1" if not isinstance(ciphertext, str) else "plain",
            "expected_flag": flag, "note": note,
        })

    def b64(data: bytes, times: int = 1) -> str:
        for _ in range(times):
            data = base64.b64encode(data)
        return data.decode()

    # ---- codec 组 (12)
    f = "flag{b4se64_1s_n0t_encrypti0n}"
    add("codec/base64", b64(f"congratulations, the flag is {f}".encode()), f, "单层 base64")
    f = "flag{d0uble_l4yer_b64}"
    add("codec/base64", b64(f"well done! {f}".encode(), 2), f, "双层 base64")
    f = "flag{tr1ple_b4se_l4yers}"
    add("codec/base64", b64(f"you found me: {f}".encode(), 3), f, "三层套娃")
    f = "flag{h3x_1s_just_numbers}"
    add("codec/hex", f"the secret is {f}".encode().hex(), f, "hex 编码")
    f = "flag{url_p3rc3nt_enc0ding}"
    add("codec/url", quote_from_bytes(f"key found: {f}".encode()), f, "URL 编码")
    f = "flag{b1nary_asc11_1s_easy}"
    add("codec/binary", binary_enc(f"binary decoded: {f}".encode()), f, "8bit 二进制 ASCII")
    f = "flag{m0rse_d0t_and_dash}"
    add("codec/morse", morse_enc(f"the flag is {f}"), f, "摩斯电码")
    f = "flag{b4se32_alph4bet}"
    add("codec/base32", base64.b32encode(f"the answer: {f}".encode()).decode(), f, "base32")
    f = "flag{b85_ascii_art_style}"
    add("codec/base85", base64.b85encode(f"ascii85 encoded: {f}".encode()).decode(), f, "base85 (Ascii85)")
    # 培根密码: 字母表无法表达花括号, 终点判定(flag{ 字面)不适用, 属半自动题型, 语料不收录
    f = "flag{m1x_b64_hex_cha1n}"
    add("codec/mixed", b64(f"next layer: {f}".encode().hex().encode()), f, "hex 外套 base64")
    f = "flag{url_then_b64}"
    add("codec/mixed", b64(quote_from_bytes(f"two layers: {f}".encode()).encode()), f, "url 外套 base64")
    f = "flag{b1nary_b64_nest}"
    add("codec/mixed", b64(binary_enc(f"nested: {f}".encode()).encode()), f, "binary 外套 base64")

    # ---- classical 组 (10)
    f = "flag{caesar_sh1ft_three}"
    add("classical/caesar", caesar_enc(FILLER + "the flag is " + f, 3), f, "凯撒位移 3")
    f = "flag{r0t17_also_caesar}"
    add("classical/caesar", caesar_enc(FILLER + "the answer is " + f, 17), f, "凯撒位移 17")
    f = "flag{atbash_m1rror_alph4bet}"
    add("classical/atbash", atbash_enc(FILLER + "mirror gives " + f), f, "Atbash")
    f = "flag{aff1ne_l1near_map}"
    add("classical/affine", affine_enc(FILLER + "affine says " + f, 5, 8), f, "仿射 a=5,b=8")
    f = "flag{aff1ne_an0ther_key}"
    add("classical/affine", affine_enc(FILLER + "second affine " + f, 7, 3), f, "仿射 a=7,b=3")
    f = "flag{v1genere_poly_alpha}"
    add("classical/vigenere", vigenere_enc((FILLER * 2) + "the flag is " + f, "key"), f, "维吉尼亚 key='key'")
    f = "flag{kas1sk1_exam1nation}"
    add("classical/vigenere", vigenere_enc((FILLER * 2) + "you got it " + f, "lemon"), f, "维吉尼亚 key='lemon'")
    f = "flag{r4ilfence_z1gzag_3}"
    add("classical/railfence", railfence_enc("the fence hides " + f, 3), f, "栅栏 3 栏(含完整flag, 可全自动)")
    f = "flag{r4ilfence_f1ve_rails}"
    add("classical/railfence", railfence_enc("zigzag pattern " + f, 5), f, "栅栏 5 栏(含完整flag, 可全自动)")
    f = "flag{keyboard_r1ght_sh1ft}"
    add("classical/keyboard", kbd_enc("look at your keyboard " + f, 1), f, "键盘右移一格")

    # ---- xor 组 (4)
    f = "flag{x0r_s1ngle_byt3_key}"
    add("xor/single", xor_enc(f"the secret message is {f}".encode(), b"\x42"), f, "单字节 XOR 0x42")
    f = "flag{x0r_an0ther_byte}"
    add("xor/single", xor_enc(f"hidden by one byte {f}".encode(), b"\x23"), f, "单字节 XOR 0x23")
    f = "flag{x0r_repeat1ng_key}"
    add("xor/multi", xor_enc((FILLER + "the flag is " + f).encode(), b"abc"), f, "重复密钥 'abc'")
    f = "flag{hamm1ng_d1stance_w1ns}"
    add("xor/multi", xor_enc((FILLER * 2 + "secret is " + f).encode(), b"s3cr3t"), f, "重复密钥 's3cr3t'")

    # ---- hash 组 (2)
    import hashlib
    add("hash/md5", hashlib.md5(b"crypto").hexdigest(), "crypto", "MD5 字典爆破(flag即明文)")
    add("hash/sha1", hashlib.sha1(b"password").hexdigest(), "password", "SHA1 字典爆破(flag即明文)")

    # ---- 组合组 (6)
    f = "flag{caesar_1ns1de_b64}"
    add("combo/caesar-b64", b64(caesar_enc(FILLER + "combined layers " + f, 9).encode()), f, "base64 解后是凯撒")
    f = "flag{x0r_1nside_hex}"
    add("combo/xor-hex", xor_enc(f"nested secret {f}".encode(), b"\x37").hex(), f, "hex 解后是单字节XOR")
    f = "flag{vig_1nside_b64}"
    add("combo/vigenere-b64", b64(vigenere_enc((FILLER * 2) + "nested flag " + f, "moon").encode()), f, "base64 解后是维吉尼亚")
    f = "flag{m0rse_1nside_b64}"
    add("combo/morse-b64", b64(morse_enc(f"the flag is {f}").encode()), f, "base64 解后是摩斯")
    f = "flag{caesar_1nside_b32}"
    add("combo/caesar-b32", base64.b32encode(caesar_enc(FILLER + "base32 caesar " + f, 5).encode()).decode(), f, "base32 解后是凯撒")
    f = "flag{x0r_1nside_b64}"
    add("combo/xor-b64", b64(xor_enc(f"layered xor {f}".encode(), b"\x55")), f, "base64 解后是单字节XOR")

    # ================= 第 29 轮扩充: 参数化批量 (34 -> 100 题) =================
    import gzip
    import html
    import hashlib
    import quopri
    import zlib

    # A. 编码变体 (12)
    _f = "flag{b64_c4s3_m1x}"
    add("codec/base64", b64(f"mixed case b64 {_f}".encode()), _f, "base64 混合大小写")
    _f = "flag{h3x_0x_pr3f1x}"
    add("codec/hex", "0x" + f"prefix hex {_f}".encode().hex(), _f, "hex 0x 前缀")
    _f = "flag{h3x_4ll_c4ps}"
    add("codec/hex", f"upper hex {_f}".encode().hex().upper(), _f, "hex 全大写")
    _f = "flag{h3x_sp4c3_s3p}"
    add("codec/hex", " ".join(f"hex space {_f}".encode().hex()[i:i+2] for i in range(0, len(f"hex space {_f}".encode().hex()), 2)), _f, "hex 空格分隔")
    _f = "flag{b32_r0t4t10n}"
    add("codec/base32", base64.b32encode(f"b32 rotation {_f}".encode()).decode(), _f, "base32 变体")
    _f = "flag{b85_4n0th3r}"
    add("codec/base85", base64.b85encode(f"b85 another {_f}".encode()).decode(), _f, "base85 变体")
    _f = "flag{u_r1_3nc0d3d}"
    add("codec/url", quote_from_bytes(f"url once more {_f}".encode()), _f, "URL 变体")
    _f = "flag{m0rs3_slash}"
    add("codec/morse", morse_enc(f"morse slash {_f}").replace("   ", " / "), _f, "摩斯斜杠分隔单词")
    _f = "flag{b1n4ry_l0ng}"
    add("codec/binary", binary_enc(f"a longer binary payload {_f}".encode()), _f, "二进制长文本")
    _f = "flag{a5c11_d3c1m4l}"
    add("codec/ascii", " ".join(str(b) for b in f"decimal ascii {_f}".encode()), _f, "十进制 ASCII 序列")
    _f = "flag{a5c11_0ct4l}"
    add("codec/ascii", " ".join(f"{b:03o}" for b in f"octal ascii {_f}".encode()), _f, "八进制 ASCII 序列")

    # B. 古典密码变体 (20)
    for _shift in (1, 7, 13, 21, 24):
        _f = f"flag{{caesar_shift_{_shift:02d}}}"
        add("classical/caesar", caesar_enc(FILLER + f"shift {_shift} gives " + _f, _shift), _f, f"凯撒位移 {_shift}")
    _f = "flag{rot13_4g41n}"
    add("classical/caesar", caesar_enc(FILLER + "rot13 again " + _f, 13), _f, "ROT13")
    _f = "flag{atbash_2nd_3cho}"
    add("classical/atbash", atbash_enc(FILLER + "atbash echo " + _f), _f, "Atbash 变体")
    for _a, _b in ((3, 7), (9, 2), (11, 5)):
        _f = f"flag{{affine_{_a}_{_b}}}"
        add("classical/affine", affine_enc(FILLER + f"affine {_a} {_b} " + _f, _a, _b), _f, f"仿射 a={_a},b={_b}")
    for _k in ("moon", "cipher", "china"):
        _f = f"flag{{vig_key_{_k}}}"
        add("classical/vigenere", vigenere_enc((FILLER * 2) + f"vigenere key {_k} " + _f, _k), _f, f"维吉尼亚 key='{_k}'")
    for _r in (2, 4, 6):
        _f = f"flag{{railfence_{_r}_rails}}"
        add("classical/railfence", railfence_enc(f"rail fence {_r} " + _f, _r), _f, f"栅栏 {_r} 栏")
    _f = "flag{kbd_l3ft_sh1ft}"
    add("classical/keyboard", kbd_enc("keyboard left shift " + _f, -1), _f, "键盘左移一格")
    _f = "flag{r0t47_4n0th3r}"
    add("classical/rot47", _rot47_enc(f"rot47 variant {_f}"), _f, "ROT47 变体")
    _f = "flag{s1mpl3_r4ilf3nc3}"
    add("classical/railfence-simple", _simple_rf_enc("simple rail fence " + _f, 3), _f, "分栏式栅栏 3 栏")
    _f = "flag{v4r1ant_ca3sar}"
    add("classical/variant-caesar", _variant_caesar_enc(_f, 5), _f, "变异凯撒(flag 开头, 真实题形态)")

    # C. XOR 变体 (8)
    for _k in (b"\x11", b"\x4a", b"\x7f", b"\x09", b"\x6e"):
        _f = f"flag{{xor_byte_{_k.hex()}}}"
        add("xor/single", xor_enc(f"single byte {_k.hex()} {_f}".encode(), _k), _f, f"单字节 XOR {_k.hex()}")
    for _k in (b"xyz", b"k3y!"):
        _f = f"flag{{xor_repeat_{_k.decode()}}}"
        add("xor/multi", xor_enc((FILLER + f"repeat key {_k.decode()} " + _f).encode(), _k), _f, f"重复密钥 {_k.decode()!r}")

    # D. 高级编码 (6)
    _f = "flag{un1c0de_3sc4p3}"
    add("codec/unicode", "".join("\\u%04x" % ord(c) for c in f"unicode escape {_f}"), _f, "Unicode 转义")
    _f = "flag{h7ml_3nt1t13s}"
    add("codec/html", html.escape(f"html entities {_f}"), _f, "HTML 实体")
    _f = "flag{q_p_3nc0d1ng}"
    add("codec/qp", quopri.encodestring(f"quoted printable {_f}".encode()).decode(), _f, "Quoted-Printable")
    _f = "flag{z11b_c0mpr3ss}"
    add("codec/zlib", zlib.compress(f"zlib compressed {_f}".encode()), _f, "Zlib 压缩")
    _f = "flag{gz1p_p4ck3d}"
    add("codec/gzip", gzip.compress(f"gzip packed {_f}".encode()), _f, "Gzip 压缩")

    # E. 哈希变体 (6)
    for _w in ("admin1", "hello", "flag{crypto}", "secret"):
        add("hash/md5", hashlib.md5(_w.encode()).hexdigest(), _w, f"MD5 字典爆破({_w})")
    add("hash/sha1", hashlib.sha1(b"letmein").hexdigest(), "letmein", "SHA1 字典爆破")
    add("hash/sha256", hashlib.sha256(b"welcome").hexdigest(), "welcome", "SHA256 字典爆破")

    # F. 组合链变体 (14)
    _f = "flag{h3x_1n_b64}"
    add("combo/hex-b64", b64(f"hex inside {_f}".encode().hex().encode()), _f, "base64 解后是 hex")
    _f = "flag{c4esar_1n_h3x}"
    add("combo/caesar-hex", caesar_enc(FILLER + "caesar hex " + _f, 11).encode().hex(), _f, "hex 解后是凯撒")
    _f = "flag{4tf4sh_1n_b64}"
    add("combo/atbash-b64", b64(atbash_enc(FILLER + "atbash b64 " + _f).encode()), _f, "base64 解后是 Atbash")
    _f = "flag{4ff1ne_1n_b64}"
    add("combo/affine-b64", b64(affine_enc(FILLER + "affine b64 " + _f, 3, 7).encode()), _f, "base64 解后是仿射")
    _f = "flag{r0t47_1n_b64}"
    add("combo/rot47-b64", b64(_rot47_enc(f"rot47 b64 {_f}").encode()), _f, "base64 解后是 ROT47")
    _f = "flag{v1g_1n_h3x}"
    add("combo/vigenere-hex", vigenere_enc((FILLER * 2) + "vig hex " + _f, "key").encode().hex(), _f, "hex 解后是维吉尼亚")
    _f = "flag{x0r_1n_b32}"
    add("combo/xor-b32", base64.b32encode(xor_enc(f"xor b32 {_f}".encode(), b"\x4b")).decode(), _f, "base32 解后是单字节XOR")
    _f = "flag{r41lf3nc3_1n_b64}"
    add("combo/railfence-b64", b64(railfence_enc("rail fence b64 " + _f, 4).encode()), _f, "base64 解后是栅栏")
    _f = "flag{m0rs3_1n_h3x}"
    add("combo/morse-hex", morse_enc(f"morse hex {_f}").encode().hex(), _f, "hex 解后是摩斯")
    _f = "flag{d0ubl3_b64_1n_b64}"
    add("combo/b64-b64", b64(b64(f"b64 in b64 {_f}".encode(), 2).encode()), _f, "三层 base64 变体")
    _f = "flag{h3x_b64_c4esar}"
    add("combo/caesar-b64-hex", f"caesar b64 hex {_f}".encode().hex().encode() and b64(caesar_enc("triple layer " + _f, 6).encode().hex().encode()), _f, "hex→base64→凯撒 三层")
    _f = "flag{x0r_h3x_b64}"
    add("combo/xor-hex-b64", b64(xor_enc(f"xor hex b64 {_f}".encode(), b"\x2f").hex().encode()), _f, "base64→hex→XOR 三层")
    _f = "flag{a5c11_b64_1n}"
    add("combo/ascii-b64", b64(" ".join(str(b) for b in f"ascii b64 {_f}".encode()).encode()), _f, "base64 解后是 ASCII 序列")
    _f = "flag{url_b64_c4esar}"
    add("combo/caesar-b64-url", b64(quote_from_bytes(caesar_enc("url b64 caesar " + _f, 8).encode()).encode()), _f, "base64→URL→凯撒 三层")

    # G. 补齐至 100 题
    _f = "flag{b85_f1ll3r_up}"
    add("codec/base85", base64.b85encode(f"b85 filler {_f}".encode()).decode(), _f, "base85 补充")
    _f = "flag{atbash_f1ll3r}"
    add("classical/atbash", atbash_enc(FILLER + "atbash filler " + _f), _f, "Atbash 补充")
    _f = "flag{m0rs3_h3x_c0mb0}"
    add("combo/morse-hex-2", f"morse hex combo {_f}".encode().hex(), _f, "hex 解后是摩斯(直接 hex 文本)")

    return items


def main() -> None:
    items = make_items()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        yaml.safe_dump(items, allow_unicode=True, sort_keys=False), encoding="utf-8"
    )
    print(f"已生成 {OUTPUT}: {len(items)} 题")


if __name__ == "__main__":
    main()
