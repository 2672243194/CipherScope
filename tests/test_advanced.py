"""高级编码插件单测: Unicode 转义 / HTML 实体 / Quoted-Printable / Punycode /
Zlib / Gzip / JWT / Latin1 乱码修复。"""
import gzip
import json
import zlib

from cipherscope.plugins.advanced import (
    GzipPlugin, HtmlEntityPlugin, JwtPlugin, Latin1ToUtf8Plugin,
    PunycodePlugin, QuotedPrintablePlugin, UnicodeEscapePlugin, ZlibPlugin,
)


def decode_all(plugin, ct):
    return list(plugin.attack(ct))


def test_unicode_escape_basic():
    p = UnicodeEscapePlugin()
    ct = r"\u4f60\u597d\uff0c\u4e16\u754c".encode()
    assert p.match(ct) >= 0.9
    outs = decode_all(p, ct)
    assert outs and outs[0].plaintext.decode() == "你好，世界"


def test_unicode_escape_short():
    p = UnicodeEscapePlugin()
    ct = r"\u4f60\u597d".encode()
    outs = decode_all(p, ct)
    assert outs and outs[0].plaintext.decode() == "你好"


def test_html_entity():
    p = HtmlEntityPlugin()
    ct = "&#x4f60;&#x597d;".encode()
    assert p.match(ct) >= 0.9
    outs = decode_all(p, ct)
    assert outs and outs[0].plaintext.decode() == "你好"


def test_quoted_printable():
    p = QuotedPrintablePlugin()
    ct = "=E4=BD=A0=E5=A5=BD".encode()
    assert p.match(ct) >= 0.8
    outs = decode_all(p, ct)
    assert outs and outs[0].plaintext.decode() == "你好"


def test_punycode():
    p = PunycodePlugin()
    ct = "xn--fiq228c".encode()
    assert p.match(ct) >= 0.9
    outs = decode_all(p, ct)
    assert outs and outs[0].plaintext.decode() == "中文"


def test_zlib_roundtrip():
    p = ZlibPlugin()
    ct = zlib.compress(b"compressed flag{zlib_roundtrip}")
    assert p.match(ct) >= 0.9
    outs = decode_all(p, ct)
    assert outs and b"flag{zlib_roundtrip}" in outs[0].plaintext


def test_gzip_roundtrip():
    p = GzipPlugin()
    ct = gzip.compress(b"gzip data payload")
    assert p.match(ct) >= 0.9
    outs = decode_all(p, ct)
    assert outs and b"gzip data payload" in outs[0].plaintext


def test_jwt_parse_and_crack():
    import base64
    import hashlib
    import hmac

    def make_jwt(secret, payload):
        h = base64.urlsafe_b64encode(
            json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()
        b = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()
        sig = base64.urlsafe_b64encode(
            hmac.new(secret.encode(), f"{h}.{b}".encode(), hashlib.sha256).digest()
        ).rstrip(b"=").decode()
        return f"{h}.{b}.{sig}"

    p = JwtPlugin()
    token = make_jwt("secret", {"user": "admin", "flag": "flag{jwt_easy}"})
    assert p.match(token.encode()) >= 0.9
    outs = decode_all(p, token.encode())
    assert outs and any("flag{jwt_easy}" in o.plaintext.decode() for o in outs)
    # HS256 弱密钥爆破: 应产出含 secret 的解
    assert any("secret" in o.method for o in outs)


def test_jwt_rejects_non_jwt():
    p = JwtPlugin()
    assert p.match(b"not.a.jwt") == 0.0
    assert p.match(b"a.b.c.d") == 0.0


def test_latin1_mojibake():
    p = Latin1ToUtf8Plugin()
    ct = "ä½\u00a0å¥½".encode("utf-8")   # "你好" 的 UTF-8 字节被 latin1 误读后再编码
    assert p.match(ct) >= 0.7
    outs = decode_all(p, ct)
    assert outs and outs[0].plaintext.decode() == "你好"
