"""XOR 插件组与管道集成测试。"""
import pytest

from cipherscope.core.pipeline import Pipeline
from cipherscope.plugins import build_default_registry
from cipherscope.plugins.xor_attack import XorMultiPlugin, XorSinglePlugin

FILLER = (
    "the security of a cipher depends on the secrecy of the key rather than "
    "the secrecy of the algorithm and this principle guides the design of "
    "modern encryption systems around the world "
).encode()


def xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


class TestXorSingle:
    def test_key_0x42(self):
        p = XorSinglePlugin()
        ct = xor_bytes(b"the secret message is flag{x0r}", b"\x42")
        assert any(b"flag{x0r}" in c.plaintext for c in p.attack(ct))


class TestXorMulti:
    def test_key_abc(self):
        p = XorMultiPlugin()
        ct = xor_bytes(FILLER + b"the flag is flag{multi}", b"abc")
        outs = list(p.attack(ct))
        assert any(b"flag{multi}" in c.plaintext for c in outs)

    def test_key_s3cr3t(self):
        p = XorMultiPlugin()
        ct = xor_bytes(FILLER * 2 + b"secret is flag{xor3}", b"s3cr3t")
        outs = list(p.attack(ct))
        assert any(b"flag{xor3}" in c.plaintext for c in outs)


class TestPipelineIntegration:
    @pytest.fixture(scope="class")
    def pipeline(self):
        return Pipeline(build_default_registry())

    def test_base64_nested(self, pipeline):
        import base64
        plain = b"well done! flag{d0uble_l4yer_b64}"
        ct = base64.b64encode(base64.b64encode(plain))
        r = pipeline.solve(ct, max_depth=4)
        assert r.found and b"flag{d0uble_l4yer_b64}" in r.plaintext

    def test_triple_layer(self, pipeline):
        import base64
        plain = b"you found me: flag{tr1ple_b4se_l4yers}"
        ct = base64.b64encode(base64.b64encode(base64.b64encode(plain)))
        r = pipeline.solve(ct, max_depth=6)
        assert r.found and b"flag{tr1ple_b4se_l4yers}" in r.plaintext

    def test_caesar_inside_b64(self, pipeline):
        import base64
        # 凯撒位移 9 后 base64
        text = (FILLER + b"the flag is flag{caesar_1ns1de_b64}").decode()
        caesar = "".join(
            chr((ord(c) - 97 + 9) % 26 + 97) if "a" <= c <= "z" else c for c in text
        ).encode()
        ct = base64.b64encode(caesar)
        r = pipeline.solve(ct, max_depth=4)
        assert r.found and b"flag{caesar_1ns1de_b64}" in r.plaintext

    def test_xor_inside_hex(self, pipeline):
        ct = xor_bytes(b"nested secret flag{x0r_1nside_hex}", b"\x37").hex().encode()
        r = pipeline.solve(ct, max_depth=4)
        assert r.found and b"flag{x0r_1nside_hex}" in r.plaintext

    def test_garbage_no_crash(self, pipeline):
        import os
        r = pipeline.solve(os.urandom(64), max_depth=3)
        assert r.found is False
