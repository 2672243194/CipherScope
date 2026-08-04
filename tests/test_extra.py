"""补充题型插件单元测试 (云影/OOK!/ROT47/uuencode/base91/分栏栅栏)。"""
import binascii

import pytest

from cipherscope.plugins.classical import (
    CloudShadowPlugin,
    Rot47Plugin,
    SimpleRailFencePlugin,
)
from cipherscope.plugins.codecs_extra import OOKPlugin, UUEncodePlugin


def decrypt(plugin, ct: bytes, needle: bytes) -> bool:
    return any(needle in c.plaintext for c in plugin.attack(ct))


class TestCloudShadow:
    def test_roundtrip(self):
        # 'h'=8 -> '8', 'i'=9 -> '81', 字母间 0 分隔
        p = CloudShadowPlugin()
        assert decrypt(p, b"8081", b"hi")

    def test_flag_with_braces(self):
        # 'f'=6->42 'l'=12->84 'a'=1 'g'=7->421 'c'=3->21 'o'=15->8421
        # 'u'=21->8841 'd'=4 's'=19->8821 'h'=8 'w'=23->88421; 字母间 0 分隔
        p = CloudShadowPlugin()
        ct = b"42084010421{21084084210884104_882108010408421088421}"
        assert decrypt(p, ct, b"flag{cloud_shadow}")


class TestUUEncode:
    def test_roundtrip(self):
        p = UUEncodePlugin()
        pt = b"flag{uu_works}"
        ct = binascii.b2a_uu(pt)
        assert p.match(ct) > 0
        assert decrypt(p, ct, pt)


class TestOOK:
    def test_translation_executes(self):
        p = OOKPlugin()
        # cell0 递增 104 次输出 'h' (ASCII 104)
        bf = "+" * 104 + "."
        ook = {
            ">": "Ook. Ook? ", "<": "Ook? Ook. ", "+": "Ook. Ook. ", "-": "Ook! Ook! ",
            ".": "Ook! Ook. ", ",": "Ook. Ook! ", "[": "Ook! Ook? ", "]": "Ook? Ook! ",
        }
        ct = "".join(ook[c] for c in bf).encode()
        assert p.match(ct) > 0
        outs = list(p.attack(ct))
        assert outs and outs[0].plaintext.startswith(b"h")


class TestRot47:
    def test_mixed_text(self):
        p = Rot47Plugin()
        pt = b"flag{r0t47_mix3d}"
        ct = bytes(33 + (b - 33 + 47) % 94 if 33 <= b <= 126 else b for b in pt)
        assert decrypt(p, ct, pt)


class TestSimpleRailFence:
    def test_rails3(self):
        p = SimpleRailFencePlugin()
        text = b"flag{simple_rf}"
        segs = [[], [], []]
        for i, b in enumerate(text):
            segs[i % 3].append(b)
        ct = bytes(b for seg in segs for b in seg)
        assert decrypt(p, ct, text)
