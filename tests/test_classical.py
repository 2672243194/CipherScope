"""古典密码插件组单元测试。"""
import pytest

from cipherscope.plugins.classical import (
    AffinePlugin,
    AtbashPlugin,
    CaesarPlugin,
    KeyboardShiftPlugin,
    RailFencePlugin,
    VigenerePlugin,
)

ENGLISH = (
    "the security of a cipher depends on the secrecy of the key rather than "
    "the secrecy of the algorithm and this principle guides the design of "
    "modern encryption systems around the world the flag is "
)


def candidates_with(plugin, ct: bytes, needle: bytes) -> bool:
    return any(needle in c.plaintext for c in plugin.attack(ct))


class TestCaesar:
    def test_shift_3(self):
        p = CaesarPlugin()
        ct = "wkh vhfxulwb ri d flskhu ghshqgv rq wkh vhfuhfb ri wkh nhb".encode()
        assert candidates_with(p, ct, b"the security of a cipher")

    def test_shift_17(self):
        p = CaesarPlugin()
        ct = "kyv jrcfezr zu k vpizre..."[:12].encode()  # 任意短串不应崩
        list(p.attack(ct))


class TestAtbash:
    def test_mirror(self):
        p = AtbashPlugin()
        # "the security of a cipher" 的 atbash: security -> hvxfirgb
        assert candidates_with(p, b"gsv hvxfirgb lu r zxrksvi", b"the security of")


class TestAffine:
    def test_a5_b8(self):
        p = AffinePlugin()
        ct = "".join(
            chr((5 * (ord(c) - 97) + 8) % 26 + 97) if "a" <= c <= "z" else c
            for c in "hello world"
        ).encode()
        assert candidates_with(p, ct, b"hello world")


class TestVigenere:
    def test_key_lemon(self):
        p = VigenerePlugin()
        # 用插件自身解密验证: 密文 = vigenere("the flag is ...", 'lemon')
        text = (ENGLISH + "flag{vigenere_works}").lower()
        key = "lemon"
        cipher = []
        ki = 0
        for c in text:
            if "a" <= c <= "z":
                cipher.append(chr((ord(c) - 97 + ord(key[ki % len(key)]) - 97) % 26 + 97))
                ki += 1
            else:
                cipher.append(c)
        ct = "".join(cipher).encode()
        assert candidates_with(p, ct, b"flag{vigenere_works}")


class TestRailFence:
    def test_rails3(self):
        p = RailFencePlugin()
        # 构造 3 栏 zigzag 密文
        text = "the fence hides the flag{r4ilfence}"
        pattern = [0, 1, 2, 1]
        fence = [[], [], []]
        for i, ch in enumerate(text):
            fence[pattern[i % 4]].append(ch)
        cipher = "".join("".join(r) for r in fence).encode()
        assert candidates_with(p, cipher, b"flag{r4ilfence}")


class TestKeyboard:
    def test_right_shift_cycle(self):
        p = KeyboardShiftPlugin()
        # 加密: 每字符右移(循环); 密文 "look" -> "appl"
        rows = ("qwertyuiop", "asdfghjkl", "zxcvbnm")
        enc = {}
        for row in rows:
            for i, ch in enumerate(row):
                enc[ch] = row[(i + 1) % len(row)]
        ct = "".join(enc.get(c, c) for c in "look at your keyboard").encode()
        assert candidates_with(p, ct, b"look at your keyboard")
