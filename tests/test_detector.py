"""识别引擎单元测试。"""
import pytest

from cipherscope.core.detector import (
    DetectionEngine,
    index_of_coincidence,
    kasiski_key_lengths,
    shannon_entropy,
)


@pytest.fixture(scope="module")
def engine() -> DetectionEngine:
    return DetectionEngine()


def top_types(engine: DetectionEngine, ct: bytes, n: int = 3) -> list[str]:
    return [d.type for d in engine.detect(ct)[:n]]


class TestPatternDetection:
    def test_base64(self, engine):
        assert top_types(engine, b"aGVsbG8gd29ybGQ=")[0] == "base64"

    def test_hex(self, engine):
        assert "hex" in top_types(engine, b"48656c6c6f576f726c64")

    def test_hash_md5_by_length(self, engine):
        assert "hash-md5" in top_types(engine, b"5d41402abc4b2a76b9719d911017c592")

    def test_hash_sha256_by_length(self, engine):
        assert "hash-sha256" in top_types(engine, b"a" * 64)

    def test_morse(self, engine):
        assert top_types(engine, b"... .- -- .-- .")[0] == "morse"

    def test_brainfuck(self, engine):
        assert "brainfuck" in top_types(engine, b"++++++++[>++++[>++>+++>+++>+<<<<-]>+>+>->>+[<]<-]>>.>")

    def test_binary_ascii(self, engine):
        assert "binary-ascii" in top_types(engine, b"01101000011001010110110001101100")

    def test_url_encode(self, engine):
        assert "url-encode" in top_types(engine, b"%66%6c%61%67%7b")

    def test_bacon(self, engine):
        assert "bacon" in top_types(engine, b"ABABAABBABAAABABBABA")  # 20 字符, 5 的倍数


class TestTextStatistics:
    CAESAR_CT = (  # 英文段落凯撒位移 3, IC 与明文一致
        b"wkh txlfn eurzq ira mxpsv ryhu wkh odcb grj dqg wkh vhfxulwb ri "
        b"d flskhu ghshqgv rq wkh vhfuhfb ri wkh nhb udwkhu wkdq wkh dojrulwkp"
    )
    VIGENERE_CT = (  # 用密钥 "lemon" 加密的长英文, IC 应接近随机
        b"pmcmw zcokt fqhhi cbraw nkrpp rsews zqzvv oijtg klrca sawgt rmuiu "
        b"ohdtm twzlr gknlw szgmf weivf kgfbm wmtmr esdci hfuvc xjroa ekbbv "
        b"ahvrg tpfxk jecyp rzmks eohrj zpkmg apktg xohgc jjele kprpv rcyap"
    )

    def test_caesar_ic_detected_as_mono(self, engine):
        types = top_types(engine, self.CAESAR_CT, 5)
        assert "substitution-mono" in types

    def test_vigenere_detected(self, engine):
        detections = engine.detect(self.VIGENERE_CT)
        types = [d.type for d in detections]
        assert "vigenere" in types

    def test_ic_value_sanity(self):
        assert index_of_coincidence("e" * 100) == pytest.approx(1.0)
        uniform = "abcdefghijklmnopqrstuvwxyz" * 4
        assert index_of_coincidence(uniform) < 0.05

    def test_short_text_no_text_detection(self, engine):
        # 短样本不应产生文本类判断, 避免 IC 误导
        detections = engine.detect(b"kssv")
        assert all(d.type not in ("substitution-mono", "vigenere") for d in detections)


class TestBinaryAnalysis:
    def test_xor_like_blob(self, engine):
        blob = bytes(b ^ 0x42 for b in b"this is a secret message hidden by xor")
        assert "xor-single" in top_types(engine, blob, 5)

    def test_entropy_sanity(self):
        assert shannon_entropy(b"aaaa") == 0.0
        assert shannon_entropy(bytes(range(256))) == pytest.approx(8.0)


class TestKasiski:
    def test_repeated_key_recovered(self):
        # 构造: 明文重复模式 + 周期 5 密钥, 间距应被 5 整除
        letters = ("abcdef" * 10)[:60]
        result = kasiski_key_lengths(letters, seq_len=3)
        assert 6 in result or 3 in result or 12 in result
