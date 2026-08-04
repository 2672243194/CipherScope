"""评分引擎单元测试。"""
import base64
import os

import pytest

from cipherscope.core.scorer import ScoringEngine, Verdict

ENGLISH_PASSAGE = (
    b"The quick brown fox jumps over the lazy dog. In cryptography, the "
    b"security of a cipher depends on the secrecy of the key rather than "
    b"the secrecy of the algorithm, and this principle has guided the "
    b"design of modern encryption systems around the world."
)


@pytest.fixture(scope="module")
def engine() -> ScoringEngine:
    return ScoringEngine()


class TestFlagDetection:
    def test_flag_hit_is_success(self, engine):
        r = engine.score(b"the answer is flag{w3lc0me_t0_crypto} good job")
        assert r.verdict is Verdict.SUCCESS
        assert r.flag_hit and r.flag_prefix == "flag{"
        assert r.score >= 70.0

    def test_word_boundary_no_false_positive(self, engine):
        # qctf{ 尾部含 ctf{, 但前缀前是字母 'q' —— 不得命中。
        # 此前子串匹配导致 affine 假解 qctf{...} 短路管道(真实 bug)。
        r = engine.score(b"qctf{5xm1004m-86t5}")
        assert not r.flag_hit
        assert r.verdict is not Verdict.SUCCESS
        # flag{ 出现在词首/空格后应命中
        assert engine.score(b"flag{ok}").flag_hit is True

    def test_nssctf_prefix(self, engine):
        r = engine.score(b"NSSCTF{th1s_1s_a_t3st}")
        assert r.verdict is Verdict.SUCCESS

    def test_custom_prefix(self):
        e = ScoringEngine(flag_prefixes=("myctf{",))
        assert e.score(b"myctf{hello}").verdict is Verdict.SUCCESS
        # 自定义引擎不含默认前缀时, 标准 flag 不应命中 success
        assert not e.score(b"myctf{hello}").flag_prefix == "flag{"

    def test_chinese_fallback_boosts_score(self, engine):
        r = engine.score("恭喜你真聪明， flag{中文题目测试} 继续加油哦".encode("utf-8"))
        assert r.verdict is Verdict.SUCCESS
        assert r.score >= 90.0


class TestPlaintextQuality:
    def test_english_passage_is_promising(self, engine):
        r = engine.score(ENGLISH_PASSAGE)
        assert r.verdict is Verdict.PROMISING
        assert not r.flag_hit

    def test_random_bytes_rejected(self, engine):
        r = engine.score(os.urandom(64))
        assert r.verdict is Verdict.REJECT

    def test_base64_blob_rejected(self, engine):
        blob = base64.b64encode(os.urandom(48))
        r = engine.score(blob)
        assert r.verdict is Verdict.REJECT

    def test_english_beats_random(self, engine):
        good = engine.score(ENGLISH_PASSAGE).score
        bad = engine.score(os.urandom(len(ENGLISH_PASSAGE))).score
        assert good > bad

    def test_short_text_not_crash(self, engine):
        # 空串 / 无法词典切分的短文本仍 REJECT; 词典词(如 hi)被短英文判定认可
        assert engine.score(b"").verdict is Verdict.REJECT
        assert engine.score(b"ab").verdict is Verdict.REJECT
        assert engine.score(b"hi").verdict is Verdict.SUCCESS
