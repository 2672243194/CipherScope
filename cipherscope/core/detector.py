"""识别引擎 (Detection Engine) —— 判定"这段密文最可能是什么"。

输出按置信度降序的候选类型列表, 调度器据此决定优先调用哪些攻击插件。

检测分三类, 按确定性从高到低:
1. 模式匹配: 字符集/长度/正则的强特征 (morse/brainfuck/base系/hash),
   置信度高且计算便宜;
2. 文本统计分析: 重合指数(IC)区分单表替换与多表替换, Kasiski 检验
   推断维吉尼亚密钥长度——仅当样本足够长时可信;
3. 二进制分析: 不可打印比例与信息熵, 给出 XOR 候选或"真加密"提示。

已知局限(设计上有意为之): 短文本(<20 字母)的 IC 不可靠, 此时文本类
检测只给低置信泛化候选, 把判断交给评分引擎和攻击插件的穷举结果。
"""
from __future__ import annotations

import math
import re
import string
from collections import Counter
from dataclasses import dataclass, field

# 哈希常见十六进制长度 -> 算法名
HASH_HEX_LENGTHS = {32: "md5", 40: "sha1", 56: "sha224", 64: "sha256", 96: "sha384", 128: "sha512"}

# IC 阈值: 英文单表替换 ≈0.066, 多表/随机 ≈0.0385
IC_MONO_THRESHOLD = 0.055
IC_POLY_THRESHOLD = 0.045
MIN_LETTERS_FOR_IC = 20
MIN_LETTERS_FOR_KASISKI = 40


@dataclass
class Detection:
    type: str                  # 如 "base64" / "hash-md5" / "caesar" / "vigenere" / "xor-single"
    confidence: float          # 0~1
    detail: str = ""           # 人类可读的判定依据
    meta: dict = field(default_factory=dict)  # 附加信息(如 kasiski 候选钥长)


# ------------------------------------------------------------ 统计工具

def shannon_entropy(data: bytes) -> float:
    """信息熵 (bits/byte)。英文文本 ~4.5, base64 ~6, 随机/真加密接近 8。"""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def index_of_coincidence(letters: str) -> float:
    """重合指数: 随机抽两字母相同的概率。单表替换保留明文的 IC。"""
    n = len(letters)
    if n < 2:
        return 0.0
    counts = Counter(letters)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


def kasiski_key_lengths(letters: str, seq_len: int = 3, top: int = 3) -> list[int]:
    """Kasiski 检验: 重复片段间距的公约数统计, 返回最可能的密钥长度。"""
    spacings: list[int] = []
    for i in range(len(letters) - seq_len):
        seq = letters[i:i + seq_len]
        j = letters.find(seq, i + 1)
        while j != -1:
            spacings.append(j - i)
            j = letters.find(seq, j + 1)
    if not spacings:
        return []
    # 统计 2~20 各长度能整除多少间距
    scores = Counter()
    for d in spacings:
        for k in range(2, 21):
            if d % k == 0:
                scores[k] += 1
    return [k for k, _ in scores.most_common(top)]


# ------------------------------------------------------------ 识别引擎

class DetectionEngine:
    """多维特征密文识别。"""

    def detect(self, data: bytes) -> list[Detection]:
        cleaned = data.strip()
        if not cleaned:
            return []
        results: list[Detection] = []
        results.extend(self._pattern_detections(cleaned))
        results.extend(self._text_detections(cleaned))
        results.extend(self._binary_detections(cleaned))
        results.sort(key=lambda d: d.confidence, reverse=True)
        return results

    # ---------------------------------------------- 1. 模式匹配类
    @staticmethod
    def _pattern_detections(ct: bytes) -> list[Detection]:
        out: list[Detection] = []
        try:
            text = ct.decode("ascii")
        except UnicodeDecodeError:
            return out
        compact = re.sub(r"\s+", "", text)

        if re.fullmatch(r"[.\- /]+", text) and "." in text and "-" in text:
            out.append(Detection("morse", 0.95, "字符集仅含 . - / 与空格, 且两种符号均出现"))

        if re.fullmatch(r"[\[\]<>+\-.,\s]+", text) and any(c in text for c in "[]"):
            out.append(Detection("brainfuck", 0.95, "字符集为 Brainfuck 八指令集"))

        if re.fullmatch(r"[01]+", compact) and len(compact) % 8 == 0:
            out.append(Detection("binary-ascii", 0.9, "纯 0/1 且长度为 8 的倍数, 疑似二进制 ASCII"))

        if re.search(r"%[0-9A-Fa-f]{2}", text):
            out.append(Detection("url-encode", 0.85, "存在 %XX 转义序列"))

        if re.fullmatch(r"[0-9A-Fa-f]+", compact) and len(compact) % 2 == 0:
            algo = HASH_HEX_LENGTHS.get(len(compact))
            if algo:
                out.append(Detection(f"hash-{algo}", 0.9,
                                     f"十六进制长度 {len(compact)} 与 {algo.upper()} 输出一致"))
            out.append(Detection("hex", 0.8 if algo else 0.85, "纯十六进制字符且偶数长度"))

        if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact) and len(compact) % 4 == 0 and len(compact) >= 8:
            # 真实 base64 输出字符多样性高; 低多样性(如纯 A/B 的培根密码)
            # 只是字符集被包含, 必须降权避免误判
            diversity = len(set(compact))
            conf = 0.85 if diversity >= 8 else 0.3
            out.append(Detection("base64", conf, f"Base64 字符集, 长度 %4==0, 字符多样性 {diversity}"))

        if re.fullmatch(r"[A-Z2-7]+=*", compact) and len(compact) % 8 == 0:
            out.append(Detection("base32", 0.8, "Base32 字符集 (A-Z2-7), 长度 %8==0"))

        if re.fullmatch(r"[A-Za-z]+", compact) and len(set(compact.lower())) <= 2 and len(compact) % 5 == 0:
            out.append(Detection("bacon", 0.8, "二元字符集且长度 %5==0, 疑似培根密码"))

        return out

    # ---------------------------------------------- 2. 文本统计类
    @staticmethod
    def _text_detections(ct: bytes) -> list[Detection]:
        out: list[Detection] = []
        try:
            text = ct.decode("ascii")
        except UnicodeDecodeError:
            return out
        letters = "".join(c for c in text.lower() if c in string.ascii_lowercase)

        # 可打印 ≠ 自然语言: 单字节 XOR 密钥落于 0x20~0x7F 时, 明文空格
        # 被映射为可见字符、字母被映射为标点, 密文全部可打印但字母占比
        # 异常偏低——CTF 实战中 XOR 题最常见的形态, 不能漏检。
        compact = re.sub(r"\s+", "", text)
        if compact:
            letter_ratio = len(letters) / len(compact)
            if letter_ratio < 0.65 and len(compact) >= 20:
                out.append(Detection(
                    "xor-single", 0.45,
                    f"文本可打印但字母占比仅 {letter_ratio:.0%}, 疑似单字节 XOR 落于标点区",
                ))

        if len(letters) < MIN_LETTERS_FOR_IC:
            return out   # 样本太短, IC 不可信, 交给攻击插件穷举 + 评分引擎

        ic = index_of_coincidence(letters)
        if ic >= IC_MONO_THRESHOLD:
            out.append(Detection(
                "substitution-mono", min(0.5 + (ic - IC_MONO_THRESHOLD) * 4, 0.85),
                f"IC={ic:.4f} 接近英文明文(≈0.066), 单表替换候选: caesar/atbash/affine",
            ))
        elif ic <= IC_POLY_THRESHOLD:
            meta: dict = {}
            detail = f"IC={ic:.4f} 接近随机(≈0.0385), 多表替换候选: vigenere"
            if len(letters) >= MIN_LETTERS_FOR_KASISKI:
                lengths = kasiski_key_lengths(letters)
                if lengths:
                    meta["key_lengths"] = lengths
                    detail += f"; Kasiski 候选钥长 {lengths}"
            out.append(Detection("vigenere", 0.55, detail, meta))
        return out

    # ---------------------------------------------- 3. 二进制分析类
    @staticmethod
    def _binary_detections(ct: bytes) -> list[Detection]:
        out: list[Detection] = []
        printable = set(bytes(string.printable, "ascii"))
        ratio = sum(b in printable for b in ct) / len(ct)
        if ratio >= 0.7:
            return out   # 可打印文本已在文本类处理

        entropy = shannon_entropy(ct)
        if entropy > 7.5:
            out.append(Detection(
                "strong-crypto", 0.4,
                f"熵={entropy:.2f} bits/byte 接近随机上限, 疑似 AES 等现代加密, 超出古典攻击范围",
            ))
        else:
            out.append(Detection(
                "xor-single", 0.5,
                f"可打印比例 {ratio:.0%}, 熵={entropy:.2f}, 单字节 XOR 候选",
            ))
            if len(ct) >= 40:
                out.append(Detection("xor-multi", 0.3, "样本足够长, 重复密钥 XOR 可尝试汉明距离分析"))
        return out
