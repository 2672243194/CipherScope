"""明文评分引擎 (Scoring Engine) —— CipherScope 的架构核心。

自动化链路的成败取决于"机器如何判断解密成功"。本模块采用多信号加权融合:

  base(自然语言可读性, 0~60) = n-gram适应度(0~25) + 可打印比例(0~10)
                              + 常用词命中(0~15) + 卡方检验(0~10)

判定逻辑 (三档裁决):
  - flag 命中            -> SUCCESS,  score = 60 + base * (40/60)
  - flag 命中 + 中文占比超阈值(0.3) -> SUCCESS,  score 保底 90 (中文兜底)
  - 无 flag, base 折算 >= 55        -> PROMISING (像自然语言, 管道应继续深挖)
  - 其余                            -> REJECT

为什么不是单一阈值: CTF 最终 flag 一定有格式, 但中间层(如 base 套娃第二层
的英文提示语)没有 flag。管道需要区分"找到 flag"(停止)与"这段明文质量高,
值得继续往下解码"(PROMISING), 单一分数无法表达这两种语义。

优雅降级: quadgram 完整频率表(data/quadgrams.json, 约 25 万组)由
tools/build_quadgrams.py 从语料生成; 表缺失时使用内置精简兜底表,
评分仍大致可用——真实工程不该因资源文件缺失而崩溃。
"""
from __future__ import annotations

import json
import math
import re
import string
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

# ---------------------------------------------------------------- 常量

DEFAULT_FLAG_PREFIXES = (
    "flag{", "ctf{", "nssctf{", "cyberpeace{", "picoctf{", "ctfhub{", "xyctf{",
)

# 英文 top 高频词 + CTF 场景高频词
COMMON_WORDS = frozenset(
    "the of and to in is you that it he was for on are as with his they i "
    "at be this have from or one had by word but not what all were we when "
    "your can said there use an each which she do how their if will up "
    "other about out many then them these so some her would make like him "
    "into time has look two more write go see number no way could people "
    "flag key crypto cipher plaintext password secret congratulations".split()
)

# 短英文明文的词典切分词表: 覆盖高频短词/助动词/代词/CTF 词/数字词。
# 用于"word-break 完全切分"判定——iloveyou = i+love+you, hello = hello;
# 随机乱码无法全部切分, 因此该信号极难误判。
COMMON_WORDS_EXT = frozenset(
    COMMON_WORDS | set(
        "a am an are as at be by do go he if in is it me my no of oh ok on or "
        "so to up us we you i love like want need have has had get got make "
        "take give come came go went see saw look find found think know knew "
        "say said tell ask help work play run walk talk hear feel keep hold "
        "put set let try try try use used wish hope guess believe understand "
        "hello world hi hey bye yes no okay thanks thank please sorry good "
        "bad day night time name game flag key crypto cipher hack ctf "
        "security secret password admin root user test welcome "
        "congratulations message text answer solve find decode encode "
        "encrypt decrypt xor base64 md5 sha rsa ciphertext plaintext "
        "cat dog bird fish sun moon star sky tree flower water fire wind "
        "rain snow cloud earth world life love hope dream heart soul mind "
        "body hand head face eye ear nose mouth hair arm leg foot feet "
        "king queen prince princess hero friend enemy team group party "
        "one two three four five six seven eight nine ten zero "
        "first second third last next new old young big small long short "
        "high low fast slow hot cold warm cool dark light white black red "
        "blue green yellow purple orange pink gray grey brown gold silver "
        "left right up down open close start stop begin end over under "
        "before after during between among within without against through "
        "above below near far here there where when why what who whom "
        "which how much many every each both either neither other another "
        "some any all most few little much more less least enough "
        "always never often sometimes usually rarely ever still yet "
        "already just only also too very really quite rather fairly "
        "together alone together together again once twice thrice "
        "please welcome goodluck good_luck lucky happy sad angry tired "
        "hungry thirsty sleepy awake alive dead strong weak brave shy "
        "smart clever quick slow careful careless silent quiet loud "
        "clean dirty fresh old young beautiful handsome cute pretty "
        "ugly tall short fat thin rich poor easy hard simple complex "
        "great nice wonderful amazing awesome perfect excellent "
        "good bad better best worse worst true false real fake "
        "right wrong correct incorrect valid invalid safe danger "
        "open close hide show send receive accept refuse agree "
        "disagree fight win lose win victory defeat success fail "
        "begin start end finish stop continue pause resume repeat "
        "read write listen speak sing dance run jump walk sit stand "
        "eat drink sleep wake smile laugh cry shout whisper scream "
        "grow change move stay turn break build destroy create "
        "delete add remove insert update save load copy paste cut "
        "undo redo zoom drag drop click press type scroll browse "
        "search scan scan hack crack break decrypt encode decode "
        "encrypt decrypt sign verify check test debug fix repair "
        "update install uninstall download upload share post comment "
        "like love hate enjoy prefer choose select pick decide "
        "remember forget learn teach study practice train master "
        "play game win lose draw tie score level stage boss enemy "
        "player character weapon armor shield magic power skill "
        "attack defense health mana gold coin gem stone sword "
        "shield bow arrow axe spear knife dagger sword hammer "
        "computer laptop phone tablet server network internet "
        "browser website page link url html css js python java "
        "c cpp go rust ruby php sql nosql db database table row "
        "column index key foreign primary unique null empty full "
        "string int float bool array list dict map set queue stack "
        "tree graph node edge vertex path cycle loop branch merge "
        "commit push pull clone fork star issue pr branch master "
        "main dev test prod staging release version update patch "
        "fix bug error warning info debug trace log level info "
        "warn error fatal critical panic crash hang freeze lock "
        "unlock encrypt decrypt sign verify hash digest salt "
        "nonce iv padding block cipher mode cbc ecb ctr gcm ofb "
        "cfb stream block key secret private public certificate "
        "token session cookie header body request response status "
        "code 200 404 500 api rest graphql json xml yaml csv "
        "text binary ascii unicode utf utf8 utf16 base32 base64 "
        "base58 base85 hex octal decimal binary morse braille "
        "rot13 rot47 caesar vigenere affine atbash railfence "
        "playfair hill bacon pigpen keyboard cloudshadow uuencode "
        "ook brainfuck gzip zlib zip tar rar 7z compress compressed "
        "compression decompress deflate inflate archive packed "
        "extract original raw data bytes byte hexdump offset".split()
    )
)

# 长文本词密度判定专用词表: 覆盖基础英文常用词(含 quick/brown/fox/lazy 等
# 基础词汇与前 100 高频词)。与 COMMON_WORDS_EXT(短文本 word-break 用)分离——
# 词密度只要求"命中率高", 不要求完全切分, 可以更宽。
COMMON_WORDS_DENSE = frozenset(
    ("the of and to in is you that it he was for on are as with his they i at be "
     "this have from or one had by word but not what all were we when your can said "
     "there use an each which she do how their if will up other about out many then "
     "them these so some her would make like him into time has look two more write "
     "go see number no way could people my than first water been call who oil its "
     "now find long down day did get come made may part over new sound take only "
     "little work know place year live me back give most very after thing our just "
     "name good sentence man think say great where help through much before line "
     "right too mean old any same tell boy follow came want show also around form "
     "three small set put end does another well large must big even such because "
     "turn here why ask went men read need land different home us move try kind "
     "hand picture again change off play spell air away animal house point page "
     "letter mother answer found study still learn should world high every near "
     "add food between own below country plant last school father keep tree never "
     "start city earth eye light thought head under story saw left don few while "
     "along might close something seem next hard open example begin life always "
     "those both paper together got group often run important until children side "
     "feet car mile night walk white sea began grow took river four carry state "
     "once book hear stop without second later miss idea enough eat face watch far "
     "indian really almost let above girl sometimes mountain cut young talk soon "
     "list song being leave family quick brown fox jumps lazy dog over through "
     "during before after again between across around behind below beneath beside "
     "beyond inside outside within without along among toward towards "
     "everybody everyone everything everywhere nothing nobody nowhere something "
     "someone somewhere anywhere anybody anyone anyway anywhere whatever whenever "
     "however therefore although though unless until whether whichever "
     "because hence since thus henceforth meanwhile nevertheless nonetheless "
     "accordingly consequently subsequently previously meanwhile eventually finally "
     "suddenly immediately quickly slowly carefully quietly loudly happily sadly "
     "angrily easily heavily lightly softly firmly gently perfectly badly "
     "absolutely completely entirely totally extremely incredibly remarkably "
     "particularly especially specifically probably possibly certainly definitely "
     "surely clearly obviously apparently evidently actually really truly "
     "simply merely only just exactly precisely roughly approximately about around "
     "nearly almost practically virtually essentially basically generally "
     "typically usually often sometimes occasionally rarely seldom never always "
     "everywhere somewhere nowhere anywhere whatever whoever whenever whichever "
     "however whatever whenever wherever whichever whomever whose whom")
    .split()
)

# 英文标准字母频率 (a~z)
ENGLISH_FREQ = {
    "a": 0.0812, "b": 0.0149, "c": 0.0271, "d": 0.0432, "e": 0.1202,
    "f": 0.0230, "g": 0.0203, "h": 0.0592, "i": 0.0731, "j": 0.0010,
    "k": 0.0069, "l": 0.0398, "m": 0.0261, "n": 0.0695, "o": 0.0768,
    "p": 0.0182, "q": 0.0011, "r": 0.0602, "s": 0.0628, "t": 0.0910,
    "u": 0.0288, "v": 0.0111, "w": 0.0209, "x": 0.0017, "y": 0.0211,
    "z": 0.0007,
}

# 内置精简 trigram 兜底表: 连续字母流上的高频英文三元组, 分层近似 log10 概率。
# 设计说明: 完整 quadgram 表(25 万组)由 tools/build_quadgrams.py 生成;
# 表缺失时使用此兜底表。两个教训直接体现在表内容里:
# 1) 选 trigram 而非稀疏 quadgram 表: 小样本下覆盖率才够, 信号不整体失效;
# 2) 表项必须取"字母流高频组合"(如 nde/edt/tis 这类跨词组合),
#    而非"高频词"(如 you/she/get)——去掉空格后跨词 trigram 占大多数。
_FALLBACK_TRIGRAMS: dict[str, float] = {"the": -1.45}
for _t in ("and ing".split()):
    _FALLBACK_TRIGRAMS[_t] = -1.9
for _t in ("tha ent ion her hat his ere for ter".split()):
    _FALLBACK_TRIGRAMS[_t] = -2.2
for _t in ("tio was you ith ver all wit thi nde has nce edt tis oft sth men "
           "ati hen ate est ers".split()):
    _FALLBACK_TRIGRAMS[_t] = -2.6
for _t in ("rea ear res con com tin not hav pro our out eve igh ess ted dth "
           "nth tth rig ect ound are but had one two see way who did get let "
           "say she too use man new now old any".split()):
    _FALLBACK_TRIGRAMS.setdefault(_t, -3.0)

# n-gram 参数: n -> (归一化最优值, 归一化最差值, 未收录惩罚 log 概率)
_NGRAM_PARAMS = {4: (-3.3, -6.5, -8.0), 3: (-2.2, -6.5, -7.0)}

# 信号权重随表模式自适应: n -> (ngram, printable, words, chi2)。
# 完整 quadgram 表(25 万组)下 ngram 是最强信号, 权重 25;
# 精简 trigram 兜底表(80 组)区分度天然不足, 硬给同等权重会让噪声主导评分,
# 故降为 8, 释放的权重转给不依赖词表的 chi2 与词典信号——
# 优雅降级的完整含义: 信号权重必须反映信号质量。
_SIGNAL_WEIGHTS = {4: (25.0, 10.0, 15.0, 10.0), 3: (8.0, 10.0, 25.0, 15.0)}
_CHI2_BEST, _CHI2_WORST = 0.02, 0.5    # 卡方归一化区间
# 中文 n-gram 字级二元组参数: 相邻字对 log10 概率, 高频对约 -2.4, 生僻对约 -6
_CHINESE_BEST, _CHINESE_WORST = -3.0, -6.5
_CHINESE_WORD_FLOOR = -9.0   # 未收录字对的惩罚 log 概率

SUCCESS_THRESHOLD = 70.0
PROMISING_THRESHOLD = 55.0      # 无 flag 时 base 折算分阈值
CHINESE_RATIO_THRESHOLD = 0.30  # 中文兜底: CJK 字符占比阈值
CHINESE_FLOOR_SCORE = 90.0      # 中文兜底触发时的保底分
FLAG_MIN_BASE = 22.0            # 假 flag 防护: flag 命中但上下文不可读时降级


class Verdict(str, Enum):
    SUCCESS = "success"        # 找到 flag, 停止搜索
    PROMISING = "promising"    # 像自然语言, 管道应继续
    REJECT = "reject"          # 噪声, 剪枝


@dataclass
class ScoreResult:
    score: float               # 0~100
    verdict: Verdict
    flag_hit: bool
    flag_prefix: str = ""      # 命中的前缀
    detail: dict[str, float] = field(default_factory=dict)  # 各信号原始分, 供调试


# ---------------------------------------------------------------- 引擎

class ScoringEngine:
    """多信号融合评分引擎。"""

    def __init__(
        self,
        flag_prefixes: tuple[str, ...] = DEFAULT_FLAG_PREFIXES,
        quadgrams_path: str | Path | None = None,
    ) -> None:
        self.flag_prefixes = tuple(p.lower() for p in flag_prefixes)
        self._ngrams, self._ngram_n = self._load_ngrams(quadgrams_path)
        # 中文 n-gram 模型 (路线图项): 字级二元组频率表随包分发, 零运行时依赖
        self._chinese_bigrams = self._load_chinese_bigrams()

    @staticmethod
    def _load_chinese_bigrams() -> dict[str, float]:
        p = Path(__file__).resolve().parent.parent / "data" / "chinese_bigrams.json"
        if p.is_file():
            with p.open("r", encoding="utf-8") as f:
                return json.load(f)
        return {}

    # -------------------------------------------------- 信号 1: flag 正则
    def _flag_signal(self, text_lower: str) -> tuple[bool, str]:
        """flag 前缀匹配带词边界: 前缀前不得是字母/数字。
        防止 qctf{ 这类串尾部包含 ctf{ 造成的假阳性——
        否则攻击穷举产生的错误候选可能借"子串命中"短路管道。"""
        for prefix in self.flag_prefixes:
            if re.search(r"(?<![a-z0-9])" + re.escape(prefix), text_lower):
                return True, prefix
        return False, ""

    # --------------------------------------------- 信号 2: n-gram 适应度
    @staticmethod
    def _load_ngrams(path: str | Path | None) -> tuple[dict[str, float], int]:
        """加载完整 quadgram 表; 缺失时回退到内置 trigram 兜底表。
        返回 (频率表, n)。n 用于 fitness 计算的窗口长度与归一化参数选择。"""
        candidates = []
        if path:
            candidates.append(Path(path))
        candidates.append(Path(__file__).resolve().parent.parent / "data" / "quadgrams.json")
        for p in candidates:
            if p.is_file():
                with p.open("r", encoding="utf-8") as f:
                    return {k: float(v) for k, v in json.load(f).items()}, 4
        return dict(_FALLBACK_TRIGRAMS), 3

    def _ngram_fitness(self, letters: str) -> float:
        """letters: 仅含 a-z 的小写串。返回 0~25。"""
        n_gram = self._ngram_n
        best, worst, floor = _NGRAM_PARAMS[n_gram]
        windows = len(letters) - n_gram + 1
        if windows <= 0:
            return 0.0
        total = sum(
            self._ngrams.get(letters[i:i + n_gram], floor)
            for i in range(windows)
        )
        fitness = total / windows                   # 平均 log10 概率
        norm = (fitness - worst) / (best - worst)
        return max(0.0, min(1.0, norm)) * 25.0

    # ---------------------------------------------- 信号 3: 可打印比例
    @staticmethod
    def _printable_score(data: bytes) -> float:
        if not data:
            return 0.0
        printable = set(bytes(string.printable, "ascii"))
        ratio = sum(b in printable for b in data) / len(data)
        return max(0.0, min(1.0, (ratio - 0.7) / 0.3)) * 10.0   # <70% 记 0

    # ----------------------------------------------- 信号 4: 常用词命中
    @staticmethod
    def _word_score(text_lower: str) -> float:
        tokens = set(re.findall(r"[a-z]+", text_lower))
        hits = len(tokens & COMMON_WORDS)
        return min(hits / 5.0, 1.0) * 15.0        # 命中 5 个不同常用词即满分

    # ------------------------------------------------- 信号 5: 卡方检验
    @staticmethod
    def _chi2_score(letters: str) -> float:
        n = len(letters)
        if n < 10:
            return 0.0
        counts = {c: letters.count(c) / n for c in string.ascii_lowercase}
        chi2 = sum(
            (counts[c] - ENGLISH_FREQ[c]) ** 2 / ENGLISH_FREQ[c]
            for c in string.ascii_lowercase
        )
        norm = (_CHI2_WORST - chi2) / (_CHI2_WORST - _CHI2_BEST)
        return max(0.0, min(1.0, norm)) * 10.0

    # ----------------------------------------------- 信号 6: 中文兜底
    @staticmethod
    def _chinese_ratio(data: bytes) -> float:
        """UTF-8 解码后 CJK 统一表意字符占比。解码失败返回 0。"""
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return 0.0
        if len(text) < 8:
            return 0.0
        cjk = sum("一" <= ch <= "鿿" for ch in text)
        return cjk / len(text)

    # --------------------------------- 中文 n-gram 字级二元组模型 (路线图项)
    def _chinese_ngram_fitness(self, text: str) -> float:
        """中文文本的字级二元组适应度, 归一化到 0~25。
        词库只统计词内字对, 中文句子跨词边界对天然缺失, 因此以
        **命中率**为唯一信号: 正常中文句 40~70%, 生僻字乱码 <20%。
        零运行时依赖。"""
        if not self._chinese_bigrams:
            return 0.0
        chars = [c for c in text if "\u4e00" <= c <= "\u9fff"]
        if len(chars) < 4:
            return 0.0   # 样本太少, 统计不可信
        grams = [chars[i] + chars[i + 1] for i in range(len(chars) - 1)]
        if not grams:
            return 0.0
        hit = sum(1 for g in grams if g in self._chinese_bigrams)
        rate = hit / len(grams)
        if rate < 0.2:
            return 0.0   # 命中率过低直接判 0(生僻字乱码)
        return rate * 25.0

    @classmethod
    def _chinese_text_success(cls, data: bytes, text: str, fitness: float) -> bool:
        """长中文文本(>24 字符)无 flag 判定: CJK 占比高 + 字级二元组适应度达标。
        覆盖 base64/unicode 解码出的长中文句——英文 ngram 信号对中文无效,
        这是中文 n-gram 模型的核心价值。"""
        if len(data) <= 24:
            return False
        if not all(c.isprintable() or c in " \t\n\r" for c in text):
            return False
        if cls._chinese_ratio(data) < 0.5:
            return False
        if re.search(r"[a-zA-Z]{3,}", text):
            return False   # 排除英文词混入(英文明文走英文路径)
        return fitness >= 10.0   # 命中率 >= 40% 视为正常中文

    def _short_cjk_success(self, data: bytes, text: str) -> bool:
        """短中文强证据: 2~24 字符, 可严格 UTF-8 解码, 全字符可打印, CJK 占比>=0.4,
        且不含英文单词。覆盖 unicode-escape/html-entity/quoted-printable/latin1
        等确定性解码产出的无 flag 短中文(如 "你好"、"今天天气不错")。
        注意: 不能用 ASCII _printable_score 判据——中文字符的 UTF-8 字节
        不是 ASCII 可打印字符, 必须用严格 UTF-8 解码 + 字符级可打印判断。"""
        try:
            strict_text = data.decode("utf-8")
        except UnicodeDecodeError:
            return False
        n = len(strict_text)
        if not (2 <= n <= 24):
            return False
        if not all(ch.isprintable() for ch in strict_text):
            return False
        cjk = sum("\u4e00" <= ch <= "\u9fff" for ch in strict_text)
        if cjk / n < 0.4:
            return False
        # 字符多样性: 重复单字(如 犇犇犇...)不是真实中文——乱码防穿透
        cjk_chars = {ch for ch in strict_text if "\u4e00" <= ch <= "\u9fff"}
        if len(cjk_chars) < 2:
            return False
        # 排除英文词混入(英文明文走 word-break 分支, 中文分支只管纯中文)
        if re.search(r"[a-zA-Z]{3,}", strict_text):
            return False
        # 样本足够(>=4 字)时用字级二元组适应度验证: 拦截随机生僻字乱码
        # (多样但无正常字对组合, 如 犄犅犆犇...); 超短词(你好/早安)直接放行
        if n >= 4 and self._chinese_ngram_fitness(strict_text) < 8.0:
            return False
        return True

    # --------------------------------- 短英文明文判定 (word-break 完全切分)
    @staticmethod
    def _word_break_possible(s: str) -> bool:
        """字符串能否完全切分为词典词。经典 DP, s 长度上限由调用方约束(<=24)。"""
        n = len(s)
        if n == 0:
            return False
        dp = [False] * (n + 1)
        dp[0] = True
        for i in range(1, n + 1):
            for j in range(i):
                if dp[j] and s[j:i] in COMMON_WORDS_EXT:
                    dp[i] = True
                    break
        return dp[n]

    @classmethod
    def _short_english_success(cls, data: bytes, text: str) -> bool:
        """短英文纯文本的强证据判定: 长度 2~24, 几乎全可打印, 仅含字母/数字/空格,
        且每个字母 token 都能被词典完全切分(数字 token 直接放行, 至少含一个字母词)。
        iloveyou = i+love+you -> True; 随机乱码无法切分 -> False。
        标点容错: 确定性解码产物常带标点(URL: hello world! / 路径: a/b/c),
        非字母数字空格统一归一化为空格后再切分。
        这是评分引擎的最后一层兜底: 覆盖摩斯/URL/栅栏等确定性解码产出的无 flag 短句。"""
        n = len(data)
        if not (2 <= n <= 24):
            return False
        if cls._printable_score(data) < 9.0:
            return False
        # 拒绝控制字符: xor 假解可能含 \x0c(form feed) 等控制符, 正常英文
        # 文本不会出现——这是 word-break 兜底的门槛, 防止标点容错被假解利用。
        # 注意 isspace() 会把 \x0c/\x0b 也算空白, 必须只用 ASCII 常见空白。
        if not all(c.isprintable() or c in " \t\n\r" for c in text):
            return False
        norm = re.sub(r"[^a-z0-9\s]", " ", text.lower())   # 标点 -> 空格
        # 字母多样性: 单一字母重复(如 aaaaaaaa, 培根/异或乱解产物)不是真实英文
        letters = "".join(c for c in norm if c.isalpha())
        if len(set(letters)) < 2:
            return False
        words = norm.split()
        if not words or not any(any(c.isalpha() for c in w) for w in words):
            return False
        # 至少一个 >=2 字母的可切分词: 防止标点+单字母交替的乱码假解
        # (如 xor 解出的 ("-'S\@Z|y/!%V}*Q) 全单字母片段被放行——真实 bug)
        has_word = False
        for w in words:
            # 拆出数字段(flag123 -> [flag, 123]): 数字段直接放行, 字母段须可切分
            for part in re.split(r"(\d+)", w):
                if not part or part.isdigit():
                    continue
                # 单字母词仅放行 a/i/o(虚词); 其余单字母须能切分(几乎不可能)
                if len(part) == 1 and part in ("a", "i", "o"):
                    continue
                if not cls._word_break_possible(part):
                    return False
                has_word = True
        return has_word

    @classmethod
    def _word_density_success(cls, data: bytes, text: str) -> bool:
        """长文本(>24 字符)无 flag 时的自然语言判定: 按词切分后词典命中率
        高的英文句子。覆盖 base64 76 字符换行/长密文解码出的完整句子——
        完整频率表缺失时 ngram 信号对长文本失效(0 分), 词密度是鲁棒替代。
        乱码长文本(随机字母串)命中率极低, 不会误伤。"""
        if len(data) <= 24:
            return False
        if cls._printable_score(data) < 9.0:
            return False
        if not all(c.isprintable() or c in " \t\n\r" for c in text):
            return False
        words = re.findall(r"[a-z]+", text.lower())
        if len(words) < 6:
            return False
        hits = sum(1 for w in words if w in COMMON_WORDS_DENSE)
        return hits / len(words) >= 0.75

    # ------------------------------------------------------- 综合评分
    def score(self, data: bytes) -> ScoreResult:
        text = data.decode("utf-8", errors="ignore")
        text_lower = text.lower()
        letters = "".join(c for c in text_lower if c in string.ascii_lowercase)

        flag_hit, flag_prefix = self._flag_signal(text_lower)
        detail = {
            "ngram": self._ngram_fitness(letters),       # 原始分 0~25
            "printable": self._printable_score(data),    # 原始分 0~10
            "words": self._word_score(text_lower),       # 原始分 0~15
            "chi2": self._chi2_score(letters),           # 原始分 0~10
        }
        w_n, w_p, w_w, w_c = _SIGNAL_WEIGHTS[self._ngram_n]
        base = (                                   # 0~60, 自然语言可读性
            detail["ngram"] / 25.0 * w_n
            + detail["printable"] / 10.0 * w_p
            + detail["words"] / 15.0 * w_w
            + detail["chi2"] / 10.0 * w_c
        )

        if flag_hit:
            # 中文兜底优先: 中文明文对英文统计模型全盲, 但 UTF-8 解码 +
            # CJK 占比达标即可信(flag 格式 + 中文字符双重证据), 直接保底。
            if self._chinese_ratio(data) >= CHINESE_RATIO_THRESHOLD:
                return ScoreResult(CHINESE_FLOOR_SCORE, Verdict.SUCCESS, True, flag_prefix, detail)
            # 假 flag 防护: 乱码中碰巧出现 flag{ 字样的概率约 1/45 万每字节,
            # 但此类文本上下文不可读(base 很低)。规则:
            # - 短文本(<50B)直接判 SUCCESS: 短乱码碰巧含 flag{ 的概率
            #   低于百万分之一, 且 url/hex 等确定性解码的提示语多为短文本;
            # - 长文本要求 base 达标, 否则降级, 避免长乱码假结果短路管道。
            # 短文本(<50B)需全可打印: xor-crib 已知明文前缀攻击会故意用 flag
            # 前缀凑出含控制字符的假解(如 nssctf{3yu\t:@s@f\r...), 直接放行
            # 会被利用——真实确定性解码产物(hex/url/ascii)均为可打印文本
            if (len(data) < 50 and all(
                c.isprintable() or c in " \t\n\r" for c in text
            )) or base >= FLAG_MIN_BASE:
                # 保底 70: SUCCESS 语义应与 SUCCESS_THRESHOLD 一致,
                # 避免"判定成功但分数低于阈值"的观感矛盾
                score = max(SUCCESS_THRESHOLD, 60.0 + base * (40.0 / 60.0))
                return ScoreResult(min(score, 100.0), Verdict.SUCCESS, True, flag_prefix, detail)
            normalized = base * (100.0 / 60.0)
            verdict = Verdict.PROMISING if normalized >= PROMISING_THRESHOLD else Verdict.REJECT
            return ScoreResult(normalized, verdict, False, "", detail)

        # 短英文强证据兜底: 确定性解码(摩斯/栅栏/ASCII 等)常产出无 flag 的
        # 短英文词句, 统计信号(ngram/chi2)对短文本天然失效, 但词典完全切分
        # 是极强证据——iloveyou 可切分为 i+love+you, 乱码不能。
        if self._short_english_success(data, text):
            score = max(SUCCESS_THRESHOLD, base * (100.0 / 60.0))
            return ScoreResult(min(score, 100.0), Verdict.SUCCESS, False, "", detail)
        # 长文本词密度兜底: 长英文句(>24 字符)ngram 表缺失时统计信号失效,
        # 词命中率高即可认可(base64 换行/长密文解码等场景)
        if self._word_density_success(data, text):
            score = max(SUCCESS_THRESHOLD, base * (100.0 / 60.0))
            return ScoreResult(min(score, 100.0), Verdict.SUCCESS, False, "", detail)
        # 中文 n-gram 模型: 长中文句(>24 字符)无 flag 时按词频适应度判定
        cjk_fitness = self._chinese_ngram_fitness(text)
        if self._chinese_text_success(data, text, cjk_fitness):
            detail["cjk_ngram"] = round(cjk_fitness, 1)
            score = max(SUCCESS_THRESHOLD, base * (100.0 / 60.0))
            return ScoreResult(min(score, 100.0), Verdict.SUCCESS, False, "", detail)
        # 短中文强证据兜底: unicode-escape/html-entity/qp/latin1 解码产出的中文短文本
        if self._short_cjk_success(data, text):
            score = max(SUCCESS_THRESHOLD, base * (100.0 / 60.0))
            return ScoreResult(min(score, 100.0), Verdict.SUCCESS, False, "", detail)

        normalized = base * (100.0 / 60.0)
        verdict = Verdict.PROMISING if normalized >= PROMISING_THRESHOLD else Verdict.REJECT
        return ScoreResult(normalized, verdict, False, "", detail)
