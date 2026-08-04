"""嵌套解码管道 (Pipeline) —— CipherScope 自动化链路的最外层。

针对"base 套娃"等多层嵌套题做广度优先搜索:
- 每个节点 = (数据, 到达它的攻击链);
- 节点扩展 = 调度器跑一轮攻击 -> 评分三档裁决:
    SUCCESS   -> 找到 flag, 立即返回(按分数排序后首个 SUCCESS 即最优);
    PROMISING -> 作为中间层加入下一层队列(限宽, 防组合爆炸);
    REJECT    -> 剪枝;
- 循环检测: 已见数据的 SHA1 入集合, 防止 A->B->A 死循环;
- 限深 10 层 + 总评分预算, 保证任何输入都有确定性的终止时间。
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from cipherscope.core.detector import DetectionEngine
from cipherscope.core.dispatcher import Dispatcher
from cipherscope.core.plugin import PluginRegistry
from cipherscope.core.scorer import ScoringEngine, Verdict

MAX_DEPTH = 10
LAYER_WIDTH = 4            # 每层最多带入下一层的候选数
TOTAL_SCORE_BUDGET = 6000  # 全流程最大评分次数

# 编码形态候选(套娃题中间层)无条件入队, 不走评分裁决:
# base64 串本就不像自然语言, 若按 REJECT 剪枝会错误截断多层解码链。
ENCODING_TYPES = {"base64", "base32", "base85", "hex", "url-encode", "binary-ascii", "morse", "brainfuck"}
# 密文形态候选(组合题中间层)同样无条件入队: 凯撒/维吉尼亚/XOR 密文
# 的评分是 REJECT(本就不像明文), 但它们值得进入下一层攻击而非剪枝。
CRYPTIC_TYPES = ENCODING_TYPES | {"substitution-mono", "vigenere", "xor-single", "xor-multi"}
HASH_HEX_LENS = {32, 40, 56, 64, 96, 128}   # hash 长度 hex 不应无限 hex 解码
CRYPTIC_MIN_CONF = 0.4


@dataclass
class Step:
    """求解过程的一个步骤 (用于生成 writeup)。"""
    stage: str          # 识别 / 解码 / 攻击 / 验证
    description: str    # 人类可读说明
    detail: str = ""    # 附加信息(置信度/密钥/分数等)


@dataclass
class SolveResult:
    found: bool
    plaintext: bytes = b""
    score: float = 0.0
    method: str = ""
    chain: list[str] = field(default_factory=list)
    depth: int = 0
    attempts: int = 0          # 总评分次数(性能观测)
    steps: list[Step] = field(default_factory=list)          # 求解步骤 (写 WP 用)
    alternatives: list[tuple[bytes, str, float]] = field(default_factory=list)  # 其他可能答案


class Pipeline:
    def __init__(self, registry: PluginRegistry, scorer: ScoringEngine | None = None) -> None:
        self.scorer = scorer or ScoringEngine()
        self.dispatcher = Dispatcher(registry, self.scorer)

    def solve(
        self,
        ct: bytes,
        max_depth: int = MAX_DEPTH,
        layer_width: int = LAYER_WIDTH,
        budget: int = TOTAL_SCORE_BUDGET,
        prefer: set[str] | None = None,
        exclude: set[bytes] | None = None,
    ) -> SolveResult:
        """exclude: 屏蔽的明文集合(用户判定答案不对时排除, 继续寻找下一个解)。"""
        seen = {hashlib.sha1(ct).digest()}
        current: list[tuple[bytes, list[str]]] = [(ct, [])]
        attempts = 0
        detector = DetectionEngine()
        layer_detects: list[tuple[int, str]] = []   # 每层识别记录 (写 WP 用)

        for depth in range(1, max_depth + 1):
            # 编码链候选分级: rank=2 确定性编码形态 > rank=1 密文形态;
            # 同 rank 时 codec 插件产物(确定性解码)优先于猜测性攻击产物
            cryptic_layer: list[tuple[int, bool, bytes, list[str]]] = []
            promising_layer: list[tuple[bytes, list[str]]] = []
            for data, chain in current:
                if attempts >= budget:
                    break
                dets = detector.detect(data)[:3]
                detect_desc = "、".join(f"{d.type}(置信度{d.confidence:.2f})" for d in dets) or "无明显特征"
                if not any(d == depth for d, _ in layer_detects):
                    layer_detects.append((depth, detect_desc))
                candidates = self.dispatcher.run(data, prefer=prefer)
                attempts += len(candidates)
                for cand in candidates:
                    full_chain = chain + cand.chain
                    # 确定性破解(哈希字典命中等): 直接返回, 无需评分背书
                    if cand.verified:
                        if exclude and cand.plaintext in exclude:
                            continue   # 用户屏蔽的答案: 跳过, 继续寻找
                        return self._build_result(
                            cand, full_chain, depth, attempts, layer_detects, candidates,
                            verify="确定性破解命中 (哈希摘要比对 / 数学运算验证)",
                        )
                    if cand.verdict is Verdict.SUCCESS:
                        if exclude and cand.plaintext in exclude:
                            continue   # 用户屏蔽的答案: 跳过, 继续寻找
                        verify = (
                            f"flag 前缀 '{cand.flag_prefix}' 命中, 上下文可读"
                            if cand.flag_prefix
                            else "短英文明文词典完全切分命中 (确定性解码结果, 无 flag 格式)"
                        )
                        return self._build_result(
                            cand, full_chain, depth, attempts, layer_detects, candidates,
                            verify=verify,
                        )
                    # 编码链优先: 候选仍是编码/密文形态则无条件入队, 继续下一层。
                    # codec 插件的确定性解码产物无条件入队(rank=2)——解码结果的
                    # 内容类型不能由当前层猜测(如维吉尼亚密文的 IC 可能因明文
                    # 重复而偏高), 探索与否应交由下一层的攻击插件决定。
                    if cand.source == "codec":
                        rank = 2
                    else:
                        rank = self._cryptic_rank(cand.plaintext, detector)
                    if rank > 0:
                        h = hashlib.sha1(cand.plaintext).digest()
                        if h not in seen:
                            seen.add(h)
                            cryptic_layer.append((rank, cand.source == "codec", cand.plaintext, full_chain))
                        continue
                    if cand.verdict is Verdict.PROMISING:
                        h = hashlib.sha1(cand.plaintext).digest()
                        if h not in seen:
                            seen.add(h)
                            promising_layer.append((cand.plaintext, full_chain))
            # 限宽: 排序键 (is_codec, rank)——确定性解码插件产物(codec)
            # 无条件优先于猜测性攻击产物; 同类内编码形态(rank=2)优先于
            # 密文形态(rank=1)。防止乱解结果(碰巧呈编码形态)挤出真解。
            cryptic_layer.sort(key=lambda x: (x[1], x[0]), reverse=True)
            next_layer = [(d, c) for _, _, d, c in cryptic_layer[:layer_width]]
            next_layer.extend(promising_layer[:max(0, layer_width - len(next_layer))])
            if not next_layer:
                break
            current = next_layer

        return SolveResult(found=False, attempts=attempts)

    @staticmethod
    def _build_result(
        cand,
        full_chain: list[str],
        depth: int,
        attempts: int,
        layer_detects: list[tuple[int, str]],
        candidates: list,
        verify: str,
    ) -> SolveResult:
        """组装最终结果: 求解步骤(写 WP) + 其他候选答案。"""
        steps = [Step("识别", f"第 {d} 层密文: {desc}") for d, desc in layer_detects]
        steps.append(Step("攻击", f"使用 {cand.method}"))
        steps.append(Step("验证", verify, detail=f"score={cand.score:.1f}"))
        # 其他可能答案: 同层剩余高分候选 (排除已选, 上限 8 个)
        alternatives = [
            (c.plaintext, c.method, c.score)
            for c in candidates if c is not cand and c.score >= 45.0
        ]
        alternatives.sort(key=lambda x: x[2], reverse=True)
        return SolveResult(
            found=True, plaintext=cand.plaintext, score=cand.score,
            method=cand.method, chain=full_chain,
            depth=depth, attempts=attempts,
            steps=steps, alternatives=alternatives[:8],
        )

    @staticmethod
    def _cryptic_rank(data: bytes, detector: DetectionEngine) -> int:
        """候选入队优先级: 2=确定性编码形态(解码链关键路径, 结果唯一且确定),
        1=密文形态(猜测性攻击产物, 可能是噪声), 0=不入队。"""
        best = 0
        for d in detector.detect(data):
            if d.type in ENCODING_TYPES and d.confidence >= 0.6:
                # 哈希长度 hex 是哈希不是编码, 不让它无限 hex 解码
                if d.type == "hex":
                    compact = data.strip()
                    if len(compact) in HASH_HEX_LENS and d.confidence < 0.85:
                        continue
                best = max(best, 2)
            elif d.type in CRYPTIC_TYPES and d.confidence >= CRYPTIC_MIN_CONF:
                best = max(best, 1)
        return best
