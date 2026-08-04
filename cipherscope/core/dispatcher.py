"""调度器 (Dispatcher) —— 对单段密文执行一轮"识别 -> 攻击 -> 评分"。

职责:
1. 用注册表的 ranked() 按插件置信度降序调度;
2. 逐个插件惰性消费候选, 评分引擎统一打分;
3. 预算控制: 评分次数有上限, 防止仿射(312 候选)这类暴力插件
   在深层递归中耗尽时间;
4. 返回按分数降序的候选列表, 是否深挖由管道决定。

调度器本身不做递归——多层嵌套是管道的职责, 职责分离保持两者可独立测试。
"""
from __future__ import annotations

from cipherscope.core.plugin import Candidate, PluginRegistry
from cipherscope.core.scorer import ScoringEngine, Verdict

DEFAULT_SCORE_BUDGET = 1500   # 单节点最大评分次数


class Dispatcher:
    def __init__(self, registry: PluginRegistry, scorer: ScoringEngine | None = None) -> None:
        self.registry = registry
        self.scorer = scorer or ScoringEngine()

    def run(self, ct: bytes, budget: int = DEFAULT_SCORE_BUDGET, prefer: set[str] | None = None) -> list[Candidate]:
        """对密文执行一轮攻击, 返回评分降序候选列表。

        两轮制: 先跑 codec 类插件(便宜、套娃高频), 若已出现高置信成功
        直接返回, 不再消耗预算在古典密码穷举上; 否则第二轮跑其余插件。
        这使多层嵌套题每层的开销从 ~400 次评分降到 ~15 次。
        prefer: 用户指定的优先攻击插件名集合, 提高其调度权重。"""
        ranked = self.registry.ranked(ct, prefer)
        codec_first = [p for p in ranked if p[0].category == "codec"]
        others = [p for p in ranked if p[0].category != "codec"]
        # 编码形态输入(如 base64/hex/QP/punycode 串)不做猜测性攻击:
        # 凯撒/仿射/xor-crib 对编码串的乱解产物仍呈编码形态, 会污染嵌套管道
        # (真实 bug: MD5 串被 affine 乱解后 xor-crib 硬凑出假 flag; QP/punycode
        # 同样被 xor-crib 假解抢答)。判断依据: 任一 codec 插件高置信匹配
        # ——比 detector 猜测更可靠, 且对普通文本不会误判。
        if self._is_encoded_input(ct):
            others = [p for p in others if p[0].category not in ("classical", "xor")]
        results: list[Candidate] = []
        spent = 0

        def _consume(plugins: list) -> bool:
            """消费插件候选并评分。返回 True 表示已出结果, 提前结束。
            单个插件异常被隔离(try/except), 不中断整个调度——
            第三方插件质量不可控, 健壮性优先。"""
            nonlocal spent
            for plugin, _confidence in plugins:
                if spent >= budget:
                    return True
                try:
                    for cand in plugin.attack(ct):
                        r = self.scorer.score(cand.plaintext)
                        cand.score = r.score
                        cand.verdict = r.verdict
                        cand.source = plugin.category
                        cand.flag_prefix = r.flag_prefix
                        cand.chain = cand.chain or [plugin.name]
                        results.append(cand)
                        spent += 1
                        if spent >= budget:
                            return True
                        if cand.verified or (r.verdict is Verdict.SUCCESS and r.score >= 85):
                            return True
                except Exception as exc:  # 插件级隔离, 记录错误不中断
                    results.append(Candidate(
                        plaintext=b"", method=f"{plugin.name}: error({type(exc).__name__})",
                        chain=[f"{plugin.name}:error"],
                    ))
            return False

        if _consume(codec_first):
            results.sort(key=lambda c: c.score, reverse=True)
            return results
        _consume(others)
        results.sort(key=lambda c: c.score, reverse=True)
        return results

    def _is_encoded_input(self, ct: bytes) -> bool:
        """任一 codec 插件高置信匹配 => 编码形态输入。普通文本不会被 codec
        特征(字符集+长度约束)高置信匹配, 因此该判断不会误伤明文。"""
        for plugin in self.registry._plugins:
            if getattr(plugin, "category", "") != "codec":
                continue
            try:
                if plugin.match(ct) >= 0.6:
                    return True
            except Exception:
                continue
        return False
