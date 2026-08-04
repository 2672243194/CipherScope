"""插件协议与注册表 —— 框架扩展性的基础。

设计要点:
- match() 与 attack() 分离: 调度器先跑所有插件的轻量 match(),
  按置信度降序调度重量级的 attack(), 避免无效计算。
- attack() 返回迭代器: 惰性产出候选, 评分引擎判定超阈值后短路,
  剩余候选不再计算。
- 插件通过 entry_points (组名 "cipherscope.plugins") 自动发现,
  第三方可用 pip 包形式扩展。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator, Optional, Protocol, runtime_checkable

from cipherscope.core.scorer import Verdict


@dataclass
class Candidate:
    """一次攻击尝试的产出。"""

    plaintext: bytes
    score: float = 0.0          # 评分引擎打分, 0~100
    method: str = ""            # 攻击方法描述, 如 "vigenere(key='lemon')"
    chain: list[str] = field(default_factory=list)  # 到达该结果的完整攻击路径
    verified: bool = False      # 确定性破解(如哈希字典命中): 无需统计评分背书
    verdict: Optional[Verdict] = None   # 调度器评分后回填, 供管道裁决(避免重复评分)
    source: str = ""            # 产出插件的 category (codec/classical/xor/...), 调度器回填
    flag_prefix: str = ""       # 评分引擎回填的命中 flag 前缀 (写 WP 用)


@runtime_checkable
class AttackPlugin(Protocol):
    """攻击插件统一协议。所有攻击模块(codecs/classical/xor/rsa)实现此接口。"""

    name: str
    category: str               # codec / classical / xor / hash / rsa

    def match(self, ct: bytes) -> float:
        """对输入密文的适用性置信度, 0~1。0 表示完全不适用。"""
        ...

    def attack(self, ct: bytes) -> Iterator[Candidate]:
        """执行攻击, 惰性产出候选明文(可能多个密钥候选, 按把握降序)。"""
        ...


class PluginRegistry:
    """插件注册表: 内置插件显式注册 + entry_points 自动发现。"""

    def __init__(self) -> None:
        self._plugins: list[AttackPlugin] = []

    def register(self, plugin: AttackPlugin) -> None:
        self._plugins.append(plugin)

    def load_entry_points(self) -> None:
        """发现并加载第三方通过 entry_points 注册的插件。"""
        from importlib.metadata import entry_points

        for ep in entry_points(group="cipherscope.plugins"):
            self.register(ep.load()())

    def all(self) -> list[AttackPlugin]:
        return list(self._plugins)

    def ranked(self, ct: bytes, prefer: set[str] | None = None) -> list[tuple[AttackPlugin, float]]:
        """对给定密文, 返回 (插件, 置信度) 排序列表, 过滤置信度为 0 的。

        prefer: 用户手动指定的插件名集合(如 {"caesar", "vigenere"}),
        命中者无条件排到最前(同组内仍按置信度)——用于用户预判题型时
        提高指定攻击的权重, 不选则纯自动识别。"""
        scored = [(p, p.match(ct)) for p in self._plugins]
        scored = [(p, c) for p, c in scored if c > 0]
        if prefer:
            scored.sort(key=lambda s: (s[0].name not in prefer, s[1]), reverse=True)
        else:
            scored.sort(key=lambda s: s[1], reverse=True)
        return scored
