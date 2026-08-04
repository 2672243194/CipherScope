"""内置攻击插件组与默认注册表构建。"""
from __future__ import annotations

from cipherscope.core.plugin import PluginRegistry


def build_default_registry(extra_words: list[str] | None = None, salt: bytes | None = None) -> PluginRegistry:
    """注册全部内置插件。extra_words: 哈希爆破外部字典; salt: 带盐哈希的盐。
    第三方插件由 PluginRegistry.load_entry_points() 发现。"""
    from cipherscope.plugins.advanced import ALL_ADVANCED
    from cipherscope.plugins.classical import ALL_CLASSICAL
    from cipherscope.plugins.codecs import ALL_CODECS
    from cipherscope.plugins.codecs_extra import ALL_EXTRA_CODECS
    from cipherscope.plugins.hash_attack import HashPlugin
    from cipherscope.plugins.xor_attack import ALL_XOR

    registry = PluginRegistry()
    for plugin in [*ALL_CODECS, *ALL_EXTRA_CODECS, *ALL_ADVANCED, *ALL_CLASSICAL, *ALL_XOR]:
        registry.register(plugin)
    registry.register(HashPlugin(extra_words=extra_words, salt=salt))

    try:  # RSA 插件为可选(v0.2), 依赖缺失时静默跳过
        from cipherscope.plugins.rsa_attack import ALL_RSA
        for plugin in ALL_RSA:
            registry.register(plugin)
    except ImportError:
        pass
    return registry
