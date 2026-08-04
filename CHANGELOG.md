# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 与语义化版本 (SemVer)。

## [Unreleased]

## [0.3.0] - 2026-08-04

### Added
- Web 可视化版 (FastAPI + 单页 UI): 自动求解、22 项手动编解码工具、RSA 求解器表单
- 中文 n-gram 评分模型: 20 万字级二元组词频表, 长中文句自动认可
- 完整 quadgram 表: 84k 组、892 万样本, 替代 trigram 兜底
- 真题语料库扩充至 100 题 (综合通过率 100%)
- GitHub Actions 动态评测徽章 (eval 100/100, blind 45/45)
- 一键启动脚本、PyInstaller 打包配置

### Changed
- 输入鲁棒性: 大小写/空白归一化, 编码形态判定不再过滤空格
- 评分引擎: flag 词边界匹配、word-break 判定、控制字符白名单、长文本词密度信号

## [0.2.0] - 2026-08-04

### Added
- RSA 攻击 12 类题型: 小 n 分解 / 低加密指数 / 共模 / 维纳 / 多 n 公约数 / 广播 / 费马 / Pollard p-1 / dp 泄露 / p,q,e 求 d / 解明文
- 哈希识别与字典爆破: MD5/SHA 系长度识别, 内置 10k 字典自动加载 + 百万级字典按需

## [0.1.0] - 2026-08-04

### Added
- 核心链路: 识别引擎 (字符集/熵/IC/Kasiski) → 调度器 → 评分引擎 (六信号融合) → 嵌套解码管道
- 插件化架构: `AttackPlugin` 协议 + `cipherscope.plugins` entry points 注册机制
- 编码插件: base16/32/58/64/85/91、ASCII 序列、URL、摩斯、Brainfuck、培根、猪圈等
- 古典密码插件: 凯撒、ROT47、Atbash、仿射、维吉尼亚、栅栏、键盘位移、云影
- XOR 攻击: 单字节/多字节/已知明文前缀
- Typer CLI: auto / detect / score / evaluate / web 子命令
- 75 单元测试、45 盲测用例、测试语料框架

[Unreleased]: https://github.com/2672243194/CipherScope/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/2672243194/CipherScope/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/2672243194/CipherScope/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/2672243194/CipherScope/releases/tag/v0.1.0
