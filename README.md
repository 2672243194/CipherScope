# CipherScope

> CTF 密码学自动化解题工具 —— 输入密文，自动识别类型、调度攻击、评分判定、输出 flag。

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)]()
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)]()
[![Eval Pass 34/34](https://img.shields.io/badge/eval-34%2F34%20(100%25)-brightgreen.svg)]()

## 它解决什么问题

CTF 密码学题目千变万化，但解题链路高度重复：**识别密文类型 → 选择攻击方法 → 验证结果**。
CipherScope 把这条链路自动化：

```
输入密文 → 识别引擎(类型+置信度) → 调度器(插件并发) → 评分引擎(多信号判定)
         → 未命中则进入下一层(嵌套解码, 处理 base 套娃) → 命中 flag
```

与现有工具的差异：

| 工具 | 定位 | CipherScope 的差异 |
|---|---|---|
| CyberChef | 手动编解码瑞士军刀 | 全自动，无需人工逐个尝试 |
| Ciphey | 自动识别+解密 | 覆盖 RSA/哈希爆破，中文赛事适配，真题评测集 |
| RsaCtfTool | RSA 攻击脚本集 | 完整识别→调度→评分链路，非单点工具 |

## 快速开始

```bash
pip install cipherscope
# 或带 Web 可视化版 (FastAPI 界面)
pip install "cipherscope[web]"

# 本地源码开发: 先装依赖再跑
# pip install -e ".[dev,web,rsa]"
# python -m cipherscope.cli web --port 8080

# 全自动求解
cipherscope auto "5L2g5aW977yMZmxhZ3s1Y2Q3YWJjZH0="
# FOUND score=82.1 depth=1
# chain: base64
# plaintext: congratulations, the flag is flag{...}

# 指定 flag 前缀 / 加深嵌套搜索
cipherscope auto "..." --flag-prefix NSSCTF{ --max-depth 8

# 只识别类型
cipherscope detect "..."
# 只对候选明文评分 (调试评分引擎)
cipherscope score "..."
# RSA 攻击
cipherscope rsa -n 90581... -e 65537 -c 43117...
# 跑真题语料库评测
cipherscope evaluate

# Web 可视化版
cipherscope web            # 浏览器打开 http://127.0.0.1:8080
```

## 支持的攻击

| 类别 | 内容 |
|---|---|
| 编码 | base16/32/58/64/85/91、ASCII 码序列(十/十六进制)、URL、二进制 ASCII、uuencode、摩斯(含扩展符号)、Brainfuck、OOK!、培根、猪圈 |
| 古典密码 | 凯撒、ROT47、Atbash、仿射、维吉尼亚(IC+Kasiski 自动定钥)、栅栏(W 型+分栏式)、键盘位移、云影密码 |
| XOR | 单字节穷举、多字节(空格启发定钥)、已知明文前缀攻击 |
| 哈希 | MD5/SHA 系长度识别 + 字典爆破(可扩展字典) |
| RSA (v0.2) | 小模数分解、低加密指数、共模攻击、维纳攻击、多 n 公约数 |

插件化架构：实现 `AttackPlugin` 协议（`match` + `attack`），通过 `entry_points` 组 `cipherscope.plugins` 注册即可扩展。

## 架构

```
cipherscope/
├── cli.py                  # typer CLI
├── core/
│   ├── plugin.py           # 插件协议 + 注册表
│   ├── detector.py         # 识别引擎: 字符集/熵/IC/Kasiski
│   ├── scorer.py           # 评分引擎: 六信号融合 + 三档裁决
│   ├── dispatcher.py       # 调度器: 置信度排序 + codec 优先两轮制
│   ├── pipeline.py         # 嵌套管道: DFS 限深10层 + 循环检测 + 限宽
│   └── evaluate.py         # 真题语料库评测
├── plugins/                # 攻击插件组 (codecs/classical/xor/hash/rsa)
├── web/                    # FastAPI Web 可视化版
├── data/                   # 词频表/字典 (quadgrams.json 由 tools/build_quadgrams.py 生成)
└── tools/                  # 语料生成/评测/打包脚本
```

**关键设计**（详见 `docs/modules/` 逐模块讲解）：
- **评分引擎**：flag 正则 + n-gram 适应度 + 可打印比例 + 词典命中 + 卡方 + 中文兜底，多信号加权融合，三档裁决 SUCCESS/PROMISING/REJECT；
- **编码链优先**：codec 插件确定性解码产物无条件进入下一层（套娃题关键），猜测性攻击产物按 detector 置信度分级入队；
- **假 flag 防护**：长乱码中碰巧出现 `flag{` 字样的候选，因上下文不可读被降级，防止错误短路。

## 评测

34 道自构造语料（覆盖全部插件正反向路径与多层组合），**综合通过率 100%**：

```
CipherScope Eval — 34/34 (100%)
┌───────────┬───────────┬──────┬───────┬──────┐
│ Platform  │ Category  │ Pass │ Total │ Rate │
├───────────┼───────────┼──────┼───────┼──────┤
│ synthetic │ classical │   10 │    10 │ 100% │
│ synthetic │ codec     │   12 │    12 │ 100% │
│ synthetic │ combo     │    6 │     6 │ 100% │
│ synthetic │ hash      │    2 │     2 │ 100% │
│ synthetic │ xor       │    4 │     4 │ 100% │
└───────────┴───────────┴──────┴───────┴──────┘
```

真实赛事题（BUUCTF/攻防世界/NSSCTF/CTFHub）可按 `tests/ctf_corpus/corpus.yaml` 格式追加。

## 路线图

- [x] v0.1 识别/评分/调度/管道 + 编码/古典/XOR 插件 + CLI
- [x] v0.2 RSA 攻击 + 哈希识别
- [x] v0.3 Web 可视化版 + 打包脚本
- [ ] 完整 quadgram 表生成与调参
- [ ] 中文 n-gram 评分模型
- [ ] 真题语料扩充至 100 题 + 通过率徽章 CI

## License

MIT
