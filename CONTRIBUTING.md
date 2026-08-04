# 贡献指南

感谢你考虑为 CipherScope 贡献代码。这份指南帮你快速上手。

## 项目简介

CipherScope 是一个 CTF 密码学自动化解题工具: 输入密文, 自动识别类型、调度攻击插件、评分判定, 输出 flag 与求解步骤。

架构速览:

```
cipherscope/
├── core/        # 识别/评分/调度/管道引擎
├── plugins/     # 攻击插件 (codecs / classical / xor / hash / rsa)
├── web/         # FastAPI Web 可视化版
├── data/        # 词频表与字典 (随包分发)
└── tools/       # 语料生成/评测/打包脚本
```

## 本地开发

```bash
# 1. 创建虚拟环境 (Python >= 3.11)
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 2. 安装开发依赖
pip install -e ".[dev,rsa,web]"

# 3. 运行全部测试
pytest -q                          # 75 个单元测试
cipherscope evaluate               # 100 题语料评测
python tools/blind_test.py         # 45 盲测用例
```

代码风格使用 `ruff check .`, 类型标注使用 `mypy cipherscope`(可选)。

## 新增攻击插件

1. 实现 `AttackPlugin` 协议 (见 `cipherscope/core/plugin.py`): 至少提供 `match(text) -> float` 和 `attack(text, **kw) -> list[Candidate]`
2. 将插件放入 `cipherscope/plugins/` 并在 `build_default_registry` 中注册
3. 在 `tests/ctf_corpus/corpus.yaml` 追加正/反向用例, 确保 `cipherscope evaluate` 通过
4. 补充单元测试

> 第三方包也可通过 `[project.entry-points."cipherscope.plugins"]` 注册插件, 无需改主仓库。

## 评分引擎注意点

评分引擎极易产生"假 flag"(乱码中碰巧出现 `flag{`)。任何新攻击的输出都必须在真实盲测中验证, 不要只看语料通过。

## 提交 PR

1. Fork 仓库并新建分支: `git checkout -b feat/my-feature`
2. 提交信息建议使用 conventional commits 风格, 例如 `fix(scorer): 修复 word-break 误判`、`feat(plugins): 新增 xx 攻击`
3. 推送前确保 `pytest`、语料评测、盲测全部通过 (CI 也会自动执行)
4. 提交 PR 时请使用仓库内置的 PR 模板

## 报告问题

Bug 或新题型请求请走 [Issues](https://github.com/2672243194/CipherScope/issues), 请附上: 密文样例、期望输出、实际输出、`cipherscope detect` 的结果。安全问题请走 [SECURITY.md](SECURITY.md) 描述的私有渠道。
