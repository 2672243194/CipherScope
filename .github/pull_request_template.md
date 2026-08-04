## 变更摘要

<!-- 用一两句话说明这个 PR 做了什么 -->

## 类型

- [ ] 新功能(新题型/新工具/新模块)
- [ ] Bug 修复
- [ ] 文档
- [ ] 性能/重构
- [ ] 其他

## 验证清单(必填)

提交前请确认:

- [ ] `pytest` 全部通过
- [ ] `python tools/blind_test.py` 全部 PASS(新增插件/修改评分必须)
- [ ] `python -c "from cipherscope.core.evaluate import run_eval; run_eval()"` 通过率未回退
- [ ] 如新增插件: 已补充对应单元测试, 并加入盲测用例
- [ ] 已运行 `ruff check`(如项目配置了 ruff)

## 测试数据示例

<!-- 如涉及新题型/修复, 附上密文与期望输出, 便于 reviewer 复现 -->

```
输入: ...
期望: ...
```

## 关联 Issue

<!-- Closes #123 -->
