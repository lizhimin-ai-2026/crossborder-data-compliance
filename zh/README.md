# 本平台 · 跨境数据合规 (crossborder-data-compliance) v2.0

本平台安全智能体核心 Skill（P0 契约层）：为本系统出海版提供跨境数据合规支持，确保数据存储、传输符合目标地区法律法规。出海前合规闸门。

## 核心能力

- **三层校验**：目标地区法规（法规库版本化）→ 数据分类（classify 自动识别）→ 传输链路（存储+加密+收费/支付/税务，缺一 CRIT）
- **法规库版本化**：每条地区记录含 version / effective / source，校验结论可回溯到具体法规版本
- **数据分类引擎**：自动识别 身份证件/生物识别/支付/凭据（敏感）→ 个人信息 → 普通业务；敏感数据零跨境
- **跨境收费/支付/税务专项校验**：charge-check 每项 PASS/BLOCK
- **双通道接口**：语音 + 点击（submit / release / classify / charge-check / query / export / report / undo）
- **人工终审**：AI 只校验；放行须管理员确认（human_decision=override + 原因）
- **撤销保护**：报告删除走 CleanKeeper 撤销区，可 undo 恢复
- **⑤ 审计汇入**：16 列契约事件汇入 审计日志

## 结构

```
crossborder-data-compliance/
├── SKILL.md                          # 技能说明（v2.0）
├── README.md
├── LICENSE.md
├── assets/
│   ├── crossborder_rules.json        # 法规版本化/数据分类/链路/charge_policy（可复算）
│   ├── results/                     # 校验结果（兼容旧路径）
│   └── scripts/
│       └── crossborder_check.py     # 三层校验 + classify + charge-check + 双通道接口
```

## 用法

```bash
# 三层校验
python crossborder_check.py --region <地区> --data-class <personal|business|sensitive> \
    --links 存储,加密,收费,支付,税务 [--override <原因>]

# 自动分类（替代 --data-class）
python crossborder_check.py --region <地区> --content "<传输数据文本>" --links 存储,加密,收费,支付,税务

# 子命令
python crossborder_check.py submit / release / classify / charge-check / register-region \
    / query / export / report / clean / undo / migrate

# 自检（24 用例）
python crossborder_check.py --selftest
```

## 判定结果

| 结果 | 含义 | 处置 |
|---|---|---|
| PASS | 三层校验通过 | 放行 |
| RISK | 敏感数据跨境 | 需合规评估通过 + 管理员确认 |
| BLOCK | 未登记地区 / 链路缺失 / 收费税务缺失 | 拦截（CRIT） |

## 红线

未登记地区不放行 / 数据分类先行（敏感数据零跨境）/ 链路完整性 / 人工终审 / 敏感值零落盘。

## 版本

- v2.0.0（2026-10-19）：法规库版本化 + 数据分类引擎 + 链路完整性强化 + charge-check + 双通道接口 + 存储迁移 + 撤销 + 24 用例 selftest
- v1.0.0（2026-10-17）：本地技能包初版，与《跨境数据合规Skill方案V1.0定稿》对齐
