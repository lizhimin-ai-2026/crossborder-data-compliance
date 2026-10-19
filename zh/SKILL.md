---
name: crossborder-data-compliance
description: 跨境数据合规出海闸门（agent skill）。三层校验——目标地区法规（法规库版本化，结论可回溯到具体版本）+ 数据分类引擎（自动识别身份证/生物识别/支付/凭据为敏感，敏感数据零跨境）+ 传输链路完整性（存储/加密/收费/支付/税务，缺一 CRIT 拦截），另含跨境收费支付税务专项校验（charge-check）、人工终审放行（release 带原因留痕）、CleanKeeper 撤销（undo）与中英双语校验报告。触发词：出海检查、出海合规、跨境传输、数据出境、跨境合规、charge-check、register-region。Python 3.11+ 标准库无第三方依赖。
---

# 本平台 · 跨境数据合规（crossborder-data-compliance）v2.0

## 概述

本平台安全智能体核心 Skill（P0 契约层）。为本系统出海版提供跨境数据合规支持，确保数据存储、传输符合目标地区法律法规。出海前合规闸门。

**核心原则**：三层校验（目标地区法规 → 数据分类 → 传输链路）+ 首批两档市场（东南亚 / 英语市场）+ 跨境收费/支付/税务专项校验 + 法规库版本化 + 数据分类引擎 + CleanKeeper 撤销 + 双通道接口。

## 使用场景

- 出海版功能上线（自动触发）
- 数据跨境传输（传输前触发）
- 跨境收费 / 支付 / 税务（纳入校验面）
- 管理员人工终审放行

## 三层校验 + 专项校验

```
出海版功能上线 / 数据跨境传输
      │ 触发
      ▼
┌──────────────────────────────┐
│  跨境合规闸门（crossborder）   │
│  ① 目标地区法规（法规库版本化） │
│  ② 数据分类（classify 自动识别）│
│  ③ 传输链路（存储/加密/收费/支付/税务，缺一 CRIT）│
│  ④ 跨境收费/支付/税务专项       │
│  → 放行 / 提示 / 拦截          │
└──────────────────────────────┘
```

| 校验层 | 检查项 | 结果 |
|---|---|---|
| ① 目标地区法规 | 目标市场 ∈ 两档且已知法规版本 | 未登记地区 → 拦截(CRIT) |
| ② 数据分类 | classify 自动识别 个人信息/普通业务/敏感数据 | 敏感数据 → 风险提示(RISK) |
| ③ 传输链路 | 存储位置 / 传输加密 / 跨境收费支付税务 | 缺失 → 拦截(CRIT) |
| ④ 收费支付税务 | 支付通道 / 资金结算 / 税务登记 | 缺失 → 拦截(BLOCK) |

## 两档市场（法规库版本化，可回溯）

| 档位 | 覆盖 | 校验要求 | 法规版本示例 |
|---|---|---|---|
| 东南亚档 | 新加坡/马来西亚/泰国/越南/印尼/菲律宾 | 目标地区数据保护法规 + 本地化要求 | 新加坡 PDPA-SG-2021 |
| 英语市场档 | 欧洲/英国/美国/加拿大/澳大利亚 | 更高合规要求（GDPR 类）+ 跨境支付/税务 | 欧洲 GDPR-EU-2018 |

> 每条地区记录含 `version`（法规版本号）+ `effective`（生效日期）+ `source`（法规依据条目），校验结论可回溯到具体版本。

## 数据分类引擎（classify）

- 自动识别传输数据中的**身份证件号 / 生物识别 / 支付信息 / 账号凭据**（敏感）→ `sensitive`
- 识别**联系方式 / 姓名**（个人）→ `personal`
- 其余 → `business`
- **敏感数据零跨境**：命中敏感 → `compliance.risk(data-class, WARN)` + 风险提示；未经合规评估 + 管理员确认不放行。
- **脱敏零落盘**：分类只输出分类结果与依据条目，0 敏感数据值。

## 跨境收费/支付/税务（charge-check 专项）

- `charge-check` 校验：支付通道要求（目标地区可用支付服务商）、资金结算与外汇合规、税务登记/税号状态；每项 PASS/BLOCK。
- 与目标地区合规面联动：`charge_policy` 字段记录支付服务商选型原则（按目标地区可用性与合规性选择）与退款/试用政策（按目标地区消费者权益要求设定并披露）；本包只校验合规面，不做定价决策。

## 红线

1. **未登记地区不放行**：目标地区不在两档内（或未登记）→ 拦截(CRIT)；放行须管理员确认留痕。
2. **数据分类先行**：传输前必须标注数据分类；敏感数据零跨境（除非合规评估通过 + 管理员确认）。
3. **链路完整性**：存储位置 + 传输加密 + 收费/支付/税务 缺任一必需项 → 拦截(CRIT)。
4. **人工终审**：AI 只校验；放行须管理员确认（human_decision=override + 原因）。
5. **密钥红线**：API Key / 支付密钥只有管理员可查填；AI 不得打开、读取、扫描任何密钥文件与云端密钥配置。
6. **不动核心数据**：不修改本系统数据库任何数据；校验事件只追加。
7. **不后台作业**：禁止无人值守后台任务与定时自动部署。
8. **敏感值零落盘**：数据分类只输出分类结果与依据条目，0 敏感数据值；报告全量 0 敏感值。

## 规则文件

- `assets/crossborder_rules.json`：两档市场（法规版本化）/ 数据分类引擎 / 链路要求 / charge_policy（可复算，0 硬编码）
- `assets/scripts/crossborder_check.py`：三层校验 + classify + charge-check + 双通道接口核心脚本
- `assets/results/` 或 `%LOCALAPPDATA%\AgentSkill\crossborder\`：校验结果记录（compliance.check / compliance.risk，汇入审计）

## 事件汇入（审计日志 16 列契约）

| 事件类型 | result | severity | 汇入审计 字段 |
|---|---|---|---|
| 校验通过 | compliance.check | INFO | target=目标市场, ref_id=法规版本 |
| 数据分类风险 | compliance.risk | WARN | rule_id=data-class |
| 链路缺失 | compliance.risk | CRIT | rule_id=link-gap |
| 未登记地区 | compliance.risk | CRIT | rule_id=region-unknown |
| 收费/税务缺失 | compliance.risk | CRIT | rule_id=charge-gap |
| 人工放行 | compliance.check | WARN | human_decision=override + 原因 |

## 脚本规范

- Python 3.11+ 标准库（无第三方依赖）
- 校验结果写入 `%LOCALAPPDATA%\AgentSkill\crossborder\events\crossborder_events.csv`（16 列契约），并汇入审计
- `--selftest` 自检：24 用例（旧 6 + 新 18）全绿

## 双通道触发规范（语音 + 点击，对齐《本平台7包双通道集成方案V1.0》）

- **总唤醒词**：本平台；本包语音指令：
  - "本平台，出海检查 <地区> <数据>" → submit（三层校验）
  - "本平台，放行跨境 <地区> <原因>" → release（人工放行，原因留痕）
- **点击入口**：本平台出海中心 → 跨境数据合规 → 发起校验 / 查看校验记录
- **授权一致**：语音确认 ≡ 点击确认（唯一执行出口）；未登记地区/链路缺失默认拦截，人工放行须管理员确认留痕
- **状态同步**：校验 PASS/RISK/BLOCK/override 事件按 16 列契约汇入审计，双通道实时可见
- **降级**：语音通道异常只 log 不外抛，点击兜底；双通道均异常 → 安全默认（拦截跨境传输）

## CLI 速查

```bash
# 三层校验（向后兼容 v1：--region/--data-class/--links/--override/--selftest）
python crossborder_check.py --region 新加坡 --data-class business --links 存储,加密,收费,支付,税务
# 自动分类（替代 --data-class）
python crossborder_check.py --region 新加坡 --content "用户护照号 E1234567 需核验" --links 存储,加密,收费,支付,税务
# 子命令
python crossborder_check.py submit   --region <地区> --data-class <类> --links <链路>
python crossborder_check.py release  --region <地区> --reason "<放行原因>"
python crossborder_check.py classify --content "<传输数据文本>"
python crossborder_check.py charge-check --region <地区> --charge 支付通道,资金结算,税务登记
python crossborder_check.py register-region --name <地区> --tier <se-asia|english> --version <版本> --effective <日期> --source <依据>
python crossborder_check.py query    --result PASS --region <地区> --rule <rule_id> --limit 20
python crossborder_check.py export   --format md|json|csv --out <文件>
python crossborder_check.py report   --out <文件>          # 中英双语分组报告
python crossborder_check.py clean    --file <报告文件>     # 安全删除（可撤销）
python crossborder_check.py undo     --list | --restore <id>
python crossborder_check.py migrate                      # 旧数据迁移（复制不删源）
```
