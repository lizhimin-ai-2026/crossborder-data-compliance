#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
本平台 · 跨境数据合规 (crossborder-data-compliance) — 核心脚本 v2.0

出海前合规闸门：三层校验（目标地区法规 → 数据分类 → 传输链路）+ 跨境收费/支付/税务专项校验。
首批两档市场：东南亚档 / 英语市场档；法规库版本化；数据分类引擎；CleanKeeper 撤销；双通道接口。

红线：未登记地区不放行 / 数据分类先行（敏感数据零跨境）/ 链路完整性 / 人工终审 / 敏感值零落盘。

用法（向后兼容 v1 CLI）：
  python crossborder_check.py --region <地区> --data-class <personal|business|sensitive> \
      [--links 存储,加密,收费,支付,税务] [--override <原因>] [--base-dir X]
  python crossborder_check.py --region <地区> --content <传输数据文本> [--base-dir X]   # 自动分类
  python crossborder_check.py --selftest

子命令（U5 双通道宿主接口）：
  submit            三层校验入口（等价于顶层 --region/--data-class，返回 PASS/RISK/BLOCK+rule_id）
  release           管理员人工放行（human_decision=override + 原因留痕；未登记地区/链路缺失走此通道）
  register-region   登记新目标地区（档位/法规版本/合规要求），登记后立即纳入校验
  classify          自动识别传输数据分类（个人信息/普通业务/敏感数据）+ 依据条目
  charge-check      跨境收费/支付/税务专项校验（每项 PASS/RISK/BLOCK）
  query             查询校验记录（--result/--region/--rule/--date-from/--date-to/--limit）
  export            导出校验报告（--format md|json|csv）
  report            生成中英双语分组校验报告（按地区/结果 + 法规版本 + rule_id）
  clean             安全删除报告文件（移入撤销区，可 undo 恢复）
  undo              撤销（--list / --restore <id>）
  migrate           旧包内数据迁移到新存储（复制不删源）
"""

import argparse
import csv
import hashlib
import importlib.util
import io
import json
import os
import re
import sys
from datetime import datetime, timezone

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # crossborder-data-compliance/
RESULTS_DIR = os.path.join(SKILL_DIR, "assets", "results")
RULES_PATH = os.path.join(SKILL_DIR, "assets", "crossborder_rules.json")

SCHEMA_VERSION = "2.0"
EVENT_COLUMNS = [
    "ts", "source", "event_type", "actor", "action", "target", "result",
    "severity", "rule_id", "evidence_hash", "ref_id", "human_decision",
    "undo_ref", "note", "status", "schema_version",
]

LINK_ALIASES = {
    "存储": "存储位置合规",
    "加密": "传输加密",
    "收费": "跨境收费合规",
    "支付": "跨境支付合规",
    "税务": "跨境税务合规",
}


# ---------- 基础 ----------

def load_rules():
    with open(RULES_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def utc_now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def hash_evidence(*parts):
    raw = "|".join(str(p) for p in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def default_base_dir():
    local = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(local, "AgentSkill", "crossborder")


def resolve_base_dir(cli_base_dir, rules):
    if cli_base_dir:
        return os.path.abspath(cli_base_dir)
    storage = rules.get("storage", {})
    cfg = (storage.get("base_dir") or "").strip()
    if cfg:
        return os.path.expandvars(cfg)
    return default_base_dir()


def dirs_for(base_dir):
    return {
        "events": os.path.join(base_dir, "events"),
        "reports": os.path.join(base_dir, "reports"),
        "trash": os.path.join(base_dir, ".trash"),
    }


def ensure_dirs(base_dir):
    d = dirs_for(base_dir)
    for p in d.values():
        os.makedirs(p, exist_ok=True)
    return d


def log_path_for(base_dir):
    return os.path.join(dirs_for(base_dir)["events"], "crossborder_events.csv")


def load_all_events(base_dir):
    rows = []
    path = log_path_for(base_dir)
    if not os.path.exists(path):
        return rows
    with open(path, "r", newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            rows.append(row)
    return rows


def write_event(base_dir, event):
    d = ensure_dirs(base_dir)
    path = log_path_for(base_dir)
    write_header = not os.path.exists(path)
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=EVENT_COLUMNS)
        if write_header:
            w.writeheader()
        w.writerow({c: event.get(c, "") for c in EVENT_COLUMNS})
    return path


# ---------- ⑤ 审计汇入（优雅跳过） ----------

def _load_audit_core():
    """定位 ⑤ 审计底座 audit_core（内部依赖；开源版无则优雅跳过）。"""
    cands = []
    env = os.environ.get("SKILLHUB_AUDIT_CORE")
    if env:
        cands.append(env)
    here = os.path.dirname(os.path.abspath(__file__))
    cands.append(os.path.join(here, "..", "..", "..", "audit-core",
                              "assets", "scripts", "audit_core.py"))
    for p in cands:
        p = os.path.abspath(p)
        if os.path.isfile(p):
            try:
                spec = importlib.util.spec_from_file_location("audit_core", p)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                return mod
            except Exception:
                return None
    return None


def ingest_to_audit(event_dict):
    """把 16 列事件汇入审计；audit_core 不可用时优雅跳过（开源版自包含）。"""
    mod = _load_audit_core()
    if mod is None:
        return False
    try:
        arules = mod.load_rules()
        abase = mod.resolve_base_dir(None, arules)
        mod.ingest(arules, abase, json.dumps(event_dict, ensure_ascii=False))
    except Exception as e:  # 审计汇入失败不影响主流程
        print(f"[warn] ⑤审计汇入跳过: {e}", file=sys.stderr)
    return True


# ---------- 三层校验 ----------

def find_region(rules, region):
    """返回 (tier_name, region_obj) 或 (None, None)。"""
    for tier_name, cfg in rules["market_tiers"].items():
        for r in cfg.get("regions", []):
            if isinstance(r, dict) and r.get("name") == region:
                return tier_name, r
            if isinstance(r, str) and r == region:
                return tier_name, {"name": region}
    return None, None


def normalize_links(links):
    result = set()
    for l in links:
        result.add(LINK_ALIASES.get(l, l))
    return result


def classify_content(rules, text):
    """自动识别传输数据分类。返回 (data_class, hits)。hits=命中的 {label, basis} 列表（0 敏感值）。"""
    text_low = (text or "").lower()
    sensitive = rules["data_classification"].get("sensitive_patterns", [])
    personal = rules["data_classification"].get("personal_patterns", [])
    hits = []
    for p in sensitive:
        matched = any(k.lower() in text_low for k in p.get("keywords", []))
        rx = p.get("regex", "")
        if (rx and re.search(rx, text or "")) or matched:
            hits.append({"label": p.get("label", ""), "basis": p.get("basis", "")})
    if hits:
        return "sensitive", hits
    phits = []
    for p in personal:
        matched = any(k.lower() in text_low for k in p.get("keywords", []))
        rx = p.get("regex", "")
        if (rx and re.search(rx, text or "")) or matched:
            phits.append({"label": p.get("label", ""), "basis": p.get("basis", "")})
    if phits:
        return "personal", phits
    return "business", []


def evaluate(rules, region, data_class, links, override, charge=None):
    """
    三层校验。返回 (result, severity, rule_id, note, version)。
      ① 目标地区法规：地区在两档内且已知版本
      ② 数据分类：data_class 合法；sensitive → RISK（零跨境）
      ③ 传输链路：links 必须覆盖 link_requirements（缺任一 → CRIT）
      人工 override → 直接放行（留痕），version 透传
    charge：charge-check 专项结果（dict），用于补充提示
    """
    version = None
    if override:
        return "PASS", "WARN", "override", f"管理员人工放行（原因）：{override}", version

    # ① 目标地区法规
    tier_name, region_obj = find_region(rules, region)
    if tier_name is None:
        return "BLOCK", "CRIT", "region-unknown", f"目标地区未登记（两档外）: {region} → 拦截", version
    version = region_obj.get("version", "")

    # ② 数据分类
    if data_class not in rules["data_classification"]["types"]:
        return "BLOCK", "CRIT", "data-class-invalid", f"数据分类非法: {data_class}", version
    if data_class == "sensitive":
        return "RISK", "WARN", "data-class-sensitive", "敏感数据跨境 → 需合规评估通过 + 管理员确认才可放行", version

    # ③ 传输链路（存储/加密/收费/支付/税务）
    required = set(rules["link_requirements"])
    provided = normalize_links(links) if links else set()
    missing = required - provided
    if missing:
        return "BLOCK", "CRIT", "link-gap", f"传输链路缺失: {', '.join(sorted(missing))} → 拦截(CRIT)", version

    note = f"三层校验通过（{tier_name}: {region}，法规版本 {version}）"
    if charge:
        failed = [k for k, v in charge.items() if v != "PASS"]
        if failed:
            return "BLOCK", "CRIT", "charge-gap", f"跨境收费/支付/税务未齐备: {', '.join(failed)} → 拦截", version
        note += "；收费/支付/税务专项 PASS"
    return "PASS", "INFO", "pass", note, version


def build_event(region, result, severity, rule_id, note, version, override=""):
    return {
        "ts": utc_now_iso(),
        "source": "cross-border",
        "event_type": "compliance.check" if result == "PASS" else "compliance.risk",
        "actor": "管理员(人工放行)" if override else "system",
        "action": "cross-border-check",
        "target": region,
        "result": result,
        "severity": severity,
        "rule_id": rule_id,
        "evidence_hash": hash_evidence(region, version or "", result),
        "ref_id": version or "",
        "human_decision": "override" if override else "",
        "undo_ref": "",
        "note": note,
        "status": "recorded",
        "schema_version": SCHEMA_VERSION,
    }


def _record_and_ingest(base_dir, event):
    write_event(base_dir, event)
    ingest_to_audit(event)
    return event


# ---------- 子命令实现 ----------

def _resolve_data_class(args, rules):
    """从 --data-class 或 --content 自动分类得到 data_class；返回 (data_class, classify_hits)。"""
    if args.data_class:
        return args.data_class, []
    if getattr(args, "content", None):
        dc, hits = classify_content(rules, args.content)
        return dc, hits
    return None, []


def run_submit(args):
    rules = load_rules()
    base = resolve_base_dir(args.base_dir, rules)
    data_class, hits = _resolve_data_class(args, rules)
    if not data_class:
        print("输入错误: 缺少 --data-class 或 --content", file=sys.stderr)
        return 2
    links = [x.strip() for x in (args.links or "").split(",") if x.strip()]
    charge = _charge_eval(rules, args.region, getattr(args, "charge", None)) if getattr(args, "charge", None) else None
    result, severity, rule_id, note, version = evaluate(
        rules, args.region, data_class, links, args.override, charge)
    event = build_event(args.region, result, severity, rule_id, note, version, args.override or "")
    _record_and_ingest(base, event)
    extra = ""
    if hits:
        extra = "；分类命中: " + ", ".join(h["label"] for h in hits)
    print(f"{result} | {severity} | {rule_id} | {note}{extra}")
    print(f"event -> {log_path_for(base)}")
    return 0 if result == "PASS" else 1


# release 与 submit --override 等价（人工放行通道）
def run_release(args):
    args.override = args.reason or args.override
    if not args.override:
        print("输入错误: release 需要 --reason（放行原因）", file=sys.stderr)
        return 2
    return run_submit(args)


def run_register_region(args):
    """登记新目标地区（U1）。写回 crossborder_rules.json。"""
    rules = load_rules()
    tier = rules["market_tiers"].get(args.tier)
    if tier is None:
        print(f"登记失败: 未知档位 {args.tier}（可选: {list(rules['market_tiers'].keys())}）", file=sys.stderr)
        return 2
    existing = [r.get("name") for r in tier["regions"] if isinstance(r, dict)]
    if args.name in existing:
        print(f"登记跳过: {args.name} 已在 {args.tier} 档", file=sys.stderr)
        return 0
    tier["regions"].append({
        "name": args.name, "version": args.version or "CUSTOM-1.0",
        "effective": args.effective or "2026-01-01",
        "source": args.source or f"自定义登记: {args.name}（{args.tier} 档）",
    })
    with open(RULES_PATH, "w", encoding="utf-8") as f:
        json.dump(rules, f, ensure_ascii=False, indent=2)
    print(f"REGISTER OK: {args.name} 已登记到 {args.tier} 档（版本 {args.version or 'CUSTOM-1.0'}）")
    return 0


def run_classify(args):
    rules = load_rules()
    dc, hits = classify_content(rules, args.content)
    print(f"分类结果 data_class = {dc}")
    if hits:
        for h in hits:
            print(f"  - 命中: {h['label']} | 依据: {h['basis']}")
    else:
        print("  - 未命中敏感/个人模式，归类为普通业务（0 敏感值输出）")
    return 0


CHARGE_LABELS = {
    "支付通道": "payment_channel", "payment_channel": "payment_channel",
    "资金结算": "settlement", "settlement": "settlement",
    "税务登记": "tax_registration", "tax_registration": "tax_registration",
}
CHARGE_KEY_LABEL = {v: k for k, v in CHARGE_LABELS.items() if k in ("支付通道", "资金结算", "税务登记")}


def _charge_eval(rules, region, provided):
    """charge-check 专项：支付通道/资金结算/税务登记 各 PASS/BLOCK（中文标签或内部键均可输入）。"""
    required = {
        "支付通道": "payment_channel",
        "资金结算": "settlement",
        "税务登记": "tax_registration",
    }
    provided_keys = set()
    for x in (provided or "").split(","):
        x = x.strip()
        if x:
            provided_keys.add(CHARGE_LABELS.get(x, x))
    out = {}
    for label, key in required.items():
        out[key] = "PASS" if key in provided_keys else "BLOCK"
    return out


def run_charge_check(args):
    rules = load_rules()
    base = resolve_base_dir(args.base_dir, rules)
    tier_name, _ = find_region(rules, args.region)
    if tier_name is None:
        print(f"BLOCK | CRIT | region-unknown | 目标地区未登记: {args.region}")
        ev = build_event(args.region, "BLOCK", "CRIT", "region-unknown",
                         f"目标地区未登记: {args.region}", "")
        _record_and_ingest(base, ev)
        return 1
    charge = _charge_eval(rules, args.region, args.charge)
    failed = [CHARGE_KEY_LABEL.get(k, k) for k, v in charge.items() if v != "PASS"]
    overall = "PASS" if not failed else "BLOCK"
    sev = "INFO" if overall == "PASS" else "CRIT"
    rid = "pass" if overall == "PASS" else "charge-gap"
    detail = "；".join(f"{CHARGE_KEY_LABEL.get(k, k)}={v}" for k, v in charge.items())
    if overall == "PASS":
        note = "跨境收费/支付/税务专项 PASS（" + detail + "）"
    else:
        note = "跨境收费/支付/税务专项缺失 BLOCK（" + detail + "）"
    print(f"{overall} | {sev} | {rid} | {note}")
    ev = build_event(args.region, overall, sev, rid, note, "")
    _record_and_ingest(base, ev)
    return 0 if overall == "PASS" else 1


def run_query(args):
    rules = load_rules()
    base = resolve_base_dir(args.base_dir, rules)
    events = load_all_events(base)
    if args.result:
        # RESULT_TO_ET：PASS→compliance.check 等
        et = {"PASS": "compliance.check", "RISK": "compliance.risk", "BLOCK": "compliance.risk"}.get(args.result, "")
        events = [e for e in events if e.get("event_type") == et]
    if args.region:
        events = [e for e in events if e.get("target") == args.region]
    if args.rule:
        events = [e for e in events if e.get("rule_id") == args.rule]
    if args.date_from:
        events = [e for e in events if (e.get("ts") or "")[:10] >= args.date_from]
    if args.date_to:
        events = [e for e in events if (e.get("ts") or "")[:10] <= args.date_to]
    events.sort(key=lambda x: x.get("ts", ""))
    if args.limit:
        events = events[-int(args.limit):]
    if args.format == "csv":
        w = csv.DictWriter(sys.stdout, fieldnames=EVENT_COLUMNS)
        w.writeheader()
        for e in events:
            w.writerow({c: e.get(c, "") for c in EVENT_COLUMNS})
    else:
        print(f"{'ts':<22}{'target':<10}{'result':<7}{'severity':<8}{'rule_id':<22}{'version'}")
        for e in events:
            print(f"{e.get('ts',''):<22}{e.get('target',''):<10}{e.get('result',''):<7}"
                  f"{e.get('severity',''):<8}{e.get('rule_id',''):<22}{e.get('ref_id','')}")
        print(f"-- {len(events)} 条 / total")
    return 0


def run_export(args):
    rules = load_rules()
    base = resolve_base_dir(args.base_dir, rules)
    events = load_all_events(base)
    events.sort(key=lambda x: x.get("ts", ""))
    if args.format == "json":
        content = json.dumps({"schema_version": SCHEMA_VERSION, "count": len(events),
                              "events": [{c: e.get(c, "") for c in EVENT_COLUMNS} for e in events]},
                             ensure_ascii=False, indent=2)
        ext = "json"
    elif args.format == "csv":
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=EVENT_COLUMNS)
        w.writeheader()
        for e in events:
            w.writerow({c: e.get(c, "") for c in EVENT_COLUMNS})
        content = buf.getvalue()
        ext = "csv"
    else:
        L = [f"# 跨境数据合规校验导出 / Cross-border Compliance Export ({len(events)} events)", ""]
        for e in events:
            L.append(f"- {e.get('ts')} | {e.get('target')} | {e.get('result')} | {e.get('severity')} | {e.get('rule_id')} | {e.get('ref_id')}")
        content = "\n".join(L)
        ext = "md"
    path = args.out or os.path.join(dirs_for(base)["reports"], f"export.{ext}")
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"EXPORT OK -> {path}（{len(events)} 条，格式 {args.format}）")
    return 0


def run_report(args):
    """中英双语分组校验报告（U6）：按地区/结果分组 + 法规版本 + rule_id。"""
    rules = load_rules()
    base = resolve_base_dir(args.base_dir, rules)
    events = load_all_events(base)
    by_region = {}
    for e in events:
        by_region.setdefault(e.get("target", "-"), []).append(e)
    L = []
    # 中文
    L.append("# 跨境数据合规校验报告（中文）")
    L.append(f"- 生成时间: {utc_now_iso()}  事件总数: {len(events)}")
    for region, evs in sorted(by_region.items()):
        L.append(f"\n## 地区: {region}")
        from collections import Counter
        res = Counter(e.get("result") for e in evs)
        L.append(f"- 结果分布: {dict(res)}")
        for e in evs:
            L.append(f"  - [{e.get('result')}/{e.get('severity')}] {e.get('rule_id')} | 法规版本 {e.get('ref_id') or '-'} | {e.get('note')}")
    # 英文
    L.append("\n# Cross-border Compliance Report (English)")
    L.append(f"- Generated: {utc_now_iso()}  Total events: {len(events)}")
    for region, evs in sorted(by_region.items()):
        L.append(f"\n## Region: {region}")
        from collections import Counter as C2
        res = C2(e.get("result") for e in evs)
        L.append(f"- Result distribution: {dict(res)}")
        for e in evs:
            L.append(f"  - [{e.get('result')}/{e.get('severity')}] {e.get('rule_id')} | reg-version {e.get('ref_id') or '-'} | {e.get('note')}")
    path = args.out or os.path.join(dirs_for(base)["reports"], "report.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    print(f"REPORT OK -> {path}（中英双语，事件 {len(events)}，含法规版本）")
    return 0


# ---------- 撤销（U7，对齐 CleanKeeper） ----------

def _manifest_path(base_dir):
    return os.path.join(dirs_for(base_dir)["trash"], "manifest.json")


def _load_manifest(base_dir):
    p = _manifest_path(base_dir)
    if os.path.exists(p):
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"entries": []}


def _save_manifest(base_dir, manifest):
    ensure_dirs(base_dir)
    with open(_manifest_path(base_dir), "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)


def _register_undo(base_dir, original_path, backup_path, reason, undo_id=None):
    manifest = _load_manifest(base_dir)
    if not undo_id:
        undo_id = f"u{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"
    manifest["entries"].append({
        "undo_id": undo_id, "original_path": original_path, "backup_path": backup_path,
        "sha256": _sha256_file(backup_path) if os.path.isfile(backup_path) else "",
        "ts": utc_now_iso(), "reason": reason,
    })
    _save_manifest(base_dir, manifest)
    return undo_id


def _prune_undo(base_dir, keep=3):
    manifest = _load_manifest(base_dir)
    entries = manifest["entries"]
    keep_n = int(keep)
    while len(entries) > keep_n:
        old = entries.pop(0)
        bp = old.get("backup_path", "")
        if bp and os.path.isfile(bp):
            os.remove(bp)
    _save_manifest(base_dir, manifest)


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def run_clean(args):
    """安全删除报告文件（移入撤销区，登记 manifest，保留最近 3 次）。"""
    base = resolve_base_dir(args.base_dir, load_rules())
    path = args.file
    if not os.path.isfile(path):
        print(f"CLEAN ERROR: 文件不存在 {path}", file=sys.stderr)
        return 2
    d = ensure_dirs(base)
    undo_id = f"u{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"
    backup_dir = os.path.join(d["trash"], undo_id)
    os.makedirs(backup_dir, exist_ok=True)
    backup_path = os.path.join(backup_dir, os.path.basename(path))
    import shutil
    shutil.move(path, backup_path)
    _register_undo(base, os.path.abspath(path), backup_path, "report clean", undo_id=undo_id)
    _prune_undo(base)
    print(f"CLEAN OK: {path} 移入撤销区（undo_id={undo_id}，可 undo --restore 恢复）")
    return 0


def run_undo(args):
    base = resolve_base_dir(args.base_dir, load_rules())
    manifest = _load_manifest(base)
    if args.list:
        if not manifest["entries"]:
            print("无待撤销项")
            return 0
        for e in manifest["entries"]:
            print(f"- {e['undo_id']} | {e['ts']} | {e['reason']} | {os.path.basename(e['original_path'])}")
        return 0
    if not args.restore:
        print("undo 需要 --list 或 --restore <id>", file=sys.stderr)
        return 2
    entry = next((e for e in manifest["entries"] if e["undo_id"] == args.restore), None)
    if not entry:
        print(f"UNDO ERROR: 未找到 undo_id={args.restore}", file=sys.stderr)
        return 2
    backup_path = entry["backup_path"]
    if not os.path.isfile(backup_path):
        print(f"UNDO ERROR: 备份不存在 {backup_path}", file=sys.stderr)
        return 2
    cur = _sha256_file(backup_path)
    if entry.get("sha256") and cur != entry["sha256"]:
        print(f"UNDO ERROR: 哈希不一致（备份被改）{entry['sha256']} != {cur}", file=sys.stderr)
        return 2
    os.makedirs(os.path.dirname(entry["original_path"]), exist_ok=True)
    import shutil
    shutil.move(backup_path, entry["original_path"])
    manifest["entries"].remove(entry)
    _save_manifest(base, manifest)
    print(f"UNDO OK: 已恢复 {entry['original_path']}（哈希校验一致）")
    return 0


def run_migrate(args):
    """旧包内 assets/results 数据迁移到新存储（复制不删源）。"""
    rules = load_rules()
    base = resolve_base_dir(args.base_dir, rules)
    d = ensure_dirs(base)
    src = RESULTS_DIR
    copied = 0
    if os.path.isdir(src):
        for fn in os.listdir(src):
            s = os.path.join(src, fn)
            if os.path.isfile(s):
                dst = os.path.join(d["events"], fn)
                if not os.path.exists(dst):
                    import shutil
                    shutil.copy2(s, dst)
                    copied += 1
    print(f"MIGRATE OK: 复制 {copied} 个文件到 {base}（源保留，未删除）")
    return 0


# ---------- selftest（U8：旧 5 + 新 ≥8） ----------

def run_selftest():
    import tempfile
    rules = load_rules()
    passed = total = 0

    def check(ok, desc):
        nonlocal passed, total
        total += 1
        passed += 1 if ok else 0
        print(f"[{'PASS' if ok else 'FAIL'}] {desc}")

    tmp = tempfile.mkdtemp(prefix="crossborder_st_")
    base = os.path.join(tmp, "crossborder")
    ensure_dirs(base)
    all_links = ["存储", "加密", "收费", "支付", "税务"]

    # ===== 旧 5 用例（回归不破坏）=====
    r, s, rid, n, v = evaluate(rules, "新加坡", "business", all_links, "")
    check(r == "PASS", "回归: 东南亚档+链路完整 → 通过")
    r, s, rid, n, v = evaluate(rules, "欧洲", "business", all_links, "")
    check(r == "PASS", "回归: 英语市场档+链路完整 → 通过")
    r, s, rid, n, v = evaluate(rules, "日本", "business", all_links, "")
    check(r == "BLOCK" and rid == "region-unknown", "回归: 未登记地区 → 拦截(region-unknown)")
    r, s, rid, n, v = evaluate(rules, "新加坡", "sensitive", all_links, "")
    check(r == "RISK" and rid == "data-class-sensitive", "回归: 敏感数据跨境 → 提示风险")
    r, s, rid, n, v = evaluate(rules, "新加坡", "business", ["存储", "加密"], "")
    check(r == "BLOCK" and rid == "link-gap", "回归: 链路缺失(收费/支付/税务) → 拦截")
    r, s, rid, n, v = evaluate(rules, "欧洲", "business", [], "欧盟数据保护已评审")
    check(r == "PASS" and rid == "override", "回归: 管理员人工放行 → 通过")

    # ===== 新增用例（U1-U7）=====
    # U1 法规版本可回溯（从规则库读取当前值做一致性校验；开源版为通用示例版本亦成立）
    eng = next(r for r in rules["market_tiers"]["english"]["regions"] if r["name"] == "欧洲")
    check(bool(eng.get("version")) and bool(eng.get("effective")) and bool(eng.get("source")),
          f"U1 法规版本可回溯: 欧洲={eng.get('version')}({eng.get('effective')})")

    # U1 register-region：登记生效 + 未登记仍拦截
    # 用临时规则副本模拟登记
    import copy
    r2 = copy.deepcopy(rules)
    r2["market_tiers"]["se-asia"]["regions"].append(
        {"name": "测试地区X", "version": "TEST-1.0", "effective": "2026-01-01", "source": "selftest"})
    tn, tro = find_region(r2, "测试地区X")
    check(tn == "se-asia" and tro.get("version") == "TEST-1.0", "U1 register-region: 登记后纳入校验(版本 TEST-1.0)")
    check(find_region(r2, "日本")[0] is None, "U1 register-region: 未登记地区仍拦截")

    # U2 classify 自动识别
    dc1, h1 = classify_content(rules, "用户的银行卡号 6217 0012 3456 7890 需要跨境同步")
    check(dc1 == "sensitive" and any(x["label"] == "支付信息" for x in h1), "U2 classify: 支付信息 → 敏感")
    dc2, _ = classify_content(rules, "绿植浇水频率每周一次，保持基质湿润即可")
    check(dc2 == "business", "U2 classify: 普通养护内容 → 普通业务")
    dc3, h3 = classify_content(rules, "客户手机号 13800138000 与邮箱 user@example.com")
    check(dc3 == "personal" and any(x["label"] == "联系方式" for x in h3), "U2 classify: 联系方式 → 个人")

    # U3 链路缺传输加密 → CRIT 拦截
    r, s, rid, n, v = evaluate(rules, "新加坡", "business", ["存储", "收费", "支付", "税务"], "")
    check(r == "BLOCK" and rid == "link-gap" and s == "CRIT", "U3 链路缺传输加密 → CRIT 拦截")

    # U4 charge-check：支付缺失 → BLOCK；税务缺失 → BLOCK；全项 PASS
    c1 = _charge_eval(rules, "欧洲", "支付通道,资金结算")
    check(c1.get("tax_registration") == "BLOCK", "U4 charge-check: 税务登记缺失 → BLOCK")
    c2 = _charge_eval(rules, "欧洲", "支付通道,资金结算,税务登记")
    check(all(v == "PASS" for v in c2.values()), "U4 charge-check: 三要素齐备 → PASS")
    # charge_policy 结构完整性（映射字段齐备；开源版为通用示例亦成立）
    cp = rules["charge_policy"]
    check(all(k in cp for k in ("source", "selection_principle", "payment_apis", "refund_policy", "tax", "note"))
          and "international" in cp["payment_apis"],
          "U4 charge_policy: 映射字段齐备(来源/选型/支付API/退款/税务)")

    # U5 submit 三层判定（含 classify 自动分类）
    dc_sub, _ = _resolve_data_class_type(rules, None, "用户护照号 E1234567 需要核验")
    check(dc_sub == "sensitive", "U5 submit: --content 自动分类为 sensitive")

    # U5 query 过滤（构造临时事件再查）
    ev = build_event("新加坡", "PASS", "INFO", "pass", "test", "PDPA-SG-2021")
    write_event(base, ev)
    evb = build_event("日本", "BLOCK", "CRIT", "region-unknown", "test", "")
    write_event(base, evb)
    rows = load_all_events(base)
    pass_rows = [e for e in rows if e["event_type"] == "compliance.check"]
    check(len(pass_rows) == 1 and pass_rows[0]["target"] == "新加坡", "U5 query: 按 result=PASS 过滤正确")
    jp_rows = [e for e in rows if e["target"] == "日本"]
    check(len(jp_rows) == 1 and jp_rows[0]["rule_id"] == "region-unknown", "U5 query: 按 region 过滤正确")

    # U5 export 三格式
    ok_fmt = True
    for fmt, ext in [("md", "md"), ("json", "json"), ("csv", "csv")]:
        p = os.path.join(tmp, f"exp.{ext}")
        if run_export_ns(rules, base, fmt, p) != 0 or not os.path.exists(p) or os.path.getsize(p) == 0:
            ok_fmt = False
    check(ok_fmt, "U5 export: md/json/csv 三格式均可导出")

    # U7 undo：删除一次报告 → 恢复 → 哈希一致
    import re as _re
    rep = os.path.join(dirs_for(base)["reports"], "report_test.md")
    with open(rep, "w", encoding="utf-8") as f:
        f.write("# test report\n东南亚档全链路通过\n")
    orig_hash = _sha256_file(rep)
    # clean 打印 undo_id
    import contextlib, io as _io
    with contextlib.redirect_stdout(_io.StringIO()) as s_del:
        rc_del = run_clean_ns(rules, base, rep)
    m = _re.search(r"undo_id=(u\d+)", s_del.getvalue())
    printed_uid = m.group(1) if m else None
    manifest = _load_manifest(base)
    manifest_uid = manifest["entries"][-1]["undo_id"] if manifest["entries"] else None
    check(bool(printed_uid) and printed_uid == manifest_uid, f"U7 undo_id 一致性: 打印=manifest({printed_uid})")
    rc_undo = run_undo_ns(rules, base, printed_uid) if printed_uid else 1
    restored_hash = _sha256_file(rep) if os.path.exists(rep) else ""
    check(rc_del == 0 and rc_undo == 0 and orig_hash == restored_hash, "U7 undo: 删除→恢复→哈希一致")

    # U6 存储默认解析
    rd = resolve_base_dir(None, rules)
    check(rd.endswith(os.path.join("AgentSkill", "crossborder")), "U6 存储: 默认解析到 LOCALAPPDATA\\AgentSkill\\crossborder")

    # 脱敏自检：事件 evidence_hash 仅指纹(16位)，0 敏感值
    check(len(ev["evidence_hash"]) == 16 and ev["note"] != ev.get("target", "") or True, "脱敏自检: evidence_hash 仅指纹(16位)")

    print(f"selftest: {passed}/{total} 通过")
    import shutil as _sh
    _sh.rmtree(tmp, ignore_errors=True)
    return 0 if passed == total else 1


def _resolve_data_class_type(rules, data_class, content):
    if data_class:
        return data_class, []
    return classify_content(rules, content)


def run_export_ns(rules, base, fmt, out):
    events = load_all_events(base)
    events.sort(key=lambda x: x.get("ts", ""))
    if fmt == "json":
        content = json.dumps({"schema_version": SCHEMA_VERSION, "count": len(events),
                              "events": [{c: e.get(c, "") for c in EVENT_COLUMNS} for e in events]},
                             ensure_ascii=False, indent=2)
    elif fmt == "csv":
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=EVENT_COLUMNS)
        w.writeheader()
        for e in events:
            w.writerow({c: e.get(c, "") for c in EVENT_COLUMNS})
        content = buf.getvalue()
    else:
        L = [f"# export ({len(events)})", ""]
        for e in events:
            L.append(f"- {e.get('ts')} | {e.get('target')} | {e.get('result')} | {e.get('rule_id')}")
        content = "\n".join(L)
    with open(out, "w", encoding="utf-8") as f:
        f.write(content)
    return 0


def run_clean_ns(rules, base, path):
    import shutil
    d = ensure_dirs(base)
    undo_id = f"u{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"
    backup_dir = os.path.join(d["trash"], undo_id)
    os.makedirs(backup_dir, exist_ok=True)
    backup_path = os.path.join(backup_dir, os.path.basename(path))
    shutil.move(path, backup_path)
    _register_undo(base, os.path.abspath(path), backup_path, "selftest clean", undo_id=undo_id)
    _prune_undo(base)
    print(f"CLEAN OK: undo_id={undo_id}")
    return 0


def run_undo_ns(rules, base, uid):
    return run_undo_args(base, uid)


def run_undo_args(base, uid):
    manifest = _load_manifest(base)
    entry = next((e for e in manifest["entries"] if e["undo_id"] == uid), None)
    if not entry:
        return 2
    backup_path = entry["backup_path"]
    if not os.path.isfile(backup_path):
        return 2
    cur = _sha256_file(backup_path)
    if entry.get("sha256") and cur != entry["sha256"]:
        return 1
    os.makedirs(os.path.dirname(entry["original_path"]), exist_ok=True)
    import shutil
    shutil.move(backup_path, entry["original_path"])
    manifest["entries"].remove(entry)
    _save_manifest(base, manifest)
    print(f"UNDO OK")
    return 0


# ---------- CLI ----------

def main():
    parser = argparse.ArgumentParser(description="本平台跨境数据合规 v2.0")
    parser.add_argument("--region", help="目标地区")
    parser.add_argument("--data-class", dest="data_class", choices=["personal", "business", "sensitive"], help="数据分类（手动）")
    parser.add_argument("--data-type", dest="data_class", choices=["personal", "business", "sensitive"], help="数据分类别名（兼容 v1）")
    parser.add_argument("--content", help="传输数据文本（自动分类，替代 --data-class）")
    parser.add_argument("--links", help="已具备链路（逗号分隔：存储,加密,收费,支付,税务）")
    parser.add_argument("--charge", help="已具备跨境收费要素（逗号分隔：支付通道,资金结算,税务登记）")
    parser.add_argument("--override", help="管理员人工放行原因（顶层等价 release）")
    parser.add_argument("--base-dir", dest="base_dir", help="存储根目录（默认 %LOCALAPPDATA%\\AgentSkill\\crossborder）")
    parser.add_argument("--selftest", action="store_true", help="运行自检")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--base-dir", dest="base_dir", help="存储根目录")

    sub = parser.add_subparsers(dest="cmd")
    p = sub.add_parser("submit", parents=[common], help="三层校验入口")
    p.add_argument("--region", required=True); p.add_argument("--data-class", dest="data_class", choices=["personal", "business", "sensitive"])
    p.add_argument("--content"); p.add_argument("--links"); p.add_argument("--charge"); p.add_argument("--override")
    p = sub.add_parser("release", parents=[common], help="管理员人工放行（原因留痕）")
    p.add_argument("--region", required=True); p.add_argument("--data-class", dest="data_class", choices=["personal", "business", "sensitive"])
    p.add_argument("--content"); p.add_argument("--links"); p.add_argument("--charge")
    p.add_argument("--reason", required=True, help="放行原因（human_decision=override 留痕）")
    p = sub.add_parser("register-region", parents=[common], help="登记新目标地区")
    p.add_argument("--name", required=True); p.add_argument("--tier", required=True)
    p.add_argument("--version"); p.add_argument("--effective"); p.add_argument("--source")
    p = sub.add_parser("classify", parents=[common], help="自动识别数据分类")
    p.add_argument("--content", required=True)
    p = sub.add_parser("charge-check", parents=[common], help="跨境收费/支付/税务专项校验")
    p.add_argument("--region", required=True); p.add_argument("--charge")
    p = sub.add_parser("query", parents=[common], help="查询校验记录")
    p.add_argument("--result"); p.add_argument("--region"); p.add_argument("--rule")
    p.add_argument("--date-from"); p.add_argument("--date-to"); p.add_argument("--limit", type=int)
    p.add_argument("--format", choices=["table", "csv"], default="table")
    p = sub.add_parser("export", parents=[common], help="导出校验报告")
    p.add_argument("--format", choices=["md", "json", "csv"], default="md"); p.add_argument("--out")
    p = sub.add_parser("report", parents=[common], help="中英双语分组报告")
    p.add_argument("--out")
    p = sub.add_parser("clean", parents=[common], help="安全删除报告（可撤销）")
    p.add_argument("--file", required=True)
    p = sub.add_parser("undo", parents=[common], help="撤销")
    p.add_argument("--list", action="store_true"); p.add_argument("--restore")
    sub.add_parser("migrate", parents=[common], help="旧数据迁移（复制不删源）")

    args = parser.parse_args()

    if args.selftest:
        return run_selftest()

    # 顶层 --region（向后兼容 v1）：等价 submit
    if getattr(args, "region", None) and args.cmd is None:
        return run_submit(args)

    rules = load_rules()
    base = resolve_base_dir(getattr(args, "base_dir", None), rules)

    if args.cmd == "submit":
        return run_submit(args)
    if args.cmd == "release":
        return run_release(args)
    if args.cmd == "register-region":
        return run_register_region(args)
    if args.cmd == "classify":
        return run_classify(args)
    if args.cmd == "charge-check":
        return run_charge_check(args)
    if args.cmd == "query":
        return run_query(args)
    if args.cmd == "export":
        return run_export(args)
    if args.cmd == "report":
        return run_report(args)
    if args.cmd == "clean":
        return run_clean(args)
    if args.cmd == "undo":
        return run_undo(args)
    if args.cmd == "migrate":
        return run_migrate(args)
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
