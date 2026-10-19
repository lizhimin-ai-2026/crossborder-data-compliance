---
name: crossborder-data-compliance
description: Cross-border data compliance gate (agent skill). Three-layer validation — target region regulation (versioned regulation library, conclusions traceable to a specific version) + data classification engine (auto-detects ID/biometric/payment/credential as sensitive; zero cross-border for sensitive data) + transmission link completeness (storage/encryption/charge/payment/tax, missing any is CRIT BLOCK), plus a dedicated cross-border charge/payment/tax check (charge-check), human final release (release with recorded reason), CleanKeeper undo, and bilingual compliance reports. Triggers: overseas check, cross-border compliance, data export, charge-check, register-region. Python 3.11+ standard library, no third-party dependencies.
---

# Cross-border Data Compliance (crossborder-data-compliance) v2.0

## Overview

A pre-departure compliance gate for cross-border data storage and transmission. Ensures data handling aligns with the target region's data protection laws before any outbound transfer or overseas feature launch.

**Core principle**: three-layer validation (target region regulation → data classification → transmission link) + two market tiers (Southeast Asia / English-speaking) + dedicated cross-border charge/payment/tax check + versioned regulation library + data classification engine + undo + dual-channel interface.

## Use cases

- Overseas feature launch (auto-triggered)
- Cross-border data transmission (triggered before transfer)
- Cross-border charge / payment / tax (in validation scope)
- Human final review & release

## Three-layer + dedicated validation

```
Overseas feature launch / cross-border data transfer
      │ trigger
      ▼
┌──────────────────────────────┐
│  Cross-border Compliance Gate │
│  ① Target region regulation   │
│  ② Data classification        │
│  ③ Transmission link          │
│  ④ Charge/payment/tax check   │
│  → PASS / RISK / BLOCK        │
└──────────────────────────────┘
```

| Layer | Checks | Result |
|---|---|---|
| ① Region regulation | Target market ∈ tiers, known regulation version | Unregistered region → BLOCK (CRIT) |
| ② Data classification | classify: PII / business / sensitive | Sensitive → RISK |
| ③ Transmission link | storage / encryption / charge / payment / tax | Missing any → BLOCK (CRIT) |
| ④ Charge/payment/tax | payment channel / settlement / tax registration | Missing → BLOCK |

## Two market tiers (versioned, traceable)

| Tier | Covers | Requirement | Example version |
|---|---|---|---|
| SE Asia | Singapore / Malaysia / Thailand / Vietnam / Indonesia / Philippines | Local data law + localization | Singapore PDPA-SG-2021 |
| English | Europe / UK / US / Canada / Australia | Higher bar (GDPR-like) + cross-border pay/tax | Europe GDPR-EU-2018 |

> Each region record carries `version` + `effective` + `source` (legal basis). A validation conclusion is traceable to the exact regulation version.

## Data classification engine (classify)

- Auto-detects ID document / biometric / payment info / credentials (sensitive) → `sensitive`
- Detects contact / name (personal) → `personal`
- Everything else → `business`
- **Zero cross-border for sensitive data**: a hit → `compliance.risk(data-class, WARN)` + advisory; not released without assessment + human confirmation.
- **Redaction**: classification outputs only label + legal basis, never the sensitive value.

## Cross-border charge / payment / tax (charge-check)

- `charge-check` validates payment channel availability (region-available providers), fund settlement & FX compliance, tax registration/number; each PASS/BLOCK.
- `charge_policy` records the payment-provider selection principle (choose by region availability & compliance) and refund/trial policy (set per region consumer-rights requirements and disclose). This package only validates the compliance surface, it does not decide pricing.

## Red lines

1. **Unregistered region not released**: target region outside tiers (or unregistered) → BLOCK (CRIT); release needs human confirmation with reason.
2. **Data classification first**: must label data class before transfer; sensitive data zero cross-border (unless assessed + human-confirmed).
3. **Link completeness**: storage + encryption + charge/payment/tax missing any → BLOCK (CRIT).
4. **Human final review**: AI only validates; release needs human confirmation (human_decision=override + reason).
5. **Key red line**: API keys / payment secrets are filled only by the operator; AI must not open, read, or scan any key file or cloud key config.
6. **No tampering with core data**: does not modify any production database; events are append-only.
7. **No background jobs**: no unattended background tasks or scheduled auto-deploy.
8. **Redaction**: classification outputs only label + basis, 0 sensitive values; reports 0 sensitive values.

## Rules & scripts

- `assets/crossborder_rules.json`: tiers (versioned) / data classification / link requirements / charge_policy (recomputable, 0 hardcoding)
- `assets/scripts/crossborder_check.py`: three-layer + classify + charge-check + dual-channel core
- Records written to `%LOCALAPPDATA%\AgentSkill\crossborder\events\crossborder_events.csv` (16-column contract) and ingested into the audit log

## Dual-channel interface (voice + click)

- Wake word: "Crossborder"; voice commands: "Crossborder, overseas check <region> <data>" → submit; "Crossborder, release cross-border <region> <reason>" → release
- Click entry: Overseas Center → Cross-border Compliance → start check / view records
- Authorization consistent: voice ≡ click; unregistered region / link gap default BLOCK; human release needs operator confirmation with reason

## CLI quick reference

```bash
python crossborder_check.py --region Singapore --data-class business --links storage,encryption,charge,payment,tax
python crossborder_check.py --region Singapore --content "<transfer text>" --links storage,encryption,charge,payment,tax
python crossborder_check.py submit / release / classify / charge-check / register-region / query / export / report / clean / undo / migrate
python crossborder_check.py --selftest
```
