# Cross-border Data Compliance (lanzhi-crossborder) v2.0

A pre-departure compliance gate for cross-border data storage and transmission. Ensures data handling aligns with the target region's data protection laws.

## Core capabilities

- **Three-layer validation**: target region regulation (versioned) → data classification (auto) → transmission link (storage+encryption+charge/payment/tax, missing any → CRIT)
- **Versioned regulation library**: each region carries version / effective / source; conclusions traceable to the exact version
- **Data classification engine**: auto-detect sensitive (ID/biometric/payment/credential) → personal → business; zero cross-border for sensitive
- **Cross-border charge/payment/tax check**: charge-check per-item PASS/BLOCK
- **Dual-channel interface**: voice + click (submit / release / classify / charge-check / query / export / report / undo)
- **Human final review**: AI only validates; release needs operator confirmation
- **Undo protection**: report deletion goes through a trash area, restorable
- **Audit ingestion**: 16-column contract events ingested into the audit log

## Structure

```
lanzhi-crossborder/
├── SKILL.md
├── README.md
├── LICENSE.md
├── assets/
│   ├── crossborder_rules.json
│   └── scripts/
│       └── crossborder_check.py
```

## Usage

```bash
python crossborder_check.py --region <region> --data-class <personal|business|sensitive> \
    --links storage,encryption,charge,payment,tax [--override <reason>]
python crossborder_check.py --region <region> --content "<transfer text>" --links storage,encryption,charge,payment,tax
python crossborder_check.py submit / release / classify / charge-check / register-region / query / export / report / clean / undo / migrate
python crossborder_check.py --selftest
```

## Result

| Result | Meaning | Action |
|---|---|---|
| PASS | three-layer pass | release |
| RISK | sensitive data cross-border | needs assessment + human confirmation |
| BLOCK | unregistered region / link gap / charge-tax gap | BLOCK (CRIT) |

## Red lines

Unregistered region not released / data classification first (zero cross-border for sensitive) / link completeness / human final review / 0 sensitive values on disk.

## Version

- v2.0.0 (2026-10-19): versioned regulation library + data classification engine + link completeness hardening + charge-check + dual-channel interface + storage migration + undo + 24-case selftest
