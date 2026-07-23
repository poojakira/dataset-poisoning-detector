# dataset-poisoning-detector

[![CI](https://github.com/poojakira/dataset-poisoning-detector/actions/workflows/ci.yml/badge.svg)](https://github.com/poojakira/dataset-poisoning-detector/actions/workflows/ci.yml)
[![Python >=3.10](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## MITRE ATT&CK v19 Coverage

This repository maps all security findings to [MITRE ATT&CK v19](https://attack.mitre.org/).

| Domain     | Tactics | Techniques | Sub-Techniques |
|------------|--------:|----------:|---------------:|
| Enterprise |      15 |       222 |            475 |
| Mobile     |      12 |      (see ATT&CK) | (see ATT&CK) |
| ICS        |      12 |      (see ATT&CK) | (see ATT&CK) |

**v19 Breaking Changes (2026-07):**
- **TA0005 renamed**: "Defense Evasion" → "Stealth"
- **TA0112 added**: "Defense Impairment" (new tactic, split from old TA0005)
- **17 techniques revoked** (auto-remapped via V19_REVOCATION_MAP)
- **48 new techniques** added (see CHANGELOG.md)

### Export ATT&CK Navigator Layer

```bash
python -m attack_mapping.reporter --output navigator_layer.json
```

Open in [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to visualize coverage. Layers generated with Navigator v4.9 format (attack: "19").

### Finding Schema

Every finding object includes:
```json
{
  "attack_mappings": [
    {
      "tactic_id":         "TA0001",
      "tactic_name":       "Initial Access",
      "technique_id":      "T1195",
      "technique_name":    "Supply Chain Compromise",
      "subtechnique_id":   "T1195.001",
      "subtechnique_name": "Compromise Software Dependencies and Development Tools",
      "domain":            "enterprise",
      "confidence":        0.85,
      "data_sources":      ["..."],
      "platforms":         ["..."],
      "url":               "https://attack.mitre.org/techniques/T1195/001/"
    }
  ]
}
```

### Dataset Poisoning Specific Mappings (v19)

| Finding Type | Techniques (v19) |
|--------------|------------------|
| backdoor_trigger_detected | T1195.001, T1565.001 |
| label_flipping_detected | T1565, T1499 |
| gradient_manipulation | T1565.003 |
| data_injection_detected | T1195, T1505 |
| distribution_shift_anomaly | T1565, T1027 |
| sleeper_agent_pattern | T1195.001, T1497, **T1688** |
| trojan_watermark_detected | T1027.002, T1565 |
| supply_chain_dataset_tampering | T1195.003 |
| mislabeling_campaign | T1565.001, T1036 |
| **anomaly_suppression** | **T1685**, **T1027** |

**New v19 additions in bold:** T1688 (Safe Mode Boot) for sleeper agent evasion. T1685 (Disable or Modify Tools) replaces T1562 for anomaly suppression as defense impairment.

### Measurable Claims

| Metric | Value | Evidence |
|--------|-------|----------|
| **Label-flip AUC (CIFAR-10)** | 0.94 | `tests/test_poisoning_roc.py` on CIFAR-10 10% flip |
| **Backdoor trigger AUC** | 0.91 | `tests/test_backdoor_auc.py` on BadNets triggers |
| **Spectral signature AUC** | 0.87 | `tests/test_spectral_roc.py` (improved from 0.53) |
| **Influence function AUC** | 0.84 | `tests/test_influence_roc.py` |
| **Test coverage** | 86% | `pytest --cov --cov-fail-under=80` |
| **ATT&CK v19 techniques mapped** | 10 unique | 10 finding types → 10 techniques (T1685, T1688) |
| **Eval runtime (CIFAR-10)** | < 30 s | `tests/benchmark_latency.py` |

### Migration from v18

See [MIGRATION_GUIDE.md](../attack-v19-core/MIGRATION_GUIDE.md) in attack-v19-core for full migration steps.

Key remappings:
- T1562, T1562.001, T1089, T1054 → T1685 (Disable or Modify Tools)
- T1070.001 → T1685.005 (Clear Windows Event Logs)
- T1070.002 → T1685.006 (Clear Linux/Mac Logs)
- T1534 → T1684.001 (Social Engineering: Impersonation)
- T1566.003 → T1684.002 (Social Engineering: Email Spoofing)