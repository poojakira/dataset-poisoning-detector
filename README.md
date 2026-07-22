## MITRE ATT&CK v19 Coverage

This repository maps all security findings to [MITRE ATT&CK v19](https://attack.mitre.org/).

| Domain     | Tactics | Techniques | Sub-Techniques |
|------------|--------:|----------:|---------------:|
| Enterprise |      15 |       222 |            475 |
| Mobile     |      12 |      (see ATT&CK) | (see ATT&CK) |
| ICS        |      12 |      (see ATT&CK) | (see ATT&CK) |

### Export ATT&CK Navigator Layer

```bash
python -m attack_mapping.reporter --output navigator_layer.json
```

Open in [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to visualize coverage.

### Finding Schema

Every finding object includes:
```json
{
  "attack_mappings": [
    {
      "tactic_id":         "TA0005",
      "tactic_name":       "Defense Evasion",
      "technique_id":      "T1195.001",
      "technique_name":    "Compromise Software Dependencies and Development Tools",
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

### Dataset Poisoning Specific Mappings

| Finding Type | Techniques |
|--------------|------------|
| backdoor_trigger_detected | T1195.001, T1565.001 |
| label_flipping_detected | T1565, T1499 |
| gradient_manipulation | T1565.003 |
| data_injection_detected | T1195, T1505 |
| distribution_shift_anomaly | T1565, T1027 |
| sleeper_agent_pattern | T1195.001, T1497 |
| trojan_watermark_detected | T1027.002, T1565 |
| supply_chain_dataset_tampering | T1195.003 |
| mislabeling_campaign | T1565.001, T1036 |