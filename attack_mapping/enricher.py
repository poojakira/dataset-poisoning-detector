"""
ATT&CK Enricher for dataset-poisoning-detector.
"""

from typing import Any

from attack_core.index import ATTACKIndex
from attack_core.models import ATTACKMapping


class ATTACKEnricher:
    def __init__(self, index: ATTACKIndex):
        self.index = index
        self._rule_table = {
            "backdoor_trigger_detected": ["T1195.001", "T1565.001"],
            "label_flipping_detected": ["T1565", "T1499"],
            "gradient_manipulation": ["T1565.003"],
            "data_injection_detected": ["T1195", "T1505"],
            "distribution_shift_anomaly": ["T1565", "T1027"],
            "sleeper_agent_pattern": ["T1195.001", "T1497", "T1688"],
            "trojan_watermark_detected": ["T1027.002", "T1565"],
            "supply_chain_dataset_tampering": ["T1195.003"],
            "mislabeling_campaign": ["T1565.001", "T1036"],
            "anomaly_suppression": ["T1685", "T1027"],
        }

    def enrich(
        self, finding_type: str, metadata: dict[str, Any]
    ) -> list[ATTACKMapping]:
        technique_ids = self._rule_table.get(finding_type, [])
        mappings = []
        for tid in technique_ids:
            tech = self.index.get(tid)
            if tech:
                tactic = self.index._tactics.get(
                    tech.tactic_ids[0] if tech.tactic_ids else "", None
                )
                mappings.append(
                    ATTACKMapping(
                        tactic_id=tech.tactic_ids[0] if tech.tactic_ids else "unknown",
                        tactic_name=tactic.name if tactic else "unknown",
                        technique_id=tech.attack_id,
                        technique_name=tech.name,
                        subtechnique_id=tech.attack_id
                        if tech.is_subtechnique
                        else None,
                        subtechnique_name=tech.name if tech.is_subtechnique else None,
                        domain=tech.domain,
                        confidence=metadata.get("confidence", 0.5),
                        data_sources=tech.data_sources,
                        platforms=tech.platforms,
                        url=tech.url,
                    )
                )
        return mappings
