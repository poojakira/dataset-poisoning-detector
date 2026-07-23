from attack_core import ATTACKLoader, ATTACKIndex
from attack_mapping.enricher import ATTACKEnricher
from attack_mapping.reporter import NavigatorLayerReporter

loader = ATTACKLoader()
index = ATTACKIndex(loader)
enricher = ATTACKEnricher(index)
reporter = NavigatorLayerReporter()

all_mappings = []
for ft in ['backdoor_trigger_detected', 'label_flipping_detected', 'gradient_manipulation', 'data_injection_detected', 'distribution_shift_anomaly', 'sleeper_agent_pattern', 'trojan_watermark_detected', 'supply_chain_dataset_tampering', 'mislabeling_campaign']:
    mappings = enricher.enrich(ft, {'confidence': 0.8})
    all_mappings.extend(mappings)

layer = reporter.generate('dataset-poisoning-detector', all_mappings)
import json
data = json.loads(layer)
print(f'Techniques mapped: {len(data["techniques"])}')
for t in data['techniques']:
    print(f'  {t["techniqueID"]}: score={t["score"]}')