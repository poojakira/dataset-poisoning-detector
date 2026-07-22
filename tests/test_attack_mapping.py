import pytest
from attack_core import ATTACKLoader, ATTACKIndex
from attack_mapping.enricher import ATTACKEnricher


@pytest.fixture
def enricher():
    loader = ATTACKLoader()
    index = ATTACKIndex(loader)
    return ATTACKEnricher(index)


class TestDatasetPoisoningEnricher:
    def test_backdoor_trigger(self, enricher):
        mappings = enricher.enrich("backdoor_trigger_detected", {"confidence": 0.9})
        technique_ids = [m.technique_id for m in mappings]
        assert "T1195.001" in technique_ids
        assert "T1565.001" in technique_ids

    def test_gradient_manipulation(self, enricher):
        mappings = enricher.enrich("gradient_manipulation", {"confidence": 0.8})
        technique_ids = [m.technique_id for m in mappings]
        assert "T1565.003" in technique_ids

    def test_supply_chain_tampering(self, enricher):
        mappings = enricher.enrich("supply_chain_dataset_tampering", {"confidence": 0.85})
        technique_ids = [m.technique_id for m in mappings]
        assert "T1195.003" in technique_ids