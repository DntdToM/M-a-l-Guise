import pytest
import os
import sys

# Add parent directory to path to allow imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from detector.interface import DetectorResult
from detector.synthetic_detector import SyntheticDetector
from detector.magic_adapter import MagicAdapter

@pytest.fixture
def dummy_pe_bytes():
    # A tiny dummy PE byte array
    return b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" * 10

def test_synthetic_detector_contract(dummy_pe_bytes):
    detector = SyntheticDetector()
    
    # Predict 1
    result1 = detector.predict(dummy_pe_bytes)
    assert isinstance(result1, DetectorResult)
    assert isinstance(result1.is_malware, bool)
    assert isinstance(result1.malware_prob, float)
    assert 0.0 <= result1.malware_prob <= 1.0
    
    # Predict 2 (Deterministic check)
    result2 = detector.predict(dummy_pe_bytes)
    assert result1.malware_prob == result2.malware_prob
    assert result1.is_malware == result2.is_malware

def test_magic_adapter_contract_schema(dummy_pe_bytes):
    # For now we only test schema/types if it doesn't raise NotImplementedError
    # We will test actual end-to-end MAGIC later
    adapter = MagicAdapter(magic_dir="detector/MAGIC")
    try:
        result = adapter.predict(dummy_pe_bytes)
        assert isinstance(result, DetectorResult)
        assert isinstance(result.is_malware, bool)
        assert isinstance(result.malware_prob, float)
        assert 0.0 <= result.malware_prob <= 1.0
    except NotImplementedError:
        pytest.skip("MAGIC model integration is not fully implemented yet.")
