import json
import pytest
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def malicious_osv_response():
    return json.loads((FIXTURES / "osv_responses" / "malicious_batch.json").read_text())


@pytest.fixture
def clean_osv_response():
    return json.loads((FIXTURES / "osv_responses" / "clean_batch.json").read_text())
