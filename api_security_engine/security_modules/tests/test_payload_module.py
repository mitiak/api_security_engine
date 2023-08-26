from unittest.mock import MagicMock

import pytest

from api_security_engine.security_modules.payload_module import MaliciousPayloadModule


@pytest.fixture
def malicious_payload_module() -> MaliciousPayloadModule:
    # Initialize the MaliciousPayloadModule class with example patterns for testing
    return MaliciousPayloadModule(
        name="test_malicious_payload_module",
        patterns=[r'\b(?:malicious|evil)\b', r'\d{4}-\d{2}-\d{2}']
    )


@pytest.mark.asyncio
async def test_no_threat_detected_empty_body(malicious_payload_module: MaliciousPayloadModule) -> None:
    request = MagicMock()
    request.body = ""

    detected_threat = await malicious_payload_module.detect_threat(request)
    assert not detected_threat


@pytest.mark.asyncio
async def test_no_threat_detected_no_match(malicious_payload_module: MaliciousPayloadModule) -> None:
    request = MagicMock()
    request.body = "This is a regular request body."

    detected_threat = await malicious_payload_module.detect_threat(request)
    assert not detected_threat


@pytest.mark.asyncio
async def test_threat_detected_single_pattern(malicious_payload_module: MaliciousPayloadModule) -> None:
    request = MagicMock()
    request.body = "This is a malicious payload."

    detected_threat = await malicious_payload_module.detect_threat(request)
    assert detected_threat


@pytest.mark.asyncio
async def test_threat_detected_another_single_pattern(malicious_payload_module: MaliciousPayloadModule) -> None:
    request = MagicMock()
    request.body = "This is a 2023-08-25 regular request body."

    detected_threat = await malicious_payload_module.detect_threat(request)
    assert detected_threat


@pytest.mark.asyncio
async def test_threat_detected_multiple_patterns(malicious_payload_module: MaliciousPayloadModule) -> None:
    request = MagicMock()
    request.body = "This is a 2023-08-25 malicious payload."

    detected_threat = await malicious_payload_module.detect_threat(request)
    assert detected_threat
