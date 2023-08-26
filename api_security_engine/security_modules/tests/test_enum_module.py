import pytest
import asyncio
from unittest.mock import MagicMock

from api_security_engine.security_modules.enum_module import EnumerationModule


@pytest.fixture
def enumeration_module() -> EnumerationModule:
    # Initialize the EnumerationModule class with appropriate values for testing
    return EnumerationModule("test_enum_module", delay=0.1, urls=["/api/resource"])


@pytest.mark.asyncio
async def test_no_threat_detected(enumeration_module: EnumerationModule) -> None:
    request = MagicMock()
    request.url = "/api/other_resource"

    detected_threat = await enumeration_module.detect_threat(request)
    assert not detected_threat


@pytest.mark.asyncio
async def test_threat_detected_delayed(enumeration_module: EnumerationModule) -> None:
    request = MagicMock()
    request.url = "/api/resource"

    # The delay should be triggered for this URL
    start_time = asyncio.get_event_loop().time()
    await enumeration_module.detect_threat(request)
    end_time = asyncio.get_event_loop().time()

    assert end_time - start_time >= 0.1  # The delay time


@pytest.mark.asyncio
async def test_threat_detected_not_delayed(enumeration_module: EnumerationModule) -> None:
    request = MagicMock()
    request.url = "/api/resource2"

    # The delay should be triggered for this URL
    start_time = asyncio.get_event_loop().time()
    await enumeration_module.detect_threat(request)
    end_time = asyncio.get_event_loop().time()

    assert end_time - start_time < 0.1  # The delay time


@pytest.mark.asyncio
async def test_threat_detected_custom_delay(enumeration_module: EnumerationModule) -> None:
    request = MagicMock()
    request.url = "/api/resource"

    enumeration_module.delay = 0.5  # Set a custom delay

    # The delay should be triggered with the custom delay
    start_time = asyncio.get_event_loop().time()
    await enumeration_module.detect_threat(request)
    end_time = asyncio.get_event_loop().time()

    assert end_time - start_time >= 0.5  # The custom delay time
