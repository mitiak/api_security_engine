import time
from unittest.mock import MagicMock

import pytest
from freezegun import freeze_time

from api_security_engine.security_modules.ddos_module import DDOSModule


@pytest.fixture
def ddos_module() -> DDOSModule:
    return DDOSModule("test_ddos_module", max_requests=3, time_window=60)


@pytest.mark.asyncio
async def test_no_threat_detected(ddos_module: DDOSModule) -> None:
    request = MagicMock()
    request.url = "/api/resource"

    # Make three requests within the time_window
    for _ in range(3):
        detected_threat = await ddos_module.detect_threat(request)
        assert not detected_threat


@pytest.mark.asyncio
async def test_threat_detected_exceeded_max_requests(ddos_module: DDOSModule) -> None:
    request = MagicMock()
    request.url = "/api/resource"

    # Simulate making more than max_requests in the specified time_window
    for _ in range(3):
        detected_threat = await ddos_module.detect_threat(request)
        assert not detected_threat

    detected_threat = await ddos_module.detect_threat(request)
    assert detected_threat


@pytest.mark.asyncio
async def test_no_threat_detected_different_urls(ddos_module: DDOSModule) -> None:
    request1 = MagicMock()
    request1.url = "/api/resource1"

    request2 = MagicMock()
    request2.url = "/api/resource2"

    # Make three requests for each URL within the time_window
    for _ in range(3):
        detected_threat = await ddos_module.detect_threat(request1)
        assert not detected_threat
        detected_threat = await ddos_module.detect_threat(request2)
        assert not detected_threat

    detected_threat = await ddos_module.detect_threat(request1)
    assert detected_threat
    detected_threat = await ddos_module.detect_threat(request2)
    assert detected_threat


@pytest.mark.asyncio
async def test_no_threat_detected_old_entries_removed(ddos_module: DDOSModule) -> None:
    request = MagicMock()
    request.url = "/api/resource"

    # Simulate adding old entries that fall outside the time_window
    old_time = time.time() - 120
    ddos_module.request_history["/api/resource"] = [old_time]

    detected_threat = await ddos_module.detect_threat(request)
    assert not detected_threat


@pytest.mark.asyncio
@freeze_time("2023-08-25 12:00:00")  # Replace with your desired time
async def test_no_threat_detected_after_time_window(ddos_module: DDOSModule) -> None:
    request = MagicMock()
    request.url = "/api/resource"

    # Make three requests within the time_window
    for _ in range(3):
        detected_threat = await ddos_module.detect_threat(request)
        assert not detected_threat

    # Freeze time to a point beyond the time_window
    with freeze_time("2023-08-25 13:01:00"):  # Time after 61 seconds
        for _ in range(3):
            detected_threat = await ddos_module.detect_threat(request)
            assert not detected_threat
