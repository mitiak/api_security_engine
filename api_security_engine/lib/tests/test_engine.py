from unittest.mock import AsyncMock, MagicMock

import pytest

from api_security_engine.lib.alert_handler import AlertHandler
from api_security_engine.lib.engine import APISecurityEngine
from api_security_engine.lib.models import SecurityEngineRequest, ThreatDetails, ThreatSeverity
from api_security_engine.lib.security_module import APISecurityModule


@pytest.fixture
def mock_security_module() -> AsyncMock:
    return AsyncMock(spec=APISecurityModule)


@pytest.fixture
def mock_alert_handler() -> MagicMock:
    return MagicMock(spec=AlertHandler)


@pytest.fixture
def api_security_engine(mock_security_module: APISecurityModule, mock_alert_handler: AlertHandler) -> APISecurityEngine:
    modules = [mock_security_module]
    alert_handlers = [mock_alert_handler]
    return APISecurityEngine(modules=modules, alert_handlers=alert_handlers)


@pytest.mark.asyncio
async def test_is_threat_detected_no_threat(
        api_security_engine: APISecurityEngine,
        mock_security_module: AsyncMock,
        mock_alert_handler: MagicMock
) -> None:
    mock_security_module.detect_threat.return_value = None

    request = SecurityEngineRequest(body="body", url="/api/resource")
    result = await api_security_engine.is_threat_detected(request)

    assert result is False
    mock_security_module.detect_threat.assert_called_once_with(request)
    mock_alert_handler.assert_not_called()


@pytest.mark.asyncio
async def test_is_threat_detected_with_threat(
        api_security_engine: APISecurityEngine,
        mock_security_module: AsyncMock,
        mock_alert_handler: MagicMock
) -> None:
    mock_security_module.detect_threat.return_value = ThreatDetails(severity=ThreatSeverity.medium)
    mock_security_module.name = "test_module"

    request = SecurityEngineRequest(body="body", url="/api/resource")
    result = await api_security_engine.is_threat_detected(request)

    assert result is True
    mock_security_module.detect_threat.assert_called_once_with(request)
    mock_alert_handler.handle_alert_by_severity.assert_called_once()


@pytest.mark.asyncio
async def test_is_threat_detected_exception(
        api_security_engine: APISecurityEngine,
        mock_security_module: AsyncMock,
        mock_alert_handler: MagicMock
) -> None:
    mock_security_module.detect_threat.side_effect = Exception("Error")

    request = SecurityEngineRequest(body="body", url="/api/resource")
    result = await api_security_engine.is_threat_detected(request)

    assert result is False
    mock_security_module.detect_threat.assert_called_once_with(request)
    mock_alert_handler.assert_not_called()
