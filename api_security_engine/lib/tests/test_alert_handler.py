import pytest
from unittest.mock import MagicMock

from api_security_engine.lib.alert_handler import AlertHandler
from api_security_engine.lib.models import SecurityEngineAlert, ThreatSeverity, ThreatDetails


@pytest.fixture
def mock_alert() -> MagicMock:
    return MagicMock(spec=SecurityEngineAlert)


@pytest.fixture
def alert_handler() -> AlertHandler:
    return AlertHandler(alert_severity=ThreatSeverity.medium)


@pytest.mark.asyncio
async def test_handle_alert_by_severity_above_threshold(alert_handler: AlertHandler, mock_alert: MagicMock) -> None:
    mock_alert.threat_details = ThreatDetails(severity=ThreatSeverity.high)

    alert_handler.handle_alert = MagicMock()    # type: ignore
    await alert_handler.handle_alert_by_severity(mock_alert)

    alert_handler.handle_alert.assert_called_once_with(mock_alert)


@pytest.mark.asyncio
async def test_handle_alert_by_severity_below_threshold(alert_handler: AlertHandler, mock_alert: MagicMock) -> None:
    mock_alert.threat_details = ThreatDetails(severity=ThreatSeverity.low)

    alert_handler.handle_alert = MagicMock()    # type: ignore
    await alert_handler.handle_alert_by_severity(mock_alert)

    alert_handler.handle_alert.assert_not_called()


@pytest.mark.asyncio
async def test_handle_alert_by_severity_exact_threshold(alert_handler: AlertHandler, mock_alert: MagicMock) -> None:
    mock_alert.threat_details = ThreatDetails(severity=ThreatSeverity.medium)

    alert_handler.handle_alert = MagicMock()    # type: ignore
    await alert_handler.handle_alert_by_severity(mock_alert)

    alert_handler.handle_alert.assert_called_once_with(mock_alert)
