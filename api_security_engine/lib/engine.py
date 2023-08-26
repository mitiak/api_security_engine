import logging
import time
from typing import List, Optional

from api_security_engine.lib.alert_handler import AlertHandler
from api_security_engine.lib.models import SecurityEngineRequest, SecurityEngineAlert
from api_security_engine.lib.security_module import APISecurityModule

logger = logging.getLogger("engine")


class APISecurityEngine:
    def __init__(
            self,
            modules: Optional[List[APISecurityModule]] = None,
            alert_handlers: Optional[List[AlertHandler]] = None,
    ) -> None:
        """
        The function initializes an object with optional parameters for modules and alert handlers.

        :param modules: The `modules` parameter is a list of `APISecurityModule` objects. It is an optional parameter,
        meaning it can be omitted when creating an instance of the class. If no value is provided, it defaults to an
        empty list
        :type modules: Optional[List[APISecurityModule]]

        :param alert_handlers: The `alert_handlers` parameter is a list of `AlertHandler` objects. It is an optional
        parameter, meaning it can be omitted when creating an instance of the class. If no value is provided for
        `alert_handlers`, an empty list will be assigned to `self.alert_handlers` in the `
        :type alert_handlers: Optional[List[AlertHandler]]
        """

        self.alert_handlers = alert_handlers or []
        self.modules: List[APISecurityModule] = modules or []

    async def is_threat_detected(self, request: SecurityEngineRequest) -> bool:
        """
        The function `is_threat_detected` iterates through a list of modules to detect threats in a security engine
        request, and if a threat is detected, it sends an alert to the alert handlers and returns True.

        Security engine is agnostic to web framework, therefore it uses a unified request type (SecurityEngineRequest)
        that should be constructed for every Python web framework accordingly.

        :param request: The `request` parameter is an instance of the `SecurityEngineRequest` class. It represents the
        request that needs to be checked for threats
        :type request: SecurityEngineRequest
        :return: a boolean value. If a threat is detected by any of the modules, the function will return True. If no
        threat is detected by any of the modules, the function will return False.
        """
        for module in self.modules:
            try:
                # Detect a threat
                if threat_details := await module.detect_threat(request):
                    detection_timestamp = time.time()

                    # Upon a detected threat, evaluate the registered alert handlers
                    for alert_handler in self.alert_handlers:
                        try:
                            await alert_handler.handle_alert_by_severity(
                                SecurityEngineAlert(
                                    request=request,
                                    module_name=module.name,
                                    timestamp=detection_timestamp,
                                    threat_details=threat_details,
                                )
                            )
                        except Exception:
                            # Log the exception and continue to the next alert handler in case of failure
                            logger.exception("Alert handler failed")
                    return True

            except Exception:
                # Log the exception and continue to the next security module in case of failure
                logger.exception("Threat detection failed")

        return False
