from typing import Optional

from api_security_engine.lib.models import SecurityEngineRequest, ThreatDetails


class APISecurityModule:
    def __init__(self, name: str) -> None:
        """
        The `APISecurityModule` class is responsible for asynchronously detecting API threats in a security engine and
        returning threat details if a threat is found.
        The above function is a constructor that initializes an object with a given name.

        :param name: The `name` parameter is a string that represents the name of an object
        :type name: str
        """
        self.name = name

    async def detect_threat(self, request: SecurityEngineRequest) -> Optional[ThreatDetails]:
        """
        The function `detect_threat` asynchronously detects API threats in a security engine and returns threat
        details in case a threat was found, otherwise None.

        :param request: The `request` parameter is an instance of the `SecurityEngineRequest` class. It represents the
        request that needs to be analyzed for potential threats
        :type request: SecurityEngineRequest
        """
        ...
