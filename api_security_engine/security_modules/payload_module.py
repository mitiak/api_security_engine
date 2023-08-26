import re
from typing import List, Optional

from api_security_engine.lib.security_module import APISecurityModule
from api_security_engine.lib.models import SecurityEngineRequest, ThreatSeverity, ThreatDetails


class MaliciousPayloadModule(APISecurityModule):
    def __init__(self, name: str, patterns: List[str]) -> None:
        """
        The function initializes an object with a name and a list of patterns, and compiles the patterns using regular
        expressions.

        :param name: The name parameter is a string that represents the name of the object being initialized
        :type name: str

        :param patterns: The `patterns` parameter is a list of strings. Each string represents a regular expression pattern
        that will be compiled using the `re.compile()` function. The resulting compiled patterns are stored in the
        `compiled_patterns` attribute of the object
        :type patterns: List[str]
        """
        super().__init__(name=name)
        self.compiled_patterns = [re.compile(pattern) for pattern in patterns]

    async def detect_threat(self, request: SecurityEngineRequest) -> Optional[ThreatDetails]:
        """
        The function `detect_threat` checks if a request body contains a malicious payload and returns threat details if
        found.

        This is a basic example and only detects specific patterns. Real payload detection modules
        would likely use more sophisticated techniques, including machine learning, and integration with threat
        intelligence sources.

        :param request: The `request` parameter is an instance of the `SecurityEngineRequest` class. It represents the
        request that needs to be checked for threats. It contains information such as the request body, headers, and other
        relevant details
        :type request: SecurityEngineRequest
        :return: an optional `ThreatDetails` object. If no threat is detected in the request body, it returns `None`.
        """
        # Handle the empty body
        if not request.body:
            return None

        # Evaluate the request body against thw compile patterns
        for compiled_pattern in self.compiled_patterns:
            if match := compiled_pattern.search(request.body):
                return ThreatDetails(
                    description=f"malicious payload found in request body. {match=}",
                    severity=ThreatSeverity.medium,
                )

        return None
