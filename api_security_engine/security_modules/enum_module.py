import asyncio
from typing import Optional, List

from api_security_engine.lib.security_module import APISecurityModule
from api_security_engine.lib.models import SecurityEngineRequest, ThreatDetails


class EnumerationModule(APISecurityModule):
    def __init__(self, name: str, delay: float = 0.1, urls: Optional[List[str]] = None) -> None:
        """
        The function initializes an object with a name, delay, and a list of URLs, with default values for delay and an
        empty list for URLs.

        :param name: The `name` parameter is a string that represents the name of the object being initialized
        :type name: str

        :param delay: The `delay` parameter is a float that represents the delay in seconds between each request made by the
        code. It is set to a default value of 0.1 seconds if no value is provided when creating an instance of the class
        :type delay: float

        :param urls: The `urls` parameter is a list of strings that represents a collection of URLs. It is an optional
        parameter, meaning that it can be omitted when creating an instance of the class. If no value is provided for
        `urls`, it defaults to an empty list (`[]`)
        :type urls: Optional[List[str]]
        """
        super().__init__(name=name)
        self.urls = urls or []
        self.delay = delay

    async def detect_threat(self, request: SecurityEngineRequest) -> Optional[ThreatDetails]:
        """
        The function introduces a slight delay for predefined URLs

        Enumeration attacks involve attempting to gather information about valid usernames, emails, or other sensitive
        data through a web application. Protecting against enumeration attacks can be done using a middleware that
        introduces a slight delay in response time for invalid requests. This delay is negligible for legitimate users
        but can slow down an attacker trying to enumerate valid entries.

        This is a basic example to demonstrate the concept. In practice, you would likely use more sophisticated
        techniques and integrate with security tools to protect against enumeration attacks.

        :param request: The `request` parameter is an instance of the `SecurityEngineRequest` class. It contains
        information about the request being made, such as the URL being accessed
        :type request: SecurityEngineRequest
        :return: `None`.
        """
        url = request.url
        if url in self.urls:
            # Introduce a slight delay
            await asyncio.sleep(self.delay)

        return None
