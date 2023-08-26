import time
from typing import Optional, Dict, List

from api_security_engine.lib.models import SecurityEngineRequest, ThreatSeverity, ThreatDetails
from api_security_engine.lib.security_module import APISecurityModule


class DDOSModule(APISecurityModule):
    def __init__(self, name: str, max_requests: int, time_window: int) -> None:
        """
        The function initializes an object with a name, maximum number of requests, time window, and an empty request
        history as a dictionary.

        :param name: The `name` parameter is a string that represents the name of the object being initialized
        :type name: str

        :param max_requests: The `max_requests` parameter represents the maximum number of requests that can be made
        within the specified time window
        :type max_requests: int

        :param time_window: The `time_window` parameter represents the duration of the time window in seconds in which
        the requests are tracked.
        :type time_window: int
        """
        super().__init__(name=name)
        self.max_requests = max_requests
        self.time_window = time_window
        self.request_history: Dict[str, List[float]] = {}

    async def detect_threat(self, request: SecurityEngineRequest) -> Optional[ThreatDetails]:
        """
        The function `detect_threat` checks if the number of requests for a given URL exceeds a specified limit within a
        time window and returns a threat details object if the limit is exceeded.
        This can help mitigate the impact of DDoS attacks by limiting the number of requests a potential attacker can make.

        This is a simplified example of a Python-based middleware system module that identify potential DDoS attacks
        using the rate limiting approach. Note that this is a basic example and not suitable for
        production use. A real-world system would require more advanced techniques and optimizations.

        :param request: The `request` parameter is an instance of the `SecurityEngineRequest` class. It contains information
        about the request being made, such as the URL being accessed
        :type request: SecurityEngineRequest
        :return: The function `detect_threat` returns an instance of `ThreatDetails` if the number of requests for a given
        URL exceeds the maximum allowed requests within a specified time window. Otherwise, it returns `None`.
        """
        url = request.url
        current_time = time.time()

        if url in self.request_history:
            url_history = self.request_history[url]

            # Remove older requests from the history
            url_history = [t for t in url_history if current_time - t <= self.time_window]

            # Compare the request count with the threshold
            if len(url_history) >= self.max_requests:
                return ThreatDetails(
                    severity=ThreatSeverity.low,
                    description=f"limit for {url=} exceeded {self.max_requests} requests in {self.time_window} sec",
                )

            # Add the current request time to history
            self.request_history[url] = url_history + [current_time]
        else:
            # Add the first request time to history
            self.request_history[url] = [current_time]

        return None
