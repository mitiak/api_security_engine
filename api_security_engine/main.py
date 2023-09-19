from http.client import HTTPResponse
from typing import Callable, Awaitable, Any, Dict

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from api_security_engine.alert_handlers.log_alert_handler import LogAlertHandler
from api_security_engine.alert_handlers.slack_alert_handler import SlackAlertHandler
from api_security_engine.lib.engine import APISecurityEngine
from api_security_engine.lib.models import SecurityEngineRequest, ThreatSeverity
from api_security_engine.security_modules.ddos_module import DDOSModule
from api_security_engine.security_modules.enum_module import EnumerationModule
from api_security_engine.security_modules.payload_module import MaliciousPayloadModule

# FastAPI application
app = FastAPI()

# A configured instance of APISecurityEngine
security_engine = APISecurityEngine(
    modules=[
        DDOSModule("ddos_protection_module", max_requests=5, time_window=10),
        EnumerationModule("enumeration_mitigation", urls=["/api/user_login/"], delay=0.1),
        MaliciousPayloadModule("malicious_payload_finder", patterns=[r"qwerty"])
    ],
    alert_handlers=[
        LogAlertHandler(
            alert_severity=ThreatSeverity.low,
        ),
        SlackAlertHandler(
            alert_severity=ThreatSeverity.medium,
            webhook_url="https://hooks.slack.com/services/TEAM_ID/CHANNEL_ID/TOKEN",
        ),
    ]
)


async def set_request_body(request: Request, body: bytes) -> None:
    """
    Trying request.body() or request.json() inside the middleware for FASTAPI will hang.
    This is a known issue in Starlette documented below:
    https://github.com/tiangolo/fastapi/issues/394#issuecomment-883524819

    The function `set_request_body` sets the request body of an HTTP request.

    :param request: The `request` parameter is an instance of the `Request` class. It represents an HTTP request received by
    a server
    :type request: Request
    :param body: The `body` parameter is of type `bytes` and represents the request body data that you want to set for the
    given `request`
    :type body: bytes
    """
    async def receive() -> Dict[str, Any]:
        return {"type": "http.request", "body": body}

    request._receive = receive


async def get_request_body(request: Request) -> bytes:
    """
    Trying request.body() or request.json() inside the middleware for FASTAPI will hang.
    This is a known issue in Starlette documented below:
    https://github.com/tiangolo/fastapi/issues/394#issuecomment-883524819

    The function `get_request_body` is an asynchronous function that takes a `Request` object as input and returns the body
    of the request as bytes.

    :param request: The `request` parameter is of type `Request`. It represents an HTTP request received by the server
    :type request: Request
    :return: the request body as bytes.
    """
    body = await request.body()
    await set_request_body(request, body)
    return body


@app.middleware("http")
async def security_engine_middleware(
        request: Request,
        call_next: Callable[[Request], Awaitable[HTTPResponse]]
) -> HTTPResponse | JSONResponse:
    """
    The function implements a FastAPI middleware that uses ApiSecurityEngine to intercept, inspect, and either allow
    or block HTTP requests in real-time based on their content and pattern.

    :param request: The `request` parameter represents the incoming HTTP request received by the middleware. It contains
    information such as the request method, headers, URL, and body
    :type request: Request

    :param call_next: The `call_next` parameter is a callable that represents the next middleware or endpoint in the
    application's request-response cycle. It takes the current `Request` object as input and returns an `HTTPResponse` or
    `JSONResponse` object as output
    :type call_next: Callable[[Request], Awaitable[HTTPResponse]]
    :return: The middleware is returning either an HTTPResponse or a JSONResponse.
    """
    # Using the workaround to get tge request body
    request_body = await get_request_body(request)

    # Security engine is agnostic to web framework, therefore it uses a unified request type (SecurityEngineRequest)
    # that should be constructed for every web framework accordingly. Here we create a unified security engine
    # request from FastAPI request.
    # This is a simplified case, more request fields should be used for more detailed and effective threat detection.
    security_engine_request = SecurityEngineRequest(
        body=request_body.decode(),
        url=request.url.path,
    )

    # Evaluate the API Security Engine and block the request if threat is detected
    if await security_engine.is_threat_detected(security_engine_request):
        return JSONResponse(content={"error": "request blocked contains suspicious pattern"}, status_code=403)

    # Propagate the request in case no threat was found
    response = await call_next(request)
    return response


# Some example FastAPI endpoints


@app.post("/api/example-endpoint/")
async def log_request(request: Request) -> Any:
    return {"request_body": await request.body()}


@app.post("/api/user_login/")
async def user_login(request: Request) -> Any:
    return {"status": "OK"}


@app.get("/api/public-data")
async def public_data() -> Any:
    return {"data": "This is public data"}
