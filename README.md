# API Security Engine

The API Security Engine is a Python-based middleware designed to monitor, analyze, and potentially block incoming API requests based on identified risks. This system is designed to be seamlessly integrated into the request-response flow of web APIs, functioning as a middleware layer. It can intercept, inspect, and either allow or block HTTP requests in real time based on their content and patterns.

As an example, the project demonstrates API Security Engine implementation in FastAPI Python framework.    

## Features

- Real-time monitoring of incoming API requests.
- Detection and prevention of potential DDoS attacks.
- Protection against enumeration attacks.
- Identification of malicious payloads and patterns.
- Middleware integration into various web frameworks.

## Installation (Docker)

1. Navigate to project root
2. Build docker image
```bash
docker build -t apisec-engine-fastapi-app .
```
3. Run FastAPI app with integrated API Security Engine in a Docker container
```bash
docker run -p 9999:9999 --name apisec-engine-fastapi-app apisec-engine-fastapi-app
```

## Installation (Poetry)

1. Install poetry (https://python-poetry.org/docs/#installation)
```bash
pip install poetry
```
2. Navigate to project root
3. Install poetry dependencies
```bash
poetry install
```
4. Run FastAPI app with integrated API Security Engine in Potery environment
```bash
poetry uvicorn api_security_engine.main:app --host 0.0.0.0 --port 9999
```

## Running Tests (Docker)

1. Run application docker container ("apisec-engine-fastapi-app")
2. Run unit tests suite from Poetry environment
```bash
docker exec -it apisec-engine-fastapi-app poetry run pytest
```

## Running Tests (Poetry)

1. Navigate to project root
2. Run unit tests suite from Poetry environment
```bash
poetry run pytest
```

## Usage 

Sending a simple valid request
```bash
curl -X POST http://localhost:9999/api/example-endpoint/ -d '{"key": "abcde"}' -H "Content-Type: application/json"
```

Detecting Malicious Pattern ("qwerty")
```bash
curl -X POST http://localhost:9999/api/example-endpoint/ -d '{"key": "qwerty"}' -H "Content-Type: application/json"
```

Detecting and blocking DDOS Attack
```bash
url="http://localhost:9999/api/example-endpoint/"
data='{"key": "abcde"}'
headers="Content-Type: application/json"

for i in {1..10}; do
    echo "Sending request $i"
    curl -X POST "$url" -d "$data" -H "$headers"
    echo ""
done
```
