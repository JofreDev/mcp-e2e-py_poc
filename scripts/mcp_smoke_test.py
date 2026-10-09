"""Exercise the complete agent authentication and MCP tool-call flow."""

import argparse
import json
import os
import sys
from http.client import HTTPConnection
from uuid import uuid4


def request_json(
    host: str,
    port: int,
    path: str,
    payload: dict[str, object],
    headers: dict[str, str],
) -> tuple[int, dict[str, str], object]:
    connection = HTTPConnection(host, port, timeout=15)
    try:
        connection.request(
            "POST",
            path,
            body=json.dumps(payload),
            headers=headers,
        )
        response = connection.getresponse()
        response_headers = {name.lower(): value for name, value in response.getheaders()}
        body = response.read().decode()
    finally:
        connection.close()

    if not body:
        return response.status, response_headers, None
    if response_headers.get("content-type", "").startswith("text/event-stream"):
        data = next(
            (line.removeprefix("data: ") for line in body.splitlines() if line.startswith("data: ")),
            None,
        )
        if data is None:
            raise RuntimeError("MCP returned an empty event stream")
        return response.status, response_headers, json.loads(data)
    return response.status, response_headers, json.loads(body)


def require_success(status: int, response: object) -> dict[str, object]:
    if not 200 <= status < 300 or not isinstance(response, dict):
        raise RuntimeError(f"Request failed with HTTP {status}: {response}")
    return response


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--amount", type=float, default=10)
    parser.add_argument("--from-currency", default="EUR")
    parser.add_argument("--to-currency", default="USD")
    parser.add_argument("--date")
    parser.add_argument("--actor-type", choices=("agent", "human"), default="agent")
    arguments = parser.parse_args()
    auth_port = int(os.getenv("AUTH_SERVICE_PORT", "8000"))
    mcp_port = int(os.getenv("MCP_SERVICE_PORT", "8001"))

    identifier = f"smoke-{uuid4().hex[:12]}"
    if arguments.actor_type == "agent":
        registration_path = "/api/v1/auth/agents/register"
        registration_payload = {"username": identifier, "password": "smoke-password"}
    else:
        registration_path = "/api/v1/auth/humans/register"
        identifier = f"{identifier}@example.com"
        registration_payload = {"email": identifier, "password": "smoke-password"}

    json_headers = {"Content-Type": "application/json"}
    status, _, response = request_json(
        "127.0.0.1", auth_port, registration_path, registration_payload, json_headers
    )
    require_success(status, response)
    status, _, response = request_json(
        "127.0.0.1",
        auth_port,
        "/api/v1/auth/login",
        {
            "actor_type": arguments.actor_type,
            "identifier": identifier,
            "password": "smoke-password",
        },
        json_headers,
    )
    token_response = require_success(status, response)
    access_token = token_response["access_token"]
    if not isinstance(access_token, str):
        raise RuntimeError("Authentication service did not return an access token")

    mcp_headers = {
        "Accept": "application/json, text/event-stream",
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    tool_arguments: dict[str, object] = {
        "amount": arguments.amount,
        "from_currency": arguments.from_currency,
        "to_currency": arguments.to_currency,
    }
    if arguments.date is not None:
        tool_arguments["date"] = arguments.date
    status, _, response = request_json(
        "127.0.0.1",
        mcp_port,
        "/mcp",
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "convert_currency", "arguments": tool_arguments},
        },
        mcp_headers,
    )
    print(json.dumps(require_success(status, response), indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError) as error:
        print(f"Smoke test failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
