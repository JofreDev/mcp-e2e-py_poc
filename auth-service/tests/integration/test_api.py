from collections.abc import Iterator
from pathlib import Path

import jwt
import pytest
from fastapi.testclient import TestClient

from auth_service.app import create_app
from auth_service.config import Settings


@pytest.fixture(scope="module")
def client(tmp_path_factory: pytest.TempPathFactory) -> Iterator[TestClient]:
    database_path = Path(tmp_path_factory.mktemp("database")) / "auth.db"
    settings = Settings(
        jwt_secret="integration-test-secret-with-at-least-32-bytes",
        database_url=f"sqlite+aiosqlite:///{database_path}",
        auto_create_schema=True,
        bootstrap_admin_email="admin@example.com",
        bootstrap_admin_password="admin-password",
    )
    with TestClient(create_app(settings)) as test_client:
        yield test_client


def register_human(client: TestClient, email: str, password: str = "password") -> None:
    response = client.post(
        "/api/v1/auth/humans/register",
        json={"email": email, "password": password},
    )
    assert response.status_code == 201, response.text


def login(
    client: TestClient,
    actor_type: str,
    identifier: str,
    password: str = "password",
) -> dict[str, str]:
    response = client.post(
        "/api/v1/auth/login",
        json={
            "actor_type": actor_type,
            "identifier": identifier,
            "password": password,
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_health_check(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_human_registration_login_and_validation(client: TestClient) -> None:
    register_human(client, "person@example.com")

    tokens = login(client, "human", "PERSON@example.com")
    response = client.get(
        "/api/v1/auth/validate",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["active"] is True
    assert payload["principal"]["identifier"] == "person@example.com"
    assert payload["principal"]["actor_type"] == "human"
    assert payload["admin"] is False
    assert payload["permissions"] == ["profile:read"]


def test_agent_registration_and_token_claims(client: TestClient) -> None:
    response = client.post(
        "/api/v1/auth/agents/register",
        json={"username": "REPORT-Agent", "password": "password"},
    )
    assert response.status_code == 201
    assert response.json()["identifier"] == "report-agent"

    tokens = login(client, "agent", "report-agent")
    claims = jwt.decode(tokens["access_token"], options={"verify_signature": False})
    refresh_claims = jwt.decode(tokens["refresh_token"], options={"verify_signature": False})

    assert claims["actor_type"] == "agent"
    assert claims["admin"] is False
    assert claims["permissions"] == ["fx:read", "profile:read"]
    assert claims["aud"] == "mcp-api"
    assert "admin" not in refresh_claims
    assert "permissions" not in refresh_claims


def test_bootstrap_administrator_has_admin_permissions(client: TestClient) -> None:
    tokens = login(client, "human", "admin@example.com", "admin-password")
    response = client.get(
        "/api/v1/auth/validate",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["admin"] is True
    assert "users:read" in payload["permissions"]
    assert "agents:create" in payload["permissions"]


def test_refresh_rotation_and_reuse_detection(client: TestClient) -> None:
    register_human(client, "rotation@example.com")
    original = login(client, "human", "rotation@example.com")

    refresh_response = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": original["refresh_token"]},
    )
    assert refresh_response.status_code == 200
    rotated = refresh_response.json()
    assert rotated["refresh_token"] != original["refresh_token"]

    reuse_response = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": original["refresh_token"]},
    )
    assert reuse_response.status_code == 401
    assert reuse_response.json()["error"]["code"] == "invalid_token"

    validation_response = client.get(
        "/api/v1/auth/validate",
        headers={"Authorization": f"Bearer {rotated['access_token']}"},
    )
    assert validation_response.status_code == 401


def test_logout_immediately_revokes_access_token(client: TestClient) -> None:
    register_human(client, "logout@example.com")
    tokens = login(client, "human", "logout@example.com")

    logout_response = client.post(
        "/api/v1/auth/logout",
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert logout_response.status_code == 204
    assert logout_response.content == b""

    validation_response = client.get(
        "/api/v1/auth/validate",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert validation_response.status_code == 401
    assert validation_response.headers["www-authenticate"] == "Bearer"


def test_duplicate_registration_returns_conflict(client: TestClient) -> None:
    register_human(client, "duplicate@example.com")

    response = client.post(
        "/api/v1/auth/humans/register",
        json={"email": "DUPLICATE@example.com", "password": "password"},
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "principal_already_exists"


@pytest.mark.parametrize(
    ("password", "expected_status"),
    [
        ("x" * 7, 422),
        ("x" * 8, 201),
        ("x" * 128, 201),
        ("x" * 129, 422),
    ],
)
def test_password_length_boundaries(
    client: TestClient, password: str, expected_status: int
) -> None:
    response = client.post(
        "/api/v1/auth/humans/register",
        json={"email": f"boundary-{len(password)}@example.com", "password": password},
    )

    assert response.status_code == expected_status


def test_invalid_credentials_do_not_reveal_identity_existence(client: TestClient) -> None:
    register_human(client, "credentials@example.com")
    existing_response = client.post(
        "/api/v1/auth/login",
        json={
            "actor_type": "human",
            "identifier": "credentials@example.com",
            "password": "wrong-password",
        },
    )
    missing_response = client.post(
        "/api/v1/auth/login",
        json={
            "actor_type": "human",
            "identifier": "missing@example.com",
            "password": "wrong-password",
        },
    )

    assert existing_response.status_code == missing_response.status_code == 401
    assert existing_response.json() == missing_response.json()


def test_validate_requires_bearer_access_token(client: TestClient) -> None:
    missing_response = client.get("/api/v1/auth/validate")
    assert missing_response.status_code == 401

    register_human(client, "wrong-token@example.com")
    tokens = login(client, "human", "wrong-token@example.com")
    wrong_type_response = client.get(
        "/api/v1/auth/validate",
        headers={"Authorization": f"Bearer {tokens['refresh_token']}"},
    )
    assert wrong_type_response.status_code == 401


def test_request_rejects_unexpected_fields(client: TestClient) -> None:
    response = client.post(
        "/api/v1/auth/agents/register",
        json={
            "username": "unexpected-fields",
            "password": "password",
            "admin": True,
        },
    )

    assert response.status_code == 422
