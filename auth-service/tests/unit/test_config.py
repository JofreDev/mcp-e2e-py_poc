import pytest
from pydantic import ValidationError

from auth_service.config import Settings

SECRET = "a-secure-test-secret-with-at-least-32-bytes"


def test_valid_settings_accept_bootstrap_administrator() -> None:
    settings = Settings(
        jwt_secret=SECRET,
        bootstrap_admin_email="ADMIN@example.com",
        bootstrap_admin_password="admin-password",
    )

    assert str(settings.bootstrap_admin_email) == "ADMIN@example.com"


@pytest.mark.parametrize(
    "overrides",
    [
        {"jwt_secret": "too-short"},
        {"jwt_secret": SECRET, "jwt_algorithm": "none"},
        {"jwt_secret": SECRET, "access_token_ttl_seconds": 0},
        {"jwt_secret": SECRET, "refresh_token_ttl_seconds": -1},
        {"jwt_secret": SECRET, "bootstrap_admin_email": "admin@example.com"},
        {"jwt_secret": SECRET, "bootstrap_admin_password": "admin-password"},
        {
            "jwt_secret": SECRET,
            "bootstrap_admin_email": "admin@example.com",
            "bootstrap_admin_password": "short",
        },
    ],
)
def test_invalid_security_settings_are_rejected(overrides: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        Settings(**overrides)  # type: ignore[arg-type]
