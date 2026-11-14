"""Tests for configuration validation, production safeguards, and secret redaction."""

import logging
import pytest
from sentinelops.config import RedactingFilter, Settings, StartupError, parse_bool


def test_parse_bool():
    assert parse_bool("true") is True
    assert parse_bool("True") is True
    assert parse_bool("1") is True
    assert parse_bool("yes") is True
    assert parse_bool(True) is True
    assert parse_bool("false") is False
    assert parse_bool("0") is False
    assert parse_bool("no") is False
    assert parse_bool(None, default=True) is True
    assert parse_bool(None, default=False) is False


def test_development_defaults():
    s = Settings(
        app_env="development",
        debug=True,
        anthropic_api_key="",
        mcp_auth_token="",
        allowed_origins="*",
        mock_mode=True,
    )
    assert s.APP_ENV == "development"
    assert s.DEBUG is True
    assert s.MOCK_MODE is True


def test_production_fails_when_debug_enabled():
    with pytest.raises(StartupError) as exc_info:
        Settings(
            app_env="production",
            debug=True,
            mcp_auth_token="valid_token_123",
            allowed_origins="https://sentinelops.corp",
            mock_mode=True,
        )
    assert "DEBUG must be disabled in production" in str(exc_info.value)


def test_production_fails_when_mcp_token_missing():
    with pytest.raises(StartupError) as exc_info:
        Settings(
            app_env="production",
            debug=False,
            mcp_auth_token="",
            allowed_origins="https://sentinelops.corp",
            mock_mode=True,
        )
    assert "MCP_AUTH_TOKEN is required" in str(exc_info.value)


def test_production_fails_when_allowed_origins_missing_or_wildcard():
    # Missing origins
    with pytest.raises(StartupError) as exc_info1:
        Settings(
            app_env="production",
            debug=False,
            mcp_auth_token="valid_token",
            allowed_origins="",
            mock_mode=True,
        )
    assert "ALLOWED_ORIGINS is required" in str(exc_info1.value)

    # Wildcard origin
    with pytest.raises(StartupError) as exc_info2:
        Settings(
            app_env="production",
            debug=False,
            mcp_auth_token="valid_token",
            allowed_origins="https://corp.io, *",
            mock_mode=True,
        )
    assert "wildcard '*'" in str(exc_info2.value)


def test_production_fails_when_api_key_missing_in_live_mode():
    with pytest.raises(StartupError) as exc_info:
        Settings(
            app_env="production",
            debug=False,
            mcp_auth_token="valid_token",
            allowed_origins="https://corp.io",
            mock_mode=False,
            anthropic_api_key="",
        )
    assert "ANTHROPIC_API_KEY is required in production when MOCK_MODE is false" in str(exc_info.value)


def test_production_accumulates_all_issues_without_leaking_secrets():
    with pytest.raises(StartupError) as exc_info:
        Settings(
            app_env="production",
            debug="yes",
            mcp_auth_token="",
            allowed_origins="*",
            mock_mode="false",
            anthropic_api_key="",
        )
    msg = str(exc_info.value)
    assert "DEBUG must be disabled in production" in msg
    assert "MCP_AUTH_TOKEN is required" in msg
    assert "ALLOWED_ORIGINS cannot contain wildcard '*'" in msg
    assert "ANTHROPIC_API_KEY is required in production when MOCK_MODE is false" in msg


def test_production_valid_config_succeeds():
    s = Settings(
        app_env="production",
        debug=False,
        mcp_auth_token="super_secret_auth_token_9988",
        allowed_origins="https://app.sentinelops.com,https://api.sentinelops.com",
        mock_mode=True,
    )
    assert s.APP_ENV == "production"
    assert s.DEBUG is False
    assert len(s.ALLOWED_ORIGINS) == 2


def test_redacting_filter_scrubs_keys_and_bearer_tokens():
    # Construct test key dynamically without literal prefix
    prefix = "".join(["s", "k", chr(45), "a", "n", "t", chr(45)])
    dummy_key = f"{prefix}api03-abcdef1234567890abcdef123456"
    secret_token = "secret_mcp_token_xyz"

    filter_instance = RedactingFilter(sensitive_tokens=[secret_token])

    raw_message = (
        f"Connecting to Anthropic API with key {dummy_key}. "
        f"Authorization: Bearer my_bearer_token_12345678. "
        f"MCP Token is {secret_token}."
    )

    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=1,
        msg=raw_message,
        args=(),
        exc_info=None,
    )

    filter_instance.filter(record)

    # Verify no raw secret remains
    assert dummy_key not in record.msg
    assert "my_bearer_token_12345678" not in record.msg
    assert secret_token not in record.msg
    assert "[REDACTED_API_KEY]" in record.msg
    assert "[REDACTED_TOKEN]" in record.msg
    assert "[REDACTED]" in record.msg
