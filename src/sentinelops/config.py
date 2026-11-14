"""Configuration management and secret redaction for SentinelOps.

Provides fail-fast environment validation, production safeguards,
and logging filters to protect sensitive credentials.
"""

from __future__ import annotations

import logging
import os
import re
from typing import List, Optional


class StartupError(Exception):
    """Raised when application configuration fails validation."""

    def __init__(self, issues: List[str]):
        self.issues = issues
        super().__init__(f"Configuration validation failed: {'; '.join(issues)}")


def parse_bool(value: Optional[str | bool], default: bool = False) -> bool:
    """Parse string or boolean values safely into a boolean."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    val_str = str(value).strip().lower()
    return val_str in ("true", "1", "yes", "t", "y", "on")


class RedactingFilter(logging.Filter):
    """Logging filter that scrubs bearer tokens, API keys, and sensitive secrets."""

    # Built with escaped regex characters to maintain secret hygiene
    _API_KEY_REGEX = re.compile(
        r"\bsk\-ant\-[A-Za-z0-9_\-]{10,}\b"
    )
    _GENERIC_KEY_REGEX = re.compile(r"\b(sk-[A-Za-z0-9_\-]{20,})\b")
    _BEARER_REGEX = re.compile(
        r"(Bearer\s+)([A-Za-z0-9_\-\.]{8,})", re.IGNORECASE
    )
    _AUTH_HEADER_REGEX = re.compile(
        r"(Authorization:\s*Bearer\s+)([^\s,;]+)", re.IGNORECASE
    )

    def __init__(self, sensitive_tokens: Optional[List[str]] = None):
        super().__init__()
        self.sensitive_tokens = [
            t.strip() for t in (sensitive_tokens or []) if t and len(t.strip()) >= 4
        ]

    def redact_text(self, text: str) -> str:
        """Redact sensitive patterns from text string."""
        if not text:
            return text

        # Mask Anthropic-style keys
        text = self._API_KEY_REGEX.sub("[REDACTED_API_KEY]", text)
        text = self._GENERIC_KEY_REGEX.sub("[REDACTED_API_KEY]", text)

        # Mask Bearer tokens
        text = self._BEARER_REGEX.sub(r"\1[REDACTED_TOKEN]", text)
        text = self._AUTH_HEADER_REGEX.sub(r"\1[REDACTED_TOKEN]", text)

        # Mask known sensitive values
        for token in self.sensitive_tokens:
            if token in text:
                text = text.replace(token, "[REDACTED]")

        return text

    def filter(self, record: logging.LogRecord) -> bool:
        """Redact record msg and args if present."""
        if isinstance(record.msg, str):
            record.msg = self.redact_text(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    k: self.redact_text(v) if isinstance(v, str) else v
                    for k, v in record.args.items()
                }
            elif isinstance(record.args, tuple):
                record.args = tuple(
                    self.redact_text(v) if isinstance(v, str) else v
                    for v in record.args
                )
        return True


class Settings:
    """Application settings with fail-fast production validation."""

    def __init__(
        self,
        app_env: Optional[str] = None,
        debug: Optional[str | bool] = None,
        anthropic_api_key: Optional[str] = None,
        mcp_auth_token: Optional[str] = None,
        allowed_origins: Optional[str | List[str]] = None,
        mock_mode: Optional[str | bool] = None,
        pause_file_path: Optional[str] = None,
    ):
        raw_env = app_env if app_env is not None else os.getenv("APP_ENV", "development")
        self.APP_ENV: str = raw_env.strip().lower()

        if self.APP_ENV not in ("development", "production"):
            raise StartupError([f"APP_ENV must be 'development' or 'production', got '{self.APP_ENV}'"])

        raw_debug = debug if debug is not None else os.getenv("DEBUG", "false")
        self.DEBUG: bool = parse_bool(raw_debug, default=False)

        self.ANTHROPIC_API_KEY: Optional[str] = (
            anthropic_api_key if anthropic_api_key is not None else os.getenv("ANTHROPIC_API_KEY", "")
        )
        if self.ANTHROPIC_API_KEY:
            self.ANTHROPIC_API_KEY = self.ANTHROPIC_API_KEY.strip()

        self.MCP_AUTH_TOKEN: Optional[str] = (
            mcp_auth_token if mcp_auth_token is not None else os.getenv("MCP_AUTH_TOKEN", "")
        )
        if self.MCP_AUTH_TOKEN:
            self.MCP_AUTH_TOKEN = self.MCP_AUTH_TOKEN.strip()

        raw_origins = allowed_origins if allowed_origins is not None else os.getenv("ALLOWED_ORIGINS", "")
        if isinstance(raw_origins, list):
            self.ALLOWED_ORIGINS: List[str] = [o.strip() for o in raw_origins if o.strip()]
        else:
            self.ALLOWED_ORIGINS = [
                o.strip() for o in str(raw_origins).split(",") if o.strip()
            ]

        raw_mock = mock_mode if mock_mode is not None else os.getenv("MOCK_MODE", "true")
        self.MOCK_MODE: bool = parse_bool(raw_mock, default=True)

        self.PAUSE_FILE_PATH: str = pause_file_path or os.getenv("PAUSE_FILE_PATH", "PAUSE")

        # Validate configuration according to environment
        self._validate()

    def _validate(self) -> None:
        """Validate settings and fail fast in production with actionable issues."""
        if self.APP_ENV != "production":
            return

        issues: List[str] = []

        if self.DEBUG:
            issues.append("DEBUG must be disabled in production")

        if not self.MCP_AUTH_TOKEN:
            issues.append("MCP_AUTH_TOKEN is required and cannot be blank in production")

        if not self.ALLOWED_ORIGINS:
            issues.append("ALLOWED_ORIGINS is required and cannot be blank in production")
        elif any("*" in origin for origin in self.ALLOWED_ORIGINS):
            issues.append("ALLOWED_ORIGINS cannot contain wildcard '*' in production")

        if not self.MOCK_MODE:
            if not self.ANTHROPIC_API_KEY:
                issues.append("ANTHROPIC_API_KEY is required in production when MOCK_MODE is false")

        if issues:
            raise StartupError(issues)


_global_settings: Optional[Settings] = None


def get_settings(reload: bool = False, **overrides) -> Settings:
    """Retrieve singleton Settings or create with overrides."""
    global _global_settings
    if _global_settings is None or reload or overrides:
        _global_settings = Settings(**overrides)
    return _global_settings


def setup_logging(settings: Optional[Settings] = None) -> logging.Logger:
    """Configure root logger with log redaction filter."""
    s = settings or get_settings()
    log_level = logging.DEBUG if s.DEBUG else logging.INFO

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Avoid duplicate handlers if re-called
    if not root_logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
        )
        handler.setFormatter(formatter)
        root_logger.addHandler(handler)

    sensitive_tokens = []
    if s.MCP_AUTH_TOKEN:
        sensitive_tokens.append(s.MCP_AUTH_TOKEN)
    if s.ANTHROPIC_API_KEY:
        sensitive_tokens.append(s.ANTHROPIC_API_KEY)

    redaction_filter = RedactingFilter(sensitive_tokens=sensitive_tokens)
    for handler in root_logger.handlers:
        # Avoid duplicate filters
        if not any(isinstance(f, RedactingFilter) for f in handler.filters):
            handler.addFilter(redaction_filter)

    return logging.getLogger("sentinelops")
