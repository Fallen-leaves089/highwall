"""Error types used by L4Wall."""

from __future__ import annotations


class L4WallError(Exception):
    """Base class for expected L4Wall failures."""


class ConfigError(L4WallError):
    """The configuration is missing, malformed, or unsafe."""


class SessionError(L4WallError):
    """A live session was closed by policy or resource limits."""

