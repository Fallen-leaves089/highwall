"""Typed errors that map to safe, non-reflective HTTP responses."""

from __future__ import annotations


class HighWallError(Exception):
    """Base class for errors that are safe to expose as a short response."""

    status = 500
    code = "internal_error"
    public_message = "Internal server error."

    def __init__(self, message: str | None = None, *, rule_id: str | None = None) -> None:
        super().__init__(message or self.public_message)
        self.rule_id = rule_id


class BadRequest(HighWallError):
    status = 400
    code = "bad_request"
    public_message = "Bad request."


class Unauthorized(HighWallError):
    status = 401
    code = "unauthorized"
    public_message = "Unauthorized."


class Forbidden(HighWallError):
    status = 403
    code = "forbidden"
    public_message = "Forbidden."


class NotFound(HighWallError):
    status = 404
    code = "not_found"
    public_message = "Not found."


class MethodNotAllowed(HighWallError):
    status = 405
    code = "method_not_allowed"
    public_message = "Method not allowed."


class RequestTimeout(HighWallError):
    status = 408
    code = "request_timeout"
    public_message = "Request timeout."


class PayloadTooLarge(HighWallError):
    status = 413
    code = "payload_too_large"
    public_message = "Payload too large."


class URITooLong(HighWallError):
    status = 414
    code = "uri_too_long"
    public_message = "URI too long."


class UnsupportedMediaType(HighWallError):
    status = 415
    code = "unsupported_media_type"
    public_message = "Unsupported media type."


class ExpectationFailed(HighWallError):
    status = 417
    code = "expectation_failed"
    public_message = "Expectation failed."


class RequestHeaderFieldsTooLarge(HighWallError):
    status = 431
    code = "request_header_fields_too_large"
    public_message = "Request header fields too large."


class TooManyRequests(HighWallError):
    status = 429
    code = "too_many_requests"
    public_message = "Too many requests."


class BadGateway(HighWallError):
    status = 502
    code = "bad_gateway"
    public_message = "Bad gateway."


class ServiceUnavailable(HighWallError):
    status = 503
    code = "service_unavailable"
    public_message = "Service unavailable."


class GatewayTimeout(HighWallError):
    status = 504
    code = "gateway_timeout"
    public_message = "Gateway timeout."