"""Sanitized failures that tools report as structured errors."""


class ServiceError(Exception):
    """`message` reaches the MCP client: keep it free of provider details and secrets."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = str(code)
