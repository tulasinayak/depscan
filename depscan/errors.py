"""User-facing errors: a short friendly message plus the underlying detail (shown in an expander / --verbose)."""


class DepscanError(Exception):
    def __init__(self, message: str, detail: str = ""):
        super().__init__(message)
        self.message = message
        self.detail = detail


class CloneError(DepscanError):
    pass


class LLMUnavailable(DepscanError):
    pass


class LLMOutputError(DepscanError):
    pass


class NotFound(DepscanError):
    pass
