"""Retry decorators using tenacity for transient network errors."""
import logging
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception,
    before_sleep_log,
)


def is_transient_error(exception: Exception) -> bool:
    """
    Check if an exception is a transient error that should be retried.
    Handles HTTP/2 ConnectionTerminated, connection resets, timeouts, etc.
    """
    transient_types = (
        ConnectionResetError,
        ConnectionError,
        TimeoutError,
        OSError,
    )

    if isinstance(exception, transient_types):
        return True

    # Check error message for h2 ConnectionTerminated and similar
    error_msg = str(exception).lower()
    transient_indicators = (
        "connectionterminated",
        "connection reset",
        "timed out",
        "temporary failure",
    )
    return any(indicator in error_msg for indicator in transient_indicators)


# Async retry decorator for Azure AD / Graph API calls
async_retry_transient = retry(
    retry=retry_if_exception(is_transient_error),
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=2, min=2, max=60),
    before_sleep=before_sleep_log(logging.getLogger(__name__), logging.WARNING),
    reraise=True,
)
