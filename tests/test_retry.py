"""Tests for retry decorator with tenacity."""
import pytest
from retry import async_retry_transient, is_transient_error


class TestIsTransientError:
    """Tests for transient error detection."""

    def test_connection_reset_is_transient(self):
        assert is_transient_error(ConnectionResetError("reset"))

    def test_connection_terminated_message_is_transient(self):
        """h2 ConnectionTerminated errors should be detected."""
        exc = Exception("ConnectionTerminated error_code:0")
        assert is_transient_error(exc)

    def test_value_error_is_not_transient(self):
        assert not is_transient_error(ValueError("bad input"))


class TestAsyncRetryTransient:
    """Tests for async retry decorator."""

    @pytest.mark.asyncio
    async def test_retries_on_transient_error(self):
        """Should retry and succeed after transient errors."""
        call_count = 0

        @async_retry_transient
        async def fails_twice():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ConnectionResetError("transient")
            return "success"

        result = await fails_twice()

        assert result == "success"
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_no_retry_on_non_transient(self):
        """Non-transient errors should not be retried."""
        call_count = 0

        @async_retry_transient
        async def raises_value_error():
            nonlocal call_count
            call_count += 1
            raise ValueError("not transient")

        with pytest.raises(ValueError):
            await raises_value_error()

        assert call_count == 1
