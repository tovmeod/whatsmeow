"""
Retry logic for WhatsApp operations.

Port of whatsmeow/retry.go
"""
import asyncio
from typing import TypeVar, Callable, Awaitable
from datetime import timedelta

T = TypeVar('T')

class RetryConfig:
    """Configuration for retry behavior."""
    def __init__(
        self,
        max_retries: int = 5,
        initial_delay: timedelta = timedelta(seconds=1),
        max_delay: timedelta = timedelta(minutes=5),
        multiplier: float = 2.0
    ):
        self.max_retries = max_retries
        self.initial_delay = initial_delay
        self.max_delay = max_delay
        self.multiplier = multiplier

async def with_retry(
    operation: Callable[[], Awaitable[T]],
    config: RetryConfig = RetryConfig(),
) -> T:
    """Execute an operation with exponential backoff retry."""
    delay = config.initial_delay
    last_error = None

    for attempt in range(config.max_retries):
        try:
            return await operation()
        except Exception as e:
            last_error = e
            if attempt == config.max_retries - 1:
                raise

            await asyncio.sleep(delay.total_seconds())
            delay = min(
                delay * config.multiplier,
                config.max_delay
            )

    raise last_error  # Should never reach here due to raise in loop
