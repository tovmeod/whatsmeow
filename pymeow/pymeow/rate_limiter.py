"""Rate limiting functionality for message sending."""
import asyncio
import time
from collections import deque
from typing import Deque, Optional
import logging

logger = logging.getLogger(__name__)

class RateLimiter:
    """Implements rate limiting with token bucket algorithm."""
    
    def __init__(self, rate: float = 1.0, capacity: int = 5):
        """Initialize the rate limiter.
        
        Args:
            rate: Number of tokens added per second
            capacity: Maximum number of tokens in the bucket
        """
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.updated_at = time.monotonic()
        self._lock = asyncio.Lock()
        self._waiting: Deque[asyncio.Future] = deque()
        
    async def acquire(self, tokens: int = 1) -> None:
        """Acquire tokens from the bucket.
        
        Args:
            tokens: Number of tokens to acquire
            
        Raises:
            ValueError: If tokens requested is greater than bucket capacity
        """
        if tokens > self.capacity:
            raise ValueError(f"Requested tokens ({tokens}) exceed bucket capacity ({self.capacity})")
            
        async with self._lock:
            # Update token count based on time passed
            self._update_tokens()
            
            # If we don't have enough tokens, wait
            if tokens > self.tokens:
                # Create a future that will be set when tokens are available
                future = asyncio.get_running_loop().create_future()
                self._waiting.append((future, tokens))
                
                # Process the waiting queue
                await self._process_waiting()
                
                # Wait for our turn
                await future
            else:
                # Take the tokens
                self.tokens -= tokens
    
    def _update_tokens(self) -> None:
        """Update the token count based on time passed."""
        now = time.monotonic()
        time_passed = now - self.updated_at
        self.updated_at = now
        
        # Add tokens based on time passed and rate
        self.tokens = min(
            self.capacity,
            self.tokens + time_passed * self.rate
        )
    
    async def _process_waiting(self) -> None:
        """Process the waiting queue of futures."""
        while self._waiting:
            future, tokens = self._waiting[0]
            
            # If we don't have enough tokens, we're done for now
            if tokens > self.tokens:
                break
                
            # We have enough tokens, fulfill this request
            self.tokens -= tokens
            future.set_result(True)
            self._waiting.popleft()
    
    def set_rate(self, rate: float) -> None:
        """Update the rate of token replenishment.
        
        Args:
            rate: New rate in tokens per second
        """
        async def _set_rate():
            async with self._lock:
                self._update_tokens()
                self.rate = rate
                # Process any waiting requests that might now be able to proceed
                await self._process_waiting()
                
        # Run in the background
        asyncio.create_task(_set_rate())
    
    def set_capacity(self, capacity: int) -> None:
        """Update the bucket capacity.
        
        Args:
            capacity: New bucket capacity
        """
        async def _set_capacity():
            async with self._lock:
                self.capacity = capacity
                self.tokens = min(self.tokens, capacity)
                # Process any waiting requests that might now be able to proceed
                await self._process_waiting()
                
        # Run in the background
        asyncio.create_task(_set_capacity())


class MessageRateLimiter:
    """Rate limiter specifically designed for WhatsApp message sending."""
    
    def __init__(self):
        """Initialize the message rate limiter with default WhatsApp limits."""
        # Default rate limits (can be adjusted based on WhatsApp's current limits)
        self.global_limiter = RateLimiter(rate=1.0, capacity=5)  # 5 messages per second
        self.per_recipient_limiters = {}  # type: dict[str, RateLimiter]
        self._lock = asyncio.Lock()
        
    async def acquire(self, recipient_id: Optional[str] = None) -> None:
        """Acquire tokens for sending a message.
        
        Args:
            recipient_id: Optional recipient ID for per-recipient rate limiting
        """
        # First acquire from the global limiter
        await self.global_limiter.acquire()
        
        # Then acquire from the per-recipient limiter if applicable
        if recipient_id:
            async with self._lock:
                if recipient_id not in self.per_recipient_limiters:
                    # 1 message per second, burst of 20 per recipient
                    self.per_recipient_limiters[recipient_id] = RateLimiter(rate=1.0, capacity=20)
                
                limiter = self.per_recipient_limiters[recipient_id]
            
            await limiter.acquire()
    
    def cleanup_old_recipients(self, max_age: int = 3600) -> None:
        """Clean up rate limiters for old recipients.
        
        Args:
            max_age: Maximum age in seconds for a recipient to be considered inactive
        """
        async def _cleanup():
            async with self._lock:
                now = time.monotonic()
                to_remove = [
                    recipient_id for recipient_id, limiter in self.per_recipient_limiters.items()
                    if now - limiter.updated_at > max_age
                ]
                
                for recipient_id in to_remove:
                    del self.per_recipient_limiters[recipient_id]
        
        # Run cleanup in the background
        asyncio.create_task(_cleanup())
