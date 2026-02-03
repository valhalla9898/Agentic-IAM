"""
API Rate Limiting with Redis Backend for Agentic-IAM

This module implements distributed rate limiting for API endpoints using Redis
as the backend store. Supports multiple algorithms and integrates with FastAPI.

## Features
- Configurable rate limits per endpoint and user
- Distributed rate limiting across multiple instances
- Sliding window and fixed window algorithms
- Redis-based storage for persistence and sharing
- FastAPI middleware integration
- Burst handling and gradual backoff
"""

import redis
import time
import json
from typing import Dict, Optional, Tuple, Callable
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)

class RateLimitAlgorithm(Enum):
    """Rate limiting algorithms"""
    FIXED_WINDOW = "fixed_window"
    SLIDING_WINDOW = "sliding_window"
    TOKEN_BUCKET = "token_bucket"
    LEAKY_BUCKET = "leaky_bucket"

@dataclass
class RateLimit:
    """Rate limit configuration"""
    requests: int
    window_seconds: int
    algorithm: RateLimitAlgorithm = RateLimitAlgorithm.FIXED_WINDOW

@dataclass
class RateLimitResult:
    """Result of rate limit check"""
    allowed: bool
    remaining: int
    reset_time: float
    retry_after: Optional[float] = None

class RedisRateLimiter:
    """
    Redis-based rate limiter with multiple algorithms
    """

    def __init__(self, redis_url: str = "redis://localhost:6379", key_prefix: str = "ratelimit"):
        self.redis_url = redis_url
        self.key_prefix = key_prefix
        self.redis = None
        self._connect_redis()

    def _connect_redis(self):
        """Connect to Redis"""
        try:
            self.redis = redis.from_url(self.redis_url, decode_responses=True)
            self.redis.ping()  # Test connection
            logger.info("Connected to Redis for rate limiting")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise

    def _make_key(self, identifier: str, endpoint: str) -> str:
        """Create Redis key for rate limiting"""
        return f"{self.key_prefix}:{identifier}:{endpoint}"

    def check_fixed_window(self, key: str, limit: int, window: int) -> RateLimitResult:
        """
        Fixed window rate limiting algorithm
        """
        current_window = int(time.time() / window) * window
        window_key = f"{key}:{current_window}"

        # Get current count
        current_count = self.redis.get(window_key)
        if current_count is None:
            current_count = 0
        else:
            current_count = int(current_count)

        remaining = max(0, limit - current_count - 1)
        allowed = current_count < limit

        if allowed:
            # Increment counter
            self.redis.incr(window_key)
            # Set expiration
            self.redis.expire(window_key, window * 2)  # Keep for 2 windows

        reset_time = current_window + window

        return RateLimitResult(
            allowed=allowed,
            remaining=remaining,
            reset_time=reset_time
        )

    def check_sliding_window(self, key: str, limit: int, window: int) -> RateLimitResult:
        """
        Sliding window rate limiting algorithm
        """
        now = time.time()
        window_start = now - window

        # Add current request
        self.redis.zadd(key, {str(now): now})
        # Remove old entries
        self.redis.zremrangebyscore(key, 0, window_start)
        # Count requests in window
        count = self.redis.zcard(key)

        # Set expiration for cleanup
        self.redis.expire(key, window * 2)

        allowed = count <= limit
        remaining = max(0, limit - count)

        # Calculate reset time (when oldest request expires)
        oldest_scores = self.redis.zrange(key, 0, 0, withscores=True)
        if oldest_scores:
            reset_time = oldest_scores[0][1] + window
        else:
            reset_time = now + window

        return RateLimitResult(
            allowed=allowed,
            remaining=remaining,
            reset_time=reset_time
        )

    def check_token_bucket(self, key: str, capacity: int, refill_rate: float) -> RateLimitResult:
        """
        Token bucket algorithm
        """
        now = time.time()

        # Get current bucket state
        bucket_key = f"{key}:tokens"
        last_refill_key = f"{key}:last_refill"

        tokens = self.redis.get(bucket_key)
        last_refill = self.redis.get(last_refill_key)

        if tokens is None:
            tokens = capacity
            last_refill = now
        else:
            tokens = float(tokens)
            last_refill = float(last_refill)

        # Refill tokens
        elapsed = now - last_refill
        tokens_to_add = elapsed * refill_rate
        tokens = min(capacity, tokens + tokens_to_add)

        allowed = tokens >= 1.0

        if allowed:
            tokens -= 1.0

        # Update Redis
        self.redis.set(bucket_key, tokens)
        self.redis.set(last_refill_key, now)
        self.redis.expire(bucket_key, int(capacity / refill_rate) * 2)
        self.redis.expire(last_refill_key, int(capacity / refill_rate) * 2)

        remaining = int(tokens)
        reset_time = now + (capacity - tokens) / refill_rate

        return RateLimitResult(
            allowed=allowed,
            remaining=remaining,
            reset_time=reset_time
        )

    def check_rate_limit(self, identifier: str, endpoint: str, rate_limit: RateLimit) -> RateLimitResult:
        """
        Check if request is within rate limit
        """
        key = self._make_key(identifier, endpoint)

        if rate_limit.algorithm == RateLimitAlgorithm.FIXED_WINDOW:
            return self.check_fixed_window(key, rate_limit.requests, rate_limit.window_seconds)
        elif rate_limit.algorithm == RateLimitAlgorithm.SLIDING_WINDOW:
            return self.check_sliding_window(key, rate_limit.requests, rate_limit.window_seconds)
        elif rate_limit.algorithm == RateLimitAlgorithm.TOKEN_BUCKET:
            # For token bucket, treat requests as capacity and window as refill time
            refill_rate = rate_limit.requests / rate_limit.window_seconds
            return self.check_token_bucket(key, rate_limit.requests, refill_rate)
        else:
            raise ValueError(f"Unsupported algorithm: {rate_limit.algorithm}")

    def reset_limits(self, identifier: str, endpoint: Optional[str] = None):
        """Reset rate limits for an identifier"""
        pattern = f"{self.key_prefix}:{identifier}:*"
        if endpoint:
            pattern = f"{self.key_prefix}:{identifier}:{endpoint}*"

        keys = self.redis.keys(pattern)
        if keys:
            self.redis.delete(*keys)
            logger.info(f"Reset rate limits for {identifier}:{endpoint or 'all'}")

# FastAPI Integration
class RateLimitMiddleware:
    """
    FastAPI middleware for rate limiting
    """

    def __init__(self, limiter: RedisRateLimiter, default_limits: Dict[str, RateLimit]):
        self.limiter = limiter
        self.default_limits = default_limits

    async def __call__(self, request, call_next):
        # Get identifier (could be IP, user ID, API key, etc.)
        identifier = self._get_identifier(request)

        # Get endpoint-specific limits
        endpoint = request.url.path
        rate_limit = self.default_limits.get(endpoint, self.default_limits.get('default'))

        if rate_limit:
            result = self.limiter.check_rate_limit(identifier, endpoint, rate_limit)

            if not result.allowed:
                # Return rate limit exceeded response
                from fastapi import HTTPException
                raise HTTPException(
                    status_code=429,
                    detail={
                        "error": "Rate limit exceeded",
                        "retry_after": result.retry_after or (result.reset_time - time.time())
                    }
                )

            # Add rate limit headers to response
            response = await call_next(request)
            response.headers["X-RateLimit-Remaining"] = str(result.remaining)
            response.headers["X-RateLimit-Reset"] = str(int(result.reset_time))
            return response

        return await call_next(request)

    def _get_identifier(self, request) -> str:
        """Extract identifier from request (IP, user, etc.)"""
        # Simple IP-based identification
        # In production, you might use user ID, API key, etc.
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host

# Dependency for FastAPI routes
def create_rate_limit_dependency(limiter: RedisRateLimiter, rate_limit: RateLimit):
    """
    Create FastAPI dependency for rate limiting
    """
    async def rate_limit_dependency(request):
        identifier = request.client.host  # Or get from user/auth
        endpoint = request.url.path

        result = limiter.check_rate_limit(identifier, endpoint, rate_limit)

        if not result.allowed:
            from fastapi import HTTPException
            raise HTTPException(
                status_code=429,
                detail="Rate limit exceeded",
                headers={"Retry-After": str(int(result.retry_after or 60))}
            )

        # Store result in request state for headers
        request.state.rate_limit = result
        return result

    return rate_limit_dependency

# Example usage
if __name__ == "__main__":
    # Initialize rate limiter
    limiter = RedisRateLimiter()

    # Define rate limits
    api_limits = {
        "/api/agents": RateLimit(requests=100, window_seconds=60, algorithm=RateLimitAlgorithm.SLIDING_WINDOW),
        "/api/auth": RateLimit(requests=10, window_seconds=60, algorithm=RateLimitAlgorithm.FIXED_WINDOW),
        "default": RateLimit(requests=50, window_seconds=60, algorithm=RateLimitAlgorithm.TOKEN_BUCKET)
    }

    # Test rate limiting
    identifier = "user123"
    endpoint = "/api/agents"

    for i in range(105):
        result = limiter.check_rate_limit(identifier, endpoint, api_limits[endpoint])
        print(f"Request {i+1}: Allowed={result.allowed}, Remaining={result.remaining}")
        if not result.allowed:
            print(f"Rate limit exceeded. Reset in {result.reset_time - time.time():.1f} seconds")
            break

    # Reset limits
    limiter.reset_limits(identifier, endpoint)
    print("Rate limits reset")