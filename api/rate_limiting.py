# API Rate Limiting with Redis Backend

This module implements rate limiting for API endpoints using Redis.

## Features
- Configurable rate limits per endpoint
- Distributed rate limiting across instances
- Integration with FastAPI middleware
- Sliding window algorithms

## Usage
```python
from api.rate_limiting import RedisRateLimiter

limiter = RedisRateLimiter(redis_url="redis://localhost:6379")
# Use as FastAPI dependency
```