import time
from typing import Dict, Tuple
from app.utils.cache import get_redis_client
from app.utils.logger import get_logger

logger = get_logger("utils.rate_limit")

# In-memory rate limiting counters: key -> (count, reset_timestamp)
_in_memory_rate_limits: Dict[str, Tuple[int, float]] = {}


async def check_rate_limit(client_identifier: str, max_requests: int = 30, window_seconds: int = 60) -> bool:
    """
    Checks if a client has exceeded their allowed requests in the time window.
    Returns True if allowed, False if rate limited.
    """
    client = await get_redis_client()
    key = f"rate_limit:{client_identifier}"
    
    if client:
        try:
            current = await client.incr(key)
            if current == 1:
                await client.expire(key, window_seconds)
            if current > max_requests:
                return False
            return True
        except Exception as e:
            logger.warning(f"Redis rate limit check error: {e}")

    # Fallback to in-memory rate limiting
    now = time.time()
    if client_identifier in _in_memory_rate_limits:
        count, reset_at = _in_memory_rate_limits[client_identifier]
        if now < reset_at:
            if count >= max_requests:
                return False
            _in_memory_rate_limits[client_identifier] = (count + 1, reset_at)
            return True
        else:
            _in_memory_rate_limits[client_identifier] = (1, now + window_seconds)
            return True
    else:
        _in_memory_rate_limits[client_identifier] = (1, now + window_seconds)
        return True
