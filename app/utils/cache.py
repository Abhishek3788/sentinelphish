import json
import time
from typing import Any, Optional
from app.config import settings
from app.utils.logger import get_logger

logger = get_logger("utils.cache")

# Fallback in-memory cache dictionary with TTL
_in_memory_cache: dict[str, tuple[Any, float]] = {}

_redis_client = None


async def get_redis_client():
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    
    try:
        import redis.asyncio as redis
        redis_url = settings.UPSTASH_REDIS_URL or settings.REDIS_URL
        client = redis.from_url(redis_url, decode_responses=True)
        await client.ping()
        _redis_client = client
        logger.info("Connected to Redis cache.")
        return _redis_client
    except Exception as e:
        logger.warning(f"Redis unavailable ({e}). Using in-memory cache fallback.")
        _redis_client = None
        return None


class AsyncCache:
    @staticmethod
    async def get(key: str) -> Optional[Any]:
        client = await get_redis_client()
        if client:
            try:
                data = await client.get(key)
                return json.loads(data) if data else None
            except Exception as e:
                logger.warning(f"Redis get error: {e}")
        
        # In-memory fallback
        if key in _in_memory_cache:
            val, expire_at = _in_memory_cache[key]
            if time.time() < expire_at:
                return val
            else:
                del _in_memory_cache[key]
        return None

    @staticmethod
    async def set(key: str, value: Any, ttl: int = 86400) -> None:
        client = await get_redis_client()
        if client:
            try:
                await client.set(key, json.dumps(value), ex=ttl)
                return
            except Exception as e:
                logger.warning(f"Redis set error: {e}")
        
        # In-memory fallback
        _in_memory_cache[key] = (value, time.time() + ttl)

    @staticmethod
    async def delete(key: str) -> None:
        client = await get_redis_client()
        if client:
            try:
                await client.delete(key)
            except Exception as e:
                logger.warning(f"Redis delete error: {e}")
        _in_memory_cache.pop(key, None)
