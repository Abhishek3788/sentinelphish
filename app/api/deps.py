from typing import Optional
from fastapi import Request, HTTPException, Security, status
from fastapi.security.api_key import APIKeyHeader
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.models import ApiKey
from app.db.session import AsyncSessionLocal
from app.utils.rate_limit import check_rate_limit
from app.utils.validators import hash_url
from app.utils.logger import get_logger

logger = get_logger("api.deps")

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def verify_rate_limit(request: Request):
    client_ip = request.client.host if request.client else "127.0.0.1"
    allowed = await check_rate_limit(client_ip, max_requests=60, window_seconds=60)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Maximum 60 requests per minute."
        )


async def verify_api_key(
    db: AsyncSession = Security(get_db),
    api_key: Optional[str] = Security(api_key_header)
) -> Optional[ApiKey]:
    if not api_key:
        return None
    
    key_h = hash_url(api_key)
    result = await db.execute(select(ApiKey).where(ApiKey.key_hash == key_h, ApiKey.is_active == True))
    db_key = result.scalar_one_or_none()
    if not db_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API Key")
    return db_key
