import asyncio
import sys
from pathlib import Path

# Ensure root project directory is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db.session import init_db
from app.utils.logger import get_logger

logger = get_logger("scripts.init_db")


async def main():
    logger.info("Initializing database tables...")
    await init_db()
    logger.info("Database initialization complete.")


if __name__ == "__main__":
    asyncio.run(main())
