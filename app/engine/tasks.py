import asyncio
from typing import List, Dict, Any
from app.celery_app import celery_app
from app.engine.orchestrator import ScanOrchestrator
from app.utils.logger import get_logger

logger = get_logger("engine.tasks")


@celery_app.task(name="tasks.scan_url_batch")
def scan_url_batch_task(urls: List[str]) -> List[Dict[str, Any]]:
    logger.info(f"Executing Celery batch scan for {len(urls)} URLs")
    orchestrator = ScanOrchestrator()
    
    async def _run():
        results = []
        for url in urls:
            res = await orchestrator.scan_url(url)
            results.append(res)
        return results

    return asyncio.run(_run())
