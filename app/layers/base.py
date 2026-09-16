from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from pydantic import BaseModel


class RedFlag(BaseModel):
    severity: str  # 'high', 'medium', 'low'
    flag: str


class LayerResult(BaseModel):
    layer_name: str
    risk_score: float  # 0.0 to 100.0
    confidence: float  # 0.0 to 1.0
    red_flags: List[RedFlag] = []
    details: Dict[str, Any] = {}
    error: Optional[str] = None


class BaseLayer(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    async def analyze(self, url: str, context: Optional[Dict[str, Any]] = None) -> LayerResult:
        pass
