import io
from pathlib import Path
from typing import Dict, Any, List, Optional
from PIL import Image
import imagehash
from app.layers.base import BaseLayer, LayerResult, RedFlag
from app.utils.sandbox import safe_fetch_page_content
from app.utils.logger import get_logger

logger = get_logger("layers.visual")

BRAND_FAVICONS_DIR = Path(__file__).parent.parent / "data" / "brand_favicons"


class VisualSimilarityLayer(BaseLayer):
    @property
    def name(self) -> str:
        return "visual"

    async def analyze(self, url: str, context: Optional[Dict[str, Any]] = None) -> LayerResult:
        red_flags: List[RedFlag] = []
        risk_score = 0.0
        details: Dict[str, Any] = {}

        try:
            screenshot_bytes = None
            if context and "screenshot_bytes" in context and context["screenshot_bytes"]:
                screenshot_bytes = context["screenshot_bytes"]
            else:
                page_data = await safe_fetch_page_content(url, timeout=8.0)
                screenshot_bytes = page_data.get("screenshot_bytes")

            if not screenshot_bytes:
                return LayerResult(
                    layer_name=self.name,
                    risk_score=0.0,
                    confidence=0.4,
                    details={"info": "Screenshot unavailable for visual analysis"}
                )

            # Load image from bytes
            img = Image.open(io.BytesIO(screenshot_bytes)).convert("RGB")
            
            # Compute perceptual hashes
            phash = str(imagehash.phash(img))
            dhash = str(imagehash.dhash(img))

            details["phash"] = phash
            details["dhash"] = dhash

            # 1. Compare hash against brand favicons/logos dataset
            matched_brand = self._compare_with_brand_dataset(img)
            if matched_brand:
                risk_score += 45.0
                red_flags.append(RedFlag(
                    severity="high",
                    flag=f"Visual signature matches known brand template: {matched_brand.upper()}"
                ))
                details["matched_brand_logo"] = matched_brand

            # 2. OCR text extraction (pytesseract if installed)
            ocr_text = self._perform_ocr(img)
            details["ocr_text_length"] = len(ocr_text)
            
            if ocr_text:
                lower_ocr = ocr_text.lower()
                for keyword in ["sign in", "login", "password", "bank", "account suspended", "security alert"]:
                    if keyword in lower_ocr:
                        risk_score += 15.0
                        red_flags.append(RedFlag(
                            severity="medium",
                            flag=f"OCR detected login/credential prompt text: '{keyword}'"
                        ))
                        break

            final_risk = min(100.0, float(risk_score))
            confidence = 0.8 if screenshot_bytes else 0.5

            return LayerResult(
                layer_name=self.name,
                risk_score=final_risk,
                confidence=confidence,
                red_flags=red_flags,
                details=details
            )

        except Exception as e:
            logger.error(f"Visual similarity error for {url}: {e}")
            return LayerResult(
                layer_name=self.name,
                risk_score=0.0,
                confidence=0.0,
                error=str(e)
            )

    def _compare_with_brand_dataset(self, target_img: Image.Image) -> Optional[str]:
        if not BRAND_FAVICONS_DIR.exists():
            return None

        target_phash = imagehash.phash(target_img)
        
        for file in BRAND_FAVICONS_DIR.glob("*.*"):
            if file.suffix.lower() in [".png", ".jpg", ".jpeg", ".ico"]:
                try:
                    ref_img = Image.open(file).convert("RGB")
                    ref_phash = imagehash.phash(ref_img)
                    diff = target_phash - ref_phash
                    if diff < 10:  # Perceptually very close
                        return file.stem
                except Exception:
                    pass
        return None

    def _perform_ocr(self, img: Image.Image) -> str:
        try:
            import pytesseract
            text = pytesseract.image_to_string(img)
            return text.strip()
        except Exception:
            return ""
