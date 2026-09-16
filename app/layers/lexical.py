import math
import re
from pathlib import Path
from typing import Dict, Any, List, Optional
import tldextract
from app.layers.base import BaseLayer, LayerResult, RedFlag
from app.utils.logger import get_logger

logger = get_logger("layers.lexical")

# Known URL shorteners
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly", "rebrand.ly", "cutt.ly"}

DATA_DIR = Path(__file__).parent.parent / "data"


def load_file_lines(filename: str) -> List[str]:
    filepath = DATA_DIR / filename
    if filepath.exists():
        with open(filepath, "r", encoding="utf-8") as f:
            return [line.strip().lower() for line in f if line.strip()]
    return []


SUSPICIOUS_KEYWORDS = set(load_file_lines("suspicious_keywords.txt"))
TOP_BRANDS = load_file_lines("top_10k_brands.txt")
SUSPICIOUS_TLDS = set(load_file_lines("suspicious_tlds.txt"))


def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum([p * math.log2(p) for p in prob])


def levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


class LexicalLayer(BaseLayer):
    @property
    def name(self) -> str:
        return "lexical"

    async def analyze(self, url: str, context: Optional[Dict[str, Any]] = None) -> LayerResult:
        red_flags: List[RedFlag] = []
        risk_score = 0.0
        details: Dict[str, Any] = {}

        try:
            parsed = tldextract.extract(url)
            subdomain = parsed.subdomain.lower()
            domain = parsed.domain.lower()
            suffix = parsed.suffix.lower()
            full_host = f"{domain}.{suffix}" if suffix else domain

            url_len = len(url)
            entropy = calculate_entropy(url)

            details["url_length"] = url_len
            details["entropy"] = round(entropy, 3)
            details["subdomain"] = subdomain
            details["domain"] = domain
            details["tld"] = suffix

            # 1. URL Length check
            if url_len > 75:
                risk_score += 15
                red_flags.append(RedFlag(severity="low", flag=f"Excessive URL length ({url_len} chars)"))
            if url_len > 120:
                risk_score += 15

            # 2. IP as hostname
            ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
            if re.match(ip_pattern, full_host) or re.match(ip_pattern, domain):
                risk_score += 35
                red_flags.append(RedFlag(severity="high", flag="IP address used directly as hostname"))
                details["is_ip_hostname"] = True

            # 3. Homograph / Punycode check
            if full_host.startswith("xn--") or "xn--" in url:
                risk_score += 30
                red_flags.append(RedFlag(severity="high", flag="Punycode/Homograph attack detected (xn--)"))
                details["is_punycode"] = True

            # 4. Suspicious TLD
            if suffix in SUSPICIOUS_TLDS:
                risk_score += 20
                red_flags.append(RedFlag(severity="medium", flag=f"High-risk TLD detected (.{suffix})"))

            # 5. Symbol counts
            hyphen_count = url.count("-")
            dot_count = url.count(".")
            at_count = url.count("@")
            slash_count = url.count("//") - 1  # exclude protocol

            if at_count > 0:
                risk_score += 25
                red_flags.append(RedFlag(severity="high", flag="Contains '@' symbol in URL path/auth"))
            if dot_count > 4:
                risk_score += 15
                red_flags.append(RedFlag(severity="medium", flag=f"Unusual number of dots ({dot_count})"))
            if hyphen_count > 3:
                risk_score += 10
                red_flags.append(RedFlag(severity="low", flag=f"High hyphen count ({hyphen_count})"))
            if slash_count > 1:
                risk_score += 15
                red_flags.append(RedFlag(severity="medium", flag="Multiple '//' sequences in URL"))

            # 6. Typosquatting distance check
            for brand in TOP_BRANDS:
                if brand and domain != brand:
                    dist = levenshtein_distance(domain, brand)
                    if dist == 1 and len(domain) > 3:
                        risk_score += 40
                        red_flags.append(RedFlag(severity="high", flag=f"Possible typosquatting of brand '{brand}' (domain: {domain})"))
                        details["typosquat_target"] = brand
                        break
                    elif dist == 2 and len(domain) > 6:
                        risk_score += 25
                        red_flags.append(RedFlag(severity="medium", flag=f"Domain closely resembles brand '{brand}'"))
                        details["typosquat_target"] = brand
                        break

            # 7. Suspicious keyword matching in domain/subdomain/path
            url_lower = url.lower()
            matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower and kw != domain]
            if matched_keywords:
                risk_score += min(30, len(matched_keywords) * 10)
                red_flags.append(RedFlag(severity="medium", flag=f"Suspicious keywords present: {', '.join(matched_keywords[:4])}"))
                details["matched_keywords"] = matched_keywords

            # 8. Known shortener check
            if full_host in SHORTENERS:
                risk_score += 15
                red_flags.append(RedFlag(severity="low", flag=f"URL uses known link shortener ({full_host})"))
                details["is_shortener"] = True

            # 9. Base64/Hex encoding in path
            if re.search(r"/[a-zA-Z0-9+/]{30,}={0,2}", url) or re.search(r"[a-fA-F0-9]{32,}", url):
                risk_score += 20
                red_flags.append(RedFlag(severity="medium", flag="Encoded base64/hex payload detected in URL"))

            final_risk = min(100.0, float(risk_score))
            confidence = 0.9 if red_flags else 0.75

            return LayerResult(
                layer_name=self.name,
                risk_score=final_risk,
                confidence=confidence,
                red_flags=red_flags,
                details=details
            )
        except Exception as e:
            logger.error(f"Lexical analysis error for {url}: {e}")
            return LayerResult(
                layer_name=self.name,
                risk_score=0.0,
                confidence=0.0,
                error=str(e)
            )
