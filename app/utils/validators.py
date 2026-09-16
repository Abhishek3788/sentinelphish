import hashlib
import re
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode
import validators as py_validators

SENSITIVE_PARAMS = {"token", "auth", "key", "password", "pass", "pwd", "secret", "session", "sid", "api_key", "bearer"}


def normalize_url(url: str) -> str:
    """Normalizes URL by stripping whitespace, standardizing protocol, and lowering hostname."""
    url = url.strip()
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "http://" + url
    
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    
    # Remove default ports
    if scheme == "http" and netloc.endswith(":80"):
        netloc = netloc[:-3]
    elif scheme == "https" and netloc.endswith(":443"):
        netloc = netloc[:-4]

    path = parsed.path or "/"
    
    return urlunparse((scheme, netloc, path, parsed.params, parsed.query, parsed.fragment))


def hash_url(url: str) -> str:
    """Generates SHA-256 hash of a normalized URL."""
    normalized = normalize_url(url)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def redact_url(url: str) -> str:
    """Redacts sensitive query parameters for privacy logging."""
    try:
        parsed = urlparse(url)
        if not parsed.query:
            return url
        
        query_params = parse_qsl(parsed.query, keep_blank_values=True)
        redacted_params = []
        for key, val in query_params:
            if key.lower() in SENSITIVE_PARAMS or any(s in key.lower() for s in ["pass", "token", "secret", "key"]):
                redacted_params.append((key, "[REDACTED]"))
            else:
                redacted_params.append((key, val))
        
        redacted_query = urlencode(redacted_params)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, redacted_query, parsed.fragment))
    except Exception:
        return url


def is_valid_url(url: str) -> bool:
    """Validates if a URL is structurally valid."""
    try:
        normalized = normalize_url(url)
        return bool(py_validators.url(normalized))
    except Exception:
        return False
