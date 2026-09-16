import math
import re
from typing import Dict
from urllib.parse import urlparse
import tldextract


def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum([p * math.log2(p) for p in prob])


def extract_url_features(url: str) -> Dict[str, float]:
    parsed_tld = tldextract.extract(url)
    parsed_url = urlparse(url)
    
    subdomain = parsed_tld.subdomain
    domain = parsed_tld.domain
    suffix = parsed_tld.suffix
    full_host = f"{domain}.{suffix}" if suffix else domain

    url_len = float(len(url))
    domain_len = float(len(domain))
    subdomain_len = float(len(subdomain))
    path_len = float(len(parsed_url.path))

    num_dots = float(url.count("."))
    num_hyphens = float(url.count("-"))
    num_digits = float(sum(c.isdigit() for c in url))
    num_subdomains = float(len(subdomain.split(".")) if subdomain else 0)

    is_ip = 1.0 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", full_host) else 0.0
    has_at = 1.0 if "@" in url else 0.0
    has_double_slash = 1.0 if "//" in parsed_url.path else 0.0
    has_https = 1.0 if parsed_url.scheme.lower() == "https" else 0.0

    entropy = float(calculate_entropy(url))

    suspicious_terms = ["login", "verify", "secure", "account", "update", "banking", "signin", "paypal", "admin", "confirm"]
    url_lower = url.lower()
    kw_count = float(sum(1 for term in suspicious_terms if term in url_lower))

    high_risk_tlds = {"xyz", "top", "zip", "mov", "stream", "work", "cfd", "site", "online", "club", "live"}
    tld_risk = 1.0 if suffix.lower() in high_risk_tlds else 0.0

    return {
        "url_length": url_len,
        "domain_length": domain_len,
        "subdomain_length": subdomain_len,
        "path_length": path_len,
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_digits": num_digits,
        "num_subdomains": num_subdomains,
        "is_ip_hostname": is_ip,
        "has_at_symbol": has_at,
        "has_double_slash": has_double_slash,
        "has_https": has_https,
        "url_entropy": round(entropy, 4),
        "suspicious_keyword_count": kw_count,
        "tld_risk_score": tld_risk
    }
