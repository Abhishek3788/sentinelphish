import asyncio
from datetime import datetime, timezone
import socket
import ssl
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
import dns.asyncresolver
import httpx
import tldextract
from app.config import settings
from app.layers.base import BaseLayer, LayerResult, RedFlag
from app.utils.logger import get_logger

logger = get_logger("layers.domain_intel")


class DomainIntelLayer(BaseLayer):
    @property
    def name(self) -> str:
        return "domain_intel"

    async def analyze(self, url: str, context: Optional[Dict[str, Any]] = None) -> LayerResult:
        red_flags: List[RedFlag] = []
        risk_score = 0.0
        details: Dict[str, Any] = {}

        try:
            parsed = tldextract.extract(url)
            domain = f"{parsed.domain}.{parsed.suffix}" if parsed.suffix else parsed.domain
            url_parsed = urlparse(url)
            hostname = url_parsed.hostname or domain

            # 1. DNS Lookups (A, MX, TXT, NS)
            dns_records = await self._fetch_dns_records(domain)
            details["dns"] = dns_records

            if not dns_records.get("A"):
                risk_score += 25
                red_flags.append(RedFlag(severity="high", flag="Domain has no valid A record (unresolved host)"))
            if not dns_records.get("MX"):
                risk_score += 10
                red_flags.append(RedFlag(severity="low", flag="Domain lacks MX (mail server) record"))

            # 2. WHOIS Domain Age & Registrar Check
            whois_info = await self._fetch_whois_info(domain)
            details["whois"] = whois_info
            
            if whois_info.get("age_days") is not None:
                age_days = whois_info["age_days"]
                if age_days < 7:
                    risk_score += 45
                    red_flags.append(RedFlag(severity="high", flag=f"Newly registered domain (registered {age_days} days ago)"))
                elif age_days < 30:
                    risk_score += 25
                    red_flags.append(RedFlag(severity="medium", flag=f"Young domain (registered {age_days} days ago)"))
                elif age_days < 90:
                    risk_score += 10
                    red_flags.append(RedFlag(severity="low", flag=f"Domain age under 3 months ({age_days} days)"))

            # 3. SSL Certificate check
            ssl_info = await self._fetch_ssl_info(hostname)
            details["ssl"] = ssl_info
            
            if not ssl_info.get("has_ssl"):
                risk_score += 20
                red_flags.append(RedFlag(severity="medium", flag="No valid SSL certificate found or connection refused"))
            elif ssl_info.get("is_expired"):
                risk_score += 30
                red_flags.append(RedFlag(severity="high", flag="SSL Certificate is expired"))
            elif ssl_info.get("issuer_org") and "Let's Encrypt" in ssl_info["issuer_org"] and whois_info.get("age_days", 365) < 30:
                risk_score += 15
                red_flags.append(RedFlag(severity="low", flag="Free short-lived SSL cert on newly registered domain"))

            # 4. Certificate Transparency (crt.sh)
            ct_logs = await self._fetch_crt_sh(domain)
            details["ct_log_count"] = ct_logs.get("cert_count", 0)
            if ct_logs.get("cert_count", 0) == 0 and ssl_info.get("has_ssl"):
                risk_score += 10
                red_flags.append(RedFlag(severity="low", flag="No Certificate Transparency logs found on crt.sh"))

            # 5. IP Reputation / Geolocation (ipapi.co / AbuseIPDB)
            if dns_records.get("A"):
                first_ip = dns_records["A"][0]
                ip_info = await self._fetch_ip_reputation(first_ip)
                details["ip_intel"] = ip_info
                if ip_info.get("abuse_score", 0) > 30:
                    risk_score += 35
                    red_flags.append(RedFlag(severity="high", flag=f"IP {first_ip} reported for malicious activity (Abuse score: {ip_info['abuse_score']})"))

            final_risk = min(100.0, float(risk_score))
            confidence = 0.85

            return LayerResult(
                layer_name=self.name,
                risk_score=final_risk,
                confidence=confidence,
                red_flags=red_flags,
                details=details
            )

        except Exception as e:
            logger.error(f"Domain Intel layer error for {url}: {e}")
            return LayerResult(
                layer_name=self.name,
                risk_score=0.0,
                confidence=0.0,
                error=str(e)
            )

    async def _fetch_dns_records(self, domain: str) -> Dict[str, List[str]]:
        results: Dict[str, List[str]] = {"A": [], "MX": [], "TXT": [], "NS": []}
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 2.0
        
        for qtype in ["A", "MX", "TXT", "NS"]:
            try:
                answers = await resolver.resolve(domain, qtype)
                results[qtype] = [str(r.to_text()) for r in answers]
            except Exception:
                pass
        return results

    async def _fetch_whois_info(self, domain: str) -> Dict[str, Any]:
        info: Dict[str, Any] = {"age_days": None, "registrar": None, "creation_date": None}
        try:
            import whois
            w = await asyncio.to_thread(whois.whois, domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date:
                if creation_date.tzinfo is None:
                    creation_date = creation_date.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                age_days = (now - creation_date).days
                info["age_days"] = age_days
                info["creation_date"] = creation_date.isoformat()
            
            info["registrar"] = str(w.registrar) if w.registrar else None
        except Exception as e:
            logger.debug(f"WHOIS lookup failed for {domain}: {e}")
        return info

    async def _fetch_ssl_info(self, hostname: str) -> Dict[str, Any]:
        info = {"has_ssl": False, "is_expired": False, "issuer_org": None, "san": []}
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            conn = asyncio.open_connection(hostname, 443, ssl=context)
            reader, writer = await asyncio.wait_for(conn, timeout=3.0)
            ssl_obj = writer.get_extra_info("ssl_object")
            cert = ssl_obj.getpeercert(binary_form=False) or {}
            writer.close()
            await writer.wait_closed()
            
            info["has_ssl"] = True
            issuer = dict(x[0] for x in cert.get("issuer", []))
            info["issuer_org"] = issuer.get("organizationName") or issuer.get("commonName")
            
            not_after_str = cert.get("notAfter")
            if not_after_str:
                exp_date = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                if datetime.now(timezone.utc) > exp_date:
                    info["is_expired"] = True
            
            sans = [val for key, val in cert.get("subjectAltName", []) if key == "DNS"]
            info["san"] = sans[:10]
        except Exception as e:
            logger.debug(f"SSL handshake failed for {hostname}: {e}")
        return info

    async def _fetch_crt_sh(self, domain: str) -> Dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                res = await client.get(f"https://crt.sh/?q=%.{domain}&output=json")
                if res.status_code == 200 and res.json():
                    return {"cert_count": len(res.json())}
        except Exception:
            pass
        return {"cert_count": 0}

    async def _fetch_ip_reputation(self, ip: str) -> Dict[str, Any]:
        info = {"ip": ip, "abuse_score": 0, "country": None, "asn": None}
        if settings.ABUSEIPDB_API_KEY:
            try:
                headers = {"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"}
                async with httpx.AsyncClient(timeout=3.0) as client:
                    resp = await client.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}", headers=headers)
                    if resp.status_code == 200:
                        data = resp.json().get("data", {})
                        info["abuse_score"] = data.get("abuseConfidenceScore", 0)
                        info["country"] = data.get("countryCode")
                        info["asn"] = data.get("isp")
                        return info
            except Exception:
                pass
        
        # Fallback to ipapi.co free endpoint
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get(f"https://ipapi.co/{ip}/json/")
                if resp.status_code == 200:
                    data = resp.json()
                    info["country"] = data.get("country_code")
                    info["asn"] = data.get("org")
        except Exception:
            pass
        return info
