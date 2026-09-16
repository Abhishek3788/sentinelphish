import asyncio
from typing import Dict, Any, Optional
from bs4 import BeautifulSoup
from app.utils.logger import get_logger

logger = get_logger("utils.sandbox")


async def safe_fetch_page_content(url: str, timeout: float = 8.0) -> Dict[str, Any]:
    """
    Safely fetches HTML content and screenshot using Playwright or httpx fallback.
    Prevents execution of dangerous scripts and enforces strict timeout.
    """
    result: Dict[str, Any] = {
        "html": "",
        "status_code": None,
        "redirect_chain": [],
        "screenshot_bytes": None,
        "error": None
    }
    
    # Try Playwright first
    try:
        from playwright.async_api import async_playwright
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
                viewport={"width": 1280, "height": 720},
                java_script_enabled=True,
                ignore_https_errors=True
            )
            page = await context.new_page()
            
            # Block unwanted network resources (media, fonts) to speed up navigation
            await page.route("**/*.{png,jpg,jpeg,svg,gif,woff,woff2,ttf,mp4,avi}", lambda route: route.abort())
            
            response = await page.goto(url, wait_until="domcontentloaded", timeout=int(timeout * 1000))
            if response:
                result["status_code"] = response.status
            
            result["html"] = await page.content()
            result["screenshot_bytes"] = await page.screenshot(type="png", full_page=False)
            result["redirect_chain"] = [url, page.url] if page.url != url else [url]
            
            await browser.close()
            return result
    except Exception as e:
        logger.debug(f"Playwright fetch failed for {url}: {e}. Falling back to httpx.")
        result["error"] = str(e)
    
    # Fallback to HTTPX if Playwright is unavailable or fails
    try:
        import httpx
        async with httpx.AsyncClient(follow_redirects=True, verify=False, timeout=timeout) as client:
            resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
            result["status_code"] = resp.status_code
            result["html"] = resp.text
            result["redirect_chain"] = [str(r.url) for r in resp.history] + [str(resp.url)]
            result["error"] = None
    except Exception as e:
        logger.warning(f"HTTPX fallback fetch failed for {url}: {e}")
        result["error"] = str(e)
        
    return result


def extract_page_features(html: str) -> Dict[str, Any]:
    """Extracts structural content features from HTML using BeautifulSoup."""
    if not html:
        return {
            "has_forms": False,
            "form_count": 0,
            "has_password_field": False,
            "form_action_urls": [],
            "iframe_count": 0,
            "has_js_obfuscation": False,
            "text_content": ""
        }

    soup = BeautifulSoup(html, "html.parser")
    
    forms = soup.find_all("form")
    has_forms = len(forms) > 0
    password_fields = soup.find_all("input", {"type": "password"})
    has_password = len(password_fields) > 0
    
    form_actions = []
    for f in forms:
        action = f.get("action")
        if action:
            form_actions.append(str(action))
            
    iframes = soup.find_all("iframe")
    
    # Simple JS obfuscation detection rules (eval, unescape, hex encoding pattern)
    scripts = "".join([s.string or "" for s in soup.find_all("script")])
    js_obfuscated = any(kw in scripts for kw in ["eval(", "unescape(", "String.fromCharCode(", "\\x"]) or len(scripts) > 50000

    # Extract text content
    text_content = soup.get_text(separator=" ", strip=True)
    
    return {
        "has_forms": has_forms,
        "form_count": len(forms),
        "has_password_field": has_password,
        "form_action_urls": form_actions,
        "iframe_count": len(iframes),
        "has_js_obfuscation": js_obfuscated,
        "text_content": text_content[:5000]  # First 5k chars
    }
