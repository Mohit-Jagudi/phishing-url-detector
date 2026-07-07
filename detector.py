import ipaddress
import re
import sys
from urllib.parse import urlparse


def _hostname(url):
    parsed = urlparse(url if "://" in url else "http://" + url)
    return (parsed.hostname or "").lower(), parsed
SUSPICIOUS_TLDS = {
    "xyz", "tk", "top", "ml", "ga", "cf", "gq", "buzz", "club",
    "work", "link", "click", "rest", "zip", "country", "stream",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
    "shorturl.at", "rb.gy",
}

SUSPICIOUS_KEYWORDS = {
    "verify", "account", "update", "secure",
    "banking", "login", "signin",
    "confirm", "password",
    "credential", "wallet",
    "suspend", "unlock",
    "invoice", "urgent",
}

COMMON_BRANDS = {
    "paypal", "apple", "amazon",
    "google", "microsoft",
    "netflix", "facebook",
    "instagram", "whatsapp",
    "icloud", "outlook",
    "sbi", "hdfc", "icici",
    "paytm",
}

def check_suspicious_tld(url):
    """Rule: TLD is commonly abused for phishing campaigns."""
    host, _ = _hostname(url)
    return host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS if "." in host else False


def check_no_https(url):
    """Rule: page is not served over HTTPS."""
    _, parsed = _hostname(url)
    return parsed.scheme != "https"


def check_url_shortener(url):
    """Rule: URL shorteners hide the real destination."""
    host, _ = _hostname(url)
    return host in URL_SHORTENERS


def check_hyphenated_brand(url):
    """Rule: brand name combined with hyphens, e.g. pay-pal-secure.com."""
    host, _ = _hostname(url)
    if "-" not in host:
        return False
    squashed = host.replace("-", "")
    return any(brand in squashed for brand in COMMON_BRANDS)

def check_punycode(url):
    """Rule: punycode ('xn--') domains can disguise homoglyph attacks."""
    host, _ = _hostname(url)
    return "xn--" in host


def check_suspicious_keywords(url):
    """Rule: phishing bait keywords appear in the URL."""
    lowered = url.lower()
    return sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in lowered) >= 2


def check_double_slash_redirect(url):
    """Rule: '//' appearing in the path indicates a redirect trick."""
    _, parsed = _hostname(url)
    return "//" in parsed.path


def check_encoded_chars(url):
    """Rule: heavy use of percent-encoding or hex to obscure the URL."""
    return len(re.findall(r"%[0-9a-fA-F]{2}", url)) >= 3

RULES = [
    (check_ip_address, 30, "Hostname is a raw IP address"),
    (check_url_length, 10, "URL is unusually long (>75 chars)"),
    (check_at_symbol, 25, "Contains '@' symbol (address-hiding trick)"),
    (check_subdomain_count, 20, "Excessive number of subdomains"),
    (check_suspicious_tld, 15, "Uses a TLD commonly abused for phishing"),
    (check_no_https, 10, "Not served over HTTPS"),
    (check_url_shortener, 15, "Uses a URL-shortening service"),
    (check_hyphenated_brand, 25, "Brand name obfuscated with hyphens"),
    (check_punycode, 25, "Punycode domain (possible homoglyph attack)"),
    (check_suspicious_keywords, 15, "Multiple phishing bait keywords"),
    (check_double_slash_redirect, 15, "Double-slash redirect in path"),
    (check_encoded_chars, 10, "Heavy percent-encoding in URL"),
]


def analyze_url(url):
    """Run all rules against a URL.

    Returns a dict with score, verdict, and triggered rule details.
    """
    url = url.strip()
    if not url:
        raise ValueError("URL must not be empty")

    triggered = []
    score = 0
    for rule, weight, reason in RULES:
        try:
            hit = rule(url)
        except Exception:  # malformed URLs should not crash a single rule
            hit = False
        if hit:
            score += weight
            triggered.append({"rule": rule.__name__, "weight": weight, "reason": reason})

    if score >= 50:
        verdict = "PHISHING"
    elif score >= 20:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    return {"url": url, "score": score, "verdict": verdict, "triggered_rules": triggered}


