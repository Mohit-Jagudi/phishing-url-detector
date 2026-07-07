import ipaddress
import re
import sys
from urllib.parse import urlparse


def _hostname(url):
    parsed = urlparse(url if "://" in url else "http://" + url)
    return (parsed.hostname or "").lower(), parsed
