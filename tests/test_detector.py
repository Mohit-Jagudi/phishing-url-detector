import pytest
# Import detector functions
from detector import (
    analyze_url,
    check_at_symbol,
    check_hyphenated_brand,
    check_ip_address,
    check_no_https,
    check_punycode,
    check_subdomain_count,
    check_suspicious_keywords,
    check_suspicious_tld,
    check_url_length,
    check_url_shortener,
)

# Tests for individual detection rules
class TestIndividualRules:
    def test_ip_address_detected(self):
        assert check_ip_address("http://192.168.1.1/login")

    def test_domain_not_flagged_as_ip(self):
        assert not check_ip_address("https://gitlab.com")

    def test_long_url(self):
        assert check_url_length("http://example.com/" + "a" * 100)

    def test_short_url(self):
        assert not check_url_length("https://gitlab.com")

    def test_at_symbol(self):
        assert check_at_symbol("http://google.com@evil.com")

    def test_subdomains(self):
        assert check_subdomain_count("http://paypal.com.secure.login.evil.xyz")

    def test_suspicious_tld(self):
        assert check_suspicious_tld("http://free-prizes.xyz")

    def test_normal_tld(self):
        assert not check_suspicious_tld("https://example.com")

    def test_no_https(self):
        assert check_no_https("http://example.com")
        assert not check_no_https("https://example.com")

    def test_shortener(self):
        assert check_url_shortener("https://bit.ly/3xYz")

    def test_hyphenated_brand(self):
        assert check_hyphenated_brand("http://pay-pal-secure.com")

    def test_punycode(self):
        assert check_punycode("http://xn--pypal-4ve.com")

    def test_keywords(self):
        assert check_suspicious_keywords("http://evil.com/verify-account-login")

# Tests for complete URL analysis
class TestAnalyzeUrl:
    def test_safe_url(self):
        result = analyze_url("https://gitlab.com")
        assert result["verdict"] == "SAFE"

    def test_phishing_url(self):
        result = analyze_url("http://paypal.com.verify-account.secure.xyz/login//redirect")
        assert result["verdict"] == "PHISHING"
        assert result["score"] >= 50

    def test_ip_based_url_is_flagged(self):
        result = analyze_url("http://203.0.113.5/secure/verify/login")
        assert result["verdict"] in ("SUSPICIOUS", "PHISHING")

    def test_empty_url_raises(self):
        with pytest.raises(ValueError):
            analyze_url("   ")
          
# Verify returned data format
    def test_result_structure(self):
        result = analyze_url("https://example.com")
        assert set(result) == {"url", "score", "verdict", "triggered_rules"}
