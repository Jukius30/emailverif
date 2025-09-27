# email_verifier_gui.py

import os
import csv
import queue
import threading
import socket
import ssl
from typing import Optional, Tuple, List

import pandas as pd
import tldextract
from email_validator import validate_email, EmailNotValidError
import dns.resolver

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# ===== Optional deps (graceful) =====
_HAS_SOCKS = False
_HAS_REQUESTS = False
try:
    import socks  # PySocks
    _HAS_SOCKS = True
except Exception:
    pass

try:
    import requests
    _HAS_REQUESTS = True
except Exception:
    pass

# ------------- SMTP settings (ENV) -------------
SMTP_HELO_DOMAIN        = os.getenv("SMTP_HELO_DOMAIN", "example.com")
SMTP_MAIL_FROM          = os.getenv("SMTP_MAIL_FROM", "probe@example.com")
SMTP_PORT               = int(os.getenv("SMTP_PORT", "25"))
SMTP_CONNECT_TIMEOUT    = float(os.getenv("SMTP_CONNECT_TIMEOUT", "8.0"))
SMTP_READ_TIMEOUT       = float(os.getenv("SMTP_READ_TIMEOUT", "25.0"))
SMTP_PREFER_IPV4        = os.getenv("SMTP_PREFER_IPV4", "true").lower() == "true"
SMTP_TLS                = os.getenv("SMTP_TLS", "false").lower() == "true"
SMTP_PRECHECK           = os.getenv("SMTP_PRECHECK", "true").lower() == "true"

# === NEW: Probe strategy & fallbacks ===
# auto | local | proxy | remote
PROBE_STRATEGY          = os.getenv("PROBE_STRATEGY", "auto").lower().strip()

# SOCKS/HTTP proxy, contoh:
# PROXY_URL=socks5h://user:pass@host:1080  (socks5h recommended)
# PROXY_URL=http://user:pass@host:8080     (HTTP CONNECT)
PROXY_URL               = os.getenv("PROXY_URL", "").strip()

# Remote probe API (self-hosted): POST {email} or {email, domain}
# Expect response JSON: {"ok": true/false, "detail": "rcpt:250 ..."}
REMOTE_PROBE_URL        = os.getenv("REMOTE_PROBE_URL", "").strip()
REMOTE_API_KEY          = os.getenv("REMOTE_API_KEY", "").strip()  # optional auth header

# ---------------------- Utils ----------------------

def normalize_registered_domain(domain: str) -> str:
    ext = tldextract.extract(domain)
    if not ext.domain:
        return ""
    rd = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    return rd.lower()

def company_match(email_domain: str, company: Optional[str], company_domain: Optional[str]):
    if company_domain:
        expected = normalize_registered_domain(company_domain.strip())
        actual = normalize_registered_domain(email_domain)
        if not expected:
            return None, "company_domain_empty"
        ok = (expected == actual)
        return ok, f"company_domain_match:{expected}=={actual}:{ok}"
    if company:
        ext = tldextract.extract(email_domain)
        sld = ext.domain.lower() if ext.domain else ""
        tokens = [t for t in ''.join(ch if ch.isalnum() else ' ' for ch in company.lower()).split() if len(t) >= 3]
        ok = any(t in sld for t in tokens) if tokens and sld else None
        return ok, f"company_fuzzy:{tokens} in {sld}:{ok}"
    return None, "company_not_provided"

def dns_check(domain: str):
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        mx_found = len(answers) > 0
        return True, mx_found, f"mx={mx_found}"
    except Exception:
        try:
            dns.resolver.resolve(domain, 'A')
            return True, False, "mx=False;A=True"
        except Exception:
            try:
                dns.resolver.resolve(domain, 'AAAA')
                return True, False, "mx=False;AAAA=True"
            except Exception as e_ip:
                return False,
