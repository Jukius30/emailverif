# email_verifier_gui.py

import os
import csv
import queue
import threading
import socket
import ssl
import re
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
    import socks  # PySocks (opsional, hanya jika pakai proxy)
    _HAS_SOCKS = True
except Exception:
    pass

try:
    import requests  # (opsional, hanya jika pakai remote probe)
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

# === Probe strategy & fallbacks ===
# auto | local | proxy | remote
PROBE_STRATEGY          = os.getenv("PROBE_STRATEGY", "auto").lower().strip()
PROXY_URL               = os.getenv("PROXY_URL", "").strip()            # e.g. socks5h://user:pass@host:1080
REMOTE_PROBE_URL        = os.getenv("REMOTE_PROBE_URL", "").strip()     # HTTP API endpoint (self-hosted)
REMOTE_API_KEY          = os.getenv("REMOTE_API_KEY", "").strip()

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
        tokens = [t for t in ''.join(ch if ch.isalnum() else ' ' for ch in (company or "").lower()).split() if len(t) >= 3]
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
                return False, False, f"dns_failed:{e_ip}"

def mx_hosts(domain: str):
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        return sorted(answers, key=lambda r: r.preference)
    except Exception:
        return []

def has_spf(domain: str) -> bool:
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for r in answers:
            txt = "".join([b.decode(errors='ignore') if isinstance(b, bytes) else str(b) for b in r.strings]) if hasattr(r, 'strings') else str(r)
            if "v=spf1" in txt.lower():
                return True
    except Exception:
        pass
    return False

def has_dmarc(domain: str) -> bool:
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        for r in answers:
            txt = "".join([b.decode(errors='ignore') if isinstance(b, bytes) else str(b) for b in r.strings]) if hasattr(r, 'strings') else str(r)
            if "v=dmarc1" in txt.lower():
                return True
    except Exception:
        pass
    return False

FREE_MAIL = {
    "gmail.com","yahoo.com","outlook.com","hotmail.com","live.com","aol.com",
    "icloud.com","yandex.com","proton.me","protonmail.com","zoho.com","gmx.com","mail.com"
}

def _getaddrinfos(host: str, port: int):
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if SMTP_PREFER_IPV4:
        infos.sort(key=lambda x: x[0] != socket.AF_INET)
    return infos

def can_reach_port25(test_host: str = "gmail-smtp-in.l.google.com", port: int = None) -> bool:
    p = port if port is not None else SMTP_PORT
    try:
        infos = _getaddrinfos(test_host, p)
        last_exc = None
        for family, socktype, proto, _, sockaddr in infos:
            try:
                s = socket.socket(family, socktype, proto)
                s.settimeout(min(SMTP_CONNECT_TIMEOUT, 5.0))
                s.connect(sockaddr)
                s.close()
                return True
            except Exception as e:
                last_exc = e
                continue
        return False
    except Exception:
        return False

# ---------------------- Socket helpers ----------------------

def _plain_socket_connect(host: str, port: int, connect_timeout: float) -> socket.socket:
    infos = _getaddrinfos(host, port)
    last_exc = None
    for family, socktype, proto, _, sockaddr in infos:
        try:
            s = socket.socket(family, socktype, proto)
            s.settimeout(connect_timeout)
            s.connect(sockaddr)
            return s
        except Exception as e:
            last_exc = e
            continue
    raise last_exc or OSError("no usable address")

def _proxy_socket_connect(host: str, port: int, connect_timeout: float, proxy_url: str) -> socket.socket:
    if not _HAS_SOCKS:
        raise RuntimeError("PySocks not installed (pip install PySocks)")
    import urllib.parse
    u = urllib.parse.urlparse(proxy_url)
    scheme = u.scheme.lower()
    if scheme in ("socks5", "socks5h"):
        ptype = socks.SOCKS5
    elif scheme in ("socks4", "socks4a"):
        ptype = socks.SOCKS4
    elif scheme in ("http", "https"):
        ptype = socks.HTTP
    else:
        raise ValueError(f"Unsupported proxy scheme: {scheme}")

    proxy_host = u.hostname
    proxy_port = u.port or (1080 if "socks" in scheme else 8080)
    proxy_username = u.username
    proxy_password = u.password
    rdns = scheme.endswith("h") or scheme.endswith("a")  # socks5h/socks4a = remote DNS

    s = socks.socksocket()
    s.set_proxy(ptype, proxy_host, proxy_port, rdns=rdns, username=proxy_username, password=proxy_password)
    s.settimeout(connect_timeout)
    s.connect((host, port))
    return s

# ---------------------- SMTP probe backends ----------------------

def _recv_block(f, sock, read_timeout: float, prefixes=(b'2', b'3')) -> Tuple[str, bool]:
    lines = []
    sock.settimeout(read_timeout)
    while True:
        line = f.readline()
        if not line:
            break
        lines.append(line)
        if len(line) >= 4 and line[3:4] != b'-':
            break
    text = b''.join(lines).decode(errors='ignore')
    return text, (text[:1].encode() in prefixes)

def _smtp_session(sock: socket.socket, host: str, recipient: str) -> Tuple[bool, str]:
    f = sock.makefile('rwb', buffering=0)

    banner, ok = _recv_block(f, sock, SMTP_READ_TIMEOUT, prefixes=(b'2',))
    if not ok:
        return False, f"banner:{banner.strip()}"

    def send(cmd: str):
        f.write(cmd.encode() + b"\r\n")

    # EHLO -> (optional) STARTTLS -> EHLO
    send(f"EHLO {SMTP_HELO_DOMAIN}")
    resp, ok = _recv_block(f, sock, SMTP_READ_TIMEOUT)
    if not ok:
        send(f"HELO {SMTP_HELO_DOMAIN}")
        resp, ok = _recv_block(f, sock, SMTP_READ_TIMEOUT)

    if SMTP_TLS and "STARTTLS" in resp.upper():
        send("STARTTLS")
        tls_resp, ok_tls = _recv_block(f, sock, SMTP_READ_TIMEOUT, prefixes=(b'2',))
        if ok_tls:
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=host)
            f = sock.makefile('rwb', buffering=0)
            send(f"EHLO {SMTP_HELO_DOMAIN}")
            resp, ok = _recv_block(f, sock, SMTP_READ_TIMEOUT)

    send(f"MAIL FROM:<{SMTP_MAIL_FROM}>")
    resp, ok = _recv_block(f, sock, SMTP_READ_TIMEOUT)
    if not ok:
        send("QUIT")
        _ = _recv_block(f, sock, SMTP_READ_TIMEOUT)
        return False, f"mailfrom:{resp.strip()}"

    send(f"RCPT TO:<{recipient}>")
    resp, _ = _recv_block(f, sock, SMTP_READ_TIMEOUT, prefixes=(b'2', b'3'))

    send("QUIT")
    _ = _recv_block(f, sock, SMTP_READ_TIMEOUT)

    r = resp.strip()
    if r.startswith("250"):
        return True, f"rcpt:{r}"
    elif r.startswith(("450", "451", "452")):
        return False, f"rcpt_tempfail:{r}"
    else:
        return False, f"rcpt:{r}"

def smtp_probe_local(recipient: str, mx_records) -> Tuple[bool, str]:
    mx_list: List = list(mx_records) if mx_records else []
    last = "no_mx_reachable"
    for mx in mx_list:
        host = str(mx.exchange).rstrip('.') if hasattr(mx, 'exchange') else str(mx).rstrip('.')
        try:
            sock = _plain_socket_connect(host, SMTP_PORT, SMTP_CONNECT_TIMEOUT)
            try:
                ok, detail = _smtp_session(sock, host, recipient)
                sock.close()
                return ok, detail
            except Exception as e:
                last = f"io_error:{host}:{e}"
                try: sock.close()
                except: pass
                continue
        except Exception as e:
            last = f"conn_error:{host}:{e}"
            continue
    return False, last

def smtp_probe_proxy(recipient: str, mx_records) -> Tuple[bool, str]:
    if not PROXY_URL:
        return False, "proxy_not_configured"
    if not _HAS_SOCKS:
        return False, "pysocks_not_installed"
    mx_list: List = list(mx_records) if mx_records else []
    last = "no_mx_reachable"
    for mx in mx_list:
        host = str(mx.exchange).rstrip('.') if hasattr(mx, 'exchange') else str(mx).rstrip('.')
        try:
            sock = _proxy_socket_connect(host, SMTP_PORT, SMTP_CONNECT_TIMEOUT, PROXY_URL)
            try:
                ok, detail = _smtp_session(sock, host, recipient)
                sock.close()
                return ok, detail
            except Exception as e:
                last = f"proxy_io_error:{host}:{e}"
                try: sock.close()
                except: pass
                continue
        except Exception as e:
            last = f"proxy_conn_error:{host}:{e}"
            continue
    return False, last

def smtp_probe_remote(recipient: str, domain: str) -> Tuple[bool, str]:
    if not REMOTE_PROBE_URL:
        return False, "remote_not_configured"
    if not _HAS_REQUESTS:
        return False, "requests_not_installed"
    try:
        headers = {}
        if REMOTE_API_KEY:
            headers["Authorization"] = f"Bearer {REMOTE_API_KEY}"
        r = requests.post(REMOTE_PROBE_URL, json={"email": recipient, "domain": domain}, headers=headers,
                          timeout=SMTP_CONNECT_TIMEOUT + SMTP_READ_TIMEOUT)
        r.raise_for_status()
        data = r.json()
        ok = bool(data.get("ok"))
        detail = str(data.get("detail", ""))
        return ok, detail or ("remote_ok" if ok else "remote_fail")
    except Exception as e:
        return False, f"remote_error:{e}"

# ---------------------- NEW: Heuristic fallback ----------------------

def _looks_random_local(local: str) -> bool:
    s = "".join(ch for ch in local if ch.isalnum())
    return len(local) >= 20 and len(s) / max(1, len(local)) > 0.9

def smtp_probe_heuristic(recipient: str, domain: str) -> Tuple[Optional[bool], str]:
    try:
        local = recipient.split("@", 1)[0]
    except Exception:
        local = ""

    dom_ok, has_mx, _ = dns_check(domain)
    spf = has_spf(domain) if dom_ok else False
    dmarc = has_dmarc(domain) if dom_ok else False
    free = domain.lower() in FREE_MAIL
    randomish = _looks_random_local(local)

    score = 0.5
    signals = []

    if dom_ok:
        signals.append("dns"); score += 0.1
    if has_mx:
        signals.append("mx"); score += 0.2
    else:
        signals.append("no-mx")
    if spf:
        signals.append("spf"); score += 0.1
    if dmarc:
        signals.append("dmarc"); score += 0.1
    if free:
        signals.append("free-mail"); score -= 0.1
    if randomish:
        signals.append("random-local"); score -= 0.2

    score = max(0.0, min(1.0, score))
    detail = f"heuristic:score={score:.2f},signals={','.join(signals) or '-'}"
    return None, detail

# ---------------------- Router ----------------------

def smtp_probe_best(recipient: str, mx_records, domain: str, port25_available: bool) -> Tuple[Optional[bool], str]:
    strat = PROBE_STRATEGY
    if strat == "auto":
        if port25_available:
            return smtp_probe_local(recipient, mx_records)
        if PROXY_URL:
            return smtp_probe_proxy(recipient, mx_records)
        if REMOTE_PROBE_URL:
            return smtp_probe_remote(recipient, domain)
        return smtp_probe_heuristic(recipient, domain)
    elif strat == "local":
        if not port25_available:
            return smtp_probe_heuristic(recipient, domain)
        return smtp_probe_local(recipient, mx_records)
    elif strat == "proxy":
        ok, d = smtp_probe_proxy(recipient, mx_records)
        if "proxy_" in (d or ""):
            return smtp_probe_heuristic(recipient, domain)
        return ok, d
    elif strat == "remote":
        ok, d = smtp_probe_remote(recipient, domain)
        if "remote_" in (d or ""):
            return smtp_probe_heuristic(recipient, domain)
        return ok, d
    else:
        return smtp_probe_heuristic(recipient, domain)

# ---------------------- Heuristics for column detection ----------------------

EMAIL_REGEX = re.compile(r"^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$", re.IGNORECASE)

def resolve_column_case_insensitive(df: pd.DataFrame, hint: Optional[str]) -> Optional[str]:
    if not hint:
        return None
    if hint in df.columns:
        return hint
    hint_low = hint.lower()
    for c in df.columns:
        if isinstance(c, str) and c.lower() == hint_low:
            return c
    return None

def autodetect_columns(df: pd.DataFrame, email_hint: str, company_hint: str) -> Tuple[Optional[str], Optional[str]]:
    email_col = resolve_column_case_insensitive(df, email_hint)
    company_col = resolve_column_case_insensitive(df, company_hint)

    if email_col is None:
        candidates = []
        for c in df.columns:
            try:
                cnt = df[c].astype(str).str.fullmatch(EMAIL_REGEX).sum()
            except Exception:
                cnt = 0
            candidates.append((cnt, c))
        candidates.sort(reverse=True)
        if candidates and candidates[0][0] > 0:
            email_col = candidates[0][1]

    if company_col is None:
        best = None
        for c in df.columns:
            if c == email_col:
                continue
            s = df[c].astype(str)
            try:
                if s.str.fullmatch(EMAIL_REGEX).mean() > 0.3:
                    continue
            except Exception:
                pass
            avg_len = s.str.len().mean()
            best = (avg_len, c) if (best is None or avg_len > best[0]) else best
        if best:
            company_col = best[1]

    return email_col, company_col

# ---------------------- Verifier core ----------------------

def verify_one(email: str, company: Optional[str], company_domain: Optional[str], do_smtp: bool, port25_available: bool):
    reason = []
    steps = []

    # Syntax (case-insensitive)
    try:
        v = validate_email(email.casefold(), check_deliverability=False)
        norm_email = v.email
        local = v.local_part
        domain = v.domain
        steps.append("syntax:OK")
    except EmailNotValidError as e:
        steps.append(f"syntax:ERR:{e}")
        return {
            "verif_syntax_ok": False, "verif_domain_ok": False, "verif_mx_found": False,
            "verif_smtp_deliverable": None, "verif_company_ok": None,
            "verif_registered_domain": None, "verif_reason": f"syntax:{e}",
            "email_norm": email, "email_local": None, "email_domain": None,
            "steps": " | ".join(steps)
        }

    dom_ok, has_mx, reason_dns = dns_check(domain)
    reason.append(reason_dns)
    steps.append(f"dns:{'OK' if dom_ok else 'ERR'};{reason_dns}")

    smtp_ok: Optional[bool] = None
    smtp_detail = ""
    if do_smtp and has_mx:
        mhosts = mx_hosts(domain)
        smtp_ok, smtp_detail = smtp_probe_best(norm_email, mhosts, domain, port25_available)
        if smtp_detail.startswith("heuristic:"):
            steps.append(f"smtp:EST;{smtp_detail}")
        else:
            if smtp_ok is None:
                steps.append(f"smtp:N/A;{smtp_detail}")
            else:
                tag = "OK" if smtp_ok else "NO"
                steps.append(f"smtp:{tag};{smtp_detail}")
        if smtp_detail:
            reason.append(smtp_detail)
    else:
        steps.append("smtp:SKIP")

    comp_ok, comp_reason = company_match(domain, (company or "").casefold() if company else None, company_domain)
    reason.append(comp_reason)
    if comp_ok is True:
        steps.append("company:OK")
    elif comp_ok is False:
        steps.append("company:NO")
    else:
        steps.append("company:N/A")

    return {
        "verif_syntax_ok": True, "verif_domain_ok": dom_ok, "verif_mx_found": has_mx,
        "verif_smtp_deliverable": smtp_ok, "verif_company_ok": comp_ok,
        "verif_registered_domain": normalize_registered_domain(domain),
        "verif_reason": ";".join([r for r in reason if r]),
        "email_norm": norm_email, "email_local": local, "email_domain": domain,
        "steps": " | ".join(steps)
    }

# ---------------------- GUI ----------------------

class VerifierGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Email Verifier - CSV Cleaner (Live Progress)")
        self.geometry("1040x740")
        self.minsize(980, 700)

        self.input_path = tk.StringVar()
        self.input_folder_mode = tk.BooleanVar(value=False)  # NEW: folder mode
        self.output_prefix = tk.StringVar(value="verified")
        self.output_name = tk.StringVar(value="")  # custom filename (optional, no extension)
        self.email_col = tk.StringVar(value="email")
        self.company_col = tk.StringVar(value="company")
        self.company_domain_col = tk.StringVar(value="company_domain")
        self.use_smtp = tk.BooleanVar(value=False)
        self.output_format = tk.StringVar(value="csv")
        self.verbose = tk.BooleanVar(value=True)
        self.live_table = tk.BooleanVar(value=True)

        self._build_widgets()
        self.queue = queue.Queue()
        self.worker: Optional[threading.Thread] = None

    # -------- UI helpers ----------
    def _suggest_columns(self, headers: List[str]):
        email_guess = next((h for h in headers if 'email' in h.lower()), None)
        if email_guess:
            self.email_col.set(email_guess)
        company_guess = next((h for h in headers if any(k in h.lower() for k in ['company','perusahaan','org','organization'])), None)
        if company_guess:
            self.company_col.set(company_guess)

    def _build_widgets(self):
        pad = {"padx": 10, "pady": 6}
        frm = ttk.Frame(self); frm.pack(fill="x", **pad)

        ttk.Label(frm, text="Input CSV/Folder").grid(row=0, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.input_path, width=60).grid(row=0, column=1, sticky="we", padx=6)
        ttk.Button(frm, text="Browse...", command=self.browse_file).grid(row=0, column=2)
        ttk.Checkbutton(frm, text="Proses seluruh folder (CSV/XLSX)", variable=self.input_folder_mode).grid(row=0, column=3, padx=5)

        ttk.Label(frm, text="Output Filename (tanpa ekstensi)").grid(row=1, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.output_name, width=30).grid(row=1, column=1, sticky="w")

        ttk.Label(frm, text="Email Column").grid(row=2, column=0, sticky="w")
        self.email_combo = ttk.Combobox(frm, textvariable=self.email_col, width=28, state="readonly")
        self.email_combo.grid(row=2, column=1, sticky="w")

        ttk.Label(frm, text="Company Column").grid(row=3, column=0, sticky="w")
        self.company_combo = ttk.Combobox(frm, textvariable=self.company_col, width=28, state="readonly")
        self.company_combo.grid(row=3, column=1, sticky="w")

        ttk.Label(frm, text="Company Domain Column").grid(row=4, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.company_domain_col, width=28).grid(row=4, column=1, sticky="w")

        ttk.Label(frm, text="Output Prefix (default)").grid(row=5, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.output_prefix, width=20).grid(row=5, column=1, sticky="w")

        opts = ttk.Frame(frm); opts.grid(row=6, column=1, sticky="w")
        ttk.Checkbutton(opts, text="SMTP probe (lebih akurat, bisa lambat)", variable=self.use_smtp).pack(anchor="w")

        row2 = ttk.Frame(frm); row2.grid(row=7, column=1, sticky="w")
        ttk.Label(frm, text="Output Format").grid(row=7, column=0, sticky="w")
        ttk.Combobox(row2, textvariable=self.output_format, values=["csv", "excel"], width=10, state="readonly").pack(side="left")
        ttk.Checkbutton(row2, text="Verbose log", variable=self.verbose).pack(side="left", padx=10)
        ttk.Checkbutton(row2, text="Live table", variable=self.live_table).pack(side="left", padx=10)

        btnfrm = ttk.Frame(self); btnfrm.pack(fill="x", **pad)
        self.run_btn = ttk.Button(btnfrm, text="Run Verification", command=self.run_verification); self.run_btn.pack(side="left")
        self.stop_btn = ttk.Button(btnfrm, text="Stop", command=self.stop_verification, state="disabled"); self.stop_btn.pack(side="left", padx=8)

        pfrm = ttk.Frame(self); pfrm.pack(fill="x", **pad)
        self.current_label = ttk.Label(pfrm, text="Current: -", anchor="w"); self.current_label.pack(fill="x")
        self.prog = ttk.Progressbar(pfrm, mode="determinate"); self.prog.pack(fill="x")

        tfrm = ttk.LabelFrame(self, text="Live Results"); tfrm.pack(fill="both", expand=True, padx=10, pady=(0,6))
        cols = ("email", "syntax", "domain", "mx", "smtp", "company", "deliverable", "reason")
        self.tree = ttk.Treeview(tfrm, columns=cols, show="headings", height=8)
        for c in cols: self.tree.heading(c, text=c.capitalize())
        self.tree.column("email", width=240)
        self.tree.column("syntax", width=70, anchor="center")
        self.tree.column("domain", width=70, anchor="center")
        self.tree.column("mx", width=60, anchor="center")
        self.tree.column("smtp", width=80, anchor="center")
        self.tree.column("company", width=80, anchor="center")
        self.tree.column("deliverable", width=90, anchor="center")
        self.tree.column("reason", width=380)
        self.tree.pack(fill="both", expand=True)

        lfrm = ttk.LabelFrame(self, text="Verbose Log"); lfrm.pack(fill="both", expand=True, padx=10, pady=(0,10))
        self.log = tk.Text(lfrm, height=8); self.log.pack(fill="both", expand=True)

        self.status = ttk.Label(self, text="Ready", anchor="w"); self.status.pack(fill="x")

        for i in range(4):
            frm.grid_columnconfigure(i, weight=(1 if i == 1 else 0))

        self.after(100, self._poll_queue)

    def browse_file(self):
        # Folder mode: pilih folder
        if self.input_folder_mode.get():
            path = filedialog.askdirectory()
            if not path:
                return
            self.input_path.set(path)
            self.log_write(f"[INFO] Folder mode aktif → {path}")
            return

        # File tunggal
        path = filedialog.askopenfilename(filetypes=[("CSV/Excel files", "*.csv;*.xlsx"), ("All files", "*.*")])
        if not path:
            return
        self.input_path.set(path)

        # --- Deteksi header/delimiter untuk prefill combo kolom ---
        headers = []
        try:
            if path.lower().endswith(".xlsx"):
                df_temp = pd.read_excel(path, nrows=1)
                headers = list(df_temp.columns)
                self.log_write(f"[INFO] Detected Excel headers: {headers}")
            else:
                with open(path, "rb") as fb:
                    sample = fb.read(4096)
                for enc in ("utf-8", "cp1252", "latin-1"):
                    try:
                        text = sample.decode(enc, errors="strict")
                        break
                    except Exception:
                        text = None
                if text is None:
                    text = sample.decode("utf-8", errors="ignore")

                try:
                    dialect = csv.Sniffer().sniff(text, delimiters=[",", ";", "\t", "|"])
                    delim = dialect.delimiter
                except Exception:
                    delim = ","

                with open(path, "r", newline="", encoding="utf-8", errors="ignore") as f:
                    reader = csv.reader(f, delimiter=delim)
                    headers = next(reader, [])
                headers = [h.strip() for h in headers]
                self.log_write(f"[INFO] Detected delimiter: {repr(delim)}; headers: {headers}")
        except Exception as e:
            headers = []
            self.log_write(f"[WARN] Gagal deteksi header: {e}")

        if headers:
            self.email_combo['values'] = headers
            self.company_combo['values'] = headers
            self._suggest_columns(headers)

    def log_write(self, text: str):
        if not self.verbose.get(): return
        self.log.insert("end", text + "\n"); self.log.see("end")

    def set_status(self, text: str): self.status.config(text=text)
    def set_current(self, text: str): self.current_label.config(text=f"Current: {text}")

    def run_verification(self):
        if self.worker and self.worker.is_alive():
            messagebox.showwarning("Sedang berjalan", "Proses verifikasi masih berjalan."); return
        if not self.input_path.get():
            messagebox.showerror("Error", "Pilih file atau folder input."); return

        input_path = self.input_path.get()
        if os.path.isdir(input_path):
            files = [os.path.join(input_path, f) for f in os.listdir(input_path)
                     if f.lower().endswith((".csv", ".xlsx"))]
            if not files:
                messagebox.showwarning("Kosong", "Tidak ada file CSV/XLSX di folder itu.")
                return
            self.log_write(f"[INFO] Akan memproses {len(files)} file dalam folder: {input_path}")
        else:
            files = [input_path]

        self.run_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.log.delete("1.0", "end")
        for i in self.tree.get_children(): self.tree.delete(i)
        self.set_status("Memulai..."); self.set_current("-")

        args = {
            "files": files,
            "output_prefix": self.output_prefix.get() or "verified",
            "email_col": self.email_col.get().strip() or "email",
            "company_col": self.company_col.get().strip() or "company",
            "company_domain_col": self.company_domain_col.get().strip() or "company_domain",
            "smtp_check": self.use_smtp.get(),
            "output_format": self.output_format.get(),
            "live_table": self.live_table.get()
        }

        self.worker = threading.Thread(target=self._worker_run_folder, args=(args,), daemon=True)
        self._stop_flag = False
        self.worker.start()

    def stop_verification(self):
        self._stop_flag = True
        self.set_status("Meminta berhenti...")

    # ---- Folder runner: panggil _worker_run untuk setiap file ----
    def _worker_run_folder(self, args):
        total_files = len(args["files"])
        for idx, path in enumerate(args["files"], start=1):
            if getattr(self, "_stop_flag", False):
                self.queue.put(("log", f"Proses folder dihentikan di file {idx}/{total_files}"))
                break
            self.queue.put(("log", f"\n[=== File {idx}/{total_files}: {os.path.basename(path)} ===]"))
            sub_args = dict(args)
            sub_args["input"] = path
            sub_args["batch_mode"] = (total_files > 1 or os.path.isdir(self.input_path.get()))
            self._worker_run(sub_args)

    def _worker_run(self, args):
        input_path = args["input"]
        ext = os.path.splitext(input_path)[1].lower()

        # --- deteksi delimiter dari file CSV ---
        delim = ","
        if ext == ".csv":
            try:
                with open(input_path, "rb") as fb:
                    sample = fb.read(4096)
                for enc in ("utf-8", "cp1252", "latin-1"):
                    try:
                        text = sample.decode(enc, errors="strict")
                        break
                    except Exception:
                        text = None
                if text is None:
                    text = sample.decode("utf-8", errors="ignore")

                try:
                    dialect = csv.Sniffer().sniff(text, delimiters=[",",";","\t","|"])
                    delim = dialect.delimiter
                except Exception:
                    delim = ","
            except Exception:
                delim = ","

        # --- load DataFrame (CSV/Excel) ---
        try:
            if ext == ".xlsx":
                df = pd.read_excel(input_path, engine="openpyxl")
            else:
                df = pd.read_csv(input_path, sep=delim, engine="python")
            # trim header
            df.rename(columns=lambda c: c.strip() if isinstance(c, str) else c, inplace=True)
            self.queue.put(("log", f"[INFO] Loaded {os.path.basename(input_path)} "
                                   f"({'Excel' if ext=='.xlsx' else f'CSV sep={repr(delim)}'}) "
                                   f"columns={list(df.columns)}; rows={len(df)}"))
        except Exception as e:
            self.queue.put(("error", f"Gagal baca {os.path.basename(input_path)}: {e}")); return

        # ===== Case-insensitive resolve + autodetect fallback =====
        email_col, company_col = autodetect_columns(df, args["email_col"], args["company_col"])
        if not email_col:
            self.queue.put(("error", f"Kolom email tidak ditemukan & gagal autodetect. Kolom tersedia: {list(df.columns)}")); return
        args["email_col"] = email_col
        if company_col: args["company_col"] = company_col

        resolved_company_domain = resolve_column_case_insensitive(df, args["company_domain_col"])
        args["company_domain_col"] = resolved_company_domain if resolved_company_domain else args["company_domain_col"]

        self.queue.put(("log", f"[INFO] Using columns → email: {args['email_col']} | company: {args.get('company_col')} | company_domain: {args.get('company_domain_col')}"))

        # Port25 availability (sekali di awal)
        port25_available = True
        if SMTP_PRECHECK:
            port25_available = can_reach_port25()
            if not port25_available:
                self.queue.put(("log", f"WARNING: Outbound ke port 25 tampaknya diblokir/timeout. "
                                        f"Strategy={PROBE_STRATEGY}. "
                                        f"{'Proxy OK' if PROXY_URL else 'No proxy'}. "
                                        f"{'Remote OK' if REMOTE_PROBE_URL else 'No remote'}. "
                                        f'Heuristic fallback aktif.'))

        total = len(df)
        self.queue.put(("start", total))

        results = []
        for idx, row in df.iterrows():
            if getattr(self, "_stop_flag", False):
                self.queue.put(("log", f"Dihentikan di baris {idx+1}/{total}")); break

            raw_email = row[args["email_col"]]
            email_original = str(raw_email).strip() if pd.notna(raw_email) else ""
            email_for_check = email_original.casefold()

            company_val = None
            if args["company_col"] in df.columns and pd.notna(row[args["company_col"]]):
                company_val = str(row[args["company_col"]]).strip()
            company_domain_val = None
            if args["company_domain_col"] in df.columns and pd.notna(row[args["company_domain_col"]]):
                company_domain_val = str(row[args["company_domain_col"]]).strip()

            self.queue.put(("current", email_original if email_original else "-"))

            if not email_original:
                self.queue.put(("progress", idx+1)); continue

            res = verify_one(email_for_check, company_val, company_domain_val, args["smtp_check"], port25_available)

            if res["verif_smtp_deliverable"] is True:
                deliverable = True
            elif res["verif_smtp_deliverable"] is False:
                deliverable = False
            else:
                deliverable = bool(res["verif_syntax_ok"] and res["verif_domain_ok"] and res["verif_mx_found"])

            c = res["verif_company_ok"]
            company_pass = (c is None) or (c is True)

            out = {**row.to_dict(),
                   "verif_syntax_ok": res["verif_syntax_ok"],
                   "verif_domain_ok": res["verif_domain_ok"],
                   "verif_mx_found": res["verif_mx_found"],
                   "verif_smtp_deliverable": res["verif_smtp_deliverable"],
                   "verif_company_ok": res["verif_company_ok"],
                   "verif_registered_domain": res["verif_registered_domain"],
                   "verif_reason": res["verif_reason"],
                   "verif_deliverable": deliverable,
                   "verif_company_pass": company_pass,
                   "_email_original": email_original,
                   "_company_original": company_val if company_val is not None else ""
                   }
            results.append(out)

            smtp_cell = "N/A"
            reason = res["verif_reason"]
            if "heuristic:" in reason:
                smtp_cell = "EST"
            else:
                if res["verif_smtp_deliverable"] is True:
                    smtp_cell = "OK"
                elif res["verif_smtp_deliverable"] is False:
                    smtp_cell = "NO"

            self.queue.put(("row", {
                "email": email_original,
                "syntax": "OK" if res["verif_syntax_ok"] else "NO",
                "domain": "OK" if res["verif_domain_ok"] else "NO",
                "mx": "YES" if res["verif_mx_found"] else "NO",
                "smtp": smtp_cell,
                "company": "OK" if c is True else ("NO" if c is False else "N/A"),
                "deliverable": "YES" if deliverable else "NO",
                "reason": res["verif_reason"],
                "steps": res.get("steps", "")
            }))

            self.queue.put(("progress", idx+1))

        out_df = pd.DataFrame(results)

        # ==== FINAL-ONLY OUTPUT ====
        if len(out_df) > 0:
            base_directory = os.path.dirname(input_path) or "."
            output_format = (args["output_format"] or "csv").lower().strip()
            if output_format not in ("csv", "excel"):
                output_format = "csv"

            filtered_final_df = out_df[(out_df["verif_deliverable"]) & (out_df["verif_company_pass"])]

            final_df = pd.DataFrame({
                "email": filtered_final_df["_email_original"].astype(str),
                "company": filtered_final_df["_company_original"].astype(str),
                "deliverable": "YES"
            })

            # Penamaan file:
            # - batch_mode True → pakai nama file input (stem)_final
            # - single file → pakai output_name jika diisi, kalau kosong gunakan prefix_final
            stem = os.path.splitext(os.path.basename(input_path))[0]
            batch_mode = bool(args.get("batch_mode"))
            if batch_mode:
                filename_safe = f"{stem}_final"
            else:
                filename_input = self.output_name.get().strip()
                filename_safe = filename_input if filename_input else f"{args['output_prefix']}_final"

            if output_format == "csv":
                final_path = os.path.join(base_directory, f"{filename_safe}.csv")
                final_df.to_csv(final_path, index=False, quoting=csv.QUOTE_NONNUMERIC)
            else:
                final_path = os.path.join(base_directory, f"{filename_safe}.xlsx")
                try:
                    final_df.to_excel(final_path, index=False, engine="openpyxl")
                except Exception as excel_error:
                    self.queue.put(("log", f"OpenPyXL error: {excel_error}. Fallback ke CSV."))
                    final_path = os.path.join(base_directory, f"{filename_safe}.csv")
                    final_df.to_csv(final_path, index=False, quoting=csv.QUOTE_NONNUMERIC)

            self.queue.put(("done_final", (final_path, len(final_df), len(out_df))))
        else:
            self.queue.put(("done_final", (None, 0, 0)))

    def _poll_queue(self):
        try:
            while True:
                msg = self.queue.get_nowait()
                self._handle_msg(msg)
        except queue.Empty:
            pass
        finally:
            self.after(100, self._poll_queue)

    def _handle_msg(self, msg):
        kind, payload = msg
        if kind == "start":
            total = payload
            self.prog.configure(maximum=total, value=0)
            self.set_status(f"Memproses {total} baris...")
        elif kind == "progress":
            self.prog['value'] = payload
        elif kind == "log":
            self.log_write(str(payload))
        elif kind == "current":
            self.set_current(str(payload))
        elif kind == "row":
            if self.live_table.get():
                data = payload
                self.tree.insert("", "end", values=(
                    data["email"], data["syntax"], data["domain"], data["mx"],
                    data["smtp"], data["company"], data["deliverable"], data["reason"]
                ))
            steps = payload.get("steps", "")
            if steps:
                self.log_write(f"[{payload['email']}] {steps}")
        elif kind == "error":
            self.run_btn.config(state="normal")
            self.stop_btn.config(state="disabled")
            self.set_status("Error")
            messagebox.showerror("Error", str(payload))
        elif kind == "done_final":
            final_path, kept_rows, total_rows = payload
            # jangan ubah tombol bila memproses banyak file—tetap enable di akhir tiap file
            self.run_btn.config(state="normal")
            self.stop_btn.config(state="disabled")
            self.set_current("-")
            if final_path:
                self.set_status("Selesai")
                self.log_write(f"Selesai. Final: {final_path}")
                self.log_write(f"Rows kept (deliverable=YES): {kept_rows}/{total_rows}")
                messagebox.showinfo(
                    "Selesai",
                    f"Berhasil!\nFinal: {final_path}\nRows kept: {kept_rows}/{total_rows}"
                )
            else:
                self.set_status("Tidak ada data tersimpan")
                messagebox.showwarning("Kosong", "Tidak ada baris yang diverifikasi.")

def main():
    app = VerifierGUI()
    app.mainloop()

if __name__ == "__main__":
    main()
