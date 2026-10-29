#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MaskProxy - proxy checker, harvester and analyzer (SOCKS4 / SOCKS5 / HTTP)

Author  : msk3d0ut
License : MIT
Needs   : Python 3.9+  (standard library only - nothing to install)

Run `python maskproxy.py` for the interactive menu,
or `python maskproxy.py --help` for command-line use.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import csv
import json
import os
import platform
import random
import re
import shutil
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

if sys.version_info < (3, 9):
    sys.exit("MaskProxy needs Python 3.9 or newer.")

APP = "MaskProxy"
VERSION = "1.0.0"
AUTHOR = "msk3d0ut"
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

IS_WIN = os.name == "nt"
IS_TERMUX = "TERMUX_VERSION" in os.environ or "com.termux" in os.environ.get("PREFIX", "")
IS_ANDROID = IS_TERMUX or ("ANDROID_ROOT" in os.environ and "ANDROID_DATA" in os.environ)

DEFAULT_TEST_URL = "http://checkip.amazonaws.com/"
DEEP_HOST = "example.com"
CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".maskproxy", "config.json")

# =============================================================================
#  TERMINAL / COLORS
# =============================================================================

RESET = BOLD = DIM = ""

CYAN = (0, 229, 255)
MAGENTA = (255, 61, 203)
VIOLET = (150, 110, 255)
GREEN = (43, 255, 136)
RED = (255, 77, 77)
YELLOW = (255, 216, 77)
GREY = (138, 143, 163)
WHITE = (235, 238, 245)


class G:
    """Glyph set (unicode by default, ascii fallback)."""
    dot, ring, ok, bad, arrow, diam = "●", "○", "✔", "✖", "»", "◆"
    bar_f, bar_e = "█", "░"
    spin = list("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
    h, v, tl, tr, bl, br = "─", "│", "┌", "┐", "└", "┘"

    @classmethod
    def use_ascii(cls):
        cls.dot, cls.ring, cls.ok, cls.bad, cls.arrow, cls.diam = "*", "o", "+", "x", ">", "*"
        cls.bar_f, cls.bar_e = "#", "-"
        cls.spin = list("|/-\\")
        cls.h, cls.v, cls.tl, cls.tr, cls.bl, cls.br = "-", "|", "+", "+", "+", "+"


class Term:
    color = False
    true = False
    anim = False

    @classmethod
    def init(cls, no_color=False, ascii_only=False):
        global RESET, BOLD, DIM
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
        tty = sys.stdout.isatty()
        vt = enable_vt() if (IS_WIN and tty) else True
        cls.color = bool(tty and vt and not no_color and "NO_COLOR" not in os.environ)
        cls.anim = bool(tty)
        ct = os.environ.get("COLORTERM", "").lower()
        cls.true = cls.color and (ct in ("truecolor", "24bit") or IS_WIN or IS_ANDROID)
        if cls.color:
            RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
        enc = (sys.stdout.encoding or "").lower()
        if ascii_only or "utf" not in enc:
            G.use_ascii()
        elif IS_WIN and "WT_SESSION" not in os.environ and "TERM_PROGRAM" not in os.environ:
            G.spin = list("|/-\\")  # old conhost fonts lack braille


def enable_vt():
    try:
        import ctypes
        k = ctypes.windll.kernel32
        h = k.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not k.GetConsoleMode(h, ctypes.byref(mode)):
            return False
        return bool(k.SetConsoleMode(h, mode.value | 0x0004))
    except Exception:
        return False


ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def vlen(s):
    return len(ANSI_RE.sub("", s))


def term_width():
    return shutil.get_terminal_size((80, 24)).columns


def _to256(r, g, b):
    def c(v):
        return 0 if v < 48 else 1 if v < 115 else min(5, (v - 35) // 40)
    return 16 + 36 * c(r) + 6 * c(g) + c(b)


def fg(rgb):
    if not Term.color:
        return ""
    r, g, b = rgb
    if Term.true:
        return "\033[38;2;%d;%d;%dm" % (r, g, b)
    return "\033[38;5;%dm" % _to256(r, g, b)


def paint(text, rgb, bold=False):
    if not Term.color:
        return str(text)
    return "%s%s%s%s" % (BOLD if bold else "", fg(rgb), text, RESET)


def dim(text):
    return paint(text, GREY)


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def tri(v):
    return 1.0 - abs((v % 2.0) - 1.0)


def gradient(text, a=CYAN, b=MAGENTA, phase=0.0, bold=True):
    if not Term.color:
        return text
    n = max(1, len(text) - 1)
    out = []
    for i, ch in enumerate(text):
        if ch == " ":
            out.append(ch)
            continue
        out.append(fg(lerp(a, b, tri(i / n + phase))) + ch)
    return (BOLD if bold else "") + "".join(out) + RESET


def clip(s, n):
    return s if len(s) <= n else s[: max(0, n - 1)] + "…"


def fmt_time(sec):
    sec = int(max(0, sec))
    h, rem = divmod(sec, 3600)
    m, s = divmod(rem, 60)
    return "%d:%02d:%02d" % (h, m, s) if h else "%02d:%02d" % (m, s)


def fmt_n(n):
    return "{:,}".format(int(n))


def clear_screen():
    if Term.color:
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()


# ----------------------------------------------------------------------------
#  Banner
# ----------------------------------------------------------------------------

FONT = {
    "M": ["█   █", "██ ██", "█ █ █", "█   █", "█   █"],
    "A": [" ███ ", "█   █", "█████", "█   █", "█   █"],
    "S": [" ████", "█    ", " ███ ", "    █", "████ "],
    "K": ["█   █", "█  █ ", "███  ", "█  █ ", "█   █"],
    "P": ["████ ", "█   █", "████ ", "█    ", "█    "],
    "R": ["████ ", "█   █", "████ ", "█  █ ", "█   █"],
    "O": [" ███ ", "█   █", "█   █", "█   █", " ███ "],
    "X": ["█   █", " █ █ ", "  █  ", " █ █ ", "█   █"],
    "Y": ["█   █", " █ █ ", "  █  ", "  █  ", "  █  "],
}


def banner_lines():
    width = term_width()
    word = "MASKPROXY"
    lines = [""]
    if width >= 56:
        rows = [" ".join(FONT[c][r] for c in word) for r in range(5)]
        w = len(rows[0])
        pad = " " * max(0, (width - w) // 2)
        for r, row in enumerate(rows):
            out = []
            for x, ch in enumerate(row):
                if ch == " ":
                    out.append(" ")
                else:
                    t = min(1.0, x / max(1, w) * 0.9 + r * 0.04)
                    out.append(fg(lerp(CYAN, MAGENTA, t)) + (ch if G.bar_f == "█" else "#"))
            lines.append(pad + (BOLD if Term.color else "") + "".join(out) + RESET)
    else:
        t = "%s MASK PROXY %s" % (G.diam, G.diam)
        lines.append(" " * max(0, (width - len(t)) // 2) + gradient(t))
    sub = "%s Checker  %s Harvester  %s Analyzer" % (G.diam, G.diam, G.diam)
    lines.append("")
    lines.append(" " * max(0, (width - len(sub)) // 2) + paint(sub, VIOLET))
    by = "by %s   v%s   %s %s" % (AUTHOR, VERSION, platform.system(), "py" + platform.python_version())
    lines.append(" " * max(0, (width - len(by)) // 2) +
                 paint("by ", GREY) + gradient(AUTHOR, YELLOW, MAGENTA) +
                 paint("   v%s   %s py%s" % (VERSION, platform.system(), platform.python_version()), GREY))
    lines.append("")
    return lines


def show_banner(animate=True):
    for ln in banner_lines():
        print(ln)
        if animate and Term.anim:
            sys.stdout.flush()
            time.sleep(0.025)


def box(lines, width, title=None, rgb=CYAN):
    inner = width - 2
    if title:
        t = " %s " % title
        top = G.tl + G.h * 2 + paint(t, WHITE, True) + paint(G.h * max(0, inner - 2 - len(t)), rgb) + G.tr
        top = paint(G.tl + G.h * 2, rgb) + paint(t, WHITE, True) + paint(G.h * max(0, inner - 2 - len(t)) + G.tr, rgb)
    else:
        top = paint(G.tl + G.h * inner + G.tr, rgb)
    out = [top]
    for ln in lines:
        pad = max(0, inner - 2 - vlen(ln))
        out.append(paint(G.v, rgb) + " " + ln + " " * pad + " " + paint(G.v, rgb))
    out.append(paint(G.bl + G.h * inner + G.br, rgb))
    return out


# =============================================================================
#  MODELS / PARSING
# =============================================================================

IPV4 = r"(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)"
HOST = IPV4 + r"|(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}"
PROXY_RE = re.compile(
    r"(?:(?P<scheme>socks5h?|socks4a?|https?)://)?"
    r"(?:(?P<user>[^\s:@/]+):(?P<pw>[^\s@/]+)@)?"
    r"(?P<host>" + HOST + r"):(?P<port>\d{2,5})(?!\d)", re.I)
COLON4_RE = re.compile(r"^\s*(?P<host>" + HOST + r"):(?P<port>\d{2,5}):(?P<user>[^:\s]+):(?P<pw>\S+)\s*$")
HTML_PAIR_RE = re.compile(r"(" + IPV4 + r")\s*</td>\s*<td[^>]*>\s*(\d{2,5})\s*</td>", re.I)
JSON_PAIR_RE = re.compile(r'"(?:ip|host|address)"\s*:\s*"(' + IPV4 + r')"[^{}]*?"port"\s*:\s*"?(\d{2,5})', re.I)
IP_ONLY_RE = re.compile(r"^" + IPV4 + r"$")
IP_FIND_RE = re.compile(IPV4)

SCHEME_MAP = {"socks5": "socks5", "socks5h": "socks5", "socks4": "socks4", "socks4a": "socks4",
              "http": "http", "https": "http"}


class Proxy:
    __slots__ = ("host", "port", "user", "pw", "hint")

    def __init__(self, host, port, user=None, pw=None, hint=None):
        self.host, self.port, self.user, self.pw, self.hint = host, int(port), user, pw, hint

    @property
    def addr(self):
        return "%s:%d" % (self.host, self.port)

    @property
    def full(self):
        return ("%s:%s@%s" % (self.user, self.pw, self.addr)) if self.user else self.addr

    @property
    def key(self):
        return (self.host, self.port, self.user, self.pw)


def _mk(host, port, user, pw, hint):
    try:
        port = int(port)
    except (TypeError, ValueError):
        return None
    if not 1 <= port <= 65535:
        return None
    return Proxy(host, port, user, pw, hint)


def parse_proxies(text, hint=None):
    """Extract proxies from arbitrary text (plain lists, HTML, JSON, URLs...)."""
    found, seen = [], set()

    def add(p):
        if p and p.key not in seen:
            seen.add(p.key)
            found.append(p)

    for line in text.splitlines():
        m = COLON4_RE.match(line)
        if m:
            add(_mk(m.group("host"), m.group("port"), m.group("user"), m.group("pw"), hint))
            continue
        for m in PROXY_RE.finditer(line):
            sch = (m.group("scheme") or "").lower()
            add(_mk(m.group("host"), m.group("port"), m.group("user"), m.group("pw"),
                    SCHEME_MAP.get(sch) or hint))
    if "</td>" in text:
        for m in HTML_PAIR_RE.finditer(text):
            add(_mk(m.group(1), m.group(2), None, None, hint))
    if '"port"' in text:
        for m in JSON_PAIR_RE.finditer(text):
            add(_mk(m.group(1), m.group(2), None, None, hint))
    return found


# =============================================================================
#  CONFIG
# =============================================================================

DEFAULTS = {
    "timeout": 6.0, "retries": 1, "concurrency": 0, "outdir": "maskproxy_results",
    "test_url": DEFAULT_TEST_URL, "geo": True, "deep": True, "harvest_limit": 3000,
    "disabled_groups": [], "custom_sources": [], "keys": {},
}


def load_config():
    conf = json.loads(json.dumps(DEFAULTS))
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            conf.update(json.load(f))
    except (OSError, ValueError):
        pass
    return conf


def save_config(conf):
    try:
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(conf, f, indent=2)
        try:
            os.chmod(CONFIG_PATH, 0o600)
        except OSError:
            pass
    except OSError as e:
        print(paint("Could not save settings: %s" % e, YELLOW))


# =============================================================================
#  SOURCES (harvesting)
# =============================================================================

_RAW = "https://raw.githubusercontent.com/"
_JSD = "https://cdn.jsdelivr.net/gh/"

BUILTIN_SOURCES = [
    # group, name, url, protocol hint, kind
    ("TheSpeedX", "socks5", _RAW + "TheSpeedX/SOCKS-List/master/socks5.txt", "socks5", "auto"),
    ("TheSpeedX", "socks4", _RAW + "TheSpeedX/SOCKS-List/master/socks4.txt", "socks4", "auto"),
    ("TheSpeedX", "http", _RAW + "TheSpeedX/SOCKS-List/master/http.txt", "http", "auto"),
    ("monosans", "socks5", _RAW + "monosans/proxy-list/main/proxies/socks5.txt", "socks5", "auto"),
    ("monosans", "socks4", _RAW + "monosans/proxy-list/main/proxies/socks4.txt", "socks4", "auto"),
    ("monosans", "http", _RAW + "monosans/proxy-list/main/proxies/http.txt", "http", "auto"),
    ("gfpcom", "socks5", _RAW + "wiki/gfpcom/free-proxy-list/lists/socks5.txt", "socks5", "auto"),
    ("gfpcom", "socks4", _RAW + "wiki/gfpcom/free-proxy-list/lists/socks4.txt", "socks4", "auto"),
    ("gfpcom", "http", _RAW + "wiki/gfpcom/free-proxy-list/lists/http.txt", "http", "auto"),
    ("VPSLab", "socks5", _RAW + "VPSLabCloud/VPSLab-Free-Proxy-List/main/socks5_all.txt", "socks5", "auto"),
    ("VPSLab", "socks4", _RAW + "VPSLabCloud/VPSLab-Free-Proxy-List/main/socks4_all.txt", "socks4", "auto"),
    ("VPSLab", "http", _RAW + "VPSLabCloud/VPSLab-Free-Proxy-List/main/http_all.txt", "http", "auto"),
    ("jetkai", "socks5", _RAW + "jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt", "socks5", "auto"),
    ("jetkai", "socks4", _RAW + "jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt", "socks4", "auto"),
    ("jetkai", "http", _RAW + "jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt", "http", "auto"),
    ("Proxifly", "socks5", _JSD + "proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt", "socks5", "auto"),
    ("Proxifly", "socks4", _JSD + "proxifly/free-proxy-list@main/proxies/protocols/socks4/data.txt", "socks4", "auto"),
    ("Proxifly", "http", _JSD + "proxifly/free-proxy-list@main/proxies/protocols/http/data.txt", "http", "auto"),
    ("HealthList", "mixed", _JSD + "xyzs996/free-proxy-health-list@main/proxies/all/data.txt", "mixed", "auto"),
    ("ProxyScrape", "socks5",
     "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=10000&country=all", "socks5", "auto"),
    ("ProxyScrape", "socks4",
     "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks4&timeout=10000&country=all", "socks4", "auto"),
    ("ProxyScrape", "http",
     "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
     "http", "auto"),
    ("GeoNode", "mixed",
     "https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc",
     "mixed", "geonode"),
    ("free-proxy-list.net", "http", "https://free-proxy-list.net/", "http", "auto"),
    ("free-proxy-list.net", "ssl", "https://www.sslproxies.org/", "http", "auto"),
]


def all_sources(conf):
    srcs = [dict(group=g, name=n, url=u, proto=p, kind=k, builtin=True) for g, n, u, p, k in BUILTIN_SOURCES]
    for c in conf.get("custom_sources", []):
        srcs.append(dict(group=c["name"], name=c["name"], url=c["url"], proto=c.get("proto", "mixed"),
                         kind="auto", builtin=False, key_header=c.get("key_header")))
    return srcs


def _opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def http_get(url, timeout=25, max_bytes=40_000_000, headers=None):
    h = {"User-Agent": UA, "Accept": "*/*"}
    h.update(headers or {})
    req = urllib.request.Request(url, headers=h)
    with _opener().open(req, timeout=timeout) as r:
        data = r.read(max_bytes)
        enc = r.headers.get_content_charset() or "utf-8"
    return data.decode(enc, "replace")


def fetch_source(src, conf):
    url, headers = src["url"], {}
    if "{KEY}" in url or src.get("key_header"):
        key = conf.get("keys", {}).get(src["name"], "")
        if not key:
            raise RuntimeError("API key missing (Sources > K)")
        url = url.replace("{KEY}", urllib.parse.quote(key))
        if src.get("key_header"):
            headers[src["key_header"]] = key
    body = http_get(url, headers=headers)
    hint = src["proto"] if src["proto"] in ("http", "socks4", "socks5") else None
    if src["kind"] == "geonode":
        out = []
        try:
            for it in json.loads(body).get("data", []):
                protos = it.get("protocols") or []
                p = _mk(it.get("ip"), it.get("port"), None, None, protos[0] if protos else None)
                if p:
                    if p.hint not in ("http", "socks4", "socks5"):
                        p.hint = None
                    out.append(p)
        except ValueError:
            pass
        return out
    return parse_proxies(body, hint)


def mix_round_robin(lists, limit):
    """Take proxies fairly from every source until `limit` unique ones are collected."""
    for lst in lists:
        random.shuffle(lst)
    seen, out = set(), []
    iters = [iter(lst) for lst in lists]
    active = list(range(len(lists)))
    while active and (not limit or len(out) < limit):
        nxt = []
        for i in active:
            for p in iters[i]:
                if p.key not in seen:
                    seen.add(p.key)
                    out.append(p)
                    break
            else:
                continue
            nxt.append(i)
            if limit and len(out) >= limit:
                break
        active = nxt
    return out


def harvest(conf, proto="auto", limit=3000, only_groups=None):
    srcs = [s for s in all_sources(conf) if s["group"] not in conf.get("disabled_groups", [])]
    if only_groups:
        wanted = {g.lower() for g in only_groups}
        srcs = [s for s in srcs if s["group"].lower() in wanted]
    if proto in ("http", "socks4", "socks5"):
        srcs = [s for s in srcs if s["proto"] in (proto, "mixed")]
    elif proto == "socks":
        srcs = [s for s in srcs if s["proto"] in ("socks4", "socks5", "mixed")]
    if not srcs:
        print(paint("No sources selected.", YELLOW))
        return []
    print(paint("  Fetching %d sources..." % len(srcs), CYAN))
    results = []
    with ThreadPoolExecutor(max_workers=10) as ex:
        futs = {ex.submit(fetch_source, s, conf): s for s in srcs}
        for fut in as_completed(futs):
            s = futs[fut]
            label = "%s/%s" % (s["group"], s["name"])
            try:
                lst = fut.result()
                if proto in ("http", "socks4", "socks5"):
                    lst = [p for p in lst if p.hint in (None, proto)]
                print("  %s %-28s %s" % (paint(G.ok, GREEN, True), label, paint(fmt_n(len(lst)), WHITE)))
                if lst:
                    results.append(lst)
            except Exception as e:
                msg = clip(str(e) or type(e).__name__, 40)
                print("  %s %-28s %s" % (paint(G.bad, RED, True), label, dim(msg)))
    total = sum(len(x) for x in results)
    chosen = mix_round_robin(results, limit)
    print("  %s collected %s entries -> using %s unique proxies" %
          (paint(G.arrow, CYAN), fmt_n(total), paint(fmt_n(len(chosen)), WHITE, True)))
    return chosen


# =============================================================================
#  PROXY PROTOCOLS
# =============================================================================

class ProxyError(Exception):
    pass


def direct_request(host, path, port=80):
    hp = host if port == 80 else "%s:%d" % (host, port)
    return ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\n"
            "Connection: close\r\n\r\n" % (path, hp, UA)).encode()


def _basic(p):
    return base64.b64encode(("%s:%s" % (p.user, p.pw)).encode()).decode()


def forward_request(p, host, port, path):
    hp = host if port == 80 else "%s:%d" % (host, port)
    auth = "Proxy-Authorization: Basic %s\r\n" % _basic(p) if p.user else ""
    return ("GET http://%s%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\n%s"
            "Connection: close\r\n\r\n" % (hp, path, hp, UA, auth)).encode()


def dechunk(data):
    out, i = b"", 0
    while True:
        j = data.find(b"\r\n", i)
        if j < 0:
            break
        try:
            size = int(data[i:j].split(b";")[0].strip() or b"0", 16)
        except ValueError:
            return data
        if size == 0:
            break
        out += data[j + 2: j + 2 + size]
        i = j + 2 + size + 2
    return out


async def read_response(reader, limit=262144):
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = await reader.read(4096)
        if not chunk:
            break
        head += chunk
        if len(head) > limit:
            raise ProxyError("oversize")
    sep = head.find(b"\r\n\r\n")
    if sep < 0:
        raise ProxyError("no_http" if head else "closed")
    raw_head, body = head[:sep], head[sep + 4:]
    lines = raw_head.split(b"\r\n")
    m = re.match(rb"HTTP/\d(?:\.\d)?\s+(\d{3})", lines[0])
    if not m:
        raise ProxyError("not_http")
    status = int(m.group(1))
    headers = {}
    for ln in lines[1:]:
        k, _, v = ln.partition(b":")
        headers[k.strip().lower().decode("latin1")] = v.strip().decode("latin1")
    chunked = "chunked" in headers.get("transfer-encoding", "").lower()
    try:
        clen = int(headers.get("content-length", "-1"))
    except ValueError:
        clen = -1
    while len(body) < limit:
        if clen >= 0 and len(body) >= clen:
            break
        if chunked and body.endswith(b"0\r\n\r\n"):
            break
        chunk = await reader.read(4096)
        if not chunk:
            break
        body += chunk
    if chunked:
        body = dechunk(body)
    return status, headers, body


async def socks5_connect(reader, writer, p, host, port):
    writer.write(b"\x05\x02\x00\x02" if p.user else b"\x05\x01\x00")
    await writer.drain()
    r = await reader.readexactly(2)
    if r[0] != 5:
        raise ProxyError("not_socks5")
    if r[1] == 0xFF:
        raise ProxyError("no_auth_method")
    if r[1] == 2:
        if not p.user:
            raise ProxyError("auth_required")
        u, pw = p.user.encode(), p.pw.encode()
        writer.write(b"\x01" + bytes([len(u)]) + u + bytes([len(pw)]) + pw)
        await writer.drain()
        a = await reader.readexactly(2)
        if a[1] != 0:
            raise ProxyError("auth_failed")
    elif r[1] != 0:
        raise ProxyError("bad_method")
    hb = host.encode()
    writer.write(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + struct.pack(">H", port))
    await writer.drain()
    h = await reader.readexactly(4)
    if h[0] != 5:
        raise ProxyError("bad_reply")
    if h[1] != 0:
        raise ProxyError("denied_%d" % h[1])
    if h[3] == 1:
        await reader.readexactly(6)
    elif h[3] == 3:
        n = (await reader.readexactly(1))[0]
        await reader.readexactly(n + 2)
    elif h[3] == 4:
        await reader.readexactly(18)
    else:
        raise ProxyError("bad_atyp")


async def socks4_connect(reader, writer, p, ip4, port):
    uid = (p.user or "").encode()
    writer.write(b"\x04\x01" + struct.pack(">H", port) + socket.inet_aton(ip4) + uid + b"\x00")
    await writer.drain()
    r = await reader.readexactly(8)
    if r[0] != 0:
        raise ProxyError("not_socks4")
    if r[1] != 0x5A:
        raise ProxyError("rejected_%02x" % r[1])


async def http_connect(reader, writer, p, host, port):
    auth = "Proxy-Authorization: Basic %s\r\n" % _basic(p) if p.user else ""
    writer.write(("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\nUser-Agent: %s\r\n%s\r\n" %
                  (host, port, host, port, UA, auth)).encode())
    await writer.drain()
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = await reader.read(2048)
        if not chunk:
            raise ProxyError("closed")
        head += chunk
        if len(head) > 16384:
            raise ProxyError("oversize")
    m = re.match(rb"HTTP/\d(?:\.\d)?\s+(\d{3})", head)
    if not m:
        raise ProxyError("not_http")
    if int(m.group(1)) != 200:
        raise ProxyError("connect_%s" % m.group(1).decode())


# =============================================================================
#  CHECK ENGINE
# =============================================================================

class Cfg:
    """Runtime settings for one run."""

    def __init__(self):
        self.timeout = 6.0
        self.retries = 1
        self.concurrency = 0
        self.proto = "auto"       # auto | socks | socks4 | socks5 | http
        self.strict = False       # only try the hinted protocol
        self.test_url = DEFAULT_TEST_URL
        self.deep = False
        self.geo = False
        self.test_host = "checkip.amazonaws.com"
        self.test_port = 80
        self.test_path = "/"
        self.custom_test = False
        self.test_ip4 = None
        self.real_ip = None
        self.deep_host = DEEP_HOST
        self.deep_ip4 = None
        self.tls_verify = True


HTTP_PORTS = {80, 81, 88, 808, 3128, 3129, 8000, 8001, 8008, 8080, 8081, 8082, 8083, 8085, 8088,
              8090, 8118, 8123, 8800, 8888, 8889, 9000, 9090, 9999}
SOCKS4_PORTS = {4145, 4153, 4550, 5678}
SOCKS5_PORTS = {1080, 1081, 1085, 1086, 1088, 9050, 9150, 10800, 10801, 7890, 7891}


def candidate_protocols(p, cfg):
    if cfg.proto in ("http", "socks4", "socks5"):
        return [cfg.proto]
    allowed = ["socks5", "socks4"] if cfg.proto == "socks" else ["socks5", "socks4", "http"]
    if p.hint in allowed:
        order = [p.hint]
        if not cfg.strict:
            order += [x for x in allowed if x != p.hint]
        return order
    if p.port in HTTP_PORTS and "http" in allowed:
        order = ["http", "socks5", "socks4"]
    elif p.port in SOCKS4_PORTS:
        order = ["socks4", "socks5", "http"]
    else:
        order = ["socks5", "http", "socks4"]
    return [x for x in order if x in allowed]


def validate_body(status, body, cfg):
    if status != 200:
        raise ProxyError("http_%d" % status)
    text = body.decode("utf-8", "replace").strip()
    if not text:
        raise ProxyError("empty")
    if cfg.custom_test:
        m = IP_FIND_RE.search(text)
        return m.group(0) if m else ""
    if not IP_ONLY_RE.match(text):
        raise ProxyError("bad_body")
    return text


def _reason(e):
    if isinstance(e, ProxyError):
        return str(e)
    if isinstance(e, asyncio.IncompleteReadError):
        return "closed"
    if isinstance(e, (asyncio.TimeoutError, TimeoutError)):
        return "timeout"
    if isinstance(e, ConnectionRefusedError):
        return "refused"
    if isinstance(e, ConnectionResetError):
        return "reset"
    if isinstance(e, ssl.SSLError):
        return "ssl"
    if isinstance(e, OSError):
        return "unreachable"
    return type(e).__name__.lower()


async def attempt(p, proto, cfg, timeout):
    """One protocol try. Returns (ok, reason, stage, latency_ms, exit_ip)."""
    stage = "connect"
    writer = None
    t0 = time.perf_counter()

    async def run():
        nonlocal stage, writer
        reader, writer = await asyncio.open_connection(p.host, p.port)
        stage = "handshake"
        if proto == "http":
            req = forward_request(p, cfg.test_host, cfg.test_port, cfg.test_path)
        else:
            if proto == "socks5":
                await socks5_connect(reader, writer, p, cfg.test_host, cfg.test_port)
            else:
                await socks4_connect(reader, writer, p, cfg.test_ip4, cfg.test_port)
            req = direct_request(cfg.test_host, cfg.test_path, cfg.test_port)
        stage = "request"
        writer.write(req)
        await writer.drain()
        return await read_response(reader)

    try:
        status, _headers, body = await asyncio.wait_for(run(), timeout)
        ip = validate_body(status, body, cfg)
        return True, "", stage, (time.perf_counter() - t0) * 1000.0, ip
    except asyncio.CancelledError:
        raise
    except Exception as e:  # noqa: BLE001
        return False, _reason(e), stage, 0.0, ""
    finally:
        if writer is not None:
            try:
                writer.transport.abort()
            except Exception:
                pass


async def open_tunnel(p, proto, host, ip4, port):
    reader, writer = await asyncio.open_connection(p.host, p.port)
    try:
        if proto == "socks5":
            await socks5_connect(reader, writer, p, host, port)
        elif proto == "socks4":
            await socks4_connect(reader, writer, p, ip4, port)
        else:
            await http_connect(reader, writer, p, host, port)
    except BaseException:
        writer.transport.abort()
        raise
    return reader, writer


async def fetch_via(p, proto, cfg, host, ip4, path="/"):
    if proto == "http":
        reader, writer = await asyncio.open_connection(p.host, p.port)
        try:
            writer.write(forward_request(p, host, 80, path))
            await writer.drain()
            return await read_response(reader)
        finally:
            writer.transport.abort()
    reader, writer = await open_tunnel(p, proto, host, ip4, 80)
    try:
        writer.write(direct_request(host, path))
        await writer.drain()
        return await read_response(reader)
    finally:
        writer.transport.abort()


async def start_tls(writer, ctx, host):
    if hasattr(writer, "start_tls"):
        await writer.start_tls(ctx, server_hostname=host)
        return
    loop = asyncio.get_running_loop()
    transport = writer.transport
    new_t = await loop.start_tls(transport, transport.get_protocol(), ctx, server_hostname=host)
    writer._transport = new_t  # noqa: SLF001


async def tls_via(p, proto, cfg, host, ip4):
    reader, writer = await open_tunnel(p, proto, host, ip4, 443)
    try:
        if cfg.tls_verify:
            ctx = ssl.create_default_context()
        else:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        await start_tls(writer, ctx, host)
        writer.write(direct_request(host, "/"))
        await writer.drain()
        status, _h, _b = await read_response(reader)
        return status
    finally:
        try:
            writer.transport.abort()
        except Exception:
            pass


async def deep_checks(p, proto, cfg, res):
    """Extra analysis for live proxies: content integrity + HTTPS/MITM test."""
    async def integrity():
        try:
            st, _h, body = await asyncio.wait_for(
                fetch_via(p, proto, cfg, cfg.deep_host, cfg.deep_ip4), cfg.timeout + 2)
        except Exception:
            return "unknown"
        txt = body.decode("utf-8", "replace").lower()
        if st != 200:
            return "unknown"
        if "example domain" not in txt:
            return "tampered" if txt.strip() else "unknown"
        if any(t in txt for t in ("<script", "<iframe", "onerror=", "document.write")):
            return "tampered"
        return "clean"

    async def tls():
        try:
            await asyncio.wait_for(tls_via(p, proto, cfg, cfg.deep_host, cfg.deep_ip4), cfg.timeout + 3)
            return "yes"
        except ssl.SSLCertVerificationError:
            return "mitm"
        except Exception:
            return "no"

    res["integrity"], res["https"] = await asyncio.gather(integrity(), tls())
    if res["integrity"] == "tampered" or res["https"] == "mitm":
        res["status"] = "suspicious"


RANK = {"connect": 0, "handshake": 1, "request": 2}


async def check_proxy(p, cfg, protos=None, stop_first=True):
    """Returns (results, fail_reason)."""
    protos = protos or candidate_protocols(p, cfg)
    found = []
    best_rank, best_reason = -1, "unknown"
    for idx, proto in enumerate(protos):
        timeout = cfg.timeout if idx == 0 else max(2.0, cfg.timeout * 0.6)
        tries = 1 + (cfg.retries if idx == 0 else 0)
        ok, reason, stage, ms, ip = False, "unknown", "connect", 0.0, ""
        for _ in range(tries):
            ok, reason, stage, ms, ip = await attempt(p, proto, cfg, timeout)
            if ok or not (reason == "timeout" and stage == "request"):
                break
        if ok:
            res = {
                "proxy": p.full, "host": p.host, "port": p.port, "protocol": proto,
                "status": "live", "latency": round(ms), "exit_ip": ip,
                "anonymity": "", "https": "", "integrity": "", "country": "", "cc": "", "reason": "",
            }
            if cfg.real_ip and ip:
                res["anonymity"] = "transparent" if ip == cfg.real_ip else "hidden"
            if cfg.deep and cfg.deep_ip4:
                await deep_checks(p, proto, cfg, res)
            found.append(res)
            if stop_first:
                break
            continue
        if RANK[stage] > best_rank:
            best_rank, best_reason = RANK[stage], "%s:%s" % (proto, reason)
        if stage == "connect":
            break
    return found, best_reason


# =============================================================================
#  SESSION + LIVE DASHBOARD
# =============================================================================

class Stats:
    def __init__(self):
        self.checked = self.live = self.dead = self.suspicious = 0
        self.by_proto = Counter()
        self.lat_min = None
        self.lat_sum = 0


class Session:
    PANEL_LINES = 7

    def __init__(self, proxies, cfg, label="Checking", target=0):
        self.proxies, self.cfg, self.label, self.target = proxies, cfg, label, target
        self.total = len(proxies)
        self.stats = Stats()
        self.live, self.suspicious, self.dead = [], [], []
        self.next_i = 0
        self.stop = False
        self.done = False
        self.interrupted = False
        self.t0 = time.perf_counter()
        self.t1 = None
        self.last = None
        self._painted = False

    # -- results -------------------------------------------------------------
    def record(self, p, found, reason):
        s = self.stats
        s.checked += 1
        if found:
            for res in found:
                if res["status"] == "live":
                    s.live += 1
                    s.by_proto[res["protocol"]] += 1
                    s.lat_sum += res["latency"]
                    s.lat_min = res["latency"] if s.lat_min is None else min(s.lat_min, res["latency"])
                    self.live.append(res)
                else:
                    s.suspicious += 1
                    self.suspicious.append(res)
                self.last = (res["protocol"], res["proxy"], res["latency"], res["status"])
            if self.target and s.live >= self.target:
                self.stop = True
        else:
            s.dead += 1
            self.dead.append((p.full, reason))

    async def worker(self):
        while not self.stop and self.next_i < self.total:
            p = self.proxies[self.next_i]
            self.next_i += 1
            try:
                found, reason = await check_proxy(p, self.cfg)
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001
                found, reason = [], "internal:%s" % type(e).__name__
            self.record(p, found, reason)

    # -- dashboard -----------------------------------------------------------
    def lines(self, final=False):
        s = self.stats
        el = max(0.001, (self.t1 or time.perf_counter()) - self.t0)
        pct = (s.checked / self.total) if self.total else 1.0
        rate = s.checked / el
        eta = 0 if final or rate <= 0 else (self.total - s.checked) / rate
        W = max(30, min(term_width() - 4, 74))
        spin = G.spin[int(el * 12) % len(G.spin)] if not final else G.ok
        bw = max(10, W - 11)
        filled = int(bw * pct)
        bar = ""
        for i in range(bw):
            if i < filled:
                bar += fg(lerp(CYAN, GREEN, i / max(1, bw - 1))) + G.bar_f if Term.color else G.bar_f
            else:
                bar += (fg(GREY) + G.bar_e) if Term.color else G.bar_e
        bar += RESET
        title = gradient("MASKPROXY", CYAN, MAGENTA, phase=el * 0.6)
        state = "done" if final and not self.interrupted else ("stopped" if final else self.label)
        l1 = " %s %s  %s" % (paint(spin, CYAN, True), title, dim(clip(state, W - 16)))
        l2 = " %s %s" % (bar, paint("%5.1f%%" % (pct * 100), WHITE, True))
        l3 = " %s %s/%s   %s %s/s   %s %s" % (
            dim("checked"), fmt_n(s.checked), fmt_n(self.total),
            dim("speed"), fmt_n(rate), dim("eta"), fmt_time(eta))
        l4 = " %s %s   %s %s   %s %s" % (
            paint(G.dot + " LIVE", GREEN, True), paint(fmt_n(s.live), GREEN, True),
            paint(G.dot + " DEAD", RED, True), paint(fmt_n(s.dead), RED),
            paint(G.dot + " SUSPECT", YELLOW, True), paint(fmt_n(s.suspicious), YELLOW))
        bp = s.by_proto
        l5 = " %s %s   %s %s   %s %s" % (
            dim("socks5"), paint(fmt_n(bp["socks5"]), CYAN), dim("socks4"), paint(fmt_n(bp["socks4"]), VIOLET),
            dim("http"), paint(fmt_n(bp["http"]), MAGENTA))
        avg = (s.lat_sum / s.live) if s.live else 0
        l6 = " %s %s   %s %s" % (
            dim("fastest"), paint("%s ms" % fmt_n(s.lat_min) if s.lat_min is not None else "-", GREEN),
            dim("avg"), paint("%s ms" % fmt_n(avg) if s.live else "-", YELLOW))
        if self.last:
            pr, ad, ms, st = self.last
            txt = clip("%s://%s  %dms" % (pr, ad, ms), W - 10)
            l7 = " %s %s" % (dim("latest"), paint(txt, GREEN if st == "live" else YELLOW))
        else:
            l7 = " %s %s" % (dim("latest"), dim(clip("waiting for the first live proxy...", W - 10)))
        return [l1, l2, l3, l4, l5, l6, l7]

    def paint_panel(self, final=False):
        if not Term.anim:
            return
        out = []
        if self._painted:
            out.append("\033[%dF" % self.PANEL_LINES)
        for ln in self.lines(final):
            out.append("\033[2K" + ln + "\n")
        sys.stdout.write("".join(out))
        sys.stdout.flush()
        self._painted = True

    async def ui(self):
        if Term.anim:
            sys.stdout.write("\033[?25l")
        last_log = time.perf_counter()
        while not self.done:
            if Term.anim:
                self.paint_panel()
            elif time.perf_counter() - last_log > 5:
                last_log = time.perf_counter()
                print("  checked %d/%d  live %d" % (self.stats.checked, self.total, self.stats.live))
            await asyncio.sleep(0.085)

    async def run(self):
        loop = asyncio.get_running_loop()
        loop.set_exception_handler(lambda _l, _c: None)
        self.t0 = time.perf_counter()
        n = max(1, min(self.cfg.concurrency, self.total))
        workers = [asyncio.create_task(self.worker()) for _ in range(n)]
        ui_task = asyncio.create_task(self.ui())
        try:
            await asyncio.gather(*workers)
        except asyncio.CancelledError:
            self.interrupted = True
            raise
        finally:
            self.done = True
            self.t1 = time.perf_counter()
            for w in workers:
                w.cancel()
            ui_task.cancel()
            await asyncio.gather(ui_task, *workers, return_exceptions=True)
            if Term.anim:
                self.paint_panel(final=True)
                sys.stdout.write("\033[?25h")
                sys.stdout.flush()

    def execute(self):
        try:
            asyncio.run(self.run())
        except KeyboardInterrupt:
            self.interrupted = True
            self.done = True
            self.t1 = self.t1 or time.perf_counter()
            if Term.anim:
                sys.stdout.write("\033[?25h\n")
            print(paint("  Interrupted - saving what was checked so far...", YELLOW))
        if self.stop and not self.interrupted and self.next_i < self.total:
            self.interrupted = False


# =============================================================================
#  PREFLIGHT / HELPERS
# =============================================================================

class PreflightError(Exception):
    pass


def parse_test_url(url):
    u = urllib.parse.urlsplit(url)
    if u.scheme != "http" or not u.hostname:
        raise PreflightError("Test URL must start with http:// (example: http://checkip.amazonaws.com/)")
    path = (u.path or "/") + (("?" + u.query) if u.query else "")
    return u.hostname, u.port or 80, path


def tls_selfcheck():
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((DEEP_HOST, 443), timeout=6) as s:
            with ctx.wrap_socket(s, server_hostname=DEEP_HOST):
                return True
    except ssl.SSLCertVerificationError:
        return False
    except Exception:
        return True  # network trouble, not a CA-store problem


def preflight(cfg):
    host, port, path = parse_test_url(cfg.test_url)
    cfg.test_host, cfg.test_port, cfg.test_path = host, port, path
    cfg.custom_test = cfg.test_url.rstrip("/") != DEFAULT_TEST_URL.rstrip("/")
    try:
        cfg.test_ip4 = socket.gethostbyname(host)
    except OSError:
        raise PreflightError("Cannot resolve %s - check your internet connection." % host)
    try:
        m = IP_FIND_RE.search(http_get(cfg.test_url, timeout=7, max_bytes=4096))
        cfg.real_ip = m.group(0) if m else None
    except Exception:
        cfg.real_ip = None
    if cfg.deep:
        try:
            cfg.deep_ip4 = socket.gethostbyname(cfg.deep_host)
            cfg.tls_verify = tls_selfcheck()
        except OSError:
            cfg.deep = False
    return cfg


def raise_fd_limit():
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        want = 65536 if hard == resource.RLIM_INFINITY else min(hard, 65536)
        if soft < want:
            resource.setrlimit(resource.RLIMIT_NOFILE, (want, hard))
            soft = want
        return soft
    except Exception:
        return None


def auto_concurrency():
    base = 150 if IS_ANDROID else (400 if IS_WIN else 600)
    soft = raise_fd_limit()
    if soft:
        base = min(base, max(50, soft - 100))
    return base


def run_with_spinner(label, func):
    box_ = {}

    def target():
        try:
            box_["v"] = func()
        except BaseException as e:  # noqa: BLE001
            box_["e"] = e

    t = threading.Thread(target=target, daemon=True)
    t.start()
    i = 0
    while t.is_alive():
        if Term.anim:
            sys.stdout.write("\r\033[2K  %s %s" % (paint(G.spin[i % len(G.spin)], CYAN, True), dim(clip(label, max(10, term_width() - 8)))))
            sys.stdout.flush()
        i += 1
        t.join(0.08)
    if Term.anim:
        sys.stdout.write("\r\033[2K")
    if "e" in box_:
        raise box_["e"]
    return box_.get("v")


def geo_lookup(ips, limit=500):
    """Country lookup for exit IPs (direct, free ip-api.com batch endpoint)."""
    out = {}
    ips = list(dict.fromkeys(ips))[:limit]
    for i in range(0, len(ips), 100):
        chunk = ips[i:i + 100]
        try:
            req = urllib.request.Request(
                "http://ip-api.com/batch?fields=status,country,countryCode,query",
                data=json.dumps(chunk).encode(),
                headers={"Content-Type": "application/json", "User-Agent": UA})
            with _opener().open(req, timeout=12) as r:
                for row in json.loads(r.read().decode("utf-8", "replace")):
                    if row.get("status") == "success":
                        out[row["query"]] = (row.get("country", ""), row.get("countryCode", ""))
        except Exception:
            break
        if i + 100 < len(ips):
            time.sleep(4.2)  # free tier: 15 batch requests / minute
    return out


# =============================================================================
#  OUTPUT
# =============================================================================

def make_run_dir(base):
    base = os.path.abspath(os.path.expanduser(base))
    stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    path, n = os.path.join(base, stamp), 2
    while os.path.exists(path):
        path = os.path.join(base, "%s_%d" % (stamp, n))
        n += 1
    os.makedirs(path)
    return path


def _write(path, lines):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))


def write_results(sess, outdir, mode, countries=None, all_candidates=None):
    run_dir = make_run_dir(outdir)
    live = sorted(sess.live, key=lambda r: r["latency"])
    if countries:
        cc = {c.strip().upper() for c in countries}
        live = [r for r in live if r["cc"] in cc]
    files = []

    def out(name, lines):
        _write(os.path.join(run_dir, name), lines)
        files.append(name)

    out("live.txt", [r["proxy"] for r in live])
    if mode == "smart":
        out("live_with_scheme.txt", ["%s://%s" % (r["protocol"], r["proxy"]) for r in live])
        for proto in ("socks5", "socks4", "http"):
            sel = [r["proxy"] for r in live if r["protocol"] == proto]
            if sel:
                out("%s.txt" % proto, sel)
        if sess.suspicious:
            out("suspicious.txt", ["%s://%s" % (r["protocol"], r["proxy"]) for r in sess.suspicious])
        out("dead.txt", [d[0] for d in sess.dead])
        cols = ["proxy", "protocol", "status", "latency", "exit_ip", "anonymity", "https",
                "integrity", "country", "cc"]
        with open(os.path.join(run_dir, "report.csv"), "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(cols)
            for r in live + sess.suspicious:
                w.writerow([r[c] for c in cols])
        files.append("report.csv")
        with open(os.path.join(run_dir, "report.json"), "w", encoding="utf-8") as f:
            json.dump({"app": APP, "version": VERSION, "author": AUTHOR,
                       "date": datetime.now().isoformat(timespec="seconds"),
                       "checked": sess.stats.checked, "live": live,
                       "suspicious": sess.suspicious}, f, indent=2)
        files.append("report.json")
    if all_candidates:
        out("harvested_all.txt", [p.full for p in all_candidates])
    return run_dir, files, live


def print_summary(sess, run_dir, files, live):
    s = sess.stats
    el = (sess.t1 or time.perf_counter()) - sess.t0
    rate = (100.0 * s.live / s.checked) if s.checked else 0.0
    W = max(36, min(term_width() - 4, 66))
    bp = s.by_proto
    n5 = sum(1 for r in live if r["protocol"] == "socks5")
    n4 = sum(1 for r in live if r["protocol"] == "socks4")
    nh = sum(1 for r in live if r["protocol"] == "http")
    body = [
        "%s %s    %s %s" % (dim("checked"), paint(fmt_n(s.checked), WHITE, True), dim("time"), fmt_time(el)),
        "%s %s  (%.1f%%)" % (paint("LIVE", GREEN, True), paint(fmt_n(len(live)), GREEN, True), rate),
        "%s %s   %s %s" % (paint("DEAD", RED, True), paint(fmt_n(s.dead), RED),
                           paint("SUSPECT", YELLOW, True), paint(fmt_n(s.suspicious), YELLOW)),
        "%s %s   %s %s   %s %s" % (dim("socks5"), fmt_n(n5), dim("socks4"), fmt_n(n4), dim("http"), fmt_n(nh)),
    ]
    if live:
        lat = [r["latency"] for r in live]
        body.append("%s %s ms   %s %s ms" % (dim("fastest"), fmt_n(min(lat)), dim("avg"), fmt_n(sum(lat) / len(lat))))
    print()
    for ln in box(body, W, "RESULTS", GREEN if live else RED):
        print("  " + ln)
    import textwrap
    for i, ln in enumerate(textwrap.wrap(run_dir, max(20, term_width() - 6), break_long_words=True, break_on_hyphens=False)):
        print("  %s %s" % (paint(G.arrow, CYAN) if i == 0 else " ", paint(ln, WHITE, True)))
    for ln in textwrap.wrap("files: " + ", ".join(files), max(20, term_width() - 4)):
        print("  " + dim(ln))
    print()


# =============================================================================
#  RUNNERS
# =============================================================================

def make_cfg(conf, **ov):
    cfg = Cfg()
    cfg.timeout = float(conf.get("timeout", 6.0))
    cfg.retries = int(conf.get("retries", 1))
    cfg.concurrency = int(conf.get("concurrency", 0))
    cfg.test_url = conf.get("test_url") or DEFAULT_TEST_URL
    cfg.deep = bool(conf.get("deep", True))
    cfg.geo = bool(conf.get("geo", True))
    for k, v in ov.items():
        if v is not None and hasattr(cfg, k):
            setattr(cfg, k, v)
    if cfg.concurrency <= 0:
        cfg.concurrency = auto_concurrency()
    else:
        soft = raise_fd_limit()
        if soft:
            cfg.concurrency = min(cfg.concurrency, max(50, soft - 100))
    return cfg


def run_check(proxies, cfg, outdir, mode="quick", label="Checking", target=0, countries=None,
              all_candidates=None):
    if not proxies:
        print(paint("  No proxies to check.", YELLOW))
        return None
    if mode == "quick":
        cfg.deep, cfg.geo = False, False
    try:
        run_with_spinner("Preflight: checking your connection...", lambda: preflight(cfg))
    except PreflightError as e:
        print(paint("  %s %s" % (G.bad, e), RED))
        return None
    if cfg.real_ip is None:
        print(dim("  note: could not read your real IP - anonymity flag disabled"))
    if cfg.deep and not cfg.tls_verify:
        print(dim("  note: system CA store not usable - MITM detection disabled"))
    print()
    sess = Session(proxies, cfg, label=label, target=target)
    sess.execute()
    if cfg.geo and sess.live:
        try:
            geo = run_with_spinner("Locating exit nodes...", lambda: geo_lookup([r["exit_ip"] or r["host"] for r in sess.live]))
            for r in sess.live:
                c = geo.get(r["exit_ip"] or r["host"])
                if c:
                    r["country"], r["cc"] = c
        except Exception:
            pass
    run_dir, files, live = write_results(sess, outdir, mode, countries, all_candidates)
    print_summary(sess, run_dir, files, live)
    return sess


def inspect_single(raw, cfg):
    found = parse_proxies(raw)
    if not found:
        print(paint("  Could not read a proxy from: %s" % raw, RED))
        return
    p = found[0]
    cfg.deep = True
    try:
        run_with_spinner("Preflight...", lambda: preflight(cfg))
    except PreflightError as e:
        print(paint("  %s %s" % (G.bad, e), RED))
        return
    print()
    print("  %s %s" % (dim("target"), paint(p.full, WHITE, True)))
    print("  " + paint(G.h * 52, GREY))

    async def go():
        asyncio.get_running_loop().set_exception_handler(lambda _l, _c: None)
        rows = []
        for proto in ("socks5", "socks4", "http"):
            found_, reason = await check_proxy(p, cfg, protos=[proto])
            rows.append((proto, found_[0] if found_ else None, reason))
        return rows

    rows = asyncio.run(go())
    any_live = False
    for proto, res, reason in rows:
        name = proto.upper().ljust(7)
        if res:
            any_live = True
            col = GREEN if res["status"] == "live" else YELLOW
            tags = []
            if res["anonymity"]:
                tags.append(res["anonymity"])
            if res["https"]:
                tags.append("https:" + res["https"])
            if res["integrity"]:
                tags.append(res["integrity"])
            print("  %s %s %s  %s" % (paint(name, WHITE, True), paint(G.dot + " " + res["status"].upper(), col, True),
                                      paint("%d ms" % res["latency"], col), dim("exit " + (res["exit_ip"] or "?"))))
            if tags:
                print("  %s %s" % (" " * 7, dim("  ".join(tags))))
        else:
            print("  %s %s  %s" % (paint(name, WHITE, True), paint(G.ring + " failed", RED), dim(reason.split(":")[-1])))
    print()
    if not any_live:
        print(paint("  This proxy is not working (or needs credentials: user:pass@ip:port).", RED))
    print()


# =============================================================================
#  INTERACTIVE MENU
# =============================================================================

def ask(text, default=None):
    d = (" [%s]" % default) if default not in (None, "") else ""
    try:
        v = input("  %s %s%s%s " % (paint(G.arrow, CYAN, True), text, dim(d), paint(":", GREY))).strip()
    except EOFError:
        raise KeyboardInterrupt
    return v if v else (default if default is not None else "")


def ask_int(text, default, lo=0, hi=10 ** 9):
    while True:
        v = ask(text, default)
        try:
            n = int(v)
            if lo <= n <= hi:
                return n
        except (TypeError, ValueError):
            pass
        print(paint("    enter a number between %d and %d" % (lo, hi), YELLOW))


def ask_float(text, default, lo=0.5, hi=120.0):
    while True:
        v = ask(text, default)
        try:
            n = float(v)
            if lo <= n <= hi:
                return n
        except (TypeError, ValueError):
            pass
        print(paint("    enter a number between %s and %s" % (lo, hi), YELLOW))


def yes_no(text, default=True):
    v = ask("%s (y/n)" % text, "y" if default else "n").lower()
    return v.startswith("y")


def read_pasted():
    print(dim("    Paste your proxies (one per line), then press Enter on an empty line (or type END):"))
    lines = []
    while True:
        try:
            ln = input()
        except EOFError:
            break
        if not ln.strip() or ln.strip().upper() == "END":
            break
        lines.append(ln)
    return "\n".join(lines)


def read_path(path):
    path = os.path.expanduser(path.strip().strip('"').strip("'"))
    if path == "-":
        return sys.stdin.read()
    if os.path.isdir(path):
        chunks = []
        for name in sorted(os.listdir(path)):
            if name.lower().endswith((".txt", ".lst", ".list", ".csv")):
                with open(os.path.join(path, name), "r", encoding="utf-8", errors="replace") as f:
                    chunks.append(f.read())
        return "\n".join(chunks)
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def choose_input():
    print()
    print("    %s  Paste them here" % paint("[1]", CYAN, True))
    print("    %s  Load from a file or folder" % paint("[2]", CYAN, True))
    print("    %s  Download from a URL" % paint("[3]", CYAN, True))
    c = ask("Where are your proxies?", "2")
    try:
        if c == "1":
            text = read_pasted()
        elif c == "3":
            url = ask("List URL")
            text = run_with_spinner("Downloading...", lambda: http_get(url))
        else:
            text = read_path(ask("File path (drag & drop works)"))
    except Exception as e:
        print(paint("    %s %s" % (G.bad, e), RED))
        return []
    proxies = parse_proxies(text)
    print("  %s found %s unique proxies" % (paint(G.ok, GREEN, True), paint(fmt_n(len(proxies)), WHITE, True)))
    return proxies


def choose_type():
    print()
    print("    %s  Auto-detect (recommended)" % paint("[1]", CYAN, True))
    print("    %s  SOCKS5 only      %s  SOCKS4 only" % (paint("[2]", CYAN, True), paint("[3]", CYAN, True)))
    print("    %s  HTTP only        %s  SOCKS (4 + 5)" % (paint("[4]", CYAN, True), paint("[5]", CYAN, True)))
    c = ask("Proxy type?", "1")
    return {"2": "socks5", "3": "socks4", "4": "http", "5": "socks"}.get(c, "auto")


MENU = [
    ("1", "Quick Check", "alive / dead only, saves live.txt"),
    ("2", "Smart Check", "type, speed, country, safety scan"),
    ("3", "Harvest", "scrape free sources, then check"),
    ("4", "Single Proxy", "full report on one proxy"),
    ("5", "Sources & Keys", "manage sources and API keys"),
    ("6", "Settings", "timeout, threads, output folder"),
    ("7", "Guide", "how everything works"),
    ("0", "Exit", ""),
]


def print_menu():
    W = max(36, min(term_width() - 4, 62))
    rows = []
    for k, name, desc in MENU:
        left = "%s %s" % (paint("[%s]" % k, CYAN, True), paint(name.ljust(16), WHITE, True))
        rows.append(left + (dim(clip(desc, max(0, W - 29))) if W >= 52 else ""))
    for ln in box(rows, W, "MENU", VIOLET):
        print("  " + ln)


def flow_check(conf, mode):
    proxies = choose_input()
    if not proxies:
        return
    cfg = make_cfg(conf, proto=choose_type())
    label = "Quick Check" if mode == "quick" else "Smart Check"
    if mode == "smart":
        cfg.deep, cfg.geo = conf.get("deep", True), conf.get("geo", True)
    run_check(proxies, cfg, conf["outdir"], mode, label)


def flow_harvest(conf):
    print()
    print("    %s  Everything (auto)    %s  SOCKS5   %s  SOCKS4   %s  HTTP" % (
        paint("[1]", CYAN, True), paint("[2]", CYAN, True), paint("[3]", CYAN, True), paint("[4]", CYAN, True)))
    proto = {"2": "socks5", "3": "socks4", "4": "http"}.get(ask("Which proxies to harvest?", "1"), "auto")
    limit = ask_int("How many to check? (0 = all, can be huge)", conf.get("harvest_limit", 3000), 0, 2_000_000)
    target = ask_int("Stop after N live proxies? (0 = check all)", 0, 0, 1_000_000)
    print("    %s  Quick (live only)    %s  Smart (full analysis)" % (paint("[1]", CYAN, True), paint("[2]", CYAN, True)))
    mode = "smart" if ask("Mode?", "1") == "2" else "quick"
    print(dim("  Tip: free lists die fast - usually only 1-10% of them are alive."))
    print()
    proxies = harvest(conf, proto, limit)
    if not proxies:
        return
    cfg = make_cfg(conf, proto=proto)
    if mode == "smart":
        cfg.deep, cfg.geo = conf.get("deep", True), conf.get("geo", True)
    run_check(proxies, cfg, conf["outdir"], mode, "Harvest + check", target=target, all_candidates=proxies)


def flow_single(conf):
    raw = ask("Proxy (ip:port or user:pass@ip:port)")
    if raw:
        inspect_single(raw, make_cfg(conf))


def flow_sources(conf):
    while True:
        print()
        srcs = all_sources(conf)
        groups = list(dict.fromkeys(s["group"] for s in srcs))
        W = max(36, min(term_width() - 4, 62))
        rows = []
        for i, g in enumerate(groups, 1):
            n = sum(1 for s in srcs if s["group"] == g)
            on = g not in conf["disabled_groups"]
            custom = any((not s["builtin"]) and s["group"] == g for s in srcs)
            keyed = g in conf["keys"]
            tag = paint("ON ", GREEN, True) if on else paint("OFF", RED, True)
            extra = " %s" % dim("custom" + (", key set" if keyed else "")) if custom else ""
            cnt = ("%d" % n) if W < 52 else ("%d list%s" % (n, "s" if n > 1 else ""))
            if W < 52:
                extra = " %s" % dim("custom") if custom else ""
            rows.append("%s %s %s %s%s" % (paint("%2d" % i, CYAN, True), tag, clip(g, min(20, max(8, W - 22))).ljust(min(20, max(8, W - 22))), dim(cnt), extra))
        for ln in box(rows, W, "SOURCES", VIOLET):
            print("  " + ln)
        print("    %s toggle   %s add   %s API key" % (paint("[T]", CYAN, True), paint("[A]", CYAN, True), paint("[K]", CYAN, True)))
        print("    %s delete custom   %s back" % (paint("[D]", CYAN, True), paint("[B]", CYAN, True)))
        c = ask("Choice", "B").lower()
        if c == "b" or not c:
            return
        if c == "t":
            n = ask_int("Group number to toggle", 1, 1, len(groups))
            g = groups[n - 1]
            if g in conf["disabled_groups"]:
                conf["disabled_groups"].remove(g)
            else:
                conf["disabled_groups"].append(g)
            save_config(conf)
        elif c == "a":
            print(dim("    Some providers need a free API key. Steps: open the provider's site, sign up,"))
            print(dim("    copy the key from the dashboard, then paste it here. Use {KEY} inside the URL"))
            print(dim("    where the key must go, e.g. https://api.example.com/list?apikey={KEY}"))
            name = ask("Source name")
            url = ask("List URL (plain text, HTML or JSON)")
            if not name or not url.lower().startswith("http"):
                print(paint("    cancelled (a name and an http(s) URL are required)", YELLOW))
                continue
            proto = {"2": "socks5", "3": "socks4", "4": "http"}.get(
                ask("Protocol? 1=mixed/unknown 2=socks5 3=socks4 4=http", "1"), "mixed")
            entry = {"name": name, "url": url, "proto": proto}
            how = "{KEY}" in url
            if not how and yes_no("Does it need an API key sent as an HTTP header?", False):
                entry["key_header"] = ask("Header name", "Authorization")
                how = True
            conf["custom_sources"] = [x for x in conf["custom_sources"] if x["name"] != name] + [entry]
            if how:
                conf["keys"][name] = ask("Paste your API key")
            save_config(conf)
            print(paint("    %s source saved" % G.ok, GREEN))
        elif c == "k":
            keyed = [s["name"] for s in srcs if not s["builtin"]]
            if not keyed:
                print(paint("    No custom sources yet - add one with [A].", YELLOW))
                continue
            print(dim("    custom sources: " + ", ".join(keyed)))
            name = ask("Source name")
            if name in keyed:
                conf["keys"][name] = ask("New API key")
                save_config(conf)
                print(paint("    %s key updated" % G.ok, GREEN))
        elif c == "d":
            name = ask("Custom source name to delete")
            conf["custom_sources"] = [x for x in conf["custom_sources"] if x["name"] != name]
            conf["keys"].pop(name, None)
            save_config(conf)


def flow_settings(conf):
    while True:
        print()
        W = max(36, min(term_width() - 4, 62))
        rows = [
            "%s timeout        %s s" % (paint("[1]", CYAN, True), paint(conf["timeout"], WHITE, True)),
            "%s retries        %s" % (paint("[2]", CYAN, True), paint(conf["retries"], WHITE, True)),
            "%s concurrency    %s" % (paint("[3]", CYAN, True), paint(conf["concurrency"] or "auto", WHITE, True)),
            "%s output folder  %s" % (paint("[4]", CYAN, True), paint(clip(conf["outdir"], W - 30), WHITE, True)),
            "%s test URL       %s" % (paint("[5]", CYAN, True), paint(clip(conf["test_url"], W - 30), WHITE, True)),
            "%s smart: deep    %s" % (paint("[6]", CYAN, True), paint("on" if conf["deep"] else "off", WHITE, True)),
            "%s smart: country %s" % (paint("[7]", CYAN, True), paint("on" if conf["geo"] else "off", WHITE, True)),
            "%s harvest limit  %s" % (paint("[8]", CYAN, True), paint(conf["harvest_limit"], WHITE, True)),
            "%s reset defaults" % paint("[9]", CYAN, True),
        ]
        for ln in box(rows, W, "SETTINGS", VIOLET):
            print("  " + ln)
        c = ask("Change which? (Enter = back)", "")
        if not c:
            return
        if c == "1":
            conf["timeout"] = ask_float("Timeout in seconds", conf["timeout"], 1, 60)
        elif c == "2":
            conf["retries"] = ask_int("Retries for slow proxies", conf["retries"], 0, 5)
        elif c == "3":
            conf["concurrency"] = ask_int("Parallel checks (0 = auto)", conf["concurrency"], 0, 5000)
        elif c == "4":
            conf["outdir"] = ask("Output folder", conf["outdir"])
        elif c == "5":
            url = ask("Test URL (http only)", conf["test_url"])
            try:
                parse_test_url(url)
                conf["test_url"] = url
            except PreflightError as e:
                print(paint("    %s" % e, YELLOW))
        elif c == "6":
            conf["deep"] = not conf["deep"]
        elif c == "7":
            conf["geo"] = not conf["geo"]
        elif c == "8":
            conf["harvest_limit"] = ask_int("Default harvest limit (0 = all)", conf["harvest_limit"], 0, 2_000_000)
        elif c == "9":
            for k in ("timeout", "retries", "concurrency", "outdir", "test_url", "geo", "deep", "harvest_limit"):
                conf[k] = DEFAULTS[k]
        save_config(conf)


GUIDE = [
    ("QUICK CHECK", "Fastest. Detects the type and keeps only working proxies -> live.txt"),
    ("SMART CHECK", "Adds latency, country, anonymity, an HTTPS test and a safety scan for "
                    "content injection / MITM. Splits the files by type."),
    ("HARVEST", "Downloads fresh free lists from many sources, mixes them fairly, "
                "checks them and saves the live ones."),
    ("SINGLE PROXY", "Tests one proxy against SOCKS5, SOCKS4 and HTTP."),
    ("INPUT", "ip:port   user:pass@ip:port   ip:port:user:pass   socks5://ip:port "
              "(lists, HTML pages and JSON work too)."),
    ("OUTPUT", "maskproxy_results/<date_time>/ - a new folder every run, nothing is overwritten."),
    ("LIVE MEANS", "A real request goes THROUGH the proxy and the answer must be a valid "
                   "IP address. A handshake alone is not enough."),
    ("SUSPECT", "The proxy answered but altered a test page or broke TLS. Never use these "
                "for anything sensitive. Free proxies are untrusted."),
    ("TIPS", "Lower the concurrency on weak phones or Wi-Fi, raise the timeout for slow "
             "lists. Run with --help for command-line options."),
]


def print_guide():
    import textwrap
    w = max(30, term_width() - 4)
    print()
    for title, text in GUIDE:
        print("  " + paint(title, CYAN, True))
        for ln in textwrap.wrap(text, w - 2):
            print("    " + ln)
    print()


def interactive(conf):
    show_banner(True)
    while True:
        print()
        print_menu()
        try:
            c = ask("Choose", "1")
        except KeyboardInterrupt:
            break
        try:
            if c == "1":
                flow_check(conf, "quick")
            elif c == "2":
                flow_check(conf, "smart")
            elif c == "3":
                flow_harvest(conf)
            elif c == "4":
                flow_single(conf)
            elif c == "5":
                flow_sources(conf)
            elif c == "6":
                flow_settings(conf)
            elif c == "7":
                print_guide()
            elif c == "0":
                break
            else:
                continue
            if c in "1234":
                try:
                    input(dim("  Press Enter to return to the menu..."))
                except EOFError:
                    break
                clear_screen()
                show_banner(False)
        except KeyboardInterrupt:
            print()
            continue
    print()
    print("  " + gradient("Thanks for using MaskProxy - made by %s" % AUTHOR, CYAN, MAGENTA))
    print()


# =============================================================================
#  SELF TEST (local mock proxies - no internet needed)
# =============================================================================

async def _pipe(r, w):
    try:
        while True:
            d = await r.read(4096)
            if not d:
                break
            w.write(d)
            await w.drain()
    except Exception:
        pass
    finally:
        try:
            w.close()
        except Exception:
            pass


async def _relay(reader, writer, host, port):
    try:
        ur, uw = await asyncio.open_connection(host, port)
    except Exception:
        writer.close()
        return False
    await asyncio.gather(_pipe(reader, uw), _pipe(ur, writer))
    return True


async def mock_target(r, w):
    try:
        await r.readuntil(b"\r\n\r\n")
        body = b"203.0.113.7\n"
        w.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s" % (len(body), body))
        await w.drain()
    except Exception:
        pass
    finally:
        w.close()


async def mock_socks5(r, w):
    try:
        head = await r.readexactly(2)
        await r.readexactly(head[1])
        w.write(b"\x05\x00")
        req = await r.readexactly(4)
        if req[3] == 3:
            n = (await r.readexactly(1))[0]
            host = (await r.readexactly(n)).decode()
        else:
            host = socket.inet_ntoa(await r.readexactly(4))
        port = struct.unpack(">H", await r.readexactly(2))[0]
        w.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        await w.drain()
        await _relay(r, w, host, port)
    except Exception:
        w.close()


async def mock_socks4(r, w):
    try:
        req = await r.readexactly(8)
        await r.readuntil(b"\x00")
        port = struct.unpack(">H", req[2:4])[0]
        host = socket.inet_ntoa(req[4:8])
        w.write(b"\x00\x5a" + req[2:8])
        await w.drain()
        await _relay(r, w, host, port)
    except Exception:
        w.close()


async def mock_http(r, w):
    try:
        head = await r.readuntil(b"\r\n\r\n")
        first = head.split(b"\r\n")[0].decode()
        method, target, _ = first.split(" ", 2)
        if method == "CONNECT":
            host, port = target.rsplit(":", 1)
            w.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            await w.drain()
            await _relay(r, w, host, int(port))
        else:
            u = urllib.parse.urlsplit(target)
            ur, uw = await asyncio.open_connection(u.hostname, u.port or 80)
            uw.write(head)
            await uw.drain()
            await asyncio.gather(_pipe(ur, w), asyncio.sleep(0))
    except Exception:
        w.close()


async def mock_junk(r, w):
    try:
        w.write(b"HELLO, I AM NOT A PROXY\r\n")
        await w.drain()
    except Exception:
        pass
    finally:
        w.close()


def selftest():
    Term.init()
    print(paint("  Running offline self-test with local mock proxies...", CYAN))

    async def go():
        servers = []
        ports = {}
        for name, fn in (("target", mock_target), ("socks5", mock_socks5), ("socks4", mock_socks4),
                         ("http", mock_http), ("junk", mock_junk)):
            srv = await asyncio.start_server(fn, "127.0.0.1", 0)
            ports[name] = srv.sockets[0].getsockname()[1]
            servers.append(srv)
        dead_port = ports["junk"] + 1 if ports["junk"] < 65000 else 40000
        cfg = Cfg()
        cfg.timeout, cfg.retries, cfg.concurrency = 3.0, 0, 20
        cfg.test_host, cfg.test_port, cfg.test_path, cfg.test_ip4 = "127.0.0.1", ports["target"], "/", "127.0.0.1"
        cases = [
            ("socks5", Proxy("127.0.0.1", ports["socks5"]), "socks5"),
            ("socks4", Proxy("127.0.0.1", ports["socks4"]), "socks4"),
            ("http", Proxy("127.0.0.1", ports["http"]), "http"),
            ("hint-wrong", Proxy("127.0.0.1", ports["socks5"], hint="http"), "socks5"),
            ("junk", Proxy("127.0.0.1", ports["junk"]), None),
            ("closed", Proxy("127.0.0.1", dead_port), None),
        ]
        sess = Session([c[1] for c in cases], cfg, "selftest")
        sess.cfg = cfg
        results = []
        for label, p, expect in cases:
            found, reason = await check_proxy(p, cfg)
            got = found[0]["protocol"] if found else None
            results.append((label, expect, got, reason))
        for s in servers:
            s.close()
        return results

    ok = True
    for label, expect, got, reason in asyncio.run(go()):
        good = expect == got
        ok &= good
        print("  %s %-11s expected=%-7s got=%-7s %s" % (
            paint(G.ok, GREEN, True) if good else paint(G.bad, RED, True), label, expect, got, dim(reason if not got else "")))
    print(paint("  SELF-TEST PASSED" if ok else "  SELF-TEST FAILED", GREEN if ok else RED, True))
    return 0 if ok else 1


# =============================================================================
#  CLI
# =============================================================================

def build_parser():
    ap = argparse.ArgumentParser(
        prog="maskproxy", description="MaskProxy - proxy checker, harvester and analyzer. "
        "Run without arguments for the interactive menu.", epilog="by %s" % AUTHOR)
    src = ap.add_argument_group("input")
    src.add_argument("-f", "--file", help="file or folder with proxies ('-' = stdin)")
    src.add_argument("-u", "--url", help="URL of a proxy list")
    src.add_argument("-p", "--proxy", help="inspect one proxy in detail")
    src.add_argument("--harvest", action="store_true", help="download free proxy lists, then check them")
    src.add_argument("--sources", help="comma-separated source groups for --harvest")
    src.add_argument("--list-sources", action="store_true", help="show all sources and exit")
    chk = ap.add_argument_group("checking")
    chk.add_argument("-m", "--mode", choices=["quick", "smart"], default="quick", help="quick = live only, smart = full analysis")
    chk.add_argument("-t", "--type", choices=["auto", "socks", "socks4", "socks5", "http"], default="auto", help="proxy type (default: auto-detect)")
    chk.add_argument("--strict", action="store_true", help="only try the protocol hinted by the source/scheme")
    chk.add_argument("-c", "--concurrency", type=int, help="parallel checks (default: auto)")
    chk.add_argument("--timeout", type=float, help="seconds per proxy (default 6)")
    chk.add_argument("--retries", type=int, help="retries for slow proxies (default 1)")
    chk.add_argument("--test-url", help="http URL used for the test request")
    chk.add_argument("--no-deep", action="store_true", help="smart mode: skip HTTPS/integrity tests")
    chk.add_argument("--no-geo", action="store_true", help="smart mode: skip country lookup")
    chk.add_argument("--country", help="smart mode: keep only these country codes, e.g. US,DE")
    chk.add_argument("-l", "--limit", type=int, help="harvest: how many proxies to check (0 = all)")
    chk.add_argument("--target", type=int, default=0, help="stop after N live proxies")
    out = ap.add_argument_group("output")
    out.add_argument("-o", "--out", help="output folder (default: maskproxy_results)")
    out.add_argument("--no-banner", action="store_true")
    out.add_argument("--no-color", action="store_true")
    out.add_argument("--ascii", action="store_true", help="plain ASCII symbols")
    out.add_argument("--selftest", action="store_true", help="offline self-test with mock proxies")
    out.add_argument("-V", "--version", action="store_true")
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.version:
        print("%s %s by %s" % (APP, VERSION, AUTHOR))
        return 0
    if args.selftest:
        return selftest()
    Term.init(no_color=args.no_color, ascii_only=args.ascii)
    conf = load_config()
    if args.out:
        conf["outdir"] = args.out
    if args.test_url:
        conf["test_url"] = args.test_url
    if args.timeout:
        conf["timeout"] = args.timeout
    if args.retries is not None:
        conf["retries"] = args.retries

    if args.list_sources:
        for s in all_sources(conf):
            off = " (disabled)" if s["group"] in conf["disabled_groups"] else ""
            print("%-22s %-7s %s%s" % (s["group"], s["proto"], s["url"], off))
        return 0

    has_input = args.file or args.url or args.proxy or args.harvest
    if not has_input:
        interactive(conf)
        return 0

    if not args.no_banner:
        show_banner(True)
    cfg_kw = dict(proto=args.type, strict=args.strict)
    if args.concurrency:
        cfg_kw["concurrency"] = args.concurrency
    cfg = make_cfg(conf, **cfg_kw)
    if args.mode == "smart":
        cfg.deep = not args.no_deep
        cfg.geo = not args.no_geo

    if args.proxy:
        inspect_single(args.proxy, cfg)
        return 0

    candidates = None
    if args.harvest:
        groups = [g.strip() for g in args.sources.split(",")] if args.sources else None
        limit = args.limit if args.limit is not None else conf.get("harvest_limit", 3000)
        proxies = harvest(conf, args.type, limit, groups)
        candidates = proxies
    elif args.url:
        try:
            proxies = parse_proxies(http_get(args.url))
        except Exception as e:
            print(paint("  %s could not download: %s" % (G.bad, e), RED))
            return 2
    else:
        try:
            proxies = parse_proxies(read_path(args.file))
        except OSError as e:
            print(paint("  %s %s" % (G.bad, e), RED))
            return 2
    print("  %s %s proxies loaded" % (paint(G.ok, GREEN, True), paint(fmt_n(len(proxies)), WHITE, True)))
    countries = args.country.split(",") if args.country else None
    sess = run_check(proxies, cfg, conf["outdir"], args.mode, "Harvest + check" if args.harvest else "Checking",
                     target=args.target, countries=countries, all_candidates=candidates)
    return 0 if sess else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.stdout.write("\033[?25h\n")
        sys.exit(130)
    except BrokenPipeError:
        try:
            sys.stdout = open(os.devnull, "w")
        except OSError:
            pass
        sys.exit(0)
