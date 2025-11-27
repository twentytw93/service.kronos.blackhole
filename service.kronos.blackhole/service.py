# -*- coding: utf-8 -*-
# Kronos Blackhole – Tracker Protection Layer (No VPN Check)
# v1.0.3 – native file logging (Windows-safe), dynamic paths, startup self-test

import os
import time
import socket
import ssl
import http.client
from datetime import datetime

import xbmc
import xbmcvfs
import xbmcaddon

# ---------- Add-on info / dynamic paths ----------
ADDON = xbmcaddon.Addon()
ADDON_ID = ADDON.getAddonInfo('id')                                   # e.g. service.kronos.blackhole
ADDON_PATH = xbmcvfs.translatePath(ADDON.getAddonInfo('path'))        # addon install dir
DATA_DIR = xbmcvfs.translatePath(f"special://profile/addon_data/{ADDON_ID}")

BLOCKLIST_PATH = os.path.join(ADDON_PATH, 'resources', 'lists', 'trackers.txt')
WHITELIST_PATH = os.path.join(ADDON_PATH, 'resources', 'lists', 'allow.txt')
LOG_FILE = os.path.join(DATA_DIR, 'blackhole.log')

SLEEP_BEFORE_START = 5  # seconds
SELF_TEST = True        # set False after you verify logging works

# ---------- Globals ----------
BLOCKED = set()
ALLOWED = set()
ORIG_getaddrinfo = socket.getaddrinfo
ORIG_wrap_socket = ssl.SSLContext.wrap_socket
ORIG_http_request = http.client.HTTPConnection.request


# ---------- Logging (native file I/O; xbmc log stays too) ----------
def _file_log(msg: str) -> None:
    """Reliable file logger using native open(); makes sure folder exists."""
    try:
        if not os.path.isdir(DATA_DIR):
            os.makedirs(DATA_DIR, exist_ok=True)
        with open(LOG_FILE, 'a', encoding='utf-8') as fh:
            fh.write(msg + "\n")
    except Exception as e:
        # Last resort: echo failure to Kodi log
        xbmc.log(f"[Kronos Blackhole] File log failed: {e}", xbmc.LOGERROR)

def log(message, level=xbmc.LOGINFO):
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {message}"
    xbmc.log(f"[Kronos Blackhole] {message}", level)
    _file_log(line)


# ---------- Lists ----------
def _read_lines_native(path_str):
    """Read text with native open()."""
    try:
        with open(path_str, 'r', encoding='utf-8', errors='ignore') as fh:
            return fh.read().splitlines()
    except Exception as e:
        log(f"Error reading {path_str}: {e}", xbmc.LOGERROR)
        return []

def load_blocklists():
    def parse(path):
        lines = _read_lines_native(path)
        out = set()
        for line in lines:
            s = line.strip().lower()
            if s and not s.startswith('#'):
                out.add(s)
        log(f"Loaded {len(out)} entries from {path}")
        return out

    global BLOCKED, ALLOWED
    BLOCKED = parse(BLOCKLIST_PATH)
    ALLOWED = parse(WHITELIST_PATH)
    log(f"Total blocked domains: {len(BLOCKED)}")
    log(f"Total whitelisted domains: {len(ALLOWED)}")


# ---------- Matching ----------
def is_blocked(hostname: str) -> bool:
    if not hostname:
        return False
    hostname = hostname.lower()
    if hostname in ALLOWED:
        return False
    parts = hostname.split('.')
    for i in range(len(parts)):
        if ".".join(parts[i:]) in BLOCKED:
            return True
    return False


# ---------- Patches ----------
def patched_getaddrinfo(host, *args, **kwargs):
    if is_blocked(host):
        log(f"BLOCKED DNS lookup: {host}")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('0.0.0.0', 0))]
    return ORIG_getaddrinfo(host, *args, **kwargs)

def patched_wrap_socket(self, *args, **kwargs):
    server_hostname = kwargs.get("server_hostname")
    if is_blocked(server_hostname):
        log(f"BLOCKED TLS/SNI: {server_hostname}")
        raise ssl.SSLError("Kronos Blackhole blocked TLS handshake")
    return ORIG_wrap_socket(self, *args, **kwargs)

def patched_http_request(self, method, url, body=None, headers=None, *a, **kw):
    if headers is None:
        headers = {}
    host = headers.get("Host")
    if is_blocked(host):
        log(f"BLOCKED HTTP Host: {host}")
        self.close()
        raise ConnectionAbortedError("Kronos Blackhole blocked HTTP request")
    return ORIG_http_request(self, method, url, body, headers, *a, **kw)


# ---------- Self-test ----------
def self_test_once():
    """Force one blocked resolution so the log file cannot stay empty."""
    try:
        # Prefer a well-known tracker if present; otherwise first from BLOCKED.
        candidate = None
        for probe in ("google-analytics.com", "stats.wp.com", "api.mixpanel.com"):
            if probe in BLOCKED:
                candidate = probe
                break
        if candidate is None and BLOCKED:
            candidate = next(iter(BLOCKED))
        if candidate:
            try:
                socket.getaddrinfo(candidate, 80)  # will be intercepted if patches are active
                log(f"SELF-TEST attempted DNS on {candidate}")
            except Exception as e:
                # Intercepted paths may raise, which is fine; we just want the log line
                log(f"SELF-TEST exception (expected if blocked): {e}")
        else:
            log("SELF-TEST skipped (empty blocklist)")
    except Exception as e:
        log(f"SELF-TEST failed: {e}", xbmc.LOGERROR)


# ---------- Lifecycle ----------
def start_blackhole():
    load_blocklists()
    socket.getaddrinfo = patched_getaddrinfo
    ssl.SSLContext.wrap_socket = patched_wrap_socket
    http.client.HTTPConnection.request = patched_http_request
    log("Protection layer activated successfully")
    if SELF_TEST:
        self_test_once()

def main_loop():
    log(f"Service starting… (addon_id={ADDON_ID})")
    # Touch log so the file is guaranteed to exist
    _file_log("=== Kronos Blackhole boot ===")
    time.sleep(SLEEP_BEFORE_START)
    try:
        start_blackhole()
        log("Entering main monitoring loop")
        monitor = xbmc.Monitor()
        while not monitor.abortRequested():
            if monitor.waitForAbort(300):  # 5 minutes
                break
            load_blocklists()  # hot-reload lists
    except Exception as e:
        log(f"Critical error in main loop: {e}", xbmc.LOGERROR)
    finally:
        # restore originals
        socket.getaddrinfo = ORIG_getaddrinfo
        ssl.SSLContext.wrap_socket = ORIG_wrap_socket
        http.client.HTTPConnection.request = ORIG_http_request
        log("Service stopped")


if __name__ == '__main__':
    log("Script started directly (not as Kodi service)")
    main_loop()