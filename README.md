# — Automated Endpoint Enumerator & Web Vulnerability Tester

Enumerate endpoints at scale, extract parameters, analyze JavaScript, then actively test for common web vulns using **external payload lists**. `test2` automates collection (no single-URL input required) by harvesting endpoints first, then testing them in bulk.


---

## ✨ What it does

* **Bulk endpoint discovery** (no manual URL feeding):

  * `waybackurls` + `ParamSpider` to harvest URLs.
  * **JS analysis** to extract additional endpoints & parameter names.
* **First-pass triage** using industry tools:

  * `gf` patterns: xss / sqli / ssrf / lfi / rce / redirect.
  * `kxss` to hint reflected-XSS candidates.
* **Active testing** with evidence-based confirmation:

  * **XSS** (reflection double-check with distinct tokens).
  * **SQLi** (error-based + time-based).
  * **Open Redirect** (3xx Location to external host, double-checked).
  * **SSRF** (OAST-supported; heuristic fallback).
  * **LFI** (content signatures like `/etc/passwd`, `win.ini`).
  * **RCE** (echo token + time-based fallback).
* **External payload files**: edit payloads without touching the code.
* **GET / POST / JSON** testing modes; POST/JSON keys read from files.
* **Cookie** support for authenticated flows; **TLS verify** toggle.
* **Interactive loop**: after each test, the menu returns so you can choose another class. **Non-interactive** mode available.
* **Outputs**: CSV per vuln class + consolidated HTML report with the **exact payload** that proved each finding.

---

## 🧱 Requirements

* **Go** ≥ 1.20 (for `waybackurls`, `gf`, `kxss`).
* **Python** ≥ 3.8 (`requests`).
* **git** (to fetch `Gf-Patterns`).

`test2` will **not reinstall** tools that already exist. If a tool is missing, it can **auto-install** it (unless you pass `--no-auto-install`).

---

## 📦 Installation

### 1) Clone

```bash
git clone <your-repo-url> test2
cd test2
```

### 2) (Optional) Manual install of external tools

```bash
# Go tools
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/gf@latest
go install github.com/tomnomnom/hacks/kxss@latest

# gf patterns
mkdir -p ~/.gf && git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf

# Python deps
pip install --user requests
# ParamSpider (choose one)
pipx install paramspider
# or
python3 -m pip install --user paramspider
```

Ensure `$(go env GOBIN)` or `$(go env GOPATH)/bin` and Python user bin (e.g., `~/.local/bin`) are in your `PATH`.

### 3) Payload & key files

Place these **next to** `test.py` (or point to them with `--payload-dir`):

```
# Payload lists (one per line; use {X} tokens when needed)
xsspayload.txt
sqlipayload_error.txt
sqlipayload_time_5.txt
sqlipayload_time_7.txt
lfipayload.txt
rcepayload_echo.txt
rcepayload_time_5.txt
rcepayload_time_7.txt
redirectpayload.txt
ssrfpayload.txt

# Body keys for POST/JSON
bodykeys.txt      # form fields for POST
jsonkeys.txt      # JSON top-level keys
```

Minimal examples:

```text
# xsspayload.txt
<svg/onload=alert('{X}')>
"><img src=x onerror=alert('{X}')>
```

```text
# sqlipayload_time_5.txt
' OR SLEEP(5)-- -
'));SELECT pg_sleep(5);--
```

---

## 🚀 Quickstart

Basic enumerate + interactive menu (menu returns after every test):

```bash
python3 test.py -d target.com --include-subdomains --payload-dir payload/
```

Non-interactive (GET/POST/JSON), with cookie + HTML report:

```bash
python3 test.py -d target.com \
  --http-methods GET,POST,JSON \
  --cookie 'session=abc' --include-subdomains \
  --payload-dir . --report --non-interactive --insecure
```

Multiple domains:

```bash
python3 test.py --domains-file targets.txt --report
```

Skip auto-installation:

```bash
python3 test.py -d target.com --no-auto-install
```

---

## 🧪 How confirmation works (low false-positives)

* **XSS**: same template with two different random tokens must reflect unencoded.
* **SQLi**: (1) error strings (MySQL/Postgres/SQLite/…); (2) time delta baseline vs `SLEEP(5/7)`.
* **Open Redirect**: `3xx` with `Location` outside original host; confirmed with two different destinations.
* **LFI**: detect `root:x:0:0:` or `[fonts]` in response.
* **RCE**: echo a random token, fallback to time-based delay.
* **SSRF**: best-effort with **OAST** (`--oast-url`), otherwise heuristic indicators.

For each `(url,param)` (or body key), testing **stops** after the first confirmed finding, and the **exact payload** used is printed and saved.

---

## 🧰 CLI (most used)

```text
-d, --domain <host>            Single target domain
    --domains-file <file>      Multiple domains (one per line)
-o, --output <dir>             Output root (default: out)
    --threads <n>              Concurrency (default: 20)
    --timeout <sec>            HTTP timeout (default: 15)
    --max-urls <n>             Cap enumeration size (default: 100000)
    --no-wayback               Skip waybackurls
    --no-paramspider           Skip ParamSpider
    --no-js                    Skip JS analysis
    --include-subdomains       Include subs in ParamSpider
    --paramspider-args "..."   Extra flags for ParamSpider
    --user-agent "..."         Custom UA
    --cookie "k=v; ..."        Cookie header (optional)
    --oast-url <https://...>   Collaborator endpoint for SSRF
    --insecure                 Disable TLS verification
    --no-auto-install          Do not auto-install missing tools
    --non-interactive          Run all tests without menu
    --payload-dir <dir>        Directory of payload & keys files
    --http-methods list        Comma list: GET,POST,JSON
    --report                   Generate HTML report
```

---

## 📂 Output structure

```
out/
  └─ <domain>/
       ├─ endpoints.txt
       ├─ endpoints_with_params.txt
       ├─ xsstest.txt
       ├─ sqlitest.txt
       ├─ ssrftest.txt
       ├─ lfitest.txt
       ├─ rcetest.txt
       ├─ redirecttest.txt
       ├─ js_urls.txt
       ├─ js_params.txt
       ├─ tooling_report.json
       └─ findings/
            ├─ xss.csv
            ├─ sqli.csv
            ├─ open_redirect.csv
            ├─ ssrf.csv
            ├─ lfi.csv
            ├─ rce.csv
            └─ report.html  # when --report or via menu option 7
```

CSV columns: `url,param,payload,evidence,evidence_type,rt_delta_ms`.

---

## 🧪 HTML report

Generate via `--report` or menu option **7**, then open `out/<domain>/findings/report.html`.

---

## 🔧 Notes on tooling

`test2` integrates community tools to maximize coverage:

* **`gf`** — pattern-based filtering (requires patterns in `~/.gf`).
* **`kxss`** — reflected XSS candidate finder.
* **`waybackurls`** — archive-based URL collection.
* **`ParamSpider`** — parameterized URL discovery.

This combination yields far more candidate endpoints than supplying a single URL manually, enabling broad, automated testing.

---

## 🐳 Docker (optional)

A minimal example you can adapt:

```Dockerfile
FROM golang:1.22-bullseye AS build
RUN go install github.com/tomnomnom/waybackurls@latest \
 && go install github.com/tomnomnom/gf@latest \
 && go install github.com/tomnomnom/hacks/kxss@latest

FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /go/bin/* /usr/local/bin/
RUN git clone https://github.com/1ndianl33t/Gf-Patterns /root/.gf \
 && pip install --no-cache-dir requests paramspider
WORKDIR /app
COPY test.py /app/test.py
COPY payloads/ /app/payloads/
ENTRYPOINT ["python","/app/test.py"]
```

Build & run:

```bash
docker build -t test2 .
docker run --rm -it -v "$PWD/out:/app/out" test2 -d target.com --payload-dir /app/payloads --include-subdomains --report --non-interactive
```

---

## 🔒 Safety checklist

* Have **written authorization** for every scope.
* Coordinate time-based tests to avoid disruption.
* Store outputs securely; they may contain sensitive data.

---

## 🙏 Acknowledgements

* [`waybackurls`](https://github.com/tomnomnom/waybackurls)
* [`gf`](https://github.com/tomnomnom/gf)
* [`kxss`](https://github.com/tomnomnom/hacks/tree/master/kxss)
* [`ParamSpider`](https://github.com/devanshbatham/ParamSpider)

---

