# XSSHuntS (`xsshunts`)

**Automated Multi-Vector Cross-Site Scripting (XSS) Scanner & Auditor — written in Go, powered by Playwright.**

XSSHuntS is an automated multi-vector XSS scanner and auditor written in Go by [zapstiko](https://github.com/zapstiko). It drives real headless browser instances through [Playwright Go](https://github.com/playwright-community/playwright-go) — Firefox, Chromium or WebKit — and hooks the browser event loop to intercept genuine JavaScript execution (`alert`, `confirm`, `prompt`). Findings are confirmed inside the DOM, eliminating the false positives typical of regex-only scanners.

> **Authorized testing only.** Use XSSHuntS strictly against systems you own or have explicit written permission to test.

---

## Features

- **7-phase audit pipeline** — parameter mining → reflection analysis → GET/DOM → POST forms → path → fragment → headers
- **Dialog-confirmed XSS** — real payload execution verified via `alert` / `confirm` / `prompt` interception
- **Parameter mining** — URL query parameters, HTML form controls, inline-script variables (`let`/`const`/`var`, `window.*`, `get()` calls), live `window` globals, and hidden-parameter probing with built-in / custom wordlists
- **Reflection engine** — canary tokens, syntactic context mapping (`html`, `attribute`, `javascript`, `url`, `dom_js_html`)
- **Special-character matrix** — classifies `' " < > / ; ( ) { } = `` as *allowed*, *escaped*, *filtered*, *replaced* or *absent*
- **POST form automation** — fills real forms via `requestSubmit()` or builds synthetic forms, with base64 HTML reproduction PoCs
- **Path / fragment / header vectors** — URL path segment injection, SPA hash routes, and 17 HTTP headers (`User-Agent`, `Cookie`, `X-Forwarded-*`, `Referer`, …)
- **Crawler & concurrency** — BFS spider with form/link discovery and a concurrent multi-tab worker pool
- **WAF / rate-limit awareness** — fingerprints Cloudflare, AWS WAF/CloudFront, Akamai, Imperva, ModSecurity, Wordfence, Sucuri, F5, and 429 throttling; automatically doubles delays and backs off
- **Authenticated scans** — cookie strings/files (Netscape, JSON, `k=v`), custom headers, per-target cookie handling
- **Reports** — console summary and JSON export with raw HTTP request blocks, confidence scores and PoCs
- **CLI** — full flag set (`-u`, `--scan`, `-m`, `-p`, `-d`, `-c`, `-H`, `--crawl`, `--show-*`, …)
- **Two engines in one repo** — the main Playwright engine plus an experimental Chromium-only `chromedp` engine (`cmd/xsshunts-chromedp`)

---

## Audit Pipeline

```
[Step 0: Mining]  ──>  [Step 1: Canary Probing]  ──>  [Step 2: GET & DOM XSS]
                                                               │
[Step 5: Fragment] <──  [Step 4: Path XSS]  <──  [Step 3: POST Form XSS]
        │
        └───> [Step 6: Header XSS]  ───> [Verification & Reporting]
```

| Step | Module | Attack Vector & Description |
| --- | --- | --- |
| **0** | `modules/mining.go` | **Parameter Mining**: extracts query params, form controls, global `window` JS variables, and probes hidden parameters using wordlists. |
| **1** | `modules/reflections.go` | **Reflection Analysis & Character Probing**: injects unique canary tokens, maps syntactic contexts, and probes the special-character reflection matrix. |
| **2** | `modules/getdom.go` | **Reflected GET & DOM XSS**: context-tuned payloads into query/DOM parameters with dialog interception. |
| **3** | `modules/forms.go` | **POST-Based Form XSS**: automates DOM form submission (`requestSubmit()`) and generates base64 HTML reproduction PoCs. |
| **4** | `modules/links.go` | **Path-Based XSS**: injects payloads into URL path segments and directory rewrites. |
| **5** | `modules/fragment.go` | **Fragment-Based XSS**: tests URL hash fragments (`#payload`) against SPA routers and DOM sinks. |
| **6** | `modules/headers.go` | **Header-Based XSS**: injects payloads into HTTP request headers (`User-Agent`, `Referer`, `Origin`, `Cookie`, `X-Forwarded-*`, …). |

---

## Installation

### Prerequisites

- Go **1.26+**
- Network access to download Playwright browser engines

```bash
# Install the binary
go install github.com/zapstiko/xsshunts@latest

# Download the Playwright browser engines (Firefox, Chromium, WebKit)
xsshunts --install-browsers
```

### Build from source

```bash
git clone https://github.com/zapstiko/xsshunts.git
cd xsshunts
go build -o xsshunts .
./xsshunts --install-browsers
```

### Alternate Chromium engine (experimental)

The repository also preserves a Chromium-only engine built on `chromedp`, useful when Playwright browsers are unavailable but a local Chrome/Chromium is installed:

```bash
go build -o xsshunts-chromedp ./cmd/xsshunts-chromedp
./xsshunts-chromedp -u "https://target.com/page?id=1" --scan get,post
```

> This engine is kept for reference/fallback. The Playwright binary is the primary, full-featured implementation.

---

## Usage Examples

### 1. Basic single target scan (GET & POST)

```bash
xsshunts -u "https://target.com/page?id=12"
```

### 2. Custom POST data fields

```bash
xsshunts -u "https://target.com/login" --scan post -d "username=admin&search=keyword"
```

### 3. Full multi-vector audit with JSON report

```bash
xsshunts -u "https://target.com/app" --scan all -o scan_report.json
```

### 4. Selecting a browser engine

```bash
xsshunts -u "https://target.com/app" -b chromium --scan all
xsshunts -u "https://target.com/app" -b webkit  --scan all
```

You can also use an installed Chrome/Edge channel instead of downloading Chromium:

```bash
xsshunts -u "https://target.com/app" -b chromium --channel chrome
```

### 5. Visible GUI browser mode (debugging)

```bash
xsshunts -u "https://target.com/search?q=test" --headless false -v
```

### 6. Fine-tuning request delays

```bash
xsshunts -u "https://target.com" --scan all --delay-min 1500 --delay-max 3000
```

### 7. Custom wordlist parameter mining

```bash
xsshunts -u "https://target.com/view" -w "wordlists/common.txt" --scan get,post
```

### 8. Parameter mining & reflection probing only

```bash
xsshunts -u "https://target.com/view" -m
```

### 9. Multi-target scanning & STDIN pipelines

```bash
xsshunts -f targets.txt

cat targets.txt | xsshunts -s
cat targets.txt | xsshunts -s -m
```

### 10. Authenticated scanning (cookies & custom headers)

```bash
xsshunts -u "https://target.com/profile" -c "PHPSESSID=abc123xyz; role=admin"
xsshunts -u "https://target.com/profile" --cookie-file cookies.txt
xsshunts -u "https://target.com/api" -H "Authorization: Bearer my_jwt_token" -H "X-API-Key: secret"
```

### 11. Custom header injection targets

```bash
xsshunts -u "https://target.com" --scan header --include-header "X-Client-IP,X-Custom-Auth"
```

### 12. Crawler / spider & concurrency

```bash
xsshunts -u "https://target.com" --crawl --depth 2 -t 3
xsshunts -u "https://target.com" --crawl --depth 3 --max-urls 100 -t 5 -m
```

### 13. Inspect the built-in knowledge bases

```bash
xsshunts --show-payloads
xsshunts --show-params
xsshunts --show-headers
```

---

## Command Line Options

```
Target Options:
  -u, --url URL                   Target URL to scan
  -f, --file FILE                 Load targets from file (one URL per line)

Browser & Engine Options:
  -b, --browser {firefox,chromium,webkit}
                                  Browser engine (default: firefox)
  --channel NAME                  Use an installed browser channel (chrome, msedge)
  --headless true|false           Run browser headless (default: true)
  --timeout MS                    Page navigation timeout in milliseconds (default: 15000)
  --delay-min MS                  Minimum request delay in ms (default: 3000)
  --delay-max MS                  Maximum request delay in ms (default: 5000)
  -t, --threads, --concurrency N  Concurrent browser workers (1-5, default: 1)

Scan Scope Options:
  --scan MODULES                  get, post, path, fragment, header, or all (default: get,post)
  -w, --wordlist FILE             Custom parameter wordlist file to probe
  -m, --mining                    Parameter mining and reflection analysis only
  -p, --param PARAMS              Parameters to test (e.g. 'p:js,q:html' or 'name')
  -e, --exclude PARAMS            Parameters to skip (comma-separated)
  -d, --data POSTFIELDS           Custom POST data fields
  -c, --cookie COOKIE             Cookie string or path to cookie file
  --cookie-file FILE              Load cookies from file (Netscape, JSON, or key=value)
  -H, --header HEADER             Custom HTTP header (repeatable)
  --context CONTEXT               Default context: js, html, attr, url, dom
  --include-header HEADERS        Extra headers to attack (comma-separated)
  --exclude-header HEADERS        Headers to skip during header scan

Crawler / Spider Options:
  --crawl                         Enable internal crawler
  --depth N                       Maximum crawl depth (1-5, default: 2)
  --max-urls N                    Maximum URLs collected (1-200, default: 50)

Information Options:
  --show-payloads                 Show all built-in XSS payloads and exit
  --show-params                   Show all built-in known parameters and exit
  --show-headers                  Show all built-in target HTTP headers and exit

Output & Reporting Options:
  -o, --output FILE               Save JSON report (relative names go to output/)
  -s, --silent                    Silent mode (findings only)
  -v, --verbose                   Verbose debugging output
  -h, --help                      Show help and exit
  --version                       Show version and exit
  --install-browsers              Download Playwright browsers and exit
```

---

## Project Layout

```
.
├── main.go                 Playwright entry point
├── cli.go                  CLI parsing, target loading, worker pool
├── appmeta/                Banner and application metadata
├── browser/                Playwright manager + dialog/navigation session
├── config/                 Built-in parameter/header knowledge bases
├── crawler/                BFS spider and dedup signatures
├── detection/              Reflection, context, matrix, confidence, WAF engines
├── logger/                 Console rendering
├── models/                 Parameters, reflections, findings, scan config
├── modules/                7 pipeline modules (mining → headers)
├── parsers/                URL/action/postdata/path helpers
├── payloads/               Multi-context payload knowledge base
├── reporter/               Console summaries + JSON export
├── scanner/                Audit orchestrator
├── utils/                  URL, HTML, PoC and match helpers
├── wordlists/              Embedded parameter wordlist
├── internal/ + cmd/xsshunts-chromedp/
│                           Alternate Chromium-only engine (experimental)
└── output/                 Default report directory
```

---

## How Confirmation Works

For every payload, XSSHuntS registers a browser dialog watcher, navigates (or submits a form) with the payload, then checks whether the dialog's type and message match the payload's expected canary (e.g. `alert("9")`). Only a matching dialog marks a finding as **verified XSS**. When dialog execution is impossible (e.g. event handlers that do not fire in the harness), a DOM reflection match is recorded as **potential** with a lower confidence score.

---

## Credits & License

- **XSSHuntS** — created and maintained by [zapstiko](https://github.com/zapstiko).
- Browser automation: [playwright-community/playwright-go](https://github.com/playwright-community/playwright-go).
- Alternate engine: [chromedp](https://github.com/chromedp/chromedp).
- Released under the [MIT License](LICENSE).

---

## Legal Disclaimer

> **Responsible Security Research Only:** XSSHuntS is developed strictly for authorized penetration testing, security auditing, educational purposes, and responsible vulnerability research.

> Testing targets without prior mutual written consent is illegal in most jurisdictions. The developer accepts no liability and is not responsible for any misuse, damage, or legal consequences caused by this software. Use responsibly.
