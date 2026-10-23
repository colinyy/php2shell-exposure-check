# PHP2Shell Exposure Checker

A lightweight, non-exploitative checker for PHP version disclosures related
to **CVE-2026-109618** and **CVE-2026-109619** (PHP2Shell).

The tool makes ordinary HTTP `GET` requests and checks response headers and
page content for PHP version information. It can also optionally request a
specified path, such as `/index.php`, and compare responses to help identify
catch-all pages that may cause false positives.

For each result, the report includes the resolved IP address and the
disclosed PHP version, if one is found.

### Scope and safety

- The tool does not send exploit payloads or attempt to trigger a vulnerability.
- It does not crawl pages. Additional paths are requested only when
  you enable `--probe-path` or `--verify`.
- Bare hostnames are tried over HTTPS and HTTP. If HTTPS returns an HTTP
  response, the HTTP result is omitted from the saved report. HTTP is kept
  as a fallback when HTTPS is unreachable.
- Requests are still sent to the specified systems. Run the tool only against
  assets you own or are explicitly authorized to assess.

## Understanding the results

The report shows two complementary fields:

- **`assessment`** reports the disclosed PHP version's patch status. If an
  optional probe returns HTTP 200, it reports `INDEX_PHP_200` instead.
- **`php_confidence`** summarizes the strength of PHP-related indicators.

For example, a result can show a vulnerable disclosed version while also
having strong PHP indicators. Treat both fields as evidence for triage, not
as a substitute for confirming the server's actual runtime.

### Assessment categories (version vulnerability)

| Assessment | Meaning |
|---|---|
| `PATCHED` | The disclosed version meets or exceeds the fixed release for its branch. |
| `LIKELY_VULNERABLE` | The disclosed version is below the fixed release for a supported branch. |
| `LIKELY_VULNERABLE_OR_UNSUPPORTED` | The disclosed version is on a branch without a listed fix. |
| `INDEX_PHP_200` | The optional probe returned HTTP 200. This is a weak signal, not a vulnerability verdict. |
| `UNKNOWN` | No PHP version was disclosed. This does not mean the host is safe. |
| `UNREACHABLE` | The request failed, for example due to a timeout, DNS, connection, or TLS error. |

### PHP presence confidence

| Confidence | Meaning |
|---|---|
| `VERIFIED_PHP` | The heuristic score reached the highest confidence threshold. |
| `POSSIBLE_PHP` | The score indicates PHP may be present, but the evidence is inconclusive. |
| `LIKELY_FALSE_POSITIVE` | The score is low. Review the listed indicators; a low score is not proof that PHP is absent. |
| `N/A` | No PHP-presence indicators were recorded. |

The confidence score is a heuristic to help prioritize manual review. It is
not a probability or a definitive determination. A low score means the
indicators were weak; it does not prove that PHP is absent.

| Indicator | Score |
|---|---:|
| phpinfo() output detected | +100 |
| X-Powered-By contains PHP | +40 |
| PHPSESSID cookie observed | +40 |
| `--probe-path` returns 200 | +10 |
| Probe response differs from the original URL response | +10 |
| Probe response differs from random `.php` | +10 |
| Probe response identical to the original URL response | −20 |
| Probe response identical to random `.php` | −30 |

Scores are classified as follows: 80 or higher → `VERIFIED_PHP`; 30–79 →
`POSSIBLE_PHP`; below 30 → `LIKELY_FALSE_POSITIVE`.

**Patched releases used for assessment:**

| Branch | Fixed release |
|---|---|
| 8.2 | 8.2.35 |
| 8.3 | 8.3.36 |
| 8.4 | 8.4.27 |
| 8.5 | 8.5.12 |

> **Important:** `UNKNOWN` does not mean safe. It means the tool did not find
> a disclosed PHP version. Confirm the actual runtime server-side whenever
> possible.

## Installation

Requirements: Python 3.10+ and the packages listed in `requirements.txt`.

On macOS or Linux:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

On Windows PowerShell:

```powershell
py -3 -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Usage

### Input file

Add one hostname, URL, or IPv4 CIDR range per line. Blank lines and lines
starting with `#` are ignored.

```text
# sites.txt
example.com
https://secure.example.com
192.0.2.0/29
```

Bare hostnames and CIDR ranges are tried over HTTPS and HTTP. URLs with an
explicit scheme are checked as written. If HTTPS returns an HTTP response,
the HTTP result is omitted from the report; HTTP is kept if HTTPS is unreachable.

### Basic scan

```bash
python php2shell_check.py sites.txt -o results.xlsx
```

Checks response headers and page content for PHP version disclosure. Probing
and verification are disabled unless their options are specified.

### CSV output

```bash
python php2shell_check.py sites.txt -o results.csv
```

### Probe `/index.php` on every host

```bash
python php2shell_check.py sites.txt --probe-path /index.php -o results.xlsx
```

Adds a second request per URL to check if `/index.php` is reachable.
HTTP 200 is flagged as `INDEX_PHP_200` for manual review.

### Full false-positive verification

```bash
python php2shell_check.py sites.txt --probe-path /index.php --verify -o results.xlsx
```

Compares the probe response with the original URL response and a generated
`.php` path. Similar responses can indicate a catch-all page and lower the
confidence score. The generated-path request is made only when the probe
returns HTTP 200.

### CIDR range scan

```bash
python php2shell_check.py ranges.txt --workers 4 -o results.xlsx
```

```text
# ranges.txt
192.0.2.0/29
10.0.0.0/28
```

Each CIDR expands to `https://` + `http://` for every usable host. Lower
`--workers` for large ranges to stay within authorization scope.

### Custom timeout and user-agent

```bash
python php2shell_check.py sites.txt --timeout 15 \
  --user-agent "Acme-Security-Audit/2.0 (contact: sec@acme.com)" \
  -o results.xlsx
```

### Combined example

```bash
python php2shell_check.py assets.txt \
  --probe-path /index.php \
  --verify \
  --workers 16 \
  --timeout 8 \
  -o php2shell_audit.xlsx
```

Full verification mode with 16 concurrent workers and an 8-second timeout.

### Options

| Option | Default | Description |
|---|---|---|
| `-o`, `--output` | `php2shell_results.xlsx` | Output path — `.xlsx` for Excel, `.csv` for CSV |
| `--timeout` | `10.0` | Per-request timeout in seconds |
| `--workers` | `8` | Concurrent checks — keep modest for CIDR scans |
| `--probe-path` | off | Extra path to probe per origin (e.g. `/index.php`); HTTP 200 is flagged `INDEX_PHP_200` |
| `--verify` | off | Compare the probe with the original URL and a generated `.php` path. Requires `--probe-path`; the extra request is made only if the probe returns 200. |
| `--user-agent` | `PHP2Shell-Exposure-Checker/1.0 (authorized security assessment)` | User-Agent header |

## Output

Console progress plus an Excel (`.xlsx`) or CSV report with columns:

```csv
url,ip,status,http_status,php_version,version_source,index_php_status,assessment,php_confidence,indicators,content_hash,content_length,content_type,server_header,page_title,detail
https://example.com,93.184.216.34,OK,200,8.5.10,server header,200,INDEX_PHP_200,VERIFIED_PHP,"phpinfo() output detected; X-Powered-By contains PHP; PHPSESSID cookie observed; /index.php returned HTTP 200",0123456789abcdef...,1234,text/html,nginx,Example,"/index.php: HTTP 200. PHP 8.5.10 is below fixed release 8.5.12."
```

- `ip` — resolved IP address of the hostname (empty if DNS fails)
- `status` — `OK` (response received) or `ERROR` (request failed)
- `index_php_status` — status returned by `--probe-path`; blank if probing is disabled or fails
- `php_confidence` — heuristic confidence rating (see [PHP presence confidence](#php-presence-confidence))
- `indicators` — semicolon-separated list of observed signals
- `content_hash` — SHA-256 hash of the first 100 KB of the response body
- `content_length`, `content_type`, `server_header`, `page_title` — response metadata for review
- `version_source` — `x-powered-by header`, `server header`,
  `response-header/body`, or `meta-generator`

In Excel output both the `assessment` and `php_confidence` columns are
color-coded for triage:

| Color | Assessment | Confidence |
|---|---|---|
| Green | `PATCHED` | `VERIFIED_PHP` |
| Yellow | `*VULNERABLE*` | `POSSIBLE_PHP` |
| Grey | — | `LIKELY_FALSE_POSITIVE` |

## Limitations

- Results depend entirely on voluntary version disclosure. Suppressed or
  stripped headers (e.g. via `expose_php = Off`, reverse proxies, WAFs)
  yield `UNKNOWN`.
- A disclosed version is the *front-end's claim* — behind a load balancer or
  proxy it may not reflect every backend node.
- Bare hostnames and CIDR ranges are tried over HTTPS and HTTP. Checks run
  concurrently (`--workers`); keep the worker count modest, especially for
  large ranges.
- An `INDEX_PHP_200` result means the probed path returned 200, which can
  be produced by catch-all rules, proxies, or non-PHP frontends. Verify
  manually before treating it as exposure.
- The version is read from the final response after redirects. The IP column
  records the original hostname's resolved address.
- **Git Bash on Windows** mangles leading-slash arguments (e.g.
  `--probe-path /index.php` becomes `C:/Program Files/Git/index.php`).
  Use `--probe-path //index.php` or run from PowerShell/CMD instead.

## Responsible use

Only run this against systems you own or are explicitly authorized to assess.
A passive version check is low-impact, but it is still a network request to
someone else's infrastructure — be identifiable (keep the default User-Agent
or set your own contact info), keep request rates modest, and honor your
authorization scope and `robots.txt`/acceptable-use policies.

## License

MIT (see `LICENSE`).
