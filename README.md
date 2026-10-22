# PHP2Shell Exposure Checker

A safe, **passive** checker that inventories websites for disclosed PHP versions
and assesses them against the patched releases for
**CVE-2026-109618** and **CVE-2026-109619** ("PHP2Shell").

It sends one ordinary `GET` request per URL — two for bare hostnames, which
are checked over both `https://` and `http://` — and inspects the response
for PHP version disclosure in:

- `X-Powered-By` response header
- `Server` response header
- `<meta name="generator" ...>` tags in the body (first 100 KB)

Each hostname is also resolved to an IP address, which is recorded in the
report alongside the result.

## What it does NOT do

- **No exploitation.** It never sends a payload and never attempts to trigger
  the vulnerability.
- **No scanning.** No crawling, no endpoint guessing, no aggressive probing —
  just a single request to each target URL.
- **No fingerprinting tricks.** If a server does not voluntarily disclose its
  PHP version, the tool reports `UNKNOWN` and moves on.

This makes it suitable for large-scale asset inventory where active probing
would be out of scope or too noisy.

## Assessment categories

| Assessment | Meaning |
|---|---|
| `PATCHED` | Disclosed PHP version meets or exceeds the fixed release for its branch |
| `LIKELY_VULNERABLE` | Disclosed version is on a patched branch but below the fixed release |
| `LIKELY_VULNERABLE_OR_UNSUPPORTED` | Disclosed version is on an unpatched / end-of-life branch |
| `UNKNOWN` | No PHP version disclosed — manual inventory required |
| `UNREACHABLE` | Connection failed (timeout, DNS, refused, TLS error, etc.) |

**Patched releases used for assessment:**

| Branch | Fixed release |
|---|---|
| 8.2 | 8.2.35 |
| 8.3 | 8.3.36 |
| 8.4 | 8.4.27 |
| 8.5 | 8.5.12 |

> `UNKNOWN` does **not** mean safe — only that the version is not publicly
> disclosed. A hidden-but-vulnerable PHP runtime will not be detected.
> Confirm versions server-side wherever possible.

## Requirements

- Python 3.10+
- Dependencies in `requirements.txt`: `requests`, `packaging`, `openpyxl`

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

```bash
python php2shell_check.py sites.txt -o results.xlsx
```

Input file format: one hostname or URL per line. Lines that are blank or
start with `#` are skipped. **Bare hostnames are checked over both `https://`
and `http://`**; lines with an explicit scheme are used as-is.

```text
# sites.txt — each line below produces the shown requests
example.com                 → https://example.com and http://example.com
example.org/path            → https://example.org/path and http://example.org/path
https://secure.example.com  → https://secure.example.com (only)
```

### Options

| Option | Default | Description |
|---|---|---|
| `-o`, `--output` | `php2shell_results.xlsx` | Output path — `.xlsx` for Excel, `.csv` for CSV |
| `--timeout` | `10.0` | Per-request timeout in seconds |
| `--user-agent` | `PHP2Shell-Exposure-Checker/1.0 (authorized security assessment)` | User-Agent header |

## Output

Console progress plus an Excel (`.xlsx`) or CSV report with columns:

```csv
url,ip,status,http_status,php_version,version_source,assessment,detail
https://example.com,93.184.216.34,OK,200,8.5.10,server header,LIKELY_VULNERABLE,PHP 8.5.10 is below fixed release 8.5.12.
```

- `ip` — resolved IP address of the hostname (empty if DNS fails)
- `status` — `OK` (response received) or `ERROR` (request failed)
- `version_source` — `x-powered-by header`, `server header`,
  `response-header/body`, or `meta-generator`

In Excel output the `assessment` column is color-coded for triage:
`PATCHED` is highlighted green, any assessment containing `VULNERABLE`
(`LIKELY_VULNERABLE`, `LIKELY_VULNERABLE_OR_UNSUPPORTED`) is highlighted
yellow, and `UNKNOWN`/`UNREACHABLE` are uncolored.

## Limitations

- Results depend entirely on voluntary version disclosure. Suppressed or
  stripped headers (e.g. via `expose_php = Off`, reverse proxies, WAFs)
  yield `UNKNOWN`.
- A disclosed version is the *front-end's claim* — behind a load balancer or
  proxy it may not reflect every backend node.
- Requests are sequential and bare hostnames are checked twice (https +
  http), so large lists take a while. Split lists per segment if needed.
- Follows redirects and reports the version disclosed by the *final* hop.

## Responsible use

Only run this against systems you own or are explicitly authorized to assess.
A passive version check is low-impact, but it is still a network request to
someone else's infrastructure — be identifiable (keep the default User-Agent
or set your own contact info), keep request rates modest, and honor your
authorization scope and `robots.txt`/acceptable-use policies.

## License

MIT (see `LICENSE`).
