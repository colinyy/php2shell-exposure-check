#!/usr/bin/env python3
"""
Safe PHP2Shell exposure checker.

Reads a list of website URLs from a text file and checks for PHP version
disclosure. It does NOT exploit CVE-2026-109618 / CVE-2026-109619.

Use only against systems you are authorized to test.
"""

import argparse
import csv
import re
import socket
import sys
from dataclasses import dataclass
from functools import lru_cache
from urllib.parse import urlparse

import requests
from openpyxl import Workbook
from openpyxl.styles import PatternFill
from openpyxl.utils import get_column_letter
from packaging.version import InvalidVersion, Version

# Patched PHP branches for PHP2Shell:
# CVE-2026-109618 and CVE-2026-109619.
PATCHED_VERSIONS = {
    (8, 2): Version("8.2.35"),
    (8, 3): Version("8.3.36"),
    (8, 4): Version("8.4.27"),
    (8, 5): Version("8.5.12"),
}

# Common safe indicators of PHP version. These are passive checks only.
HEADER_KEYS = ("x-powered-by", "server")
PHP_VERSION_RE = re.compile(
    r"(?:PHP[/ ]|PHP\s*)(\d+\.\d+(?:\.\d+)?(?:[.-][0-9A-Za-z]+)*)",
    re.IGNORECASE,
)
META_GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
    re.IGNORECASE,
)


@dataclass
class Result:
    url: str
    ip: str | None
    status: str
    http_status: int | None
    php_version: str | None
    source: str | None
    assessment: str
    detail: str


def normalize_url(raw: str) -> str | None:
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return None
    if not urlparse(raw).scheme:
        raw = "https://" + raw
    parsed = urlparse(raw)
    if not parsed.netloc:
        return None
    return raw


def expand_urls(raw: str) -> list[str]:
    """Return the URLs to check for one input line.

    Lines with an explicit scheme are used as-is; bare hostnames or
    host/path values are expanded to both https:// and http://.
    """
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return []
    if urlparse(raw).scheme:
        url = normalize_url(raw)
        return [url] if url else []
    if not urlparse("https://" + raw).netloc:
        return []
    return [f"https://{raw}", f"http://{raw}"]


def extract_php_version(text: str) -> tuple[str | None, str | None]:
    """Return (version, source) from a header value or HTML body."""
    match = PHP_VERSION_RE.search(text)
    if match:
        return match.group(1), "response-header/body"

    generator = META_GENERATOR_RE.search(text)
    if generator:
        gen_match = PHP_VERSION_RE.search(generator.group(1))
        if gen_match:
            return gen_match.group(1), "meta-generator"

    return None, None


def assess_version(version: str | None) -> tuple[str, str]:
    if not version:
        return "UNKNOWN", "No PHP version disclosure found; manual inventory required."

    try:
        parsed = Version(version)
    except InvalidVersion:
        return "UNKNOWN", f'Could not parse disclosed PHP version "{version}".'

    branch = (parsed.major, parsed.minor)

    if branch not in PATCHED_VERSIONS:
        return (
            "LIKELY_VULNERABLE_OR_UNSUPPORTED",
            f'PHP {version} is not in a currently patched branch '
            f"(8.2, 8.3, 8.4, or 8.5). Verify the actual server runtime and upgrade path.",
        )

    fixed = PATCHED_VERSIONS[branch]
    if parsed >= fixed:
        return "PATCHED", f"PHP {version} meets or exceeds the fixed release {fixed}."
    return "LIKELY_VULNERABLE", f"PHP {version} is below fixed release {fixed}."


@lru_cache(maxsize=None)
def resolve_host(hostname: str) -> str | None:
    """Resolve a hostname to its first IP address, or None on failure."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return None
    return infos[0][4][0]


def check_site(session: requests.Session, url: str, timeout: float) -> Result:
    ip = resolve_host(urlparse(url).hostname or "")
    try:
        response = session.get(url, timeout=timeout, allow_redirects=True)
    except requests.RequestException as exc:
        return Result(url, ip, "ERROR", None, None, None, "UNREACHABLE", str(exc))

    version = None
    source = None

    # Passive header inspection.
    for header in HEADER_KEYS:
        value = response.headers.get(header, "")
        found, found_source = extract_php_version(value)
        if found:
            version, source = found, f"{header} header"
            break

    # Passive body inspection, limited to the first 100 KB.
    if not version:
        body = response.text[:100_000]
        version, source = extract_php_version(body)

    assessment, detail = assess_version(version)

    return Result(
        url=url,
        ip=ip,
        status="OK",
        http_status=response.status_code,
        php_version=version,
        source=source,
        assessment=assessment,
        detail=detail,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Passively check websites for disclosed PHP versions and PHP2Shell patch status."
    )
    parser.add_argument("input_file", help="Text file containing one URL per line")
    parser.add_argument(
        "-o",
        "--output",
        default="php2shell_results.xlsx",
        help="Output file (.xlsx for Excel, .csv for CSV)",
    )
    parser.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout in seconds")
    parser.add_argument(
        "--user-agent",
        default="PHP2Shell-Exposure-Checker/1.0 (authorized security assessment)",
    )
    args = parser.parse_args()

    try:
        with open(args.input_file, encoding="utf-8") as handle:
            raw_urls = handle.readlines()
    except OSError as exc:
        print(f"Cannot read input file: {exc}", file=sys.stderr)
        return 2

    urls: list[str] = []
    for line in raw_urls:
        urls.extend(expand_urls(line))

    if not urls:
        print("No valid URLs found in input file.", file=sys.stderr)
        return 2

    session = requests.Session()
    session.headers.update({"User-Agent": args.user_agent})

    results: list[Result] = []
    for url in urls:
        result = check_site(session, url, args.timeout)
        results.append(result)
        print(
            f"{result.assessment:<32} {url} "
            f"({result.ip or 'no DNS'}) "
            f"PHP={result.php_version or 'not disclosed'}"
        )

    if args.output.lower().endswith(".csv"):
        write_csv(args.output, results)
    else:
        write_xlsx(args.output, results)

    print(f"\nResults written to {args.output}")
    return 0


CSV_HEADER = [
    "url",
    "ip",
    "status",
    "http_status",
    "php_version",
    "version_source",
    "assessment",
    "detail",
]

PATCHED_FILL = PatternFill(start_color="C6EFCE", end_color="C6EFCE", fill_type="solid")
VULNERABLE_FILL = PatternFill(start_color="FFEB9C", end_color="FFEB9C", fill_type="solid")
ASSESSMENT_COLUMN = CSV_HEADER.index("assessment") + 1


def result_row(result: Result) -> list:
    return [
        result.url,
        result.ip,
        result.status,
        result.http_status,
        result.php_version,
        result.source,
        result.assessment,
        result.detail,
    ]


def write_csv(path: str, results: list[Result]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(CSV_HEADER)
        for result in results:
            writer.writerow(result_row(result))


def write_xlsx(path: str, results: list[Result]) -> None:
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "results"
    sheet.append(CSV_HEADER)
    sheet.freeze_panes = "A2"

    for result in results:
        sheet.append(result_row(result))
        cell = sheet.cell(row=sheet.max_row, column=ASSESSMENT_COLUMN)
        if cell.value == "PATCHED":
            cell.fill = PATCHED_FILL
        elif cell.value and "VULNERABLE" in cell.value:
            cell.fill = VULNERABLE_FILL

    for index, header in enumerate(CSV_HEADER, start=1):
        width = max(
            [len(header)]
            + [len(str(row[index - 1] or "")) for row in (result_row(r) for r in results)]
        )
        sheet.column_dimensions[get_column_letter(index)].width = min(width + 2, 80)

    workbook.save(path)


if __name__ == "__main__":
    raise SystemExit(main())
