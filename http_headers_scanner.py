import argparse
import asyncio
import json
import re
import sys
from dataclasses import dataclass
from typing import Literal

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

Severity = Literal["high", "medium", "low"]
Status = Literal["ok", "weak", "missing"]

@dataclass(frozen=True, slots=True)
class HeaderRule:
    header: str
    severity: Severity
    description: str
    recommendation: str
    must_match: str | None = None

RULES: list[HeaderRule] = [
    HeaderRule(
        header="Strict-Transport-Security",
        severity="high",
        description="Forces HTTPS for return visits, defeating SSL-stripping.",
        recommendation="Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        must_match=r"max-age\s*=\s*[1-9]",
    ),
    HeaderRule(
        header="Content-Security-Policy",
        severity="high",
        description="Controls which scripts/styles/frames may load - the strongest XSS defense.",
        recommendation="Add a Content-Security-Policy that disallows 'unsafe-inline'.",
    ),
    HeaderRule(
        header="X-Content-Type-Options",
        severity="medium",
        description="Stops MIME-sniffing - the browser must trust the declared Content-Type.",
        recommendation="Add: X-Content-Type-Options: nosniff",
        must_match="nosniff",
    ),
    HeaderRule(
        header="X-Frame-Options",
        severity="medium",
        description="Prevents the page being embedded in an iframe - defeats clickjacking.",
        recommendation="Add: X-Frame-Options: DENY",
    ),
    HeaderRule(
        header="Referrer-Policy",
        severity="low",
        description="Limits how much of the URL leaks to other sites on outbound clicks.",
        recommendation="Add: Referrer-Policy: strict-origin-when-cross-origin",
    ),
    HeaderRule(
        header="Permissions-Policy",
        severity="low",
        description="Disables browser features (camera, mic, geolocation) the page does not use.",
        recommendation="Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
    ),
    HeaderRule(
        header="Cross-Origin-Opener-Policy",
        severity="medium",
        description="Isolates the page from cross-origin window access (Spectre defense).",
        recommendation="Add: Cross-Origin-Opener-Policy: same-origin",
        must_match="same-origin",
    )
]

SEVERITY_POINTS: dict[Severity, int] = {
    "high": 30,
    "medium": 15,
    "low": 5
}

@dataclass(frozen=True, slots=True)
class HeaderFinding:
    rule: HeaderRule
    status: Status
    actual_value: str | None
    note: str


@dataclass(frozen=True, slots=True)
class ScanReport:
    url: str
    final_url: str
    status_code: int
    findings: list[HeaderFinding]

    @property
    def score(self) -> int:
        total = sum(SEVERITY_POINTS[r.severity] for r in RULES)
        if total == 0:
            return 0

        earned = 0.0
        for finding in self.findings:
            full = SEVERITY_POINTS[finding.rule.severity]
            if finding.status == "ok":
                earned += full
            elif finding.status == "weak":
                earned += full / 2

        return int((earned / total) * 100 + 0.5)

    @property
    def grade(self) -> str:
        score = self.score
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 60:
            return "D"
        return "F"
    

def evaluate_header(
        rule: HeaderRule,
        response_headers: dict[str, str],
) -> HeaderFinding:
    target = rule.header.lower()

    actual_value: str | None = None
    for name, value in response_headers.items():
        if name.lower() == target:
            actual_value = value
            break

    if actual_value is None:
        return HeaderFinding(
            rule=rule,
            status="missing",
            actual_value=None,
            note=f"Header `{rule.header}` is not set",
        )

    if rule.must_match is None:
        return HeaderFinding(
            rule=rule,
            status="ok",
            actual_value=actual_value,
            note="Present",
        )

    if re.search(rule.must_match, actual_value, re.IGNORECASE):
        return HeaderFinding(
            rule=rule,
            status="ok",
            actual_value=actual_value,
            note=f"Present and matches `{rule.must_match}`",
        )

    return HeaderFinding(
        rule=rule,
        status="weak",
        actual_value=actual_value,
        note=(
            f"Present but does not match `{rule.must_match}` "
            f"got `{actual_value}`"
        ),
    )

DEFAULT_USER_AGENT: str = (
    "http-headers-scanner/1.0 "
    "(+https://github.com/coybo/https-headers-scanner)"
)

def _build_report(url: str, response: httpx.Response) -> ScanReport:
    response_headers = dict(response.headers)
    findings = [evaluate_header(rule, response_headers) for rule in RULES]
    return ScanReport(
        url=url,
        final_url=str(response.url),
        status_code=response.status_code,
        findings=findings,
    )


def scan(
        url: str,
        *,
        timeout: float = 10.0,
        user_agent: str = DEFAULT_USER_AGENT,
) -> ScanReport:
    response = httpx.get(
        url,
        timeout=timeout,
        follow_redirects=True,
        headers={"User-Agent": user_agent},
    )
    return _build_report(url, response)

async def scan_async(
        url: str,
        *,
        timeout: float = 10.0,
        user_agent: str = DEFAULT_USER_AGENT,
) -> ScanReport:
    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=timeout,
        headers={"User-Agent": user_agent},
    ) as client:
        response = await client.get(url)
    return _build_report(url, response)


async def scan_many(
        urls: list[str],
        *,
        concurrency: int = 20,
        timeout: float = 10.0,
        user_agent: str = DEFAULT_USER_AGENT,
) -> list[ScanReport | httpx.RequestError]:
    sem = asyncio.Semaphore(concurrency)

    async def bounded(u: str) -> ScanReport | httpx.RequestError:
        async with sem:
            try:
                return await scan_async(u, timeout=timeout, user_agent=user_agent)
            except httpx.RequestError as exc:
                return exc

    return await asyncio.gather(*(bounded(u) for u in urls))

STATUS_COLORS: dict[Status, str] = {
    "ok": "green",
    "weak": "yellow",
    "missing": "red",
}

GRADE_COLORS: dict[str, str] = {
    "A": "bright_green",
    "B": "green",
    "C": "yellow",
    "D": "red",
    "F": "bright_red",
}

GRADE_ORDER: dict[str, int] = {
    "F": 0,
    "D": 1,
    "C": 2, 
    "B": 3, 
    "A": 4
}

def _render_report(report: ScanReport, console: Console) -> None:
    table = Table(
        title=f"Headers for {report.final_url} (HTTP {report.status_code})",
        title_style="bold cyan",
    )
    table.add_column("header", style="bold white", no_wrap=True)
    table.add_column("status", no_wrap=True)
    table.add_column("severity", no_wrap=True)
    table.add_column("note", style="dim")

    for finding in report.findings:
        color = STATUS_COLORS[finding.status]
        table.add_row(
            finding.rule.header,
            f"[{color}]{finding.status}[/{color}]",
            finding.rule.severity,
            finding.note,
        )
    console.print(table)

    if report.final_url.startswith("http://"):
        console.print(
            "[yellow]Note:[/yellow] served over plain HTTP. Browsers IGNORE "
            "HSTS over HTTP, so any HSTS grade above is misleading."
        )

    grade_color = GRADE_COLORS[report.grade]
    panel = Panel(
        f"[bold {grade_color}] Grade: {report.grade}[/bold {grade_color}]\n"
        f"Score: {report.score} / 100",
        title="Result",
        border_style=grade_color,
    )
    console.print(panel)

    actionable = [f for f in report.findings if f.status != "ok"]
    if actionable:
        console.print("\n[bold]Recommendations:[/bold]")
        for finding in actionable:
            console.print(
                f"  - [yellow]{finding.rule.header}[/yellow] "
                f"- {finding.rule.recommendation}"
            )


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="headers",
        description="Scan a URL for HTTP security headers and grade it A-F.",
    )
    parser.add_argument(
        "url",
        help="Full URL to scan (must include http:// or https://).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Seconds before giving up on the request (default: 10).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the report as JSON instead of a table.",
    )
    parser.add_argument(
        "--min-grade",
        choices=list("ABCDF"),
        default="C",
        help="Minimum acceptable grade (default: C).",
    )
    return parser


def _exit_code(report: ScanReport, min_grade: str) -> int:
    if GRADE_ORDER[report.grade] >= GRADE_ORDER[min_grade]:
        return 0
    return 1


def main() -> int:
    parser = _build_argument_parser()
    args = parser.parse_args()
    console = Console()

    try:
        report = scan(args.url, timeout=args.timeout)
    except httpx.RequestError as exc:
        Console(stderr=True).print(
            f"[red]Request failed:[/red] {type(exc).__name__}: {exc}"
        )
        return 2

    if args.json:
        payload = {
            "url": report.url,
            "final_url": report.final_url,
            "score": report.score,
            "grade": report.grade,
            "findings": [
                {
                    "header": f.rule.header,
                    "status": f.status,
                    "severity": f.rule.severity,
                    "actual_value": f.actual_value,
                }
                for f in report.findings
            ],
        }
        print(json.dumps(payload, indent=2))
        return _exit_code(report, args.min_grade)

    _render_report(report, console)
    return _exit_code(report, args.min_grade)

if __name__ == "__main__":
    sys.exit(main())
