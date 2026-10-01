import asyncio
import json
import sys

import httpx
import pytest
import respx

from http_headers_scanner import (
    RULES,
    SEVERITY_POINTS,
    HeaderRule,
    ScanReport,
    _exit_code,
    evaluate_header,
    main,
    scan,
    scan_many,
)

GOOD_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}


def headers_without(*missing: str) -> dict[str, str]:
    return {k: v for k, v in GOOD_HEADERS.items() if k not in missing}


def make_report(*missing: str) -> ScanReport:
    headers = headers_without(*missing)
    return ScanReport(
        url="https://x.example.com/",
        final_url="https://x.example.com/",
        status_code=200,
        findings=[evaluate_header(rule, headers) for rule in RULES],
    )


@pytest.fixture
def hsts_rule() -> HeaderRule:
    return HeaderRule(
        header="Strict-Transport-Security",
        severity="high",
        description="Forces HTTPS",
        recommendation="Add max-age=31536000",
        must_match=r"max-age\s*=\s*[1-9]",
    )


# --- evaluate_header -------------------------------------------------------

def test_max_age_zero_is_weak(hsts_rule: HeaderRule) -> None:
    headers = {"Strict-Transport-Security": "max-age=0; includeSubDomains"}
    assert evaluate_header(hsts_rule, headers).status == "weak"


def test_missing_header_is_reported(hsts_rule: HeaderRule) -> None:
    assert evaluate_header(hsts_rule, {}).status == "missing"


def test_header_lookup_is_case_insensitive(hsts_rule: HeaderRule) -> None:
    headers = {"strict-transport-security": "max-age=31536000"}
    assert evaluate_header(hsts_rule, headers).status == "ok"


def test_coop_unsafe_none_is_weak() -> None:
    coop = next(r for r in RULES if r.header == "Cross-Origin-Opener-Policy")
    finding = evaluate_header(coop, {"Cross-Origin-Opener-Policy": "unsafe-none"})
    assert finding.status == "weak"


# --- scan / scoring --------------------------------------------------------

@respx.mock
def test_scan_grades_a_clean_response() -> None:
    respx.get("https://safe.example.com/").mock(
        return_value=httpx.Response(200, headers=GOOD_HEADERS)
    )

    report = scan("https://safe.example.com/")

    assert report.score == 100
    assert report.grade == "A"
    assert all(f.status == "ok" for f in report.findings)


@respx.mock
def test_scan_with_no_security_headers_fails() -> None:
    respx.get("https://bare.example.com/").mock(return_value=httpx.Response(200))

    report = scan("https://bare.example.com/")

    assert report.score == 0
    assert report.grade == "F"
    assert all(f.status == "missing" for f in report.findings)


def test_missing_one_medium_header_costs_proportional_points() -> None:
    report = make_report("Cross-Origin-Opener-Policy")

    total = sum(SEVERITY_POINTS[r.severity] for r in RULES)
    earned = total - SEVERITY_POINTS["medium"]
    assert report.score == int(earned / total * 100 + 0.5)


# --- --min-grade / exit codes ---------------------------------------------

@pytest.mark.parametrize(
    ("missing", "min_grade", "expected"),
    [
        ((), "A", 0),                                              # grade A
        (("Cross-Origin-Opener-Policy",), "A", 1),                 # grade B
        (("Cross-Origin-Opener-Policy",), "B", 0),
        (("Content-Security-Policy",), "C", 0),                    # grade C
        (("Content-Security-Policy",), "B", 1),
        (("Content-Security-Policy", "X-Frame-Options"), "D", 0),  # grade D
        (("Content-Security-Policy", "X-Frame-Options"), "C", 1),
        (("Strict-Transport-Security", "Content-Security-Policy"), "C", 1),  # F
        (("Strict-Transport-Security", "Content-Security-Policy"), "F", 0),
    ],
)
def test_exit_code_respects_min_grade(
    missing: tuple[str, ...], min_grade: str, expected: int
) -> None:
    assert _exit_code(make_report(*missing), min_grade) == expected


# --- --json ----------------------------------------------------------------

@respx.mock
def test_json_output_is_valid_and_complete(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    respx.get("https://safe.example.com/").mock(
        return_value=httpx.Response(200, headers=GOOD_HEADERS)
    )
    monkeypatch.setattr(sys, "argv", ["headers", "https://safe.example.com/", "--json"])

    exit_code = main()

    data = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert data["score"] == 100
    assert data["grade"] == "A"
    assert len(data["findings"]) == len(RULES)
    assert {"header", "status", "severity", "actual_value"} <= data["findings"][0].keys()


# --- async -----------------------------------------------------------------

@respx.mock
def test_scan_many_preserves_order_and_isolates_failures() -> None:
    respx.get("https://good.example.com/").mock(
        return_value=httpx.Response(200, headers=GOOD_HEADERS)
    )
    respx.get("https://bare.example.com/").mock(return_value=httpx.Response(200))
    respx.get("https://down.example.com/").mock(side_effect=httpx.ConnectError("boom"))

    results = asyncio.run(
        scan_many(
            [
                "https://good.example.com/",
                "https://down.example.com/",
                "https://bare.example.com/",
            ]
        )
    )

    assert results[0].grade == "A"
    assert isinstance(results[1], httpx.RequestError)
    assert results[2].grade == "F"