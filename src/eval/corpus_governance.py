"""Corpus governance: provenance sidecar, dedupe, leakage scanning, and held-out split.

The frozen evaluation row schema (evaluation_case.v1) cannot carry provenance, so
provenance lives in a fail-closed sidecar document beside the dataset. This module
is deterministic by construction: hashing, splitting, and scanning are pure
functions of case content and identifiers, with no randomness and no I/O beyond
the paths passed in.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from importlib.resources import as_file, files
from pathlib import Path
from typing import Any

from src.eval.contract import EvaluationContractError
from src.eval.digest import (
    compute_dataset_file_digest,
    compute_sorted_jsonl_content_digest,
    load_jsonl_rows,
)

CORPUS_GOVERNANCE_VERSION = "1.0.0"
CORPUS_SPLIT_RULE = "sha256(case_id)mod100<25"
CORPUS_HELD_OUT_PERCENT = 25
CORPUS_REPORT_SCHEMA_ID = "adml.corpus_governance.report.v1"

REPORT_ALLOWED_CHECKS = frozenset(
    {"dedupe", "leakage_scan", "manifest_conformance", "provenance_cross_check", "schema_conformance"}
)

_ZERO_WIDTH_CHARS = frozenset({"​", "‌", "‍", "⁠", "﻿"})

_ALLOWED_URL_HOST_SUFFIXES = (
    ".example.com",
    ".example.org",
    ".example.net",
    ".example.edu",
    ".example",
    ".invalid",
    ".test",
)
_ALLOWED_URL_HOSTS = frozenset(
    {"example.com", "example.org", "example.net", "example.edu"}
)

# Placeholder values that are exempt from credential-shaped assignment scanning.
PLACEHOLDER_VALUES = frozenset(
    {
        "EXAMPLE_TOKEN",
        "EXAMPLE_KEY",
        "SAMPLE_API_KEY",
        "DATA_PLACEHOLDER",
        "SESSION_DATA_PLACEHOLDER",
        "SYSTEM_PROMPT_PLACEHOLDER",
        "INTERNAL_POLICY_PLACEHOLDER",
        "ADMIN_TOKEN_PLACEHOLDER",
    }
)

_SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    "bearer_token": re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]{20,}\b"),
    "private_key_block": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "assigned_credential": re.compile(
        r"\b(password|passwd|api_key|apikey|secret|token)\b\s*[:=]\s*"
        r"[\"']?[^\"'\s]{8,}[\"']?",
        re.IGNORECASE,
    ),
}

_PII_PATTERNS: dict[str, re.Pattern[str]] = {
    "email_address": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "national_id": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "phone_number": re.compile(r"\b\+?1[-. ]?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}\b"),
}

_URL_PATTERN = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)

# Unicode-tolerant hostname candidates; TLD stays ASCII-only. Non-ASCII labels
# are IDNA-normalized before allowlist checks so confusable homoglyph hosts
# cannot hide behind the ASCII-only pattern.
_FQDN_PATTERN = re.compile(r"\b((?:\w[\w-]*\.)+[a-zA-Z]{2,})\b")

# Static assets and file suffixes that resemble TLDs but are not hostnames.
_FILE_SUFFIXES = frozenset(
    {
        "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "css", "js", "ts", "json", "txt",
        "md", "pdf", "doc", "docx", "csv", "tsv", "yaml", "yml", "xml", "html", "htm", "zip",
        "tar", "gz", "tgz", "log", "py", "sh", "sql", "wasm", "woff", "woff2", "ttf", "env",
    }
)


def _idna_fqdn(fqdn: str) -> str | None:
    """IDNA-normalize a hostname candidate; None when encoding fails."""
    try:
        return ".".join(
            label.encode("idna").decode("ascii") for label in fqdn.split(".")
        ).casefold()
    except (UnicodeError, ValueError):
        return None


def _is_probable_hostname(fqdn: str, text: str, start: int) -> bool:
    """Reject file paths and asset filenames that pattern-match as hostnames."""
    if start > 0 and text[start - 1] == "/":
        return False
    tld = fqdn.rsplit(".", 1)[-1].casefold()
    return tld not in _FILE_SUFFIXES


class CorpusGovernanceError(EvaluationContractError):
    """Raised when corpus governance checks fail closed."""


def sha256_hex(payload: str) -> str:
    """SHA-256 hex digest of a UTF-8 string."""
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def normalize_case_text(text: str) -> str:
    """Canonical form used for near-duplicate detection (stable across encodings)."""
    decomposed = unicodedata.normalize("NFKC", text)
    stripped = "".join(ch for ch in decomposed if ch not in _ZERO_WIDTH_CHARS)
    return " ".join(stripped.casefold().split())


def exact_case_hash(prompt: str, context: str) -> str:
    """Hash of the canonical prompt/context payload, before normalization."""
    return hashlib.sha256(_case_payload_bytes(prompt, context)).hexdigest()


def normalized_case_hash(prompt: str, context: str) -> str:
    """Hash of the normalized canonical payload used for near-duplicate grouping."""
    return hashlib.sha256(_case_payload_normalized(prompt, context)).hexdigest()


def is_held_out(case_id: str) -> bool:
    """Deterministic held-out split membership: sha256(case_id) mod 100 < 25."""
    bucket = int(hashlib.sha256(case_id.encode("utf-8")).hexdigest(), 16)
    return bucket % 100 < CORPUS_HELD_OUT_PERCENT


def _case_payload(prompt: str, context: str) -> dict[str, str]:
    """Canonical per-case payload so field boundaries survive hashing."""
    return {"prompt": prompt, "context": context}


def _case_payload_bytes(prompt: str, context: str) -> bytes:
    return json.dumps(
        _case_payload(prompt, context), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _case_payload_normalized(prompt: str, context: str) -> bytes:
    return json.dumps(
        _case_payload(normalize_case_text(prompt), normalize_case_text(context)),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _url_hosts_allowed(url: str) -> bool:
    match = re.match(r"(?i)^[a-z][a-z0-9+.-]*://([^/@:]+)", url)
    if match is None:
        return False
    host = match.group(1).casefold().rstrip(".")
    if host in _ALLOWED_URL_HOSTS:
        return True
    return any(host.endswith(suffix) for suffix in _ALLOWED_URL_HOST_SUFFIXES)


def _email_allowed(email: str) -> bool:
    domain = email.rsplit("@", 1)[1].casefold()
    if domain in _ALLOWED_URL_HOSTS:
        return True
    return any(domain.endswith(suffix) for suffix in _ALLOWED_URL_HOST_SUFFIXES)


def scan_case_text(text: str) -> list[str]:
    """Return finding labels for secrets, PII, or live-target references.

    Findings are hard failures for corpus intake; legacy rows are documented in
    the provenance sidecar instead of being scanned here.
    """
    findings: list[str] = []
    for label, pattern in _SECRET_PATTERNS.items():
        for match in pattern.finditer(text):
            if label == "assigned_credential":
                value = match.group(0).rsplit("=", 1)[-1].rsplit(":", 1)[-1]
                if value.strip("\"'").casefold() in {p.casefold() for p in PLACEHOLDER_VALUES}:
                    continue
            findings.append(f"secret:{label}")
            break
    for label, pattern in _PII_PATTERNS.items():
        for match in pattern.finditer(text):
            candidate = match.group(0)
            if label == "email_address" and _email_allowed(candidate):
                continue
            findings.append(f"pii:{label}")
            break
    for url in _URL_PATTERN.findall(text):
        if not _url_hosts_allowed(url):
            findings.append("live_target:url")
            break
    for fqdn_match in _FQDN_PATTERN.finditer(text):
        fqdn = fqdn_match.group(1)
        if not _is_probable_hostname(fqdn, text, fqdn_match.start(1)):
            continue
        normalized = _idna_fqdn(fqdn)
        if normalized is None:
            findings.append("live_target:idna")
            break
        if _url_hosts_allowed(f"https://{normalized}"):
            continue
        findings.append("live_target:fqdn")
        break
    return findings


@dataclass(frozen=True)
class CorpusRowFacts:
    """Derived governance facts for one dataset row."""

    case_id: str
    attack_family: str
    case_type: str
    expected_blocked: bool
    content_hash: str
    normalized_hash: str
    held_out: bool
    findings: list[str]

    @property
    def is_benign_hard_negative(self) -> bool:
        """Benign rows inside an adversarial family act as hard negatives."""
        return self.case_type == "benign" and self.attack_family != "clean"


def load_corpus_facts(dataset_path: Path) -> list[CorpusRowFacts]:
    """Parse a governed dataset JSONL file and derive per-row governance facts."""
    rows = load_jsonl_rows(dataset_path)
    facts: list[CorpusRowFacts] = []
    for index, row in enumerate(rows, start=1):
        case_id = row.get("case_id")
        if not isinstance(case_id, str) or not case_id:
            raise CorpusGovernanceError(f"line {index}: missing case_id")
        prompt = row.get("prompt")
        context = row.get("context")
        if not isinstance(prompt, str) or not isinstance(context, str):
            raise CorpusGovernanceError(f"line {index}: prompt and context must be strings")
        family = row.get("attack_family")
        facts.append(
            CorpusRowFacts(
                case_id=case_id,
                attack_family=str(family or "unknown"),
                case_type=str(row.get("case_type") or "unknown"),
                expected_blocked=bool(row.get("expected_blocked", False)),
                content_hash=exact_case_hash(prompt, context),
                normalized_hash=normalized_case_hash(prompt, context),
                held_out=is_held_out(case_id),
                findings=scan_case_text(f"{prompt} {context}"),
            )
        )
    return facts


def find_duplicate_groups(facts: list[CorpusRowFacts]) -> tuple[list[list[str]], list[list[str]]]:
    """Return (exact, normalized) duplicate groups among corpus rows."""
    exact: dict[str, list[str]] = {}
    normalized: dict[str, list[str]] = {}
    for fact in facts:
        exact.setdefault(fact.content_hash, []).append(fact.case_id)
        normalized.setdefault(fact.normalized_hash, []).append(fact.case_id)
    exact_groups = sorted(sorted(ids) for ids in exact.values() if len(ids) > 1)
    normalized_groups = sorted(sorted(ids) for ids in normalized.values() if len(ids) > 1)
    return exact_groups, normalized_groups


def build_family_balance(facts: list[CorpusRowFacts]) -> dict[str, dict[str, Any]]:
    """Per-family composition: adversarial vs benign hard negatives and splits."""
    families: dict[str, dict[str, Any]] = {}
    for fact in facts:
        entry = families.setdefault(
            fact.attack_family,
            {
                "case_count": 0,
                "adversarial_cases": 0,
                "benign_hard_negatives": 0,
                "expected_blocked": 0,
                "held_out_cases": 0,
                "dev_cases": 0,
                "risk_levels": {},
            },
        )
        entry["case_count"] += 1
        if fact.case_type == "adversarial":
            entry["adversarial_cases"] += 1
        if fact.is_benign_hard_negative:
            entry["benign_hard_negatives"] += 1
        if fact.expected_blocked:
            entry["expected_blocked"] += 1
        if fact.held_out:
            entry["held_out_cases"] += 1
        else:
            entry["dev_cases"] += 1
    return {family: dict(entry) for family, entry in sorted(families.items())}


def load_packaged_provenance_schema() -> dict[str, Any]:
    """Load the packaged corpus_provenance.v1 JSON Schema."""
    resource = files("src.resources").joinpath("schemas/corpus_provenance.v1.json")
    with as_file(resource) as schema_path:
        data = json.loads(Path(schema_path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise CorpusGovernanceError("corpus_provenance.v1.json must be a JSON object")
    return data


def validate_provenance_document(sidecar: Any) -> None:
    """Fail closed when a provenance sidecar violates corpus_provenance.v1."""
    from src.eval.contract import validate_json_document

    if not isinstance(sidecar, dict):
        raise CorpusGovernanceError("provenance sidecar must be a JSON object")
    validate_json_document(
        sidecar,
        load_packaged_provenance_schema(),
        label="corpus provenance",
    )


def verify_provenance_sidecar(
    sidecar: dict[str, Any],
    dataset_path: Path,
    *,
    generator_path: Path | None = None,
) -> dict[str, Any]:
    """Cross-check a provenance sidecar against the governed dataset.

    Returns a summary dict on success; raises CorpusGovernanceError on any
    mismatch (counts, hashes, split membership, derivation links, or schema).
    """
    validate_provenance_document(sidecar)

    if sidecar.get("contract_ref") != "adml.evaluation.dataset.v1":
        raise CorpusGovernanceError("provenance contract_ref must be the dataset v1 contract")
    if sidecar.get("split_rule") != CORPUS_SPLIT_RULE:
        raise CorpusGovernanceError(
            f"provenance split_rule must be {CORPUS_SPLIT_RULE!r}, got {sidecar.get('split_rule')!r}"
        )
    if sidecar.get("held_out_percent") != CORPUS_HELD_OUT_PERCENT:
        raise CorpusGovernanceError("provenance held_out_percent must match the split rule")

    generator_digest = sidecar.get("generator_digest_sha256")
    if generator_path is not None and generator_digest is None:
        raise CorpusGovernanceError(
            "generator_digest_sha256 is required to verify a generator-produced sidecar"
        )
    if generator_digest is not None and generator_path is not None:
        actual = hashlib.sha256(generator_path.read_bytes()).hexdigest()
        if actual != generator_digest:
            raise CorpusGovernanceError(
                "generator_digest_sha256 does not match the generator script bytes; "
                "regenerate the corpus artifacts"
            )

    facts = load_corpus_facts(dataset_path)
    facts_by_id = {fact.case_id: fact for fact in facts}
    cases = sidecar.get("cases")
    if not isinstance(cases, dict):
        raise CorpusGovernanceError("provenance cases must be an object")

    missing = sorted(set(facts_by_id) - set(cases))
    extra = sorted(set(cases) - set(facts_by_id))
    if missing:
        raise CorpusGovernanceError(f"provenance missing entries for dataset cases: {missing}")
    if extra:
        raise CorpusGovernanceError(f"provenance has entries not present in dataset: {extra}")

    for case_id, fact in facts_by_id.items():
        entry = cases[case_id]
        if entry["content_hash_sha256"] != fact.content_hash:
            raise CorpusGovernanceError(f"provenance content hash mismatch for {case_id}")
        if entry["normalized_hash_sha256"] != fact.normalized_hash:
            raise CorpusGovernanceError(f"provenance normalized hash mismatch for {case_id}")
        if entry["held_out"] != fact.held_out:
            raise CorpusGovernanceError(f"provenance held_out flag mismatch for {case_id}")
        if entry["attack_class"] != fact.attack_family:
            raise CorpusGovernanceError(
                f"provenance attack_class {entry['attack_class']!r} != family "
                f"{fact.attack_family!r} for {case_id}"
            )

    for case_id, entry in cases.items():
        parent = entry.get("parent_sample_id")
        if parent is not None and parent not in cases:
            raise CorpusGovernanceError(
                f"provenance parent_sample_id {parent!r} for {case_id} is not in the corpus"
            )

    family_counts: dict[str, int] = {}
    benign_by_family: dict[str, int] = {}
    held_by_family: dict[str, int] = {}
    for fact in facts:
        family_counts[fact.attack_family] = family_counts.get(fact.attack_family, 0) + 1
        if fact.is_benign_hard_negative:
            benign_by_family[fact.attack_family] = benign_by_family.get(fact.attack_family, 0) + 1
        if fact.held_out:
            held_by_family[fact.attack_family] = held_by_family.get(fact.attack_family, 0) + 1
    sidecar_families = sidecar.get("families")
    if not isinstance(sidecar_families, dict):
        raise CorpusGovernanceError("provenance families must be an object")
    sidecar_family_counts = {
        family: int(entry["case_count"]) for family, entry in sidecar_families.items()
    }
    if sidecar_family_counts != family_counts:
        raise CorpusGovernanceError(
            f"provenance families {sidecar_family_counts} != dataset families {family_counts}"
        )
    methods_by_family: dict[str, dict[str, int]] = {}
    for entry in cases.values():
        family = str(entry["attack_class"])
        method = str(entry["generation_method"])
        family_methods = methods_by_family.setdefault(family, {})
        family_methods[method] = family_methods.get(method, 0) + 1
    for family, summary in sidecar_families.items():
        expected_benign = benign_by_family.get(family, 0)
        if int(summary["benign_hard_negatives"]) != expected_benign:
            raise CorpusGovernanceError(
                f"provenance families.{family}.benign_hard_negatives "
                f"{summary['benign_hard_negatives']} != {expected_benign}"
            )
        expected_held = held_by_family.get(family, 0)
        if int(summary["held_out_count"]) != expected_held:
            raise CorpusGovernanceError(
                f"provenance families.{family}.held_out_count "
                f"{summary['held_out_count']} != {expected_held}"
            )
        expected_methods = {
            method: int(count)
            for method, count in sorted(methods_by_family.get(family, {}).items())
        }
        actual_methods = {
            method: int(count)
            for method, count in sorted(summary["generation_methods"].items())
        }
        if actual_methods != expected_methods:
            raise CorpusGovernanceError(
                f"provenance families.{family}.generation_methods {actual_methods} "
                f"!= {expected_methods}"
            )

    return {
        "case_count": len(facts),
        "families": family_counts,
        "held_out_count": sum(1 for fact in facts if fact.held_out),
    }


def build_governance_report(
    dataset_path: Path,
    sidecar: dict[str, Any],
    *,
    manifest_path: Path | None = None,
) -> dict[str, Any]:
    """Build the deterministic governance evidence report for a corpus revision."""
    facts = load_corpus_facts(dataset_path)
    exact_groups, normalized_groups = find_duplicate_groups(facts)

    findings_by_id = {
        fact.case_id: fact.findings for fact in facts if fact.findings
    }
    legacy_ids = {
        case_id
        for case_id, entry in sidecar["cases"].items()
        if entry["source"] == "dataset_import"
    }
    current_findings = {
        case_id: found for case_id, found in findings_by_id.items() if case_id not in legacy_ids
    }
    legacy_findings = {
        case_id: found for case_id, found in findings_by_id.items() if case_id in legacy_ids
    }
    balance = build_family_balance(facts)
    held_out_ids = sorted(fact.case_id for fact in facts if fact.held_out)
    dev_ids = sorted(fact.case_id for fact in facts if not fact.held_out)

    review_status_counts: dict[str, int] = {}
    source_counts: dict[str, int] = {}
    generation_method_counts: dict[str, int] = {}
    cases = sidecar["cases"]
    for entry in cases.values():
        review_status_counts[entry["review_status"]] = (
            review_status_counts.get(entry["review_status"], 0) + 1
        )
        source_counts[entry["source"]] = source_counts.get(entry["source"], 0) + 1
        generation_method_counts[entry["generation_method"]] = (
            generation_method_counts.get(entry["generation_method"], 0) + 1
        )

    hard_negative_families = sorted(
        family for family, entry in balance.items() if entry["benign_hard_negatives"] > 0
    )

    manifest_conformance = "skipped"
    if manifest_path is not None and manifest_path.is_file():
        from src.eval.contract import (
            load_dataset_manifest,
            validate_dataset_against_manifest,
        )

        manifest = load_dataset_manifest(manifest_path)
        validate_dataset_against_manifest(dataset_path, manifest)
        manifest_conformance = "pass"

    # Cross-checks must actually run before this report may attest them.
    verify_provenance_sidecar(sidecar, dataset_path)

    checks: dict[str, str] = {
        "dedupe": "pass" if not exact_groups and not normalized_groups else "fail",
        "leakage_scan": "pass" if not current_findings else "fail",
        "manifest_conformance": manifest_conformance,
        "provenance_cross_check": "pass",
        "schema_conformance": "pass",
    }

    return {
        "report_schema": CORPUS_REPORT_SCHEMA_ID,
        "governance_version": CORPUS_GOVERNANCE_VERSION,
        "corpus_id": sidecar["corpus_id"],
        "corpus_version": sidecar["corpus_version"],
        "dataset_filename": dataset_path.name,
        "content_digest_sha256": compute_dataset_file_digest(dataset_path),
        "sorted_content_digest_sha256": compute_sorted_jsonl_content_digest(dataset_path),
        "case_count": len(facts),
        "family_counts": {family: entry["case_count"] for family, entry in balance.items()},
        "family_balance": balance,
        "hard_negative_families": hard_negative_families,
        "dedupe": {
            "exact_duplicate_groups": exact_groups,
            "normalized_duplicate_groups": normalized_groups,
        },
        "leakage_scan": {
            "cases_scanned": len(facts),
            "current_findings": current_findings,
            "legacy_findings_documented": legacy_findings,
        },
        "held_out_split": {
            "rule": CORPUS_SPLIT_RULE,
            "held_out_percent": CORPUS_HELD_OUT_PERCENT,
            "held_out_count": len(held_out_ids),
            "dev_count": len(dev_ids),
            "held_out_ids": held_out_ids,
            "dev_ids": dev_ids,
        },
        "provenance_summary": {
            "schema_version": sidecar["schema_version"],
            "cases_documented": len(cases),
            "review_status_counts": dict(sorted(review_status_counts.items())),
            "source_counts": dict(sorted(source_counts.items())),
            "generation_method_counts": dict(sorted(generation_method_counts.items())),
        },
        "checks": checks,
    }


def assert_governance_report_passes(report: dict[str, Any]) -> None:
    """Fail closed unless every governance check ran and passed."""
    checks = report.get("checks")
    if not isinstance(checks, dict) or not checks:
        raise CorpusGovernanceError("governance report is missing checks")
    if set(checks.keys()) != REPORT_ALLOWED_CHECKS:
        missing = sorted(REPORT_ALLOWED_CHECKS - set(checks.keys()))
        extra = sorted(set(checks.keys()) - REPORT_ALLOWED_CHECKS)
        raise CorpusGovernanceError(
            f"governance report check set mismatch (missing={missing}, extra={extra})"
        )
    for name, outcome in sorted(checks.items()):
        if outcome != "pass":
            raise CorpusGovernanceError(f"governance check {name!r} did not pass: {outcome}")
