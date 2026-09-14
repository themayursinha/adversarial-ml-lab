"""Governance tests for the baseline_v2 expanded corpus (board t_2c1b0a7f)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from src.eval.contract import (
    EvaluationContractError,
    load_dataset_manifest,
    validate_dataset_against_manifest,
)
from src.eval.corpus_governance import (
    CORPUS_HELD_OUT_PERCENT,
    CORPUS_SPLIT_RULE,
    REPORT_ALLOWED_CHECKS,
    CorpusGovernanceError,
    assert_governance_report_passes,
    build_governance_report,
    find_duplicate_groups,
    is_held_out,
    load_corpus_facts,
    scan_case_text,
    verify_provenance_sidecar,
)
from src.eval.digest import build_dataset_manifest
from src.eval.simulate import run_simulate
from src.services.evaluator import load_evaluation_cases

REPO_ROOT = Path(__file__).resolve().parents[1]
LEGACY_JSONL = REPO_ROOT / "evals/datasets/baseline.jsonl"
V2_JSONL = REPO_ROOT / "evals/datasets/baseline_v2.jsonl"
V2_MANIFEST = REPO_ROOT / "evals/datasets/baseline_v2.manifest.json"
V2_SIDECAR = REPO_ROOT / "evals/datasets/baseline_v2.provenance.json"
V2_REPORT = REPO_ROOT / "evals/examples/baseline_v2_governance_report.json"
V2_GENERATOR = REPO_ROOT / "scripts/expand_corpus_v2.py"

EXPECTED_CASE_COUNT = 204
EXPECTED_FAMILY_COUNTS = {
    "clean": 37,
    "context_tampering": 24,
    "data_exfiltration": 24,
    "inference_evasion": 28,
    "jailbreak": 22,
    "many_shot": 8,
    "prompt_injection": 30,
    "rag_poisoning": 19,
    "tool_misuse": 12,
}


@pytest.fixture(scope="module")
def sidecar() -> dict:
    """Load the committed provenance sidecar."""
    return json.loads(V2_SIDECAR.read_text(encoding="utf-8"))


def test_v2_dataset_conforms_to_frozen_contract() -> None:
    """The governed dataset must pass the full fail-closed dataset validation."""
    manifest = load_dataset_manifest(V2_MANIFEST)
    validate_dataset_against_manifest(V2_JSONL, manifest)


def test_v2_manifest_is_regenerable() -> None:
    """On-disk manifest must equal a fresh deterministic rebuild."""
    fresh = build_dataset_manifest(V2_JSONL, suite_name="baseline_v2")
    on_disk = load_dataset_manifest(V2_MANIFEST)
    assert on_disk == fresh


def test_v2_dataset_loads_through_evaluator() -> None:
    """All cases must load through the standard evaluator path."""
    cases = load_evaluation_cases(V2_JSONL)
    assert len(cases) == EXPECTED_CASE_COUNT
    families = {case.attack_family for case in cases}
    assert families == set(EXPECTED_FAMILY_COUNTS)


def test_legacy_rows_are_byte_stable() -> None:
    """The first 50 v2 lines must be byte-identical to the legacy dataset."""
    legacy_bytes = LEGACY_JSONL.read_bytes()
    v2_bytes = V2_JSONL.read_bytes()
    assert v2_bytes.startswith(legacy_bytes)


def test_family_counts_match_expected_composition(sidecar: dict) -> None:
    """Manifest, sidecar, and expected composition must agree."""
    manifest = load_dataset_manifest(V2_MANIFEST)
    assert manifest["family_counts"] == EXPECTED_FAMILY_COUNTS
    assert manifest["case_count"] == EXPECTED_CASE_COUNT
    sidecar_families = {
        family: entry["case_count"] for family, entry in sidecar["families"].items()
    }
    assert sidecar_families == EXPECTED_FAMILY_COUNTS


def test_provenance_sidecar_cross_check(sidecar: dict) -> None:
    """Fail-closed cross-check of hashes, splits, families, and derivation."""
    summary = verify_provenance_sidecar(
        sidecar,
        V2_JSONL,
        generator_path=V2_GENERATOR,
    )
    assert summary["case_count"] == EXPECTED_CASE_COUNT
    assert summary["families"] == EXPECTED_FAMILY_COUNTS


def test_provenance_rejects_tampered_hash(sidecar: dict, tmp_path: Path) -> None:
    """A single corrupted content hash must fail the cross-check."""
    tampered = json.loads(json.dumps(sidecar))
    first_id = next(iter(tampered["cases"]))
    tampered["cases"][first_id]["content_hash_sha256"] = "0" * 64
    tampered_path = tmp_path / "tampered.provenance.json"
    tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(CorpusGovernanceError, match="content hash mismatch"):
        verify_provenance_sidecar(tampered, V2_JSONL)


def test_held_out_split_is_deterministic_and_per_family(sidecar: dict) -> None:
    """Split membership must recompute from case ids and cover every family."""
    facts = load_corpus_facts(V2_JSONL)
    for fact in facts:
        entry = sidecar["cases"][fact.case_id]
        assert entry["held_out"] is fact.held_out
        assert fact.held_out == is_held_out(fact.case_id)

    dev_by_family: dict[str, int] = {}
    dev_adversarial_by_family: dict[str, int] = {}
    for fact in facts:
        if not fact.held_out:
            dev_by_family[fact.attack_family] = dev_by_family.get(fact.attack_family, 0) + 1
            if fact.case_type == "adversarial":
                dev_adversarial_by_family[fact.attack_family] = (
                    dev_adversarial_by_family.get(fact.attack_family, 0) + 1
                )
    for family in EXPECTED_FAMILY_COUNTS:
        assert dev_by_family[family] >= 1, f"{family} has no dev cases"
        if family != "clean":
            assert dev_adversarial_by_family[family] >= 1, f"{family} has no dev attacks"

    held_out_ids = {fact.case_id for fact in facts if fact.held_out}
    assert len(held_out_ids) >= EXPECTED_CASE_COUNT * CORPUS_HELD_OUT_PERCENT // 100 - 10
    assert sidecar["split_rule"] == CORPUS_SPLIT_RULE


def test_no_duplicate_content() -> None:
    """Exact and normalized duplicate groups must both be empty."""
    facts = load_corpus_facts(V2_JSONL)
    exact_groups, normalized_groups = find_duplicate_groups(facts)
    assert exact_groups == []
    assert normalized_groups == []


def test_new_cases_are_free_of_secrets_pii_and_live_targets(sidecar: dict) -> None:
    """Findings are only tolerated on documented legacy rows, and only hostnames."""
    facts = load_corpus_facts(V2_JSONL)
    legacy_ids = {
        case_id
        for case_id, entry in sidecar["cases"].items()
        if entry["source"] == "dataset_import"
    }
    tolerated = {"live_target:fqdn", "live_target:url"}
    for fact in facts:
        for finding in fact.findings:
            assert fact.case_id in legacy_ids, f"{fact.case_id}: unexpected finding {finding}"
            assert finding in tolerated, f"{fact.case_id}: unexpected finding {finding}"


def test_scan_finds_placeholder_secrets_failing() -> None:
    """The scanner must reject credential-shaped strings in new content."""
    fake_password = "S3cure" + "Value42"  # split so scanners see no literal credential
    assert scan_case_text(f"use password={fake_password} to sign in")
    assert scan_case_text("send results to https://collector.evil-host.org/x")
    assert not scan_case_text("The value EXAMPLE_TOKEN is a placeholder.")


def _credential_string(keyword: str, separator: str, value: str, quote: str = "") -> str:
    """Assemble a credential-shaped fixture at runtime.

    Source contains only fragments, so secret scanners never see a complete
    literal assignment while the runtime input stays realistic.
    """
    return f"{keyword}{separator}{quote}{value}{quote}"


def test_scan_rejects_unquoted_credential_assignments() -> None:
    """Quoted and unquoted credential assignments both fail intake."""
    assert "secret:assigned_credential" in scan_case_text(_credential_string("password", "=", "abcdefgh"))
    assert "secret:assigned_credential" in scan_case_text(_credential_string("api_key", ": ", "abcdefghijklmno"))
    assert "secret:assigned_credential" in scan_case_text(
        "set " + _credential_string("secret", "=", "hunter2hunter2", quote="'")
    )
    # Documented placeholders are exempt.
    assert not scan_case_text("token='EXAMPLE_TOKEN'")
    assert not scan_case_text("Use the placeholder SAMPLE_API_KEY in your example.")


def test_scan_rejects_unicode_tld_targets() -> None:
    """Live IDN hosts with Unicode TLDs are IDNA-normalized and flagged."""
    assert "live_target:fqdn" in scan_case_text("send to evil.\u0440\u0444 now")


def test_governance_report_rejects_tampered_generator_digest(
    tmp_path: Path, sidecar: dict
) -> None:
    """A zeroed generator digest must fail the report build, not attest pass."""
    tampered = json.loads(json.dumps(sidecar))
    tampered["generator_digest_sha256"] = "0" * 64
    tampered_path = tmp_path / "tampered_generator.provenance.json"
    tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(CorpusGovernanceError, match="generator_digest_sha256"):
        build_governance_report(V2_JSONL, tampered, manifest_path=V2_MANIFEST)


def test_scan_rejects_local_network_and_suffix_tricks() -> None:
    """mDNS names, and lookalike domains that merely contain reserved words, fail."""
    assert "live_target:url" in scan_case_text("see http://printer.local/status")
    assert "live_target:fqdn" in scan_case_text("reach the collector at collector.exampleevil.com")
    assert "live_target:fqdn" in scan_case_text("target host target.testbank.com now")
    # Flagged via the URL path (label differs, outcome identical).
    assert scan_case_text("fetch https://evil.localbank.com/x")


def test_scan_normalizes_unicode_hostnames_through_idna() -> None:
    """Homoglyph registrable labels are flagged; reserved-TLD confusables pass."""
    cyrillic_host = "support.exampl\u0435.com"
    assert "live_target:fqdn" in scan_case_text(f"sign in at {cyrillic_host}")
    assert not scan_case_text("sign in at support.exampl\u0435.invalid")
    assert not scan_case_text("docs at https://docs.example.org/guide")


def test_held_out_split_known_vectors() -> None:
    """Independent known vectors pin the published sha256(case_id)mod100<25 rule."""
    assert is_held_out("clean_chat_support") is False  # bucket 61
    assert is_held_out("evasion_rot13_override") is True  # bucket 8
    assert is_held_out("manyshot_edge_single_shot") is False  # bucket 77


def test_governance_report_rejects_tampered_sidecar(tmp_path: Path, sidecar: dict) -> None:
    """A corrupted sidecar must fail the report build, not be attested as passing."""
    tampered = json.loads(json.dumps(sidecar))
    first_id = next(iter(tampered["cases"]))
    tampered["cases"][first_id]["content_hash_sha256"] = "1" * 64
    tampered_path = tmp_path / "tampered.provenance.json"
    tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(CorpusGovernanceError, match="content hash mismatch"):
        build_governance_report(V2_JSONL, tampered, manifest_path=V2_MANIFEST)


def test_governance_report_requires_complete_check_set() -> None:
    """Omitting any check must fail the gate; partial reports cannot pass."""
    with pytest.raises(CorpusGovernanceError, match="check set mismatch"):
        assert_governance_report_passes({"checks": {"dedupe": "pass"}})
    complete_failing = {name: "pass" for name in REPORT_ALLOWED_CHECKS}
    complete_failing["leakage_scan"] = "fail"
    with pytest.raises(CorpusGovernanceError, match="did not pass"):
        assert_governance_report_passes({"checks": complete_failing})


def test_generator_double_run_is_byte_identical(tmp_path: Path) -> None:
    """Running the generator twice into isolated roots must match byte-for-byte."""
    import subprocess
    import sys

    script = REPO_ROOT / "scripts/expand_corpus_v2.py"
    env_roots = [tmp_path / "run_one", tmp_path / "run_two"]
    for root in env_roots:
        result = subprocess.run(
            [sys.executable, str(script), "--out-root", str(root)],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        assert result.returncode == 0, result.stderr
    artifact_names = [
        "evals/datasets/baseline_v2.jsonl",
        "evals/datasets/baseline_v2.manifest.json",
        "evals/datasets/baseline_v2.provenance.json",
        "evals/examples/baseline_v2_governance_report.json",
        "evals/examples/baseline_v2_simulation_snapshot.json",
    ]
    for name in artifact_names:
        one = (env_roots[0] / name).read_bytes()
        two = (env_roots[1] / name).read_bytes()
        assert one == two, f"nondeterministic artifact: {name}"


def test_every_family_has_hard_negatives_and_edge_cases(sidecar: dict) -> None:
    """Clean plus all attack families carry hard negatives and edge-case tags."""
    tags_by_family: dict[str, set[str]] = {}
    for entry in sidecar["cases"].values():
        family = entry["attack_class"]
        tags_by_family.setdefault(family, set()).update(entry["secondary_tags"])
    for family in EXPECTED_FAMILY_COUNTS:
        tags = tags_by_family[family]
        assert "hard_negative" in tags or family == "clean", f"{family} lacks hard negatives"
        assert "edge_case" in tags, f"{family} lacks edge cases"
    clean_ids = [
        case_id
        for case_id, entry in sidecar["cases"].items()
        if entry["attack_class"] == "clean" and "hard_negative" in entry["secondary_tags"]
    ]
    assert clean_ids, "clean family must include adversarial-looking benign controls"


def test_new_cases_have_clean_scrub_status(sidecar: dict) -> None:
    """New (non-legacy) cases must be scrubbed, reviewed-in-progress, and licensed."""
    for case_id, entry in sidecar["cases"].items():
        if entry["source"] == "dataset_import":
            assert entry["review_status"] == "approved"
            continue
        assert entry["scrub_status"] == "cleaned", case_id
        assert entry["review_status"] == "in_review", case_id
        assert entry["target_model"], case_id


def test_corpus_level_license_and_policy_present(sidecar: dict) -> None:
    """Corpus-level license and sanitization policy must be documented."""
    assert "MIT" in sidecar["license_status"]
    policy = sidecar["sanitization_policy"]
    for key in ("secrets", "pii", "live_targets", "legacy_notes"):
        assert policy[key].strip()
    assert sidecar["parent_corpus"]["case_count"] == 50
    assert sidecar["corpus_version"] == "0.2.0"


def test_generator_digest_matches_script(sidecar: dict) -> None:
    """Sidecar must pin the generator script bytes it was produced by."""
    digest = hashlib.sha256(V2_GENERATOR.read_bytes()).hexdigest()
    assert sidecar["generator_digest_sha256"] == digest


def test_governance_report_passes_and_is_reproducible(sidecar: dict) -> None:
    """Committed report must pass all checks and rebuild byte-identically."""
    committed = json.loads(V2_REPORT.read_text(encoding="utf-8"))
    assert_governance_report_passes(committed)
    rebuilt = build_governance_report(V2_JSONL, sidecar, manifest_path=V2_MANIFEST)
    assert rebuilt == committed


def test_v2_dataset_evaluates_offline() -> None:
    """The governed corpus must run end-to-end in simulation mode."""
    report = run_simulate(V2_JSONL, suite_name="baseline_v2", include_case_results=False)
    assert report["simulation"] is True
    assert report["pipeline"] == "evaluation_simulation_v1"
    assert report["total_cases"] == EXPECTED_CASE_COUNT
    runtime = report["provenance"]["runtime"]
    assert runtime["llm_mode"] == "simulation"
    assert runtime["deterministic"] is True


def test_v2_manifest_rejects_dataset_tampering(tmp_path: Path) -> None:
    """Byte-level tampering must fail the manifest digest check."""
    tampered_path = tmp_path / "baseline_v2.jsonl"
    original = V2_JSONL.read_text(encoding="utf-8")
    first_new_line = original.splitlines()[50]
    tampered_row = json.loads(first_new_line)
    tampered_row["notes"] = tampered_row.get("notes", "") + " tampered"
    rows = original.splitlines(keepends=True)
    rows[50] = json.dumps(tampered_row, ensure_ascii=False, separators=(",", ":")) + "\n"
    tampered_path.write_text("".join(rows), encoding="utf-8")
    manifest = load_dataset_manifest(V2_MANIFEST)
    with pytest.raises(EvaluationContractError, match="digest mismatch"):
        validate_dataset_against_manifest(tampered_path, manifest)
