from __future__ import annotations

import json


def test_malware_families_are_counted_from_mvt_metadata_and_not_guessed(tmp_path) -> None:
    from pegasushunter.report import analyze_results

    (tmp_path / "alerts.json").write_text(json.dumps([
        {"severity": "CRITICAL", "data": {"matched_indicator": {"name": "Predator Spyware"}}},
        {"severity": "HIGH", "data": {"matched_indicator": {"name": "Pegasus Spyware"}}},
        {"severity": "LOW", "message": "generic warning"},
    ]))

    report = analyze_results(tmp_path)

    assert report["family_counts"] == {"Pegasus Spyware": 1, "Predator Spyware": 1}
    assert report["unattributed_finding_count"] == 1
    assert report["overall_assessment"] == "indicator_match_found"

def test_targeting_attempt_and_successful_infection_have_distinct_assessments(tmp_path) -> None:
    from pegasushunter.report import analyze_results

    (tmp_path / "alerts.json").write_text(json.dumps([
        {"severity": "HIGH", "data": {"matched_indicator": {"name": "Pegasus"}}}
    ]))

    report = analyze_results(tmp_path)

    assert report["overall_assessment"] == "indicator_match_found"
    assert "targeting" in report["plain_summary"].lower()
    assert "active infection" not in report["plain_summary"].lower()


def test_corrupt_mvt_finds_audit_or_unknown_files_reduce_coverage_level(tmp_path) -> None:
    from pegasushunter.report import analyze_results

    (tmp_path / "alerts.json").write_text("[]")
    (tmp_path / "command.log").write_text("MVT WARNING: module failed; skipped")
    (tmp_path / "info.json").write_text(json.dumps({"platform": "Android", "version": "test"}))

    report = analyze_results(tmp_path)

    assert report["coverage_level"] == "limited"
    assert report["coverage_warnings"]
    assert report["overall_assessment"] == "limited_no_match"
