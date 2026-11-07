from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from pegasushunter.report import analyze_results, render_text


def test_indicator_matches_are_separated_from_heuristic_alerts(tmp_path: Path) -> None:
    (tmp_path / "alerts.json").write_text(json.dumps([
        {"level": "MEDIUM", "module": "aqf_packages", "message": "Package is unusual", "matched_indicator": None},
        {"level": "HIGH", "module": "mounts", "message": "System partition is read-write", "matched_indicator": None},
        {"level": "CRITICAL", "module": "DnsEvent", "message": "IOC hit", "matched_indicator": {"name": "Pegasus collection", "id": "indicator--1"}},
    ]))
    (tmp_path / "info.json").write_text('{"mvt_version":"2026.11.2","date":"2026-11-05"}')
    (tmp_path / "pegasushunter_scan.json").write_text('{"indicator_status":"complete","indicator_collections":["Pegasus collection"]}')

    report = analyze_results(tmp_path)
    text = render_text(report).lower()

    assert report["indicator_match_count"] == 1
    assert report["heuristic_alert_count"] == 2
    assert report["module_alert_counts"] == {"aqf_packages": 1, "mounts": 1}
    assert report["overall_assessment"] == "indicator_match_found"
    assert "one public spyware indicator match" in text
    assert "two additional heuristic findings" in text
    assert "does not by itself prove infection" in text


def test_scan_androidqf_uses_mvt_androidqf_and_records_source_scope(tmp_path, monkeypatch, capsys) -> None:
    from pegasushunter import cli

    source = tmp_path / "androidqf"
    (source / "intrusion_logs").mkdir(parents=True)
    (source / "intrusion_logs" / "log.txt").write_text("{}\\n")
    (source / "bugreport.zip").write_bytes(b"bugreport")
    (source / "backup.ab").write_bytes(b"ANDROID BACKUP\\n")
    (source / "command.log").write_text("Acquisition completed successfully\\n")
    output = tmp_path / "results"
    monkeypatch.setattr(cli.shutil, "which", lambda name: f"/usr/bin/{name}")
    captured = {}

    def fake_run(command, check, env):
        captured["command"] = command
        captured["env"] = env
        output.mkdir(parents=True, exist_ok=True)
        (output / "alerts.json").write_text("[]")
        (output / "info.json").write_text(json.dumps({
            "mvt_version": "2026.11.2", "date": "2026-11-05",
            "target_path": str(source), "ioc_files": [],
        }))
        (output / "command.log").write_text("MVT extraction complete\\n")
        return type("Completed", (), {"returncode": 0})()

    args = type("Args", (), {
        "source": source, "output": output, "platform": "android",
        "acquisition": "androidqf", "ioc": [], "indicator_cache": None,
    })()
    assert cli._run_scan(args, runner=fake_run) == 0
    assert captured["command"][:2] == ["/usr/bin/mvt-android", "check-androidqf"]
    assert captured["env"]["MVT_NETWORK_ACCESS_ALLOWED"] == "false"
    report = json.loads((output / "pegasushunter_report.json").read_text())
    assert report["coverage"]["androidqf"]["intrusion_logs"] == "collected"
    assert report["coverage"]["androidqf"]["bugreport_present"] is True
    assert report["coverage"]["androidqf"]["acquisition_completion"] == "complete"
    assert "AndroidQF acquisition metadata/logs show its collected modules completed" in capsys.readouterr().out


def test_androidqf_acquisition_without_snapshot_is_marked_unverified(tmp_path) -> None:
    results=tmp_path/"results"
    results.mkdir()
    (results/"alerts.json").write_text("[]")
    (results/"info.json").write_text(json.dumps({"mvt_version":"2026.11.2","date":"now","target_path":"/not-followed","ioc_files":[]}))
    (results/"pegasushunter_scan.json").write_text(json.dumps({"platform":"android","acquisition":"androidqf"}))
    report=analyze_results(results)
    assert report["coverage"]["androidqf"] is None
    assert any("snapshot is unavailable" in warning for warning in report["coverage_warnings"])


def test_no_indicator_matches_with_many_heuristic_alerts_is_not_reported_as_pegasus(tmp_path: Path) -> None:
    noisy = [
        {"level": "MEDIUM", "module": "mounts", "message": f"Suspicious mount option {i}", "matched_indicator": None}
        for i in range(80)
    ]
    noisy.extend([
        {"level": "HIGH", "module": "mounts", "message": "System partition read-write", "matched_indicator": None},
        {"level": "MEDIUM", "module": "aqf_packages", "message": "Rooting-related package", "matched_indicator": None},
    ])
    (tmp_path / "alerts.json").write_text(json.dumps(noisy))
    (tmp_path / "info.json").write_text('{"mvt_version":"2026.11.2"}')
    (tmp_path / "pegasushunter_scan.json").write_text('{"indicator_status":"complete"}')

    report = analyze_results(tmp_path)
    text = render_text(report).lower()

    assert report["indicator_match_count"] == 0
    assert report["heuristic_alert_count"] == 82
    assert report["overall_assessment"] == "heuristics_need_review"
    assert "no public spyware-indicator matches were found" in text
    assert "82 heuristic findings" in text
    assert "pegasus infection" not in text


def test_mount_summary_keeps_repeated_read_write_alerts_counted(tmp_path: Path) -> None:
    alerts=[
        {"module":"mounts","message":"System partition /system is mounted as read-write."},
        {"module":"mounts","message":"System partition /vendor is mounted as read-write."},
        {"module":"mounts","message":"Suspicious mount options found for /system: noatime"},
        {"module":"mounts","message":"Suspicious mount options found for /vendor: noatime"},
    ]
    (tmp_path/"alerts.json").write_text(json.dumps(alerts))
    (tmp_path/"info.json").write_text(json.dumps({"mvt_version":"test","date":"now","ioc_files":[]}))
    report=analyze_results(tmp_path)
    assert report["finding_count"] == 4
    assert report["repetitive_mounts"]["read_write_mount_count"] == 2
    assert report["repetitive_mounts"]["repeated_noatime_count"] == 2


def test_androidqf_legacy_scan_metadata_is_reported_unverified_not_clean(tmp_path: Path) -> None:
    results=tmp_path/"legacy"
    results.mkdir()
    (results/"alerts.json").write_text("[]")
    (results/"info.json").write_text(json.dumps({"mvt_version":"2026.11.2","date":"now","ioc_files":[]}))
    (results/"pegasushunter_scan.json").write_text(json.dumps({"platform":"android","acquisition":"androidqf","indicator_status":"complete"}))
    report=analyze_results(results)
    assert report["coverage"]["androidqf"] is None
    assert report["overall_assessment"] == "limited_no_match"
    assert report["coverage_level"] == "limited"
    assert any("snapshot is unavailable" in w for w in report["coverage_warnings"])


def test_androidqf_fixture_preserves_mount_findings_and_context(tmp_path: Path) -> None:
    fixture = Path(__file__).parent / "fixtures" / "androidqf"
    results = tmp_path / "fixture-results"
    results.mkdir()
    for name in ("alerts.json", "info.json", "pegasushunter_scan.json", "command.log"):
        shutil.copy2(fixture / name, results / name)

    report = analyze_results(results)
    text = render_text(report).lower()

    assert report["finding_count"] == 6
    assert report["indicator_match_count"] == 0
    assert report["heuristic_alert_count"] == 6
    assert report["coverage"]["ioc_collections"] == ["pegasus.stix2", "predator.stix2"]
    assert report["coverage_level"] == "results_present"
    assert report["repetitive_mounts"]["read_write_mount_count"] == 2
    assert "2 distinct read-write mount alerts for expert review" in text
    assert "possible system modification, not a spyware-indicator match" in text
    assert "no public spyware-indicator matches were found" in text


def test_synthetic_published_trace_scenario_is_cautiously_reported(tmp_path: Path) -> None:
    """Exercise report wording using fiction; this is not a real positive sample."""
    fixture = Path(__file__).parent / "fixtures" / "published_trace_synthetic"
    results = tmp_path / "synthetic-results"
    results.mkdir()
    for name in ("alerts.json", "info.json", "README.txt", "pegasushunter_scan.json"):
        shutil.copy2(fixture / name, results / name)

    report = analyze_results(results)
    text = render_text(report).lower()

    assert report["indicator_match_count"] == 1
    assert report["overall_assessment"] == "synthetic_test_fixture"
    assert "does not by itself prove infection" in text
    assert "potential match does not prove successful infection" in " ".join(report["limitations"]).lower()
    assert "synthetic" in (results / "README.txt").read_text().lower()
    assert report["coverage"]["test_fixture"] == "synthetic_published_trace_regression"
    assert report["coverage"]["indicator_status"] == "complete"
    assert "synthetic test fixture" in text
    assert "not an assessment of a real device" in text
    assert "synthetic test fixture" in report["plain_summary"].lower()
    assert "not an assessment of a real device" in report["plain_summary"].lower()
    assert report["status"] == "synthetic_test_fixture"
    assert report["overall_assessment"] == "synthetic_test_fixture"
    assert "/synthetic/device/path" not in json.dumps(report)


def test_unrecognized_synthetic_metadata_does_not_relabel_real_findings(tmp_path: Path) -> None:
    (tmp_path / "alerts.json").write_text(json.dumps([{
        "level": "CRITICAL", "module": "ios_processes", "message": "ordinary result match",
        "matched_indicator": {"name": "Test indicator", "id": "indicator--test"},
    }]))
    (tmp_path / "info.json").write_text(json.dumps({"mvt_version": "2026.11.2", "date": "now", "ioc_files": []}))
    (tmp_path / "pegasushunter_scan.json").write_text(json.dumps({"test_fixture": "synthetic_user_claim"}))

    report = analyze_results(tmp_path)

    assert report["status"] == "evidence_found"
    assert report["overall_assessment"] == "indicator_match_found"
    assert report["synthetic_test_fixture"] is False
    assert report["coverage"]["test_fixture"] is None
    assert report["indicator_match_count"] == 1


def test_synthetic_report_keeps_original_finding_assessment_for_machine_readers(tmp_path: Path) -> None:
    fixture = Path(__file__).parent / "fixtures" / "published_trace_synthetic"
    for name in ("alerts.json", "info.json", "pegasushunter_scan.json"):
        shutil.copy2(fixture / name, tmp_path / name)

    report = analyze_results(tmp_path)

    assert report["status"] == "synthetic_test_fixture"
    assert report["overall_assessment"] == "synthetic_test_fixture"
    assert report["synthetic_test_fixture"] is True
    assert report["device_evidence_status"] == "evidence_found"
    assert report["device_evidence_assessment"] == "indicator_match_found"


def test_ordinary_device_report_retains_indicator_assessment(tmp_path: Path) -> None:
    (tmp_path / "alerts.json").write_text(json.dumps([{
        "level": "CRITICAL", "module": "ios_processes", "message": "ordinary regression match",
        "matched_indicator": {"name": "Test indicator", "id": "indicator--test"},
    }]))
    (tmp_path / "info.json").write_text(json.dumps({"mvt_version": "2026.11.2", "date": "now", "ioc_files": []}))
    (tmp_path / "pegasushunter_scan.json").write_text(json.dumps({"indicator_status": "complete"}))

    report = analyze_results(tmp_path)
    text = render_text(report).lower()

    assert report["status"] == "evidence_found"
    assert report["overall_assessment"] == "indicator_match_found"
    assert report["synthetic_test_fixture"] is False
    assert not report["plain_summary"].lower().startswith("synthetic test fixture")
    assert "synthetic test fixture" not in text


def test_read_write_mount_alerts_get_custom_rom_context_without_dismissal(tmp_path: Path) -> None:
    alerts = []
    for index in range(7):
        mount = f"/system/partition-{index}"
        alerts.append({
            "level": "HIGH", "module": "mounts",
            "message": f"System partition {mount} is mounted as read-write (rw). This may indicate system modifications.",
            "matched_indicator": None,
        })
        alerts.append({
            "level": "MEDIUM", "module": "mounts",
            "message": f"Suspicious mount options found for {mount}: rw",
            "matched_indicator": None,
        })
    alerts.extend([
        {"level":"MEDIUM", "module":"mounts", "message":"Suspicious mount options found for /system/lib/example-a: noatime"},
        {"level":"MEDIUM", "module":"mounts", "message":"Suspicious mount options found for /system/lib/example-b: noatime"},
    ])
    (tmp_path / "alerts.json").write_text(json.dumps(alerts))
    (tmp_path / "info.json").write_text('{"mvt_version":"2026.11.2","date":"2026-11-06"}')
    (tmp_path / "pegasushunter_scan.json").write_text(json.dumps({"platform":"android","acquisition":"androidqf","indicator_status":"complete"}))

    report = analyze_results(tmp_path)
    text = render_text(report).lower()

    assert report["repetitive_mounts"]["read_write_mount_count"] == 7
    assert "rooted or custom-rom devices can have system partitions mounted read-write" in text
    assert "these alerts indicate possible system modification, not a spyware-indicator match" in text
    assert "confirm whether this matches the phone's intended setup" in text
    assert "not proof that the alerts are harmless" in text
    assert "this acquisition included 7 distinct read-write mount alerts for expert review" in text
    assert "no public spyware-indicator matches were found" in text


def test_real_mvt_results_group_repeated_mount_noise_and_expose_ioc_provenance() -> None:
    results_path = os.environ.get("PEGASUSHUNTER_REAL_ANDROIDQF_RESULTS")
    if results_path is None:
        pytest.skip("set PEGASUSHUNTER_REAL_ANDROIDQF_RESULTS to opt into a local real-device evidence test")
    results_dir = Path(results_path).expanduser()
    if not results_dir.is_dir():
        pytest.skip("configured local AndroidQF results directory does not exist")

    report = analyze_results(results_dir)
    text = render_text(report)

    assert report["heuristic_alert_count"] == 2037
    assert report["indicator_match_count"] == 0
    assert report["overall_assessment"] == "heuristics_need_review"
    assert report["module_alert_counts"]["mounts"] == 2008
    assert report["repetitive_mounts"]["repeated_noatime_count"] == 1994
    assert report["repetitive_mounts"]["read_write_mount_count"] == 7
    assert "1994 repeated noatime" in text
    assert "7 distinct read-write" in text
    assert report["coverage"]["ioc_collections"] == [
        "pegasus.stix2", "predator.stix2", "rcs.stix2", "malware.stix2",
        "kingspawn.stix2", "wyrmspy_dragonegg.stix2", "wintego_helios.stix2",
        "novispy.stix2", "eaglemsgspy.stix2", "candiru.stix2",
        "residentbat.stix2", "cellebrite.stix2", "morpheus.stix2",
        "btmob.stix2", "spyrtacus.stix2", "stalkerware.stix2",
    ]
    assert "no public spyware-indicator matches" in text.lower()
