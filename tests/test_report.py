from __future__ import annotations

import json
from pathlib import Path

import pytest

from pegasushunter.report import ReportError, analyze_results, render_text


def test_detected_artifact_is_explained_without_claiming_infection(tmp_path: Path) -> None:
    (tmp_path / "safari_history_detected.json").write_text(
        json.dumps([{"url": "https://example.invalid", "matched_indicator": {"name": "test"}}])
    )
    report = analyze_results(tmp_path)
    text = render_text(report)
    assert report["status"] == "evidence_found"
    assert report["finding_count"] == 1
    assert "potential spyware-related evidence" in text.lower()
    assert "does not prove" in text.lower()
    assert "Pegasus" not in report["families"]


def test_empty_results_are_not_described_as_clean(tmp_path: Path) -> None:
    (tmp_path / "info.json").write_text(json.dumps({"platform": "iOS", "version": "test"}))
    report = analyze_results(tmp_path)
    text = render_text(report).lower()
    assert report["status"] == "no_known_matches"
    assert "no known spyware matches were found" in text
    assert "does not prove the phone is clean" in text


def test_alerts_json_and_detected_file_duplicate_are_not_double_counted(tmp_path: Path) -> None:
    record = {"severity": "CRITICAL", "message": "Indicator match", "data": {"x": 1}}
    (tmp_path / "alerts.json").write_text(json.dumps([record]))
    (tmp_path / "sms_detected.json").write_text(json.dumps([record]))
    report = analyze_results(tmp_path)
    assert report["status"] == "evidence_found"
    assert report["finding_count"] == 1
    assert report["source"] == "alerts.json, sms_detected.json"


def test_empty_detected_file_is_not_a_finding(tmp_path: Path) -> None:
    (tmp_path / "cache_detected.json").write_text("[]")
    report = analyze_results(tmp_path)
    assert report["status"] == "no_known_matches"
    assert report["finding_count"] == 0


def test_nonexistent_results_directory_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ReportError, match="does not exist"):
        analyze_results(tmp_path / "missing")


@pytest.mark.parametrize("content", ["{bad json", "{\"unexpected\": true}", "[1, 2]"])
def test_malformed_or_unrecognized_alert_output_fails_closed(tmp_path: Path, content: str) -> None:
    (tmp_path / "alerts.json").write_text(content)
    with pytest.raises(ReportError):
        analyze_results(tmp_path)


def test_empty_alerts_json_does_not_hide_detected_files(tmp_path: Path) -> None:
    (tmp_path / "alerts.json").write_text("[]")
    (tmp_path / "sms_detected.json").write_text('[{"message":"finding"}]')
    report = analyze_results(tmp_path)
    assert report["status"] == "evidence_found"
    assert report["finding_count"] == 1


def test_summary_avoids_serializing_entire_sensitive_artifacts(tmp_path: Path) -> None:
    (tmp_path / "alerts.json").write_text(json.dumps([
        {"message": "Possible match", "data": {"private_message": "secret phrase", "phone_number": "555-0100"}}
    ]))
    report = analyze_results(tmp_path)
    assert report["finding_count"] == 1
    assert "private_message" not in json.dumps(report)
    assert "555-0100" not in json.dumps(report)


def test_safe_finding_fields_are_kept_but_free_text_is_not_emitted(tmp_path: Path) -> None:
    (tmp_path / "alerts.json").write_text(json.dumps([
        {"severity": "CRITICAL", "module": "SafariHistory", "message": "private content", "data": {}}
    ]))
    report = analyze_results(tmp_path)
    assert report["findings"] == [{"severity": "CRITICAL"}]


def test_campaign_labels_come_from_mvt_indicator_metadata(tmp_path: Path) -> None:
    (tmp_path / "alerts.json").write_text(json.dumps([
        {"title": "Spyware indicator", "data": {"matched_indicator": {"name": "Pegasus"}}}
    ]))
    report = analyze_results(tmp_path)
    assert report["families"] == ["Pegasus"]


def test_detected_files_are_read_alongside_alerts(tmp_path: Path) -> None:
    (tmp_path / "alerts.json").write_text("[]")
    (tmp_path / "sms_detected.json").write_text('[{"title":"Detected A"}]')
    (tmp_path / "cache_detected.json").write_text('[{"title":"Detected B"}]')
    report = analyze_results(tmp_path)
    assert report["status"] == "evidence_found"
    assert report["finding_count"] == 2


def test_indicator_freshness_metadata_and_explanation_are_exposed(tmp_path: Path) -> None:
    (tmp_path / "alerts.json").write_text(json.dumps([
        {"severity": "CRITICAL", "data": {"matched_indicator": {"name": "NSO Group Pegasus indicators"}}}
    ]))
    (tmp_path / "info.json").write_text('{"platform":"iOS","version":"2026.11.2"}')
    (tmp_path / "pegasushunter_scan.json").write_text(json.dumps({
        "indicator_status": "complete",
        "indicator_collections": ["NSO Group Pegasus indicators"],
        "indicator_updated_at": "2026-11-05T00:00:00+00:00",
    }))

    report = analyze_results(tmp_path)
    text = render_text(report).lower()

    assert report["families"] == ["NSO Group Pegasus indicators"]
    assert report["coverage"]["indicator_status"] == "complete"
    assert report["coverage"]["indicator_updated_at"] == "2026-11-05T00:00:00+00:00"
    assert "not confirmation of infection" in text
    assert "does not prove successful infection" in " ".join(report["limitations"]).lower()


def test_summarize_rejects_symlinked_detected_json(tmp_path: Path) -> None:
    import pytest

    from pegasushunter.report import ReportError

    outside=tmp_path/"private-detected.json"
    outside.write_text(json.dumps([{"message":"private finding"}]))
    results=tmp_path/"results"
    results.mkdir()
    (results/"info.json").write_text(json.dumps({"mvt_version":"test","date":"now","ioc_files":[]}))
    (results/"sms_detected.json").symlink_to(outside)
    with pytest.raises(ReportError,match="must not be symlinks"):
        analyze_results(results)


def test_summarize_rejects_symlinked_scan_metadata(tmp_path: Path) -> None:
    import pytest

    from pegasushunter.report import ReportError

    outside=tmp_path/"private-metadata.json"
    outside.write_text(json.dumps({"platform":"android","acquisition":"androidqf","androidqf_coverage":{"arbitrary":"private"}}))
    results=tmp_path/"results"
    results.mkdir()
    (results/"alerts.json").write_text("[]")
    (results/"info.json").write_text(json.dumps({"mvt_version":"test","date":"now","ioc_files":[]}))
    (results/"pegasushunter_scan.json").symlink_to(outside)
    with pytest.raises(ReportError,match="must not be symlinks"):
        analyze_results(results)


def test_summarize_rejects_symlinked_info_json(tmp_path: Path) -> None:
    import pytest

    from pegasushunter.report import ReportError

    outside=tmp_path/"private-info.json"
    outside.write_text(json.dumps({"mvt_version":"test","target_path":"/private/path"}))
    results=tmp_path/"results"
    results.mkdir()
    (results/"alerts.json").write_text("[]")
    (results/"info.json").symlink_to(outside)
    with pytest.raises(ReportError,match="must not be symlinks"):
        analyze_results(results)


def test_ioc_provenance_sanitizes_windows_paths_and_deduplicates(tmp_path: Path) -> None:
    (tmp_path/"alerts.json").write_text("[]")
    (tmp_path/"info.json").write_text(json.dumps({"mvt_version":"2026.11.2","ioc_files":[r"C:\Users\person\pegasus.stix2", "pegasus.stix2"]}))
    report=analyze_results(tmp_path)
    assert report["coverage"]["ioc_collections"] == ["pegasus.stix2"]
    assert "Users" not in json.dumps(report)


def test_androidqf_summary_does_not_follow_mvt_target_path(tmp_path: Path) -> None:
    outside=tmp_path/"untrusted-target"
    outside.mkdir()
    (outside/"command.log").write_text("Acquisition completed.\n")
    (outside/"acquisition.json").write_text(json.dumps({"module_results":[{"name":"private","status":"completed"}]}))
    results=tmp_path/"results"
    results.mkdir()
    (results/"alerts.json").write_text("[]")
    (results/"info.json").write_text(json.dumps({"mvt_version":"2026.11.2","date":"now","target_path":str(outside),"ioc_files":[]}))
    (results/"pegasushunter_scan.json").write_text(json.dumps({"platform":"android","acquisition":"androidqf","indicator_status":"complete"}))

    report=analyze_results(results)

    assert report["coverage"]["androidqf"] is None
    assert any("coverage snapshot is unavailable" in warning.lower() for warning in report["coverage_warnings"])


def test_androidqf_snapshot_sanitizes_control_characters_in_module_names(tmp_path: Path) -> None:
    (tmp_path/"alerts.json").write_text("[]")
    (tmp_path/"info.json").write_text(json.dumps({"mvt_version":"2026.11.2","date":"now","ioc_files":[]}))
    snapshot={"acquisition_completion":"complete","intrusion_logs":"collected","module_results":[{"name":"‮private-module","status":"completed"}]}
    (tmp_path/"pegasushunter_scan.json").write_text(json.dumps({"platform":"android","acquisition":"androidqf","indicator_status":"complete","androidqf_coverage":snapshot}))
    report=analyze_results(tmp_path)
    assert report["coverage"]["androidqf"]["module_results"] == [{"name":"module-1","status":"completed"}]


def test_androidqf_snapshot_rejects_non_string_module_values(tmp_path: Path) -> None:
    (tmp_path/"alerts.json").write_text("[]")
    (tmp_path/"info.json").write_text(json.dumps({"mvt_version":"2026.11.2","date":"now","ioc_files":[]}))
    snapshot={"acquisition_completion":[],"intrusion_logs":{},"module_results":[{"name":{},"status":[]}]}
    (tmp_path/"pegasushunter_scan.json").write_text(json.dumps({"platform":"android","acquisition":"androidqf","indicator_status":"complete","androidqf_coverage":snapshot}))
    report=analyze_results(tmp_path)
    assert report["coverage"]["androidqf"]["acquisition_completion"] == "unverified"
    assert report["coverage"]["androidqf"]["intrusion_logs"] == "not_collected"
    assert report["coverage"]["androidqf"]["module_results"] == [{"name":"module-1","status":"unknown"}]


def test_androidqf_snapshot_rejects_backslash_module_path(tmp_path: Path) -> None:
    (tmp_path/"alerts.json").write_text("[]")
    (tmp_path/"info.json").write_text(json.dumps({"mvt_version":"2026.11.2","date":"now","ioc_files":[]}))
    snapshot={"acquisition_completion":"complete","intrusion_logs":"collected","module_results":[{"name":"private\\device","status":"completed"}]}
    (tmp_path/"pegasushunter_scan.json").write_text(json.dumps({"platform":"android","acquisition":"androidqf","indicator_status":"complete","androidqf_coverage":snapshot}))
    report=analyze_results(tmp_path)
    assert report["coverage"]["androidqf"]["module_results"] == [{"name":"module-1","status":"completed"}]


def test_androidqf_snapshot_is_sanitized_before_rendering(tmp_path: Path) -> None:
    (tmp_path / "alerts.json").write_text("[]")
    (tmp_path / "info.json").write_text(json.dumps({"mvt_version":"2026.11.2","date":"now","ioc_files":[]}))
    malicious={
        "acquisition_completion":"complete", "intrusion_logs":"collected",
        "module_results":[
            {"name":"/private/device/path", "status":"completed", "error":"secret"},
            {"name":"bugreport", "status":"partial", "error":"private detail"},
        ],
        "backup_size_bytes":5, "backup_present":True,
        "bugreport_present":True, "dumpsys_present":True,
        "process_list_present":True, "services_list_present":True,
        "acquisition_log_present":True, "acquisition_metadata_present":True,
        "intrusion_log_file_count":1,
        "limitations":["/private/device/path"],
        "arbitrary":"private raw data",
    }
    (tmp_path / "pegasushunter_scan.json").write_text(json.dumps({
        "platform":"android","acquisition":"androidqf","indicator_status":"complete",
        "androidqf_coverage":malicious,
    }))
    report=analyze_results(tmp_path)
    text=render_text(report)
    serialized=json.dumps(report)
    assert "/private/device/path" not in serialized
    assert "private detail" not in serialized
    assert "private raw data" not in serialized
    assert report["coverage"]["androidqf"]["module_results"] == [
        {"name":"module-1","status":"completed"},
        {"name":"bugreport","status":"partial"},
    ]
    assert "1 completed, 1 partial/failed" in text


def test_mvt_routine_missing_androidqf_artifact_logs_are_not_failure_warnings(tmp_path: Path) -> None:
    (tmp_path / "info.json").write_text(json.dumps({
        "mvt_version": "2026.11.2", "date": "now", "ioc_files": []
    }))
    (tmp_path / "command.log").write_text(
        "ERROR - packages.json file not found in this androidqf bundle. Possibly malformed?\n"
        "INFO - getprop.txt file not found\n"
        "WARNING - Could not find getprop.txt file. Some timestamps may be incorrect.\n"
        "WARNING - Skipping bugreport modules as no bugreport.zip found in AndroidQF data.\n"
        "WARNING - Skipping backup modules as no backup.ab found in AndroidQF data.\n"
        "INFO - Analysis finished\n"
    )
    (tmp_path / "pegasushunter_scan.json").write_text(json.dumps({
        "platform": "android", "acquisition": "androidqf", "indicator_status": "complete",
        "androidqf_coverage": {
            "acquisition_completion": "unverified", "acquisition_log_present": True,
            "acquisition_metadata_present": False, "bugreport_present": False,
            "dumpsys_present": False, "process_list_present": False,
            "services_list_present": False, "backup_present": False, "backup_size_bytes": 0,
            "module_results": [], "intrusion_logs": "not_collected", "intrusion_log_file_count": 0,
            "limitations": ["No Intrusion Logs were included in this acquisition."],
        },
    }))

    report = analyze_results(tmp_path)

    assert not any("command log reports an error" in warning.lower() for warning in report["coverage_warnings"])
    assert any("acquisition completion could not be verified" in warning.lower() for warning in report["coverage_warnings"])
    assert report["overall_assessment"] == "limited_no_match"


def test_mvt_real_failure_is_still_reported_alongside_routine_missing_artifact(tmp_path: Path) -> None:
    (tmp_path / "info.json").write_text(json.dumps({
        "mvt_version": "2026.11.2", "date": "now", "ioc_files": []
    }))
    (tmp_path / "command.log").write_text(
        "ERROR - packages.json file not found in this androidqf bundle. Possibly malformed?\n"
        "ERROR - Module failed; skipped after malformed acquisition metadata.\n"
    )
    (tmp_path / "pegasushunter_scan.json").write_text(json.dumps({
        "platform": "android", "acquisition": "androidqf", "indicator_status": "complete",
    }))

    report = analyze_results(tmp_path)

    assert any("command log reports an error or failed module" in warning.lower() for warning in report["coverage_warnings"])


def test_mvt_failure_on_same_line_as_routine_missing_artifact_is_not_hidden(tmp_path: Path) -> None:
    (tmp_path / "info.json").write_text(json.dumps({
        "mvt_version": "2026.11.2", "date": "now", "ioc_files": []
    }))
    (tmp_path / "command.log").write_text(
        "ERROR - packages.json file not found in this androidqf bundle; Module failed; skipped\n"
    )

    report = analyze_results(tmp_path)

    assert any("command log reports an error or failed module" in warning.lower() for warning in report["coverage_warnings"])


def test_mvt_source_provenance_lists_each_sparse_result_file_once(tmp_path: Path) -> None:
    (tmp_path / "info.json").write_text(json.dumps({
        "mvt_version": "2026.11.2", "date": "now", "ioc_files": []
    }))
    (tmp_path / "command.log").write_text("Analysis finished\n")

    report = analyze_results(tmp_path)

    assert report["source"] == "info.json, command.log"


def test_report_redacts_local_result_and_input_paths(tmp_path: Path) -> None:
    private_input = "/private/subject/device-export.zip"
    (tmp_path / "alerts.json").write_text("[]")
    (tmp_path / "info.json").write_text(json.dumps({
        "mvt_version": "2026.11.2", "date": "now", "ioc_files": [],
        "target_path": private_input,
        "command": f"mvt-android check-androidqf {private_input}",
    }))

    report = analyze_results(tmp_path)
    serialized = json.dumps(report)

    assert private_input not in serialized
    assert str(tmp_path.resolve()) not in serialized
    assert "results_directory" not in report["coverage"]
    assert "command" not in report["coverage"]["mvt_metadata"]


def test_androidqf_coverage_survives_summarize_from_scan_metadata(tmp_path: Path) -> None:
    (tmp_path / "alerts.json").write_text("[]")
    (tmp_path / "info.json").write_text(json.dumps({
        "mvt_version":"2026.11.2", "date":"now", "target_path":"/private/acquisition.zip", "ioc_files":[]
    }))
    coverage={
        "acquisition_completion":"partial", "acquisition_metadata_present":True,
        "module_results":[{"name":"bugreport","status":"partial"}],
        "backup_present":True,"backup_size_bytes":3608,"bugreport_present":True,
        "dumpsys_present":True,"process_list_present":True,"services_list_present":True,
        "acquisition_log_present":True,"intrusion_logs":"not_collected","intrusion_log_file_count":0,
        "limitations":["Android app data and diagnostic logs can be unavailable or inconsistent across devices."],
    }
    (tmp_path / "pegasushunter_scan.json").write_text(json.dumps({
        "platform":"android", "acquisition":"androidqf", "indicator_status":"complete",
        "androidqf_coverage":coverage,
    }))
    report=analyze_results(tmp_path)
    text=render_text(report)
    assert report["coverage"]["androidqf"] == coverage
    (tmp_path/"pegasushunter_report.json").write_text(json.dumps(report))
    assert json.loads((tmp_path/"pegasushunter_report.json").read_text())["coverage"]["androidqf"] == coverage
    assert report["coverage_level"] == "limited"
    assert "1 partial/failed" in text


def test_real_mvt_run_without_aggregate_alerts_is_not_misreported_as_failed(tmp_path: Path) -> None:
    (tmp_path / "info.json").write_text(json.dumps({
        "target_path": "/private/device-backup",
        "mvt_version": "2026.11.2",
        "date": "2026-11-05T17:00:00",
        "ioc_files": ["/private/iocs/pegasus.stix2"],
    }))
    (tmp_path / "sms.json").write_text("[]")
    (tmp_path / "backup_info.json").write_text(json.dumps({"Device Name": "private device name"}))
    (tmp_path / "command.log").write_text("INFO MVT extraction complete\n")
    (tmp_path / "pegasushunter_scan.json").write_text(json.dumps({
        "indicator_status": "complete",
        "indicator_collections": ["NSO Group Pegasus indicators"],
        "indicator_updated_at": "2026-11-05T16:00:00+00:00",
    }))

    report = analyze_results(tmp_path)
    text = render_text(report).lower()

    assert report["coverage_level"] == "results_present"
    assert report["coverage"]["mvt_metadata"]["mvt_version"] == "2026.11.2"
    assert "no known spyware matches were found" in text
    assert "missing; this might not be a completed" not in text
    assert "private device name" not in text
    assert "does not prove the phone is clean" in text
