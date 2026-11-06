from __future__ import annotations

import json
import os
import subprocess
import sys
import zipfile

from pegasushunter.cli import main


def test_summarize_command_prints_plain_language_warning(tmp_path, capsys) -> None:
    (tmp_path / "info.json").write_text(json.dumps({"platform": "iOS"}))
    assert main(["summarize", str(tmp_path)]) == 0
    output = capsys.readouterr().out.lower()
    assert "no known spyware matches were found" in output
    assert "does not prove the phone is clean" in output


def test_json_summary_is_machine_readable(tmp_path, capsys) -> None:
    (tmp_path / "sms_detected.json").write_text('[{"matched_indicator": {"name": "sample"}}]')
    assert main(["summarize", str(tmp_path), "--format", "json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "evidence_found"
    assert result["finding_count"] == 1


def test_scan_fails_before_creating_output_if_mvt_missing(tmp_path, monkeypatch, capsys) -> None:
    from pegasushunter import cli
    source = tmp_path / "backup"
    source.mkdir()
    output = tmp_path / "results"
    monkeypatch.setattr(cli, "_find_mvt", lambda _: None)
    assert main(["scan", "ios", str(source), "--output", str(output)]) == 2
    assert not output.exists()
    assert "mvt-ios is not installed" in capsys.readouterr().err


def test_scan_finds_mvt_in_active_python_environment_when_not_on_path(tmp_path, monkeypatch, capsys) -> None:
    from pegasushunter import cli
    source = tmp_path / "acquisition"
    source.mkdir()
    (source / "command.log").write_text("acquisition completed successfully\n")
    output = tmp_path / "results"
    fake = tmp_path / "venv" / "bin" / "mvt-android"
    fake.parent.mkdir(parents=True)
    fake.write_text("#!/bin/sh\n")
    fake.chmod(0o755)
    monkeypatch.setattr(cli.shutil, "which", lambda _: None)
    monkeypatch.setattr(cli.sys, "executable", str(tmp_path / "venv" / "bin" / "python"))
    monkeypatch.setattr(cli, "analyze_results", lambda path: {
        "coverage": {}, "coverage_warnings": [], "coverage_level": "results_present",
        "limitations": [], "indicator_match_count": 0, "heuristic_alert_count": 0,
        "indicator_counts": {}, "module_alert_counts": {}, "unattributed_finding_count": 0,
        "families": [], "plain_summary": "No known matches.", "overall_assessment": "no_known_matches",
        "status": "no_known_matches", "finding_count": 0, "source": None,
        "repetitive_mounts": None,
    })
    captured = {}
    def fake_run(command, check, env):
        captured["command"] = command
        captured["env"] = env
        (output / "alerts.json").write_text("[]")
        (output / "info.json").write_text(json.dumps({"mvt_version":"test","date":"now","target_path":str(source),"ioc_files":[]}))
        return type("Completed", (), {"returncode":0})()
    assert cli._run_scan(type("Args", (), {
        "source": source, "output": output, "platform": "android", "acquisition": "androidqf",
        "ioc": [], "indicator_cache": None,
    })(), runner=fake_run) == 0
    assert captured["command"][0] == str(fake)
    assert "AndroidQF acquisition metadata/logs show its collected modules completed" in capsys.readouterr().out


def test_androidqf_directory_metadata_can_verify_complete_acquisition(tmp_path) -> None:
    from pegasushunter.cli import _androidqf_coverage

    source=tmp_path/"aqf"
    source.mkdir()
    (source/"acquisition.json").write_text(json.dumps({
        "module_results":[{"name":"backup","status":"completed"},{"name":"bugreport","status":"completed"}]
    }))
    (source/"backup.ab").write_bytes(b"abc")
    (source/"bugreport.zip").write_bytes(b"zip")
    coverage=_androidqf_coverage(source)
    assert coverage["acquisition_completion"] == "complete"
    assert coverage["acquisition_metadata_present"] is True
    assert coverage["backup_size_bytes"] == 3
    assert coverage["bugreport_present"] is True
    assert coverage["module_results"] == [
        {"name":"backup","status":"completed"},
        {"name":"bugreport","status":"completed"},
    ]


def test_androidqf_fatal_log_cannot_be_overridden_by_complete_metadata(tmp_path) -> None:
    from pegasushunter.cli import _androidqf_coverage

    source = tmp_path / "aqf"
    source.mkdir()
    (source / "command.log").write_text("FATAL ERROR: acquisition interrupted\nAcquisition completed.\n")
    (source / "acquisition.json").write_text(json.dumps({
        "module_results": [{"name": "backup", "status": "completed"}],
    }))

    coverage = _androidqf_coverage(source)

    assert coverage["acquisition_completion"] == "failed"


def test_androidqf_failed_metadata_status_is_not_cleared_by_completion_log(tmp_path) -> None:
    from pegasushunter.cli import _androidqf_coverage

    source = tmp_path / "aqf"
    source.mkdir()
    (source / "command.log").write_text("Acquisition completed.\n")
    (source / "acquisition.json").write_text(json.dumps({
        "module_results": [{"name": "backup", "status": "failed"}],
    }))

    assert _androidqf_coverage(source)["acquisition_completion"] == "failed"


def test_androidqf_failed_module_is_not_downgraded_by_partial_module(tmp_path) -> None:
    from pegasushunter.cli import _androidqf_coverage

    source = tmp_path / "aqf"
    source.mkdir()
    (source / "acquisition.json").write_text(json.dumps({
        "module_results": [
            {"name": "backup", "status": "failed"},
            {"name": "bugreport", "status": "partial"},
        ],
    }))

    assert _androidqf_coverage(source)["acquisition_completion"] == "failed"


def test_androidqf_non_string_module_status_is_rejected(tmp_path) -> None:
    import pytest

    from pegasushunter.cli import _androidqf_coverage
    from pegasushunter.report import ReportError

    source = tmp_path / "aqf"
    source.mkdir()
    (source / "acquisition.json").write_text(json.dumps({
        "module_results": [{"name": "backup", "status": []}],
    }))

    with pytest.raises(ReportError, match="unknown module status"):
        _androidqf_coverage(source)


def test_androidqf_module_results_exclude_raw_error_details(tmp_path) -> None:
    from pegasushunter.cli import _androidqf_coverage

    source=tmp_path/"aqf"
    source.mkdir()
    (source/"acquisition.json").write_text(json.dumps({
        "module_results":[
            {"name":"bugreport","status":"partial","error":"secret private file path /phone/data"},
            {"name":"/private/person","status":"completed","error":"secret"},
        ]
    }))
    coverage=_androidqf_coverage(source)
    assert coverage["acquisition_completion"] == "partial"
    assert coverage["module_results"] == [
        {"name":"bugreport","status":"partial"},
        {"name":"module-2","status":"completed"},
    ]
    assert "/phone/data" not in json.dumps(coverage)


def test_androidqf_directory_rejects_symlinked_sensitive_artifact(tmp_path) -> None:
    import pytest

    from pegasushunter.cli import _androidqf_coverage
    from pegasushunter.report import ReportError

    source=tmp_path/"aqf"
    source.mkdir()
    (source/"backup.ab").symlink_to(tmp_path/"elsewhere.ab")
    with pytest.raises(ReportError,match="symlinked AndroidQF artifact"):
        _androidqf_coverage(source)


def test_androidqf_directory_does_not_claim_symlinked_command_log(tmp_path) -> None:
    from pegasushunter.cli import _androidqf_coverage

    source=tmp_path/"aqf"
    source.mkdir()
    target=tmp_path/"external.log"
    target.write_text("Acquisition completed.\n")
    (source/"command.log").symlink_to(target)
    coverage=_androidqf_coverage(source)
    assert coverage["acquisition_log_present"] is False
    assert coverage["acquisition_completion"] == "unverified"


def test_androidqf_directory_rejects_duplicate_backup_artifacts(tmp_path) -> None:
    import pytest

    from pegasushunter.cli import _androidqf_coverage
    from pegasushunter.report import ReportError

    source=tmp_path/"aqf"
    (source/"one").mkdir(parents=True)
    (source/"two").mkdir()
    (source/"one"/"backup.ab").write_bytes(b"1")
    (source/"two"/"backup.ab").write_bytes(b"22")
    with pytest.raises(ReportError,match=r"multiple backup\.ab"):
        _androidqf_coverage(source)


def test_androidqf_directory_rejects_duplicate_bugreport_artifacts(tmp_path) -> None:
    import pytest

    from pegasushunter.cli import _androidqf_coverage
    from pegasushunter.report import ReportError

    source=tmp_path/"aqf"
    (source/"one").mkdir(parents=True)
    (source/"two").mkdir()
    (source/"one"/"bugreport.zip").write_bytes(b"1")
    (source/"two"/"bugreport.zip").write_bytes(b"2")
    with pytest.raises(ReportError,match=r"multiple bugreport\.zip"):
        _androidqf_coverage(source)


def test_androidqf_directory_rejects_duplicate_services_artifacts(tmp_path) -> None:
    import pytest

    from pegasushunter.cli import _androidqf_coverage
    from pegasushunter.report import ReportError

    source=tmp_path/"aqf"
    (source/"one").mkdir(parents=True)
    (source/"two").mkdir()
    (source/"one"/"services.txt").write_text("one")
    (source/"two"/"services.txt").write_text("two")
    with pytest.raises(ReportError,match=r"multiple services\.txt"):
        _androidqf_coverage(source)


def test_androidqf_directory_rejects_duplicate_acquisition_json(tmp_path) -> None:
    import pytest

    from pegasushunter.cli import _androidqf_coverage
    from pegasushunter.report import ReportError

    source=tmp_path/"aqf"
    (source/"nested").mkdir(parents=True)
    content=json.dumps({"module_results":[{"name":"backup","status":"completed"}]})
    (source/"acquisition.json").write_text(content)
    (source/"nested"/"acquisition.json").write_text(content)
    with pytest.raises(ReportError,match=r"multiple acquisition\.json"):
        _androidqf_coverage(source)


def test_androidqf_coverage_records_processes_txt_artifact(tmp_path) -> None:
    from pegasushunter.cli import _androidqf_coverage

    source=tmp_path/"aqf"
    source.mkdir()
    (source/"processes.txt").write_text("process info")
    assert _androidqf_coverage(source)["process_list_present"] is True


def test_androidqf_coverage_ignores_symlinked_intrusion_log(tmp_path) -> None:
    from pegasushunter.cli import _androidqf_coverage

    source=tmp_path/"aqf"
    intrusion=source/"intrusion_logs"
    intrusion.mkdir(parents=True)
    outside=tmp_path/"outside.txt"
    outside.write_text("not an acquired log")
    (intrusion/"linked.txt").symlink_to(outside)
    coverage=_androidqf_coverage(source)
    assert coverage["intrusion_logs"] == "not_collected"
    assert coverage["intrusion_log_file_count"] == 0


def test_androidqf_partial_zip_metadata_is_not_called_complete(tmp_path, monkeypatch) -> None:
    import zipfile

    from pegasushunter import cli

    source = tmp_path / "partial.zip"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("acquisition.json", json.dumps({
            "module_results": [
                {"name":"backup", "status":"completed"},
                {"name":"bugreport", "status":"partial", "error":"permission denied"},
            ]
        }))
        archive.writestr("command.log", "Acquisition finalized with 1 incomplete module(s).\n")
        archive.writestr("backup.ab", b"backup")
        archive.writestr("bugreport.zip", b"report")
    output = tmp_path / "results"
    monkeypatch.setattr(cli.shutil, "which", lambda _: "/usr/bin/mvt-android")

    def fake_run(command, check, env):
        output.mkdir(exist_ok=True)
        (output / "alerts.json").write_text("[]")
        (output / "info.json").write_text(json.dumps({
            "mvt_version":"2026.11.2", "date":"2026-11-06", "target_path":str(source), "ioc_files":[]
        }))
        return type("Completed", (), {"returncode":0})()

    args=type("Args", (), {"source":source,"output":output,"platform":"android","acquisition":"androidqf","ioc":[],"indicator_cache":None})()
    assert cli._run_scan(args, runner=fake_run)==0
    report=json.loads((output/"pegasushunter_report.json").read_text())
    assert report["coverage"]["androidqf"]["acquisition_completion"] == "partial"
    assert report["coverage_level"] == "limited"
    assert any("module" in w.lower() and "partial" in w.lower() for w in report["coverage_warnings"])


def test_encrypted_androidqf_archive_is_rejected_before_mvt(tmp_path, monkeypatch) -> None:
    import pytest

    from pegasushunter import cli
    from pegasushunter.report import ReportError

    source=tmp_path/"encrypted.zip.age"
    source.write_bytes(b"encrypted")
    args=type("Args",(),{"source":source,"output":tmp_path/"results","platform":"android","acquisition":"androidqf","ioc":[],"indicator_cache":None})()
    monkeypatch.setattr(cli,"_find_mvt",lambda _:"/usr/bin/mvt-android")
    with pytest.raises(ReportError,match="decrypted with age"):
        cli._run_scan(args,runner=lambda *a,**k: (_ for _ in ()).throw(AssertionError("must not run MVT")))
    assert not (tmp_path/"results").exists()


def test_androidqf_scan_persists_source_coverage_and_summarize_keeps_it(tmp_path, monkeypatch) -> None:
    import zipfile

    from pegasushunter import cli
    from pegasushunter.report import analyze_results

    source=tmp_path/"aqf.zip"
    with zipfile.ZipFile(source,"w") as archive:
        archive.writestr("acquisition.json",json.dumps({"module_results":[{"name":"bugreport","status":"partial"}]}))
        archive.writestr("command.log","Acquisition finalized with 1 incomplete module(s).\n")
        archive.writestr("bugreport.zip",b"report")
    output=tmp_path/"results"
    monkeypatch.setattr(cli,"_find_mvt",lambda _:"/usr/bin/mvt-android")
    def fake_run(command,check,env):
        (output/"alerts.json").write_text("[]")
        (output/"info.json").write_text(json.dumps({"mvt_version":"2026.11.2","date":"now","target_path":str(source),"ioc_files":[]}))
        return type("Completed",(),{"returncode":0})()
    args=type("Args",(),{"source":source,"output":output,"platform":"android","acquisition":"androidqf","ioc":[],"indicator_cache":None})()
    assert cli._run_scan(args,runner=fake_run)==0
    report=analyze_results(output)
    assert report["coverage_level"] == "limited"
    assert report["coverage"]["androidqf"]["acquisition_completion"] == "partial"
    assert report["coverage"]["androidqf"]["module_results"] == [{"name":"bugreport","status":"partial"}]


def test_androidqf_zip_input_is_scanned_and_reports_archive_artifacts(tmp_path, monkeypatch, capsys) -> None:
    import zipfile

    from pegasushunter import cli

    source = tmp_path / "acquisition.zip"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("run/backup.ab", b"android-backup")
        archive.writestr("run/bugreport.zip", b"bugreport")
        archive.writestr("run/command.log", "Acquisition completed successfully\n")
        archive.writestr("run/intrusion_logs/events.txt", "{}\n")
    output = tmp_path / "results"
    monkeypatch.setattr(cli.shutil, "which", lambda _: "/usr/bin/mvt-android")
    captured = {}

    def fake_run(command, check, env):
        captured["command"] = command
        output.mkdir(exist_ok=True)
        (output / "alerts.json").write_text("[]")
        (output / "info.json").write_text(json.dumps({
            "mvt_version": "2026.11.2", "date": "2026-11-06",
            "target_path": str(source), "ioc_files": [],
        }))
        (output / "command.log").write_text("MVT extraction complete\n")
        return type("Completed", (), {"returncode": 0})()

    args = type("Args", (), {
        "source": source, "output": output, "platform": "android",
        "acquisition": "androidqf", "ioc": [], "indicator_cache": None,
    })()
    assert cli._run_scan(args, runner=fake_run) == 0
    assert captured["command"][-1] == str(source.resolve())
    metadata = json.loads((output / "pegasushunter_scan.json").read_text())
    assert metadata["androidqf_coverage"]["acquisition_completion"] == "complete"
    source.unlink()
    report = json.loads((output / "pegasushunter_report.json").read_text())
    coverage = report["coverage"]["androidqf"]
    assert coverage["acquisition_completion"] == "complete"
    assert coverage["acquisition_metadata_present"] is False
    assert coverage["acquisition_log_present"] is True
    assert coverage["backup_present"] is True
    assert coverage["bugreport_present"] is True
    assert coverage["intrusion_logs"] == "collected"


def test_androidqf_rejects_malformed_module_statuses(tmp_path) -> None:
    import pytest

    from pegasushunter.cli import _androidqf_coverage
    from pegasushunter.report import ReportError

    source=tmp_path/"aqf"
    source.mkdir()
    (source/"acquisition.json").write_text(json.dumps({"module_results":[{"name":"backup","status":"done"}]}))
    with pytest.raises(ReportError,match="unknown module status"):
        _androidqf_coverage(source)


def test_androidqf_rejects_acquisition_json_with_no_module_results(tmp_path) -> None:
    import pytest

    from pegasushunter.cli import _androidqf_coverage
    from pegasushunter.report import ReportError

    source=tmp_path/"aqf"
    source.mkdir()
    (source/"acquisition.json").write_text(json.dumps({"status":"complete"}))
    with pytest.raises(ReportError,match="nonempty list"):
        _androidqf_coverage(source)


def test_androidqf_rejects_missing_or_duplicate_module_names(tmp_path) -> None:
    import pytest

    from pegasushunter.cli import _androidqf_coverage
    from pegasushunter.report import ReportError

    source=tmp_path/"aqf"
    source.mkdir()
    for rows in ([{"status":"completed"}], [{"name":"backup","status":"completed"},{"name":"backup","status":"failed"}]):
        (source/"acquisition.json").write_text(json.dumps({"module_results":rows}))
        with pytest.raises(ReportError,match="missing or duplicate module names"):
            _androidqf_coverage(source)


def test_androidqf_rejects_empty_module_results_metadata(tmp_path) -> None:
    import pytest

    from pegasushunter.cli import _androidqf_coverage
    from pegasushunter.report import ReportError

    source=tmp_path/"aqf"
    source.mkdir()
    (source/"acquisition.json").write_text(json.dumps({"module_results":[]}))
    with pytest.raises(ReportError,match="nonempty list"):
        _androidqf_coverage(source)


def test_androidqf_zip_rejects_duplicate_backup_artifacts(tmp_path) -> None:
    import zipfile

    import pytest

    from pegasushunter.cli import _androidqf_coverage
    from pegasushunter.report import ReportError

    source=tmp_path/"duplicate-backup.zip"
    with zipfile.ZipFile(source,"w") as archive:
        archive.writestr("a/backup.ab",b"one")
        archive.writestr("b/backup.ab",b"two")
    with pytest.raises(ReportError,match=r"multiple backup\.ab"):
        _androidqf_coverage(source)


def test_androidqf_zip_rejects_duplicate_acquisition_metadata(tmp_path) -> None:
    import zipfile

    import pytest

    from pegasushunter.cli import _androidqf_coverage
    from pegasushunter.report import ReportError

    source=tmp_path/"duplicate.zip"
    with zipfile.ZipFile(source,"w") as archive:
        archive.writestr("acquisition.json",json.dumps({"module_results":[]}))
        archive.writestr("nested/acquisition.json",json.dumps({"module_results":[]}))
    with pytest.raises(ReportError,match=r"multiple acquisition\.json"):
        _androidqf_coverage(source)


def test_androidqf_coverage_rejects_encrypted_zip_entry_flag(tmp_path, monkeypatch) -> None:
    import zipfile

    import pytest

    from pegasushunter import cli
    from pegasushunter.report import ReportError

    source=tmp_path/"encrypted.zip"
    with zipfile.ZipFile(source,"w") as archive:
        archive.writestr("backup.ab",b"backup")
    original=zipfile.ZipFile.infolist
    def encrypted_infolist(archive):
        entries=original(archive)
        entries[0].flag_bits |= 0x1
        return entries
    monkeypatch.setattr(zipfile.ZipFile,"infolist",encrypted_infolist)
    with pytest.raises(ReportError,match="encrypted entries"):
        cli._androidqf_coverage(source)


def test_androidqf_coverage_reads_real_androidqf_zip_metadata_and_logs(tmp_path) -> None:
    import zipfile

    from pegasushunter.cli import _androidqf_coverage

    source=tmp_path/"saved.zip"
    with zipfile.ZipFile(source,"w") as archive:
        archive.writestr("acquisition.json",json.dumps({"module_results":[{"name":"bugreport","status":"completed"}]}))
        archive.writestr("command.log","Acquisition completed.\n")
        archive.writestr("backup.ab",b"12345")
        archive.writestr("dumpsys.txt","details")
        archive.writestr("intrusion_logs/event.txt","event")
    coverage=_androidqf_coverage(source)
    assert coverage["acquisition_completion"]=="complete"
    assert coverage["backup_present"] is True
    assert coverage["backup_size_bytes"] == 5
    assert coverage["bugreport_present"] is False
    assert coverage["dumpsys_present"] is True
    assert coverage["intrusion_log_file_count"]==1


def test_scan_rejects_nonempty_output_directory_before_running_mvt(tmp_path, monkeypatch, capsys) -> None:
    from pegasushunter import cli
    source = tmp_path / "backup"
    source.mkdir()
    output = tmp_path / "results"
    output.mkdir()
    (output / "old.txt").write_text("preserve")
    monkeypatch.setattr(cli.shutil, "which", lambda _: "/usr/bin/mvt-ios")
    assert main(["scan", "ios", str(source), "--output", str(output)]) == 2
    assert (output / "old.txt").read_text() == "preserve"
    assert "new or empty" in capsys.readouterr().err


def test_scan_invokes_mvt_with_privacy_options_and_summarizes(tmp_path, monkeypatch, capsys) -> None:
    from pegasushunter import cli
    source = tmp_path / "backup"
    source.mkdir()
    output = tmp_path / "results"
    captured = {}
    monkeypatch.setattr(cli.shutil, "which", lambda _: "/usr/bin/mvt-ios")

    def fake_run(command, check, env):
        captured["command"] = command
        captured["env"] = env
        (output / "alerts.json").write_text("[]")
        return type("Completed", (), {"returncode": 0})()

    assert cli._run_scan(type("Args", (), {
        "source": source, "output": output, "platform": "ios",
        "acquisition": "backup", "ioc": [],
    })(), runner=fake_run) == 0
    assert captured["command"] == [
        "/usr/bin/mvt-ios", "check-backup", "--output", str(output.resolve()), str(source.resolve())
    ]
    assert captured["env"]["MVT_NETWORK_ACCESS_ALLOWED"] == "false"
    assert "does not prove the phone is clean" in capsys.readouterr().out.lower()


def test_android_filesystem_mode_is_explicitly_unsupported(tmp_path, monkeypatch, capsys) -> None:
    from pegasushunter import cli
    source = tmp_path / "image"
    source.mkdir()
    output = tmp_path / "results"
    monkeypatch.setattr(cli.shutil, "which", lambda _: "/usr/bin/mvt-android")
    assert main(["scan", "android", str(source), "--output", str(output), "--acquisition", "filesystem"]) == 2
    assert not output.exists()
    assert "not supported" in capsys.readouterr().err


def test_ios_androidqf_mode_is_rejected_before_creating_output(tmp_path, monkeypatch, capsys) -> None:
    from pegasushunter import cli

    source = tmp_path / "androidqf"
    source.mkdir()
    (source / "command.log").write_text("Acquisition completed.\n")
    output = tmp_path / "results"
    monkeypatch.setattr(cli, "_find_mvt", lambda _: "/usr/bin/mvt-ios")

    assert main(["scan", "ios", str(source), "--acquisition", "androidqf", "--output", str(output)]) == 2

    assert not output.exists()
    assert "AndroidQF is supported only for Android" in capsys.readouterr().err


def test_mvt_failure_does_not_print_verdict_and_preserves_partial_output(tmp_path, monkeypatch, capsys) -> None:
    from pegasushunter import cli
    source = tmp_path / "backup"
    source.mkdir()
    output = tmp_path / "results"
    monkeypatch.setattr(cli.shutil, "which", lambda _: "/usr/bin/mvt-ios")

    def fake_run(command, check, env):
        (output / "partial.json").write_text("partial evidence")
        return type("Completed", (), {"returncode": 3})()

    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    assert main(["scan", "ios", str(source), "--output", str(output)]) == 3
    output_text = capsys.readouterr().out.lower()
    assert "no verdict was generated" in output_text
    assert "phone is clean" not in output_text
    assert (output / "partial.json").read_text() == "partial evidence"
    partial_report=json.loads((output / "pegasushunter_partial.json").read_text())
    assert partial_report["mvt_returncode"] == 3
    assert partial_report["verdict_generated"] is False
    assert partial_report["status"] == "mvt_failed"
    assert partial_report["scan_metadata"]["platform"] == "ios"
    assert partial_report["scan_metadata"]["acquisition"] == "backup"
    scan_metadata = json.loads((output / "pegasushunter_scan.json").read_text())
    assert scan_metadata["acquisition"] == "backup"


def test_androidqf_scan_failure_retains_sanitized_source_snapshot(tmp_path, monkeypatch, capsys) -> None:
    from pegasushunter import cli

    source=tmp_path/"aqf"
    source.mkdir()
    (source/"command.log").write_text("Acquisition completed. private identifier SECRET-ID\n")
    (source/"acquisition.json").write_text(json.dumps({"module_results":[{"name":"backup","status":"completed","error":"private /data/path"}]}))
    output=tmp_path/"results"
    monkeypatch.setattr(cli,"_find_mvt",lambda _:"/usr/bin/mvt-android")
    def fail_mvt(command,check,env):
        (output/"partial.json").write_text("partial")
        return type("Completed",(),{"returncode":4})()
    args=type("Args",(),{"source":source,"output":output,"platform":"android","acquisition":"androidqf","ioc":[],"indicator_cache":None})()
    assert cli._run_scan(args,runner=fail_mvt)==4
    partial=json.loads((output/"pegasushunter_partial.json").read_text())
    snapshot=partial["scan_metadata"]["androidqf_coverage"]
    serialized=json.dumps(partial)
    assert snapshot["acquisition_completion"] == "complete"
    assert snapshot["module_results"] == [{"name":"backup","status":"completed"}]
    assert "SECRET-ID" not in serialized
    assert "private /data/path" not in serialized
    assert "no verdict was generated" in capsys.readouterr().out.lower()


def test_androidqf_coverage_snapshot_does_not_store_raw_log_content(tmp_path) -> None:
    from pegasushunter.cli import _androidqf_coverage

    source=tmp_path/"aqf"
    source.mkdir()
    (source/"command.log").write_text("Acquisition completed. private device serial SECRET-123\\n")
    (source/"acquisition.json").write_text(json.dumps({"module_results":[{"name":"backup","status":"completed","error":"private /data path"}]}))
    coverage=_androidqf_coverage(source)
    serialized=json.dumps(coverage)
    assert coverage["acquisition_completion"] == "complete"
    assert "SECRET-123" not in serialized
    assert "private /data path" not in serialized
    assert "device serial" not in serialized


def test_scan_refuses_output_path_inside_input(tmp_path, monkeypatch, capsys) -> None:
    from pegasushunter import cli
    source = tmp_path / "backup"
    source.mkdir()
    monkeypatch.setattr(cli.shutil, "which", lambda _: "/usr/bin/mvt-ios")
    assert main(["scan", "ios", str(source), "--output", str(source / "results")]) == 2
    assert not (source / "results").exists()
    assert "outside the input" in capsys.readouterr().err


def test_module_entrypoint_displays_help() -> None:
    result = subprocess.run([sys.executable, "-m", "pegasushunter", "--help"], capture_output=True, text=True, check=False)
    assert result.returncode == 0
    assert "summarize" in result.stdout
    assert "scan" in result.stdout


def test_real_mvt_androidqf_zip_smoke(tmp_path) -> None:
    import pytest

    if os.environ.get("PEGASUSHUNTER_TEST_MVT_INTEGRATION") != "1":
        pytest.skip("set PEGASUSHUNTER_TEST_MVT_INTEGRATION=1 to exercise the installed MVT CLI")

    source = tmp_path / "minimal-androidqf.zip"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("command.log", "Synthetic input; no device evidence included.\n")
    output = tmp_path / "mvt-results"

    assert main([
        "scan", "android", str(source), "--acquisition", "androidqf",
        "--output", str(output), "--indicator-cache", str(tmp_path / "missing-cache"),
    ]) == 0

    report = json.loads((output / "pegasushunter_report.json").read_text())
    assert report["coverage"]["mvt_info_present"] is True
    assert report["coverage"]["androidqf"]["acquisition_completion"] == "unverified"
    assert report["coverage_level"] == "limited"
    assert report["overall_assessment"] == "limited_no_match"
    assert any("Intrusion Logs" in warning for warning in report["coverage_warnings"])
