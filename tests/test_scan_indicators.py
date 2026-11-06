from __future__ import annotations

import json


def test_scan_adds_fresh_cache_iocs_while_respecting_user_explicit_iocs(tmp_path, monkeypatch, capsys) -> None:
    from pegasushunter import cli
    from pegasushunter.indicators import COLLECTIONS

    cache = tmp_path / "cache"
    cache.mkdir()
    cache_files = []
    selected=[item for item in COLLECTIONS if "ios" in item["platforms"]]
    for item in selected:
        name = item["url"].rsplit("/", 1)[-1]
        (cache / name).write_text(json.dumps({"type":"bundle","objects":[{"type":"indicator","name":"Test","pattern":"[domain-name:value='example.org']"}]}))
        cache_files.append({**item, "file": name, "indicator_count": 1})
    (cache / "manifest.json").write_text(json.dumps({
        "schema_version": 1, "updated_at": "2026-11-05T00:00:00+00:00", "status": "complete", "collections": cache_files
    }))
    source = tmp_path / "backup"
    source.mkdir()
    explicit = tmp_path / "custom.stix2"
    explicit.write_text(json.dumps({"type":"bundle","objects":[{"type":"indicator","name":"Custom","pattern":"[domain-name:value='custom.example']"}]}))
    output = tmp_path / "out"
    calls = []
    monkeypatch.setattr(cli.shutil, "which", lambda name: f"/usr/bin/{name}")

    def fake_run(command, check, env):
        calls.append(command)
        (output / "alerts.json").write_text("[]")
        (output / "info.json").write_text('{"platform":"iOS","version":"test"}')
        return type("Completed", (), {"returncode": 0})()

    assert cli._run_scan(type("Args", (), {
        "source": source, "output": output, "platform": "ios", "acquisition": "backup",
        "ioc": [explicit], "indicator_cache": cache,
    })(), runner=fake_run) == 0

    scan_command = calls[0]
    passed = [scan_command[index + 1] for index, value in enumerate(scan_command[:-1]) if value == "--iocs"]
    assert passed == [str(explicit.resolve()), *[str((cache / item["url"].rsplit("/", 1)[-1]).resolve()) for item in selected]]
    assert "NSO Group Pegasus indicators" in capsys.readouterr().out


def test_empty_or_partial_indicator_cache_warns_in_report(tmp_path) -> None:
    import json

    from pegasushunter.report import analyze_results

    (tmp_path / "alerts.json").write_text("[]")
    (tmp_path / "info.json").write_text('{"platform":"Android"}')
    (tmp_path / "pegasushunter_scan.json").write_text(json.dumps({"indicator_status": "missing"}))

    result = analyze_results(tmp_path)
    assert result["coverage_level"] == "limited"
    assert any("indicator" in warning.lower() for warning in result["coverage_warnings"])


def test_cache_marked_complete_but_missing_platform_feeds_is_reported_partial(tmp_path, monkeypatch, capsys) -> None:
    from pegasushunter import cli

    cache=tmp_path/"cache"
    cache.mkdir()
    (cache/"manifest.json").write_text(json.dumps({"schema_version":1,"status":"complete","updated_at":"2026-11-06T00:00:00+00:00","collections":[]}))
    source=tmp_path/"backup.ab"
    source.write_bytes(b"backup")
    output=tmp_path/"results"
    monkeypatch.setattr(cli,"_find_mvt",lambda _:"/usr/bin/mvt-android")
    def fake_run(command,check,env):
        (output/"alerts.json").write_text("[]")
        (output/"info.json").write_text('{"mvt_version":"test","date":"now","ioc_files":[]}')
        return type("Completed",(),{"returncode":0})()
    args=type("Args",(),{"source":source,"output":output,"platform":"android","acquisition":"backup","ioc":[],"indicator_cache":cache})()
    assert cli._run_scan(args,runner=fake_run)==0
    metadata=json.loads((output/"pegasushunter_scan.json").read_text())
    report=json.loads((output/"pegasushunter_report.json").read_text())
    assert metadata["indicator_status"] == "partial"
    assert report["coverage_level"] == "limited"
    assert "some public indicator files" in capsys.readouterr().out.lower()


def test_indicator_cache_symlinked_manifest_stops_before_mvt(tmp_path, monkeypatch) -> None:
    import pytest

    from pegasushunter import cli
    from pegasushunter.report import ReportError

    cache=tmp_path/"cache"
    cache.mkdir()
    outside=tmp_path/"outside.json"
    outside.write_text(json.dumps({"schema_version":1,"status":"complete","updated_at":"2026-11-05T00:00:00+00:00","collections":[]}))
    (cache/"manifest.json").symlink_to(outside)
    source=tmp_path/"backup.ab"
    source.write_bytes(b"backup")
    monkeypatch.setattr(cli,"_find_mvt",lambda _:"/usr/bin/mvt-ios")
    args=type("Args",(),{"source":source,"output":tmp_path/"out","platform":"ios","acquisition":"backup","ioc":[],"indicator_cache":cache})()
    with pytest.raises(ReportError,match="manifest must not be a symlink"):
        cli._run_scan(args,runner=lambda *a,**k: (_ for _ in ()).throw(AssertionError("MVT must not run")))
    assert not (tmp_path/"out").exists()


def test_corrupt_cached_indicator_bundle_stops_before_running_mvt(tmp_path, monkeypatch) -> None:
    import pytest

    from pegasushunter import cli
    from pegasushunter.indicators import COLLECTIONS
    from pegasushunter.report import ReportError

    cache=tmp_path/"cache"
    cache.mkdir()
    item={**COLLECTIONS[0],"file":COLLECTIONS[0]["url"].rsplit("/",1)[-1],"indicator_count":1}
    (cache/item["file"]).write_text("not a STIX bundle")
    (cache/"manifest.json").write_text(json.dumps({"schema_version":1,"status":"complete","updated_at":"2026-11-05T00:00:00+00:00","collections":[item]}))
    source=tmp_path/"backup.ab"
    source.write_bytes(b"backup")
    args=type("Args",(),{"source":source,"output":tmp_path/"out","platform":"ios","acquisition":"backup","ioc":[],"indicator_cache":cache})()
    monkeypatch.setattr(cli,"_find_mvt",lambda _:"/usr/bin/mvt-ios")
    with pytest.raises(ReportError,match="not valid JSON"):
        cli._run_scan(args,runner=lambda *a,**k: (_ for _ in ()).throw(AssertionError("MVT must not start")))
    assert not (tmp_path/"out").exists()


def test_invalid_indicator_cache_manifest_stops_before_running_mvt(tmp_path, monkeypatch) -> None:
    from pegasushunter import cli
    from pegasushunter.cli import main

    source = tmp_path / "backup"
    source.mkdir()
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "manifest.json").write_text("{bad")
    output = tmp_path / "out"
    monkeypatch.setattr(cli.shutil, "which", lambda name: f"/usr/bin/{name}")

    assert main(["scan", "ios", str(source), "--output", str(output), "--indicator-cache", str(cache)]) == 2
    assert not output.exists()


def test_cache_status_is_present_in_scan_metadata_even_on_failed_mvt(tmp_path, monkeypatch) -> None:
    from pegasushunter import cli
    from pegasushunter.indicators import COLLECTIONS

    cache = tmp_path / "cache"
    cache.mkdir()
    cache_rows=[]
    for item in (entry for entry in COLLECTIONS if "ios" in entry["platforms"]):
        filename=item["url"].rsplit("/",1)[-1]
        (cache/filename).write_text(json.dumps({"type":"bundle","objects":[{"type":"indicator","name":"Test","pattern":"[domain-name:value='example.org']"}]}))
        cache_rows.append({**item,"file":filename,"indicator_count":1})
    (cache / "manifest.json").write_text(json.dumps({"schema_version": 1, "status": "complete", "updated_at": "2026-11-05T00:00:00+00:00", "collections": cache_rows}))
    source = tmp_path / "backup"
    source.mkdir()
    output = tmp_path / "out"
    monkeypatch.setattr(cli.shutil, "which", lambda name: f"/usr/bin/{name}")

    def fake_run(command, check, env):
        assert any(x == "--iocs" for x in command)
        assert env["MVT_NETWORK_ACCESS_ALLOWED"] == "false"
        return type("Completed", (), {"returncode": 4})()

    args = type("Args", (), {
        "source": source, "output": output, "platform": "ios", "acquisition": "backup",
        "ioc": [], "indicator_cache": cache,
    })()
    assert cli._run_scan(args, runner=fake_run) == 4
    metadata = json.loads((output / "pegasushunter_scan.json").read_text())
    assert metadata["indicator_status"] == "complete"
    assert metadata["indicator_collections"] == [item["name"] for item in COLLECTIONS if "ios" in item["platforms"]]
