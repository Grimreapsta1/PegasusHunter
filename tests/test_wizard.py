from __future__ import annotations

import json


def test_wizard_updates_indicator_cache_then_runs_scan_with_fresh_iocs(tmp_path, monkeypatch, capsys) -> None:
    from pegasushunter import cli
    from pegasushunter.indicators import COLLECTIONS

    cache = tmp_path / "indicators"
    monkeypatch.setattr(cli, "_default_indicator_cache", lambda: cache)
    source = tmp_path / "ios-backup"
    source.mkdir()
    output = tmp_path / "results"
    answers = iter(["1", "1", str(source), str(output), "y", "y"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    monkeypatch.setattr(cli.shutil, "which", lambda name: f"/usr/bin/{name}")
    calls = []

    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, limit):
            return json.dumps({"type": "bundle", "objects": [
                {"type": "indicator", "name": "Test", "pattern": "[domain-name:value='example.org']"}
            ]}).encode()

    monkeypatch.setattr(cli, "update_indicator_cache", lambda folder: {
        "status": "complete", "updated_at": "2026-11-05T00:00:00+00:00", "collections": [
            {**item, "file": item["url"].rsplit("/", 1)[-1], "indicator_count": 1}
            for item in COLLECTIONS if "ios" in item["platforms"]
        ], "failures": []
    })
    cache.mkdir()
    cache_items=[item for item in COLLECTIONS if "ios" in item["platforms"]]
    for item in cache_items:
        (cache/item["url"].rsplit("/",1)[-1]).write_text(json.dumps({"type":"bundle","objects":[{"type":"indicator","name":"Test","pattern":"[domain-name:value='example.org']"}]}))
    (cache / "manifest.json").write_text(json.dumps({
        "schema_version":1,"status": "complete", "updated_at": "2026-11-05T00:00:00+00:00",
        "collections": [{**item, "file": item["url"].rsplit("/",1)[-1], "indicator_count": 1} for item in cache_items], "failures": []
    }))

    def fake_run(command, check, env):
        calls.append((command, env.copy()))
        if "check-backup" in command:
            (output / "alerts.json").write_text("[]")
            (output / "info.json").write_text('{"platform":"iOS","version":"test"}')
        return type("Completed", (), {"returncode": 0})()

    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    assert cli.main(["wizard"]) == 0

    assert len(calls) == 1
    assert calls[0][0][0:2] == ["/usr/bin/mvt-ios", "check-backup"]
    assert "--iocs" in calls[0][0]
    assert calls[0][1]["MVT_NETWORK_ACCESS_ALLOWED"] == "false"
    result = capsys.readouterr().out.lower()
    assert "nso group pegasus indicators" in result
    assert "does not prove the phone is clean" in result


def test_androidqf_wizard_accepts_zip_archive_and_passes_it_to_mvt(tmp_path, monkeypatch, capsys) -> None:
    import zipfile

    from pegasushunter import cli
    from pegasushunter.indicators import COLLECTIONS

    source = tmp_path / "aqf.zip"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("acquisition.json", json.dumps({"module_results":[{"name":"backup","status":"completed"}]}))
        archive.writestr("command.log", "Acquisition completed.\n")
    cache = tmp_path / "cache"
    cache.mkdir()
    cache_items=[item for item in COLLECTIONS if "android" in item["platforms"]]
    for item in cache_items:
        (cache/item["url"].rsplit("/",1)[-1]).write_text(json.dumps({"type":"bundle","objects":[{"type":"indicator","name":"Test","pattern":"[domain-name:value='example.org']"}]}))
    (cache / "manifest.json").write_text(json.dumps({"schema_version":1,"status":"complete","updated_at":"2026-11-06T00:00:00+00:00","collections":[{**item,"file":item["url"].rsplit("/",1)[-1],"indicator_count":1} for item in cache_items],"failures":[]}))
    monkeypatch.setattr(cli, "_default_indicator_cache", lambda: cache)
    answers=iter(["2","2",str(source),str(tmp_path/"results"),"n","y"])
    monkeypatch.setattr("builtins.input",lambda prompt="":next(answers))
    monkeypatch.setattr(cli.shutil,"which",lambda name:"/usr/bin/mvt-android")
    seen={}
    def fake_run(command,check,env):
        seen["command"]=command
        output=tmp_path/"results"
        (output/"alerts.json").write_text("[]")
        (output/"info.json").write_text(json.dumps({"mvt_version":"2026.11.2","date":"now","target_path":str(source),"ioc_files":[]}))
        return type("Completed",(),{"returncode":0})()
    monkeypatch.setattr(cli.subprocess,"run",fake_run)
    assert cli.main(["wizard"])==0
    assert seen["command"][1]=="check-androidqf"
    assert seen["command"][-1]==str(source.resolve())
    assert "ZIP archive" in capsys.readouterr().out


def test_wizard_requires_complete_cached_indicators_if_user_declines_update(tmp_path, monkeypatch, capsys) -> None:
    from pegasushunter import cli

    cache = tmp_path / "indicators"
    cache.mkdir()
    (cache / "manifest.json").write_text(json.dumps({"schema_version": 1,"status": "partial", "updated_at": None, "collections": [], "failures": []}))
    monkeypatch.setattr(cli, "_default_indicator_cache", lambda: cache)
    source = tmp_path / "android.ab"
    source.write_bytes(b"backup")
    output = tmp_path / "results"
    answers = iter(["2", "1", str(source), str(output), "n"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    monkeypatch.setattr(cli, "update_indicator_cache", lambda folder: (_ for _ in ()).throw(AssertionError("update declined")))
    monkeypatch.setattr(cli.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must stop before scan")))

    assert cli.main(["wizard"]) == 2
    assert "no complete" in capsys.readouterr().err.lower()


def test_wizard_cancellation_does_not_start_scan_or_download(tmp_path, monkeypatch, capsys) -> None:
    from pegasushunter import cli
    monkeypatch.setattr("builtins.input", lambda prompt="": "q")
    monkeypatch.setattr(cli.subprocess, "run", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("should not run")))
    assert cli.main(["wizard"]) == 0
    assert "cancelled" in capsys.readouterr().out.lower()


def test_wizard_rejects_invalid_menu_choice_without_guessing(tmp_path, monkeypatch, capsys) -> None:
    from pegasushunter import cli
    answers = iter(["9", "q"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    monkeypatch.setattr(cli.subprocess, "run", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("should not run")))
    assert cli.main(["wizard"]) == 2
    assert "choose 1 or 2" in capsys.readouterr().out.lower()
