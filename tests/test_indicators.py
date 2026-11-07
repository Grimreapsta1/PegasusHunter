from __future__ import annotations

import json
from datetime import UTC, datetime


def test_indicator_catalog_matches_current_official_mvt_index() -> None:
    import os
    import re
    import urllib.request

    import pytest

    if os.environ.get("PEGASUSHUNTER_TEST_LIVE_INDICATORS") != "1":
        pytest.skip("set PEGASUSHUNTER_TEST_LIVE_INDICATORS=1 to compare with MVT's live index")

    from pegasushunter.indicators import COLLECTIONS

    index_url = "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/indicators.yaml"
    request = urllib.request.Request(index_url, headers={"User-Agent": "PegasusHunter-test/0.1"})
    with urllib.request.urlopen(request, timeout=30) as response:
        index_text = response.read().decode("utf-8")

    upstream = set()
    blocks = re.findall(r"(?ms)^  -\s*\n(.*?)(?=^  -\s*\n|\Z)", index_text)
    for block in blocks:
        source_types = re.findall(r"(?m)^    type: (.+)$", block)
        assert source_types == ["github"], f"Review unsupported MVT index entry type(s): {source_types}"
        fields = {
            key: value
            for key, value in re.findall(r"(?m)^      (owner|repo|branch|path): (.+)$", block)
        }
        assert set(fields) == {"owner", "repo", "branch", "path"}
        upstream.add(
            "https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}".format(**fields)
        )

    local = {entry["url"] for entry in COLLECTIONS}

    assert upstream == local


def test_indicator_catalog_urls_are_live_and_parseable() -> None:
    import os
    import urllib.request

    import pytest

    if os.environ.get("PEGASUSHUNTER_TEST_LIVE_INDICATORS") != "1":
        pytest.skip("set PEGASUSHUNTER_TEST_LIVE_INDICATORS=1 to check upstream indicator URLs")

    from pegasushunter.indicators import COLLECTIONS, _validate_stix

    for collection in COLLECTIONS:
        request=urllib.request.Request(collection["url"],headers={"User-Agent":"PegasusHunter-test/0.1"})
        with urllib.request.urlopen(request,timeout=30) as response:
            assert response.status == 200
            text=response.read(20_000_001).decode("utf-8")
        bundle=_validate_stix(text,collection["name"])
        assert any(isinstance(obj,dict) and obj.get("type")=="indicator" for obj in bundle["objects"])


def test_update_saves_only_valid_stix_bundles_and_provenance(tmp_path) -> None:
    from pegasushunter.indicators import COLLECTIONS, update_indicator_cache

    payload = json.dumps({
        "type": "bundle", "id": "bundle--test", "objects": [
            {"type": "indicator", "id": "indicator--test", "name": "test", "pattern": "[domain-name:value='example.org']"}
        ]
    }).encode()

    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, limit): return payload

    def opener(request, timeout):
        assert timeout == 30
        return Response()

    fixed = datetime(2026, 11, 5, tzinfo=UTC)
    manifest = update_indicator_cache(tmp_path, opener=opener, now=fixed)

    assert manifest["status"] == "complete"
    assert len(manifest["collections"]) == len(COLLECTIONS)
    assert all(item["indicator_count"] == 1 for item in manifest["collections"])
    assert manifest["updated_at"] == fixed.isoformat()
    for collection in manifest["collections"]:
        assert (tmp_path / collection["file"]).is_file()
        assert collection["url"].startswith("https://raw.githubusercontent.com/")


def test_stix_bundle_validation_rejects_indicator_missing_pattern(tmp_path) -> None:
    import pytest

    from pegasushunter.indicators import _validate_stix
    from pegasushunter.report import ReportError

    with pytest.raises(ReportError,match="missing its pattern"):
        _validate_stix(json.dumps({"type":"bundle","objects":[{"type":"indicator","name":"missing pattern"}]}),"bad")


def test_stix_bundle_validation_rejects_unsupported_pattern_type() -> None:
    import pytest

    from pegasushunter.indicators import _validate_stix
    from pegasushunter.report import ReportError

    payload={"type":"bundle","objects":[{"type":"indicator","pattern":"x","pattern_type":"yara"}]}
    with pytest.raises(ReportError,match="unsupported STIX pattern type"):
        _validate_stix(json.dumps(payload),"bad")


def test_invalid_stix_does_not_replace_cached_file_and_marks_partial(tmp_path) -> None:
    from pegasushunter.indicators import COLLECTIONS, update_indicator_cache

    (tmp_path / "pegasus.stix2").write_text("old valid-cache sentinel")
    payload = b"not a STIX bundle"

    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, limit): return payload

    manifest = update_indicator_cache(
        tmp_path,
        opener=lambda request, timeout: Response(),
        now=datetime(2026, 11, 5, tzinfo=UTC),
    )

    assert manifest["status"] == "failed"
    assert len(manifest["failures"]) == len(COLLECTIONS)
    assert (tmp_path / "pegasus.stix2").read_text() == "old valid-cache sentinel"


def test_update_does_not_follow_precreated_indicator_temp_symlink(tmp_path) -> None:
    from pegasushunter.indicators import update_indicator_cache

    outside = tmp_path / "outside.txt"
    outside.write_text("keep this file unchanged")
    (tmp_path / "pegasus.stix2.tmp").symlink_to(outside)
    payload = json.dumps({
        "type": "bundle", "id": "bundle--test", "objects": [
            {"type": "indicator", "id": "indicator--test", "pattern": "[domain-name:value='example.org']"}
        ],
    }).encode()

    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, limit): return payload

    manifest = update_indicator_cache(tmp_path, opener=lambda request, timeout: Response())

    assert manifest["status"] == "complete"
    assert outside.read_text() == "keep this file unchanged"
    assert (tmp_path / "pegasus.stix2").is_file()
    assert not (tmp_path / "pegasus.stix2").is_symlink()


def test_update_manifest_temp_file_does_not_follow_symlink(tmp_path) -> None:
    from pegasushunter.indicators import update_indicator_cache

    outside = tmp_path / "outside-manifest.txt"
    outside.write_text("preserve manifest target")
    (tmp_path / "manifest.json.tmp").symlink_to(outside)

    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, limit):
            return json.dumps({
                "type": "bundle", "objects": [
                    {"type": "indicator", "pattern": "[domain-name:value='example.org']"}
                ],
            }).encode()

    manifest = update_indicator_cache(tmp_path, opener=lambda request, timeout: Response())

    assert manifest["status"] == "complete"
    assert outside.read_text() == "preserve manifest target"
    assert not (tmp_path / "manifest.json").is_symlink()
    assert json.loads((tmp_path / "manifest.json").read_text())["status"] == "complete"


def test_update_preserves_existing_indicator_bundle_symlink_target(tmp_path) -> None:
    from pegasushunter.indicators import COLLECTIONS, update_indicator_cache

    outside = tmp_path / "outside-existing.stix2"
    outside.write_text("external file must not be replaced")
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "pegasus.stix2").symlink_to(outside)
    payload = json.dumps({
        "type": "bundle", "objects": [
            {"type": "indicator", "pattern": "[domain-name:value='example.org']"}
        ],
    }).encode()

    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, limit): return payload

    manifest = update_indicator_cache(cache, opener=lambda request, timeout: Response())

    assert manifest["status"] == "complete"
    assert outside.read_text() == "external file must not be replaced"
    assert (cache / "pegasus.stix2").is_file()
    assert not (cache / "pegasus.stix2").is_symlink()
    assert COLLECTIONS[0]["url"].endswith("/pegasus.stix2")


def test_update_manifest_replace_does_not_modify_existing_symlink_target(tmp_path) -> None:
    from pegasushunter.indicators import update_indicator_cache

    outside = tmp_path / "outside-manifest-target.txt"
    outside.write_text("keep existing target")
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "manifest.json").symlink_to(outside)

    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, limit):
            return json.dumps({
                "type": "bundle", "objects": [
                    {"type": "indicator", "pattern": "[domain-name:value='example.org']"}
                ],
            }).encode()

    manifest = update_indicator_cache(cache, opener=lambda request, timeout: Response())

    assert manifest["status"] == "complete"
    assert outside.read_text() == "keep existing target"
    assert (cache / "manifest.json").is_file()
    assert not (cache / "manifest.json").is_symlink()


def test_indicator_cache_rejects_symlinked_cache_directory(tmp_path) -> None:
    import pytest

    from pegasushunter.indicators import load_indicator_cache
    from pegasushunter.report import ReportError

    outside=tmp_path/"outside"
    outside.mkdir()
    (outside/"manifest.json").write_text(json.dumps({"schema_version":1,"status":"complete","updated_at":None,"collections":[]}))
    linked=tmp_path/"linked"
    linked.symlink_to(outside,target_is_directory=True)
    with pytest.raises(ReportError,match="cache directory must not be a symlink"):
        load_indicator_cache(linked)


def test_indicator_cache_rejects_collection_path_traversal(tmp_path) -> None:
    import pytest

    from pegasushunter.indicators import load_indicator_cache
    from pegasushunter.report import ReportError

    (tmp_path / "manifest.json").write_text(json.dumps({
        "schema_version":1,"status":"complete","updated_at":"2026-11-05T00:00:00+00:00","collections":[{"name":"bad","file":"../../outside.stix2","platforms":["android"]}]
    }))
    with pytest.raises(ReportError, match="filename"):
        load_indicator_cache(tmp_path)


def test_indicator_cache_rejects_malformed_collection_rows(tmp_path) -> None:
    import pytest

    from pegasushunter.indicators import load_indicator_cache
    from pegasushunter.report import ReportError

    (tmp_path / "manifest.json").write_text(json.dumps({"schema_version":1,"status":"complete","updated_at":"2026-11-05T00:00:00+00:00","collections":["not-an-object"]}))
    with pytest.raises(ReportError, match="collection"):
        load_indicator_cache(tmp_path)


def test_indicator_cache_rejects_unknown_source_url(tmp_path) -> None:
    import pytest

    from pegasushunter.indicators import load_indicator_cache
    from pegasushunter.report import ReportError

    (tmp_path / "manifest.json").write_text(json.dumps({
        "schema_version":1,"status":"complete","updated_at":"2026-11-05T00:00:00+00:00","collections":[{"name":"bad","file":"bad.stix2","platforms":["android"],"url":"https://attacker.invalid/bad.stix2"}]
    }))
    with pytest.raises(ReportError, match="known source"):
        load_indicator_cache(tmp_path)


def test_indicator_manifest_requires_string_collection_fields(tmp_path) -> None:
    import pytest

    from pegasushunter.indicators import COLLECTIONS, load_indicator_cache
    from pegasushunter.report import ReportError

    base={**COLLECTIONS[0],"file":COLLECTIONS[0]["url"].rsplit("/",1)[-1],"indicator_count":1}
    for field,value in (("name",[]),("source",{}),("platforms",[[]])):
        item={**base,field:value}
        (tmp_path/"manifest.json").write_text(json.dumps({"schema_version":1,"status":"complete","updated_at":"2026-11-05T00:00:00+00:00","collections":[item]}))
        with pytest.raises(ReportError):
            load_indicator_cache(tmp_path)


def test_indicator_manifest_requires_supported_schema_version(tmp_path) -> None:
    import pytest

    from pegasushunter.indicators import load_indicator_cache
    from pegasushunter.report import ReportError

    for version in (None,2,"1"):
        value={"status":"complete","updated_at":"2026-11-05T00:00:00+00:00","collections":[]}
        if version is not None:
            value["schema_version"] = version
        (tmp_path/"manifest.json").write_text(json.dumps(value))
        with pytest.raises(ReportError,match="schema version"):
            load_indicator_cache(tmp_path)


def test_indicator_manifest_rejects_malformed_status_freshness_and_count(tmp_path) -> None:
    import pytest

    from pegasushunter.indicators import COLLECTIONS, load_indicator_cache
    from pegasushunter.report import ReportError

    item={**COLLECTIONS[0],"file":COLLECTIONS[0]["url"].rsplit("/",1)[-1],"indicator_count":1}
    for manifest, match in [
        ({"schema_version":1,"status":"stale","collections":[item]},"status"),
        ({"schema_version":1,"status":"complete","updated_at":5,"collections":[item]},"timestamp"),
        ({"schema_version":1,"status":"complete","updated_at":"not-a-date","collections":[item]},"timestamp"),
        ({"schema_version":1,"status":"complete","collections":[item]},"timestamp"),
        ({"schema_version":1,"status":"complete","updated_at":"2026-11-05T00:00:00+00:00","collections":[{**item,"indicator_count":-1}]},"count"),
    ]:
        (tmp_path/"manifest.json").write_text(json.dumps(manifest))
        with pytest.raises(ReportError,match=match):
            load_indicator_cache(tmp_path)


def test_scan_rejects_symlinked_indicator_cache_file(tmp_path, monkeypatch) -> None:
    import pytest

    from pegasushunter import cli
    from pegasushunter.indicators import COLLECTIONS
    from pegasushunter.report import ReportError

    source=tmp_path/"backup.ab"
    source.write_bytes(b"backup")
    outside=tmp_path/"outside.stix2"
    outside.write_text("private untrusted data")
    cache=tmp_path/"cache"
    cache.mkdir()
    collection={**COLLECTIONS[0],"file":"pegasus.stix2","indicator_count":1}
    (cache/"pegasus.stix2").symlink_to(outside)
    (cache/"manifest.json").write_text(json.dumps({"schema_version":1,"status":"complete","updated_at":"2026-11-05T00:00:00+00:00","collections":[collection]}))
    monkeypatch.setattr(cli,"_find_mvt",lambda name:"/usr/bin/mvt-ios")
    args=type("Args",(),{"source":source,"output":tmp_path/"out","platform":"ios","acquisition":"backup","ioc":[],"indicator_cache":cache})()
    with pytest.raises(ReportError,match="regular non-symlink"):
        cli._run_scan(args,runner=lambda *a,**k: (_ for _ in ()).throw(AssertionError("must not invoke MVT")))


def test_indicator_manifest_rejects_wrong_catalog_platforms(tmp_path) -> None:
    import pytest

    from pegasushunter.indicators import COLLECTIONS, load_indicator_cache
    from pegasushunter.report import ReportError

    item={**COLLECTIONS[0],"file":COLLECTIONS[0]["url"].rsplit("/",1)[-1],"platforms":["windows"]}
    (tmp_path/"manifest.json").write_text(json.dumps({"schema_version":1,"status":"complete","updated_at":"2026-11-05T00:00:00+00:00","collections":[item]}))
    with pytest.raises(ReportError,match="invalid"):
        load_indicator_cache(tmp_path)


def test_indicator_manifest_rejects_filename_source_mismatch(tmp_path) -> None:
    import pytest

    from pegasushunter.indicators import COLLECTIONS, load_indicator_cache
    from pegasushunter.report import ReportError

    item={**COLLECTIONS[0],"file":"different.stix2","indicator_count":1}
    value={"schema_version":1,"status":"complete","updated_at":"2026-11-05T00:00:00+00:00","collections":[item]}
    (tmp_path/"manifest.json").write_text(json.dumps(value))
    with pytest.raises(ReportError,match="does not match its source URL"):
        load_indicator_cache(tmp_path)


def test_indicator_manifest_rejects_duplicate_collections(tmp_path) -> None:
    import pytest

    from pegasushunter.indicators import COLLECTIONS, load_indicator_cache
    from pegasushunter.report import ReportError

    item={**COLLECTIONS[0],"file":COLLECTIONS[0]["url"].rsplit("/",1)[-1],"indicator_count":1}
    (tmp_path/"manifest.json").write_text(json.dumps({"schema_version":1,"status":"complete","updated_at":"2026-11-05T00:00:00+00:00","collections":[item,item]}))
    with pytest.raises(ReportError,match="duplicate"):
        load_indicator_cache(tmp_path)


def test_load_indicator_cache_explicitly_marks_missing_cache(tmp_path) -> None:
    from pegasushunter.indicators import load_indicator_cache

    assert load_indicator_cache(tmp_path) == {"status": "missing", "updated_at": None, "collections": [], "failures": []}


def test_partial_update_preserves_failures_and_successes(tmp_path) -> None:
    from pegasushunter.indicators import COLLECTIONS, update_indicator_cache

    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, limit):
            return json.dumps({"type": "bundle", "objects": [{"type": "indicator", "pattern": "[domain-name:value='x']"}]}).encode()

    calls = 0
    def opener(request, timeout):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("offline")
        return Response()

    manifest = update_indicator_cache(tmp_path, opener=opener)

    assert manifest["status"] == "partial"
    assert len(manifest["collections"]) == len(COLLECTIONS) - 1
    assert len(manifest["failures"]) == 1
    assert json.loads((tmp_path / "manifest.json").read_text())["status"] == "partial"
