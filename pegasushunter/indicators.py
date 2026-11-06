from __future__ import annotations

import json
import os
import tempfile
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .report import ReportError

# This is the current public MVT-compatible collection index, with campaign
# labels and canonical raw URLs. Never auto-download from a results report.
COLLECTIONS = [
    {
        "name": "NSO Group Pegasus indicators",
        "source": "Amnesty International",
        "url": "https://raw.githubusercontent.com/AmnestyTech/investigations/master/2021-07-18_nso/pegasus.stix2",
        "platforms": ["ios", "android"],
    },
    {
        "name": "Predator spyware indicators",
        "source": "MVT Indicators (community-referenced research)",
        "url": "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/intellexa_predator/predator.stix2",
        "platforms": ["ios", "android"],
    },
    {
        "name": "RCS Lab spyware indicators",
        "source": "MVT Indicators",
        "url": "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/2022-06-23_rcs_lab/rcs.stix2",
        "platforms": ["ios", "android"],
    },
    {
        "name": "Android spyware campaign indicators",
        "source": "Amnesty International",
        "url": "https://raw.githubusercontent.com/AmnestyTech/investigations/master/2023-03-29_android_campaign/malware.stix2",
        "platforms": ["android"],
    },
    {
        "name": "KingsPawn indicators",
        "source": "MVT Indicators",
        "url": "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/2023-04-11_quadream/kingspawn.stix2",
        "platforms": ["ios", "android"],
    },
    {
        "name": "Operation Triangulation indicators",
        "source": "MVT Indicators",
        "url": "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/2023-06_01_operation_triangulation/operation_triangulation.stix2",
        "platforms": ["ios"],
    },
    {
        "name": "WyrmSpy and DragonEgg indicators",
        "source": "MVT Indicators",
        "url": "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/2023-07-25_wyrmspy_dragonegg/wyrmspy_dragonegg.stix2",
        "platforms": ["android"],
    },
    {
        "name": "Wintego Helios indicators",
        "source": "Amnesty International",
        "url": "https://raw.githubusercontent.com/AmnestyTech/investigations/master/2024-05-02_wintego_helios/wintego_helios.stix2",
        "platforms": ["ios", "android"],
    },
    {
        "name": "NoviSpy indicators",
        "source": "Amnesty International",
        "url": "https://raw.githubusercontent.com/AmnestyTech/investigations/master/2024-12-16_serbia_novispy/novispy.stix2",
        "platforms": ["android"],
    },
    {
        "name": "EagleMsgSpy indicators",
        "source": "MVT Indicators",
        "url": "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/2024-12-25_eaglemsgspy/eaglemsgspy.stix2",
        "platforms": ["android"],
    },
    {
        "name": "Candiru indicators",
        "source": "MVT Indicators",
        "url": "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/candiru/candiru.stix2",
        "platforms": ["ios", "android"],
    },
    {
        "name": "ResidentBat indicators",
        "source": "MVT Indicators",
        "url": "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/ResidentBat/residentbat.stix2",
        "platforms": ["android"],
    },
    {
        "name": "Cellebrite-related indicators",
        "source": "MVT Indicators",
        "url": "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/cellebrite/cellebrite.stix2",
        "platforms": ["ios", "android"],
    },
    {
        "name": "DarkSword indicators",
        "source": "Google Threat Intelligence Group, iVerify, Lookout (via MVT Indicators)",
        "url": "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/2026-03-30_darksword/darksword.stix2",
        "platforms": ["ios"],
    },
    {
        "name": "Coruna indicators",
        "source": "Google Threat Intelligence Group, iVerify (via MVT Indicators)",
        "url": "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/2026-03-03_coruna_cryptowaters/coruna.stix2",
        "platforms": ["ios"],
    },
    {
        "name": "Morpheus indicators",
        "source": "Osservatorio Nessuno (via MVT Indicators)",
        "url": "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/2026-04-23_ips_morpheus/morpheus.stix2",
        "platforms": ["ios", "android"],
    },
    {
        "name": "BTMOB indicators",
        "source": "ESET, Cyble Research, Zimperium (via MVT Indicators)",
        "url": "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/2026-05-26_btmob/btmob.stix2",
        "platforms": ["android"],
    },
    {
        "name": "Spyrtacus indicators",
        "source": "Osservatorio Nessuno (via MVT Indicators)",
        "url": "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/2026-04-09_sio_spyrtacus/spyrtacus.stix2",
        "platforms": ["ios", "android"],
    },
    {
        "name": "Android stalkerware indicators",
        "source": "AssoEchap",
        "url": "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/stalkerware.stix2",
        "platforms": ["android"],
    },
]


def _validate_stix(text: str, label: str) -> dict[str, Any]:
    try:
        bundle = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ReportError(f"{label}: response is not valid JSON") from exc
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle" or not isinstance(bundle.get("objects"), list):
        raise ReportError(f"{label}: not a STIX 2 bundle")
    if isinstance(bundle.get("id"), str) and not bundle["id"].startswith("bundle--"):
        raise ReportError(f"{label}: STIX bundle ID is malformed")
    indicators = [obj for obj in bundle["objects"] if isinstance(obj, dict) and obj.get("type") == "indicator"]
    if not indicators:
        raise ReportError(f"{label}: STIX bundle contains no indicators")
    for indicator in indicators:
        if not isinstance(indicator.get("pattern"), str) or not indicator["pattern"].strip():
            raise ReportError(f"{label}: STIX indicator is missing its pattern")
        if indicator.get("pattern_type", "stix") != "stix":
            raise ReportError(f"{label}: unsupported STIX pattern type")
        pattern_version = indicator.get("pattern_version")
        if pattern_version is not None and not isinstance(pattern_version, str):
            raise ReportError(f"{label}: STIX pattern version is malformed")
    return bundle


def load_indicator_cache(cache_dir: Path) -> dict[str, Any]:
    """Read a previously fetched Pegasus Hunter indicator manifest."""
    cache = Path(cache_dir)
    if cache.is_symlink() or (cache.exists() and not cache.is_dir()):
        raise ReportError("indicator cache directory must not be a symlink")
    path = cache / "manifest.json"
    if path.is_symlink():
        raise ReportError("indicator manifest must not be a symlink")
    if not path.is_file():
        return {"status": "missing", "updated_at": None, "collections": [], "failures": []}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReportError("could not read indicator manifest") from exc
    if not isinstance(value, dict) or not isinstance(value.get("collections"), list):
        raise ReportError("indicator manifest has an invalid format")
    if value.get("schema_version") != 1:
        raise ReportError("indicator manifest schema version is missing or unsupported")

    if value.get("status") not in {"complete", "partial", "failed"}:
        raise ReportError("indicator manifest status is invalid")
    updated_at = value.get("updated_at")
    if updated_at is not None and not isinstance(updated_at, str):
        raise ReportError("indicator manifest timestamp is invalid")
    if value["collections"] and not updated_at:
        raise ReportError("indicator manifest timestamp is missing")
    if isinstance(updated_at, str):
        try:
            datetime.fromisoformat(updated_at)
        except ValueError as exc:
            raise ReportError("indicator manifest timestamp is invalid") from exc
    seen_urls: set[str] = set()
    seen_files: set[str] = set()
    for collection in value["collections"]:
        if not isinstance(collection, dict):
            raise ReportError("indicator manifest contains an invalid collection entry")
        filename = collection.get("file")
        if not isinstance(filename, str) or not filename or Path(filename).name != filename or filename in {".", ".."}:
            raise ReportError("indicator manifest collection filename must be a simple file name")
        platforms = collection.get("platforms")
        if not isinstance(platforms, list) or any(not isinstance(platform, str) or platform not in {"ios", "android"} for platform in platforms):
            raise ReportError("indicator manifest collection platforms are invalid")
        url = collection.get("url")
        if not isinstance(url, str):
            raise ReportError("indicator manifest collection URL is not a known source")
        catalog_entry = next((item for item in COLLECTIONS if item["url"] == url), None)
        if catalog_entry is None:
            raise ReportError("indicator manifest collection URL is not a known source")
        if filename != url.rsplit("/", 1)[-1]:
            raise ReportError("indicator manifest filename does not match its source URL")
        if collection.get("name") != catalog_entry["name"] or collection.get("source") != catalog_entry["source"] or platforms != catalog_entry["platforms"]:
            raise ReportError("indicator manifest collection metadata does not match the known catalog")
        indicator_count = collection.get("indicator_count")
        if type(indicator_count) is not int or indicator_count < 1:
            raise ReportError("indicator manifest collection indicator count is invalid")
        if url in seen_urls or filename in seen_files:
            raise ReportError("indicator manifest contains a duplicate collection")
        seen_urls.add(url)
        seen_files.add(filename)
    return value


def update_indicator_cache(cache_dir: Path, *, opener=urllib.request.urlopen, now=None) -> dict[str, Any]:
    """Fetch public STIX bundles to a local cache, validating before replace."""
    cache = Path(cache_dir).expanduser()
    if cache.is_symlink() or (cache.exists() and not cache.is_dir()):
        raise ReportError("indicator cache directory must not be a symlink")
    cache.mkdir(parents=True, exist_ok=True)
    if not cache.is_dir():
        raise ReportError("indicator cache directory must be a real directory")
    manifest_entries = []
    failures = []
    for item in COLLECTIONS:
        try:
            request = urllib.request.Request(item["url"], headers={"User-Agent": "PegasusHunter/0.1"})
            with opener(request, timeout=30) as response:
                payload = response.read(20_000_001)
            if len(payload) > 20_000_000:
                raise ReportError("download exceeds 20 MB safety limit")
            text = payload.decode("utf-8")
            bundle = _validate_stix(text, item["name"])
            filename = item["url"].rsplit("/", 1)[-1]
            destination = cache / filename
            fd, temp_name = tempfile.mkstemp(prefix=f".{filename}.", suffix=".tmp", dir=cache)
            temp = Path(temp_name)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump(bundle, handle, sort_keys=True)
                    handle.flush()
                    os.fsync(handle.fileno())
                temp.replace(destination)
            finally:
                temp.unlink(missing_ok=True)
            manifest_entries.append({
                **item,
                "file": filename,
                "indicator_count": sum(1 for obj in bundle["objects"] if isinstance(obj, dict) and obj.get("type") == "indicator"),
            })
        except (OSError, UnicodeDecodeError, urllib.error.URLError, ReportError) as exc:
            failures.append({"name": item["name"], "error": str(exc)})

    timestamp = (now or datetime.now(UTC)).isoformat()
    manifest = {
        "schema_version": 1,
        "updated_at": timestamp,
        "status": "complete" if not failures else "partial" if manifest_entries else "failed",
        "collections": manifest_entries,
        "failures": failures,
        "warning": "Public indicators are incomplete and cannot prove a device is clean.",
    }
    fd, temp_name = tempfile.mkstemp(prefix=".manifest.", suffix=".tmp", dir=cache)
    temp_manifest = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(manifest, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temp_manifest.replace(cache / "manifest.json")
    finally:
        temp_manifest.unlink(missing_ok=True)
    return manifest
