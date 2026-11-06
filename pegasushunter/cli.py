from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import zipfile
from collections.abc import Sequence
from pathlib import Path

from .indicators import COLLECTIONS, _validate_stix, load_indicator_cache, update_indicator_cache
from .report import ReportError, analyze_results, render_text


def build_parser():
    import argparse

    parser = argparse.ArgumentParser(prog="pegasushunter", description="Plain-English mobile spyware triage powered by MVT.")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("wizard", help="guided scan for people who are not forensic specialists")
    update_iocs = commands.add_parser("update-indicators", help="download public MVT spyware indicator collections")
    update_iocs.add_argument("--cache", type=Path, help="cache directory (default: ~/.pegasushunter/indicators)")
    summarize = commands.add_parser("summarize", help="explain an existing MVT results directory")
    summarize.add_argument("results", type=Path)
    summarize.add_argument("--format", choices=("text", "json"), default="text")
    scan = commands.add_parser("scan", help="run MVT on an existing device backup or iOS filesystem dump")
    scan.add_argument("platform", choices=("ios", "android"))
    scan.add_argument("source", type=Path, help="existing backup or filesystem dump")
    scan.add_argument("--output", type=Path, required=True, help="new or empty MVT results directory")
    scan.add_argument("--acquisition", choices=("backup", "filesystem", "androidqf"), default="backup")
    scan.add_argument("--indicator-cache", type=Path, help="Pegasus Hunter public indicator cache (default: ~/.pegasushunter/indicators)")
    scan.add_argument("--ioc", type=Path, action="append", default=[], metavar="STIX2")
    return parser


def _find_mvt(name: str) -> str | None:
    executable = shutil.which(name)
    if executable:
        return executable
    candidate = Path(sys.executable).parent / name
    return str(candidate) if candidate.is_file() and os.access(candidate, os.X_OK) else None


def _run_scan(args, *, runner=None) -> int:
    if runner is None:
        runner = subprocess.run
    source = args.source.expanduser().resolve()
    output = args.output.expanduser().resolve()
    if not source.exists():
        raise ReportError(f"input does not exist: {source}")
    if source.is_file() and source.suffix.lower() == ".age":
        raise ReportError("Encrypted AndroidQF archives must be decrypted with age before analysis; do not share the private key")
    if args.acquisition == "androidqf" and args.platform != "android":
        raise ReportError("AndroidQF is supported only for Android scans")
    if output == source or output in source.parents:
        raise ReportError("output must not be the input path or one of its parent directories")
    if source.is_dir() and output.is_relative_to(source):
        raise ReportError("output must be outside the input directory")
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ReportError(f"output must be a new or empty directory: {output}")
    custom_indicators = [ioc.expanduser().resolve() for ioc in args.ioc]
    indicators = list(custom_indicators)
    indicator_cache = getattr(args, "indicator_cache", None)
    cache_status = "missing"
    manifest = None
    if indicator_cache:
        indicator_cache = indicator_cache.expanduser()
        manifest = load_indicator_cache(indicator_cache)
        cache_status = manifest.get("status", "missing")
    supported = [item for item in manifest.get("collections", []) if args.platform in item.get("platforms", [])] if manifest else []
    if manifest and manifest.get("status") == "complete" and not supported:
        cache_status = "partial"
    expected_supported = [item for item in COLLECTIONS if args.platform in item["platforms"]]
    if manifest and manifest.get("status") == "complete":
        listed_urls = {item.get("url") for item in supported}
        if any(item["url"] not in listed_urls for item in expected_supported):
            cache_status = "partial"
    for collection in supported:
        cached = indicator_cache / collection["file"] if indicator_cache else None
        if cached and cached.is_symlink():
            raise ReportError(f"indicator file must be a regular non-symlink file: {cached.name}")
        if cached and cached.is_file():
            _validate_stix(cached.read_text(encoding="utf-8"), collection["name"])
            indicators.append(cached.resolve())
        else:
            cache_status = "partial"
    indicators.extend(path for path in custom_indicators if path not in indicators)
    if cache_status == "missing":
        print("Warning: no cached public indicators are available; results may miss known threats.")
    elif cache_status == "failed":
        print("Warning: public indicator update failed; known threats may be missed.")
    elif cache_status == "partial":
        print("Warning: only some public indicator files are available.")
    else:
        print("Using Pegasus Hunter public indicator cache; results still cannot cover every threat.")
        print("Indicator collections: " + ", ".join(item["name"] for item in supported))
        if manifest and manifest.get("updated_at"):
            print("Indicator cache last updated: " + str(manifest["updated_at"]))
    for path in indicators:
        if not path.is_file():
            raise ReportError(f"indicator file does not exist: {path}")
    if args.platform == "ios":
        executable = _find_mvt("mvt-ios")
        if not executable:
            raise ReportError("mvt-ios is not installed; install MVT using its official documentation")
        command = [executable, "check-fs" if args.acquisition == "filesystem" else "check-backup"]
    else:
        if args.acquisition == "filesystem":
            raise ReportError("Android filesystem acquisition is not supported")
        if args.acquisition == "androidqf":
            if not source.is_dir() and not (source.is_file() and zipfile.is_zipfile(source)):
                raise ReportError("AndroidQF acquisition input must be a directory or a valid ZIP archive")
            executable = _find_mvt("mvt-android")
            if not executable:
                raise ReportError("mvt-android is not installed; install MVT using its official documentation")
            command = [executable, "check-androidqf"]
        else:
            executable = _find_mvt("mvt-android")
            if not executable:
                raise ReportError("mvt-android is not installed; install MVT using its official documentation")
            command = [executable, "check-backup"]

    command.extend(["--output", str(output)])
    for ioc in indicators:
        command.extend(["--iocs", str(ioc)])
    scan_metadata: dict[str, object] = {
        "platform": args.platform,
        "acquisition": args.acquisition,
        "indicator_status": cache_status,
        "indicator_collections": [item["name"] for item in supported] if manifest else [],
        "indicator_updated_at": manifest.get("updated_at") if manifest else None,
    }
    command.append(str(source))
    output.mkdir(parents=True, exist_ok=True)
    metadata_path = output / "pegasushunter_scan.json"
    metadata_tmp = metadata_path.with_suffix(".json.tmp")
    if args.acquisition == "androidqf":
        try:
            scan_metadata["androidqf_coverage"] = _androidqf_coverage(source)
        except (OSError, UnicodeDecodeError, zipfile.BadZipFile) as exc:
            raise ReportError(f"could not safely inspect AndroidQF acquisition: {exc}") from exc
    else:
        scan_metadata["androidqf_coverage"] = None
    metadata_tmp.write_text(json.dumps(scan_metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    metadata_tmp.replace(metadata_path)
    environment = os.environ.copy()
    environment["MVT_NETWORK_ACCESS_ALLOWED"] = "false"
    if args.acquisition == "androidqf":
        print("Running MVT locally on an AndroidQF forensic acquisition. Network lookups are disabled for this scan.")
    else:
        print("Running MVT locally. Network lookups are disabled for this scan.")
    print("The input and output can contain private messages and other sensitive records. Keep them private.")
    try:
        completed = runner(command, check=False, env=environment)
    except OSError as exc:
        raise ReportError(f"could not start MVT: {exc}") from exc
    if completed.returncode != 0:
        _annotate_partial_results(output, completed.returncode, scan_metadata)
        print(f"MVT exited with status {completed.returncode}. No verdict was generated; keep any partial results for an expert.")
        return int(completed.returncode) if int(completed.returncode) > 0 else 1
    acq = scan_metadata.get("androidqf_coverage") if args.acquisition == "androidqf" else None
    if args.acquisition == "androidqf":
        if not isinstance(acq, dict):
            raise ReportError("AndroidQF coverage metadata is missing")
        if acq["acquisition_completion"] != "complete":
            completion_description = "reports partial or failed module outcomes" if acq["acquisition_completion"] in {"partial", "failed"} else "has no verified completion status"
            print(f"Warning: AndroidQF acquisition {completion_description}; treat this scan as incomplete.")
        if acq["intrusion_logs"] != "collected":
            print("Coverage note: Android Intrusion Logs were not collected; intrusion-log IOC checking was unavailable.")
        if acq["acquisition_completion"] == "complete":
            print("AndroidQF acquisition metadata/logs show its collected modules completed; MVT is analyzing the saved acquisition locally.")
        elif acq["acquisition_completion"] == "partial":
            print("AndroidQF acquisition metadata/logs report partial module outcomes; MVT is analyzing the saved data, but coverage is limited.")
        else:
            print("AndroidQF acquisition completion remains unverified; MVT is analyzing the saved acquisition locally.")
    report = analyze_results(output)
    report["coverage"]["source_acquisition"] = args.acquisition
    if isinstance(acq, dict):
        report["coverage"]["androidqf"] = acq
        if acq["acquisition_completion"] == "partial":
            report["coverage_warnings"].append("AndroidQF acquisition metadata reports partial or failed module outcomes; inspect module_results in the report.")
        elif acq["acquisition_completion"] != "complete":
            report["coverage_warnings"].append("AndroidQF acquisition completion could not be verified from its log.")
        report["limitations"].extend(acq["limitations"])
    report["coverage_warnings"] = list(dict.fromkeys(report["coverage_warnings"]))
    report["coverage_level"] = "limited" if report["coverage_warnings"] else "results_present"
    report_path = output / "pegasushunter_report.json"
    report_tmp = report_path.with_suffix(".json.tmp")
    report_tmp.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    report_tmp.replace(report_path)
    print(render_text(report))
    return 0


def _annotate_partial_results(output: Path, returncode: int, scan_metadata: dict[str, object]) -> None:
    """Keep input-scope provenance with partial MVT artifacts, without issuing a verdict."""
    report_path = output / "pegasushunter_partial.json"
    record = {
        "status": "mvt_failed",
        "mvt_returncode": int(returncode),
        "verdict_generated": False,
        "scan_metadata": scan_metadata,
        "message": "MVT did not complete successfully. Preserve and review any partial result files; no assessment was generated.",
    }
    temp = report_path.with_suffix(".json.tmp")
    temp.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temp.replace(report_path)


def _ask(prompt: str) -> str:
    return input(prompt).strip()


def _default_indicator_cache() -> Path:
    return Path.home() / ".pegasushunter" / "indicators"


def _androidqf_coverage(source: Path) -> dict[str, object]:
    acquisition_log = source / "command.log" if source.is_dir() else None
    log_text = ""
    if acquisition_log and acquisition_log.is_file() and not acquisition_log.is_symlink():
        log_text = acquisition_log.read_text(encoding="utf-8", errors="replace")
    if source.is_file() and zipfile.is_zipfile(source):
        with zipfile.ZipFile(source) as archive:
            candidates = [name for name in archive.namelist() if Path(name).name.lower() == "command.log"]
            if len(candidates) > 1:
                raise ReportError("AndroidQF ZIP contains multiple command.log entries")
            for log_name in candidates:
                log_text += "\n" + archive.read(log_name).decode("utf-8", errors="replace")
    lowered_log = log_text.lower()
    completion_markers = ("acquisition completed.", "acquisition complete", "acquisition completed", "acquisition finished")
    failed_markers = ("fatal error", "acquisition failed", "traceback")
    partial_marker = "acquisition finalized with" in lowered_log
    complete = any(marker in lowered_log for marker in completion_markers)
    failed = any(marker in lowered_log for marker in failed_markers)
    artifact_counts: dict[str, int] = {}
    intrusion_file_count = 0
    acquisition_metadata_count = 0
    archive_backup_size: int | None = None
    acquisition_metadata: dict[str, object] | None = None
    if source.is_dir():
        for path in source.rglob("*"):
            if path.is_symlink():
                if path.name.lower() == "command.log":
                    continue
                if path.name.lower() in {"acquisition.json", "backup.ab", "bugreport.zip", "dumpsys.txt", "processes.json", "processes.txt", "services.txt"}:
                    raise ReportError(f"symlinked AndroidQF artifact is not accepted: {path.name}")
                continue
            if not path.is_file():
                continue
            artifact_name = path.name.lower()
            artifact_counts[artifact_name] = artifact_counts.get(artifact_name, 0) + 1
            if artifact_name in {"backup.ab", "bugreport.zip", "acquisition.json", "services.txt", "dumpsys.txt"} and artifact_counts[artifact_name] > 1:
                raise ReportError(f"AndroidQF directory contains multiple {artifact_name} artifacts")
            if artifact_name == "acquisition.json":
                acquisition_metadata_count += 1
                if acquisition_metadata_count > 1:
                    raise ReportError("AndroidQF directory contains multiple acquisition.json files")
                try:
                    value = json.loads(path.read_text(encoding="utf-8"))
                    if not isinstance(value, dict):
                        raise ReportError("AndroidQF acquisition.json must contain an object")
                    acquisition_metadata = value
                except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise ReportError(f"AndroidQF acquisition.json is malformed: {path.name}") from exc
            try:
                in_intrusion_dir = "intrusion_logs" in (part.lower() for part in path.relative_to(source).parts[:-1])
                if in_intrusion_dir and path.stat().st_size > 0:
                    intrusion_file_count += 1
            except OSError:
                continue
    elif source.is_file() and zipfile.is_zipfile(source):
        with zipfile.ZipFile(source) as archive:
            for entry in archive.infolist():
                if entry.is_dir():
                    continue
                if entry.flag_bits & 0x1:
                    raise ReportError("encrypted entries inside AndroidQF ZIP are not supported")
                parts = Path(entry.filename.replace("\\", "/")).parts
                artifact_name = Path(parts[-1]).name.lower()
                artifact_counts[artifact_name] = artifact_counts.get(artifact_name, 0) + 1
                if artifact_name in {"backup.ab", "bugreport.zip", "acquisition.json", "services.txt", "dumpsys.txt"} and artifact_counts[artifact_name] > 1:
                    raise ReportError(f"AndroidQF ZIP contains multiple {artifact_name} artifacts")
                if artifact_name == "backup.ab":
                    if archive_backup_size is not None:
                        raise ReportError("AndroidQF ZIP contains multiple backup.ab artifacts")
                    archive_backup_size = entry.file_size
                if artifact_name == "acquisition.json":
                    acquisition_metadata_count += 1
                    if acquisition_metadata_count > 1:
                        raise ReportError("AndroidQF ZIP contains multiple acquisition.json entries")
                    if acquisition_metadata is not None:
                        raise ReportError("AndroidQF ZIP contains multiple acquisition.json entries")
                    try:
                        value = json.loads(archive.read(entry).decode("utf-8"))
                        if not isinstance(value, dict):
                            raise ReportError("AndroidQF acquisition.json must contain an object")
                        acquisition_metadata = value
                    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                        raise ReportError("AndroidQF acquisition.json is malformed") from exc
                if any(part.lower() == "intrusion_logs" for part in parts[:-1]) and entry.file_size > 0:
                    intrusion_file_count += 1
    module_failed = False
    module_partial = partial_marker
    if acquisition_metadata is None and artifact_counts.get("acquisition.json", 0) > 0:
        raise ReportError("AndroidQF acquisition.json could not be parsed")
    if acquisition_metadata is not None:
        outcomes = acquisition_metadata.get("module_results")
        if not isinstance(outcomes, list) or not outcomes or any(not isinstance(item, dict) for item in outcomes):
            raise ReportError("AndroidQF acquisition.json module_results must be a nonempty list of objects")
        statuses = [item.get("status") for item in outcomes if isinstance(item, dict)]
        if any(not isinstance(status, str) or status not in {"completed", "partial", "failed"} for status in statuses):
            raise ReportError("AndroidQF acquisition.json contains an unknown module status")
        names = [item.get("name") for item in outcomes]
        if any(not isinstance(name, str) or not name.strip() for name in names) or len(set(names)) != len(names):
            raise ReportError("AndroidQF acquisition.json contains missing or duplicate module names")
        if all(status == "completed" for status in statuses):
            complete, module_partial = True, False
        elif any(status in {"partial", "failed"} for status in statuses):
            complete = False
            failed = any(status == "failed" for status in statuses)
            module_failed = failed
            module_partial = not failed or partial_marker
    raw_module_results = acquisition_metadata.get("module_results") if acquisition_metadata else None
    module_results_safe: list[dict[str, str]] = []
    if isinstance(raw_module_results, list):
        for index, item in enumerate(raw_module_results, start=1):
            if not isinstance(item, dict):
                continue
            module_name = item.get("name")
            if not isinstance(module_name, str) or not module_name or Path(module_name).name != module_name or any(char in module_name for char in ("/", "\\", "\x00")) or any(ord(char) < 32 or ord(char) == 127 or 0x202A <= ord(char) <= 0x202E or 0x2066 <= ord(char) <= 0x2069 for char in module_name):
                module_name = f"module-{index}"
            raw_status = item.get("status")
            module_status = raw_status if isinstance(raw_status, str) and raw_status in {"completed", "partial", "failed"} else "unknown"
            module_results_safe.append({"name": module_name, "status": module_status})
    backup = source / "backup.ab" if source.is_dir() else None
    backup_present = artifact_counts.get("backup.ab", 0) > 0
    try:
        if backup and backup.is_file() and not backup.is_symlink():
            backup_size = backup.stat().st_size
        else:
            backup_size = archive_backup_size or 0
    except OSError:
        backup_size = 0
    return {
        "acquisition_completion": "complete" if complete and not failed else "failed" if failed and (module_failed or "fatal error" in lowered_log or "acquisition failed" in lowered_log) else "partial" if module_partial else "unverified",
        "acquisition_log_present": (source / "command.log").is_file() and not (source / "command.log").is_symlink() if source.is_dir() else artifact_counts.get("command.log", 0) > 0,
        "acquisition_metadata_present": acquisition_metadata_count > 0,
        "bugreport_present": artifact_counts.get("bugreport.zip", 0) > 0,
        "dumpsys_present": artifact_counts.get("dumpsys.txt", 0) > 0,
        "process_list_present": artifact_counts.get("processes.json", 0) > 0 or artifact_counts.get("processes.txt", 0) > 0,
        "services_list_present": artifact_counts.get("services.txt", 0) > 0,
        "backup_present": backup_present,
        "backup_size_bytes": backup_size,
        "module_results": module_results_safe,
        "intrusion_logs": "collected" if intrusion_file_count else "not_collected",
        "intrusion_log_file_count": intrusion_file_count,
        "limitations": [
            "AndroidQF over ADB does not provide a full-device filesystem image.",
            "Android app data and diagnostic logs can be unavailable or inconsistent across devices.",
            "No Intrusion Logs were included in this acquisition." if not intrusion_file_count else "Intrusion Logs were included, but may cover only the period after the feature was enabled.",
        ],
    }


def _wizard(*, runner=None) -> int:
    if runner is None:
        runner = subprocess.run
    print("Pegasus Hunter — phone spyware check")
    print("This works on an existing phone backup or forensic export; it does not connect to a phone by itself.")
    print("No software can prove a phone is completely free of spyware.")
    print("Only check a device you own or have permission to examine. Type q to quit.\n")

    try:
        platform_answer = _ask("Choose 1 or 2 (or q to quit): ").lower()
    except (EOFError, KeyboardInterrupt):
        print("Cancelled. Nothing was scanned or uploaded.")
        return 0
    if platform_answer == "q":
        print("Cancelled. Nothing was scanned or uploaded.")
        return 0
    if platform_answer not in {"1", "2"}:
        print("Please restart Pegasus Hunter and choose 1 or 2.")
        return 2
    platform = "ios" if platform_answer == "1" else "android"
    acquisition = "backup"
    if platform == "ios":
        try:
            choice = _ask("iOS input: 1) backup folder  2) filesystem export (q to quit): ").lower()
        except (EOFError, KeyboardInterrupt):
            print("Cancelled. Nothing was scanned or uploaded.")
            return 0
        if choice == "q":
            print("Cancelled. Nothing was scanned or uploaded.")
            return 0
        if choice not in {"1", "2"}:
            print("Please restart Pegasus Hunter and choose 1 or 2.")
            return 2
        acquisition = "backup" if choice == "1" else "filesystem"
    else:
        print("Android: use an existing AndroidQF acquisition directory or ZIP archive; the guided Android backup option is SMS-only.")
        try:
            choice = _ask("Android input: 1) SMS backup  2) AndroidQF acquisition directory (q to quit): ").lower()
        except (EOFError, KeyboardInterrupt):
            print("Cancelled. Nothing was scanned or uploaded.")
            return 0
        if choice == "q":
            print("Cancelled. Nothing was scanned or uploaded.")
            return 0
        if choice not in {"1", "2"}:
            print("Please restart Pegasus Hunter and choose 1 or 2.")
            return 2
        acquisition = "backup" if choice == "1" else "androidqf"

    try:
        source_text = _ask("Enter the input backup/acquisition path (or q to quit): ")
        if source_text.lower() == "q":
            print("Cancelled. Nothing was scanned or uploaded.")
            return 0
        output_text = _ask("Enter a NEW results folder path (or q to quit): ")
        if output_text.lower() == "q":
            print("Cancelled. Nothing was scanned or uploaded.")
            return 0
    except (EOFError, KeyboardInterrupt):
        print("Cancelled. Nothing was scanned or uploaded.")
        return 0

    source, output = Path(source_text).expanduser(), Path(output_text).expanduser()
    if not source.exists():
        print("Input path does not exist. Nothing was scanned.", file=sys.stderr)
        return 2
    if acquisition == "androidqf" and not source.is_dir() and not (source.is_file() and zipfile.is_zipfile(source)):
        print("AndroidQF input must be a directory or valid ZIP archive. Nothing was scanned.", file=sys.stderr)
        return 2
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        print("Results folder must be new or empty; existing files were not changed.", file=sys.stderr)
        return 2

    try:
        update = _ask("Update public MVT spyware indicators from the internet first? (y/N): ").lower()
    except (EOFError, KeyboardInterrupt):
        print("Cancelled. Nothing was scanned or uploaded.")
        return 0
    if update not in {"y", "yes", "n", "no", ""}:
        print("Please answer y or n. Nothing was scanned.", file=sys.stderr)
        return 2
    if update in {"y", "yes"}:
        print("Updating Pegasus Hunter's public MVT-compatible indicator cache. This contacts indicator source sites only; your device backup is not uploaded.")
        cache = _default_indicator_cache()
        try:
            manifest = update_indicator_cache(cache)
        except (OSError, ReportError) as exc:
            print(f"Indicator update failed: {exc}. Stopping without scanning.", file=sys.stderr)
            return 2
        if manifest["status"] != "complete":
            print(f"Only a {manifest['status']} indicator update was obtained. Fix the listed download failures and run again; no scan was run.", file=sys.stderr)
            for failure in manifest["failures"]:
                print(f"  {failure['name']}: {failure['error']}", file=sys.stderr)
            return 2
        print(f"Updated {len(manifest['collections'])} public collections at {manifest['updated_at']}.")
    else:
        cache = _default_indicator_cache()
        manifest = load_indicator_cache(cache)
        if manifest["status"] != "complete":
            print("No complete Pegasus Hunter indicator cache is available. Update the indicators to continue.", file=sys.stderr)
            return 2
        print(f"Using cached public indicators updated {manifest['updated_at']}.")

    try:
        consent = _ask("Ready to scan this saved device data locally? (y/N): ").lower()
    except (EOFError, KeyboardInterrupt):
        print("Cancelled. Nothing was scanned or uploaded.")
        return 0
    if consent not in {"y", "yes"}:
        print("Cancelled. Nothing was scanned.")
        return 0

    args = type("Args", (), {
        "platform": platform,
        "acquisition": acquisition,
        "source": source,
        "output": output,
        "ioc": [],
        "indicator_cache": cache,
    })()
    return _run_scan(args, runner=runner)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "wizard":
            return _wizard()
        if args.command == "update-indicators":
            cache = args.cache or _default_indicator_cache()
            manifest = update_indicator_cache(cache)
            print(json.dumps({"cache": str(cache.resolve()), **manifest}, indent=2, sort_keys=True))
            return 0 if manifest["status"] == "complete" else 2
        if args.command == "scan":
            if args.indicator_cache is None:
                args.indicator_cache = _default_indicator_cache()
            return _run_scan(args)
        if args.command == "summarize":
            report = analyze_results(args.results)
            print(json.dumps(report, sort_keys=True, indent=2) if args.format == "json" else render_text(report))
            return 0
        return _run_scan(args)
    except (ReportError, OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"pegasushunter: {exc}", file=sys.stderr)
        return 2
