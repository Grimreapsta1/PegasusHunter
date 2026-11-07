from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class ReportError(ValueError):
    """MVT results are missing or can't be interpreted safely."""


def _repetitive_mount_summary(findings: list[dict[str, Any]]) -> dict[str, Any] | None:
    mounts = [row for row in findings if row.get("module") == "mounts"]
    if len(mounts) < 2:
        return None
    groups: dict[str, list[dict[str, Any]]] = {}
    read_write_mounts = 0
    for row in mounts:
        message = row.get("message")
        if isinstance(message, str) and "mounted as read-write" in message.lower():
            read_write_mounts += 1
        if not isinstance(message, str) or "Suspicious mount options found for " not in message:
            continue
        descriptor = message.split("Suspicious mount options found for ", 1)[1].rsplit(":", 1)[-1].strip()
        if descriptor.lower() == "rw":
            continue
        groups.setdefault(descriptor, []).append(row)
    repeated = [(name, rows) for name, rows in groups.items() if len(rows) > 1]
    if not repeated:
        return None
    return {
        "repeated_finding_count": sum(len(rows) for _, rows in repeated),
        "repeated_noatime_count": sum(len(rows) for name, rows in groups.items() if name.lower() == "noatime"),
        "distinct_pattern_count": len(repeated),
        "patterns": [
            {"pattern": name, "count": len(rows)}
            for name, rows in sorted(repeated, key=lambda item: (-len(item[1]), item[0]))[:3]
        ],
        "read_write_mount_count": read_write_mounts,
    }


def _records(value: Any, filename: str) -> list[dict[str, Any]]:
    if isinstance(value, list):
        if all(isinstance(row, dict) for row in value):
            return value
        raise ReportError(f"{filename} must contain a JSON list of objects")
    if isinstance(value, dict):
        if any(key in value for key in ("level", "severity", "module", "message", "description", "data")):
            return [value]
        raise ReportError(f"{filename} does not contain an MVT alert record")
    raise ReportError(f"{filename} must contain a JSON object or list")


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReportError(f"cannot read {path.name}: {exc}") from exc


def _indicator_object(row: dict[str, Any]) -> dict[str, Any] | None:
    matched = row.get("matched_indicator")
    if matched is None and isinstance(row.get("data"), dict):
        matched = row["data"].get("matched_indicator")
    return matched if isinstance(matched, dict) else None


def _indicator_label(row: dict[str, Any]) -> str | None:
    matched = _indicator_object(row)
    if matched is None:
        return None
    label = matched.get("name") or matched.get("malware_family") or matched.get("family")
    return label.strip() if isinstance(label, str) and label.strip() else "Named public indicator"


def _coverage_warnings(directory: Path, info: dict[str, Any] | None, alerts_path: Path, sources: list[str]) -> list[str]:
    warnings: list[str] = []
    if info is None:
        warnings.append("MVT run metadata is missing or unreadable; scan completion cannot be confirmed.")
    if not alerts_path.is_file() and info is None:
        warnings.append("Neither MVT alerts nor usable run metadata were found; this may not be a completed scan.")
    log = directory / "command.log"
    if log.is_file():
        try:
            text = log.read_text(encoding="utf-8", errors="replace")
        except OSError:
            warnings.append("MVT's command log could not be read.")
        else:
            lowered = text.lower()
            # MVT logs individual heuristic alerts at ERROR severity. Only
            # recognize explicit completion/failure messages here.
            routine_markers = (
                "packages.json file not found in this androidqf bundle",
                "getprop.txt file not found",
                "no root_binaries.json file found",
                "no mount information file found",
                "skipping bugreport modules as no bugreport.zip found",
                "skipping backup modules as no backup.ab found",
            )
            relevant_lines: list[str] = []
            for line in lowered.splitlines():
                if any(token in line for token in ("traceback", "fatal error", "exception", "module failed", "failed; skipped")):
                    relevant_lines.append(line)
                    continue
                if any(marker in line for marker in routine_markers):
                    continue
                relevant_lines.append(line)
            relevant_log = "\n".join(relevant_lines)
            fatal_markers = ("traceback", "fatal error", "exception", "module failed", "failed; skipped")
            if any(token in relevant_log for token in fatal_markers):
                warnings.append("MVT's command log reports an error or failed module; some scan steps may be incomplete.")
            elif "warning" in relevant_log and "failed" in relevant_log:
                warnings.append("MVT's command log reports a warning about a failed module.")
    if info is not None and "mvt_version" not in info and "version" not in info:
        warnings.append("MVT version metadata is missing; this may be an incomplete result set.")
    if "incomplete-run-metadata" in sources:
        warnings.append("MVT run metadata is incomplete; result is a summary of the supplied files only.")
    return warnings


def _sanitize_androidqf_snapshot(value: dict[str, Any]) -> dict[str, Any]:
    """Allowlist fields in the stored AndroidQF coverage snapshot."""
    completions = {"complete", "partial", "failed", "unverified"}
    completion = value.get("acquisition_completion")
    if not isinstance(completion, str) or completion not in completions:
        completion = "unverified"
    raw_modules = value.get("module_results")
    modules: list[dict[str, str]] = []
    if isinstance(raw_modules, list):
        for index, row in enumerate(raw_modules, start=1):
            if not isinstance(row, dict):
                continue
            name = row.get("name")
            if not isinstance(name, str) or not name or Path(name).name != name or any(c in name for c in ("/", "\\", "\x00")) or any(ord(c) < 32 or ord(c) == 127 or 0x202A <= ord(c) <= 0x202E or 0x2066 <= ord(c) <= 0x2069 for c in name):
                name = f"module-{index}"
            raw_status = row.get("status")
            status = raw_status if isinstance(raw_status, str) and raw_status in {"completed", "partial", "failed"} else "unknown"
            modules.append({"name": name, "status": status})
    limitations = value.get("limitations")
    known_limitations = {
        "AndroidQF over ADB does not provide a full-device filesystem image.",
        "Android app data and diagnostic logs can be unavailable or inconsistent across devices.",
        "No Intrusion Logs were included in this acquisition.",
        "Intrusion Logs were included, but may cover only the period after the feature was enabled.",
    }
    safe_limitations = [item for item in limitations if item in known_limitations] if isinstance(limitations, list) else []
    backup_size = value.get("backup_size_bytes")
    intrusion_count = value.get("intrusion_log_file_count")
    return {
        "acquisition_completion": completion,
        "acquisition_log_present": value.get("acquisition_log_present") is True,
        "acquisition_metadata_present": value.get("acquisition_metadata_present") is True,
        "module_results": modules,
        "bugreport_present": value.get("bugreport_present") is True,
        "dumpsys_present": value.get("dumpsys_present") is True,
        "process_list_present": value.get("process_list_present") is True,
        "services_list_present": value.get("services_list_present") is True,
        "backup_present": value.get("backup_present") is True,
        "backup_size_bytes": backup_size if type(backup_size) is int and backup_size >= 0 else 0,
        "intrusion_logs": value.get("intrusion_logs") if isinstance(value.get("intrusion_logs"), str) and value.get("intrusion_logs") in {"collected", "not_collected"} else "not_collected",
        "intrusion_log_file_count": intrusion_count if type(intrusion_count) is int and intrusion_count >= 0 else 0,
        "limitations": safe_limitations,
    }


def analyze_results(results_dir: Path) -> dict[str, Any]:
    directory = Path(results_dir).expanduser()
    if not directory.exists() or not directory.is_dir():
        raise ReportError(f"results directory does not exist or is not a directory: {directory}")

    alerts_path = directory / "alerts.json"
    detected_paths = sorted(directory.glob("*_detected.json"))
    if any(path.is_symlink() for path in detected_paths):
        raise ReportError("MVT result files must not be symlinks")
    detected_files = [path for path in detected_paths if path.is_file()]
    info_path = directory / "info.json"
    scan_meta_path = directory / "pegasushunter_scan.json"
    if any(path.is_symlink() for path in (info_path, alerts_path, scan_meta_path)):
        raise ReportError("MVT result metadata and alerts must not be symlinks")
    info_value = _read_json(info_path) if info_path.is_file() else None
    info = info_value if isinstance(info_value, dict) else None

    def read_result_file(path: Path) -> Any:
        if path.is_symlink():
            raise ReportError(f"MVT result file must not be a symlink: {path.name}")
        return _read_json(path)

    findings: list[dict[str, Any]] = []
    sources: list[str] = []
    if alerts_path.is_file():
        findings.extend(_records(read_result_file(alerts_path), alerts_path.name))
        sources.append(alerts_path.name)
        for path in detected_files:
            findings.extend({"_source_file": path.name, **row} for row in _records(read_result_file(path), path.name))
            sources.append(path.name)
    else:
        # MVT 2026 AndroidQF may report through per-module JSON and omit alerts.json.
        for path in detected_files:
            findings.extend({"_source_file": path.name, **row} for row in _records(read_result_file(path), path.name))
            sources.append(path.name)
        if not detected_files:
            if not info:
                raise ReportError("MVT output has no alerts, module results, or usable run metadata")
            if ("version" in info and "mvt_version" not in info) or "mvt_version" not in info or not (directory / "command.log").is_file():
                sources.extend([info_path.name, "incomplete-run-metadata"])
            else:
                sources.extend([info_path.name, "command.log"])
                if not info.get("date") or "ioc_files" not in info:
                    sources.append("incomplete-run-metadata")

    unique: dict[str, dict[str, Any]] = {}
    for row in findings:
        canonical = dict(row)
        canonical.pop("_source_file", None)
        unique.setdefault(json.dumps(canonical, sort_keys=True, separators=(",", ":"), default=str), row)
    findings = list(unique.values())

    scan_meta = None
    if scan_meta_path.is_file():
        try:
            value = read_result_file(scan_meta_path)
            scan_meta = value if isinstance(value, dict) else None
        except ReportError:
            warnings = ["Pegasus Hunter scan metadata is unreadable; indicator provenance is uncertain."]
        else:
            warnings = []
    else:
        warnings = []
    if not detected_files and not alerts_path.is_file():
        if info is None:
            raise ReportError("MVT output has no alerts, module results, or usable run metadata")
        sources.append(info_path.name)
        if "version" not in info and "mvt_version" not in info:
            sources.append("incomplete-run-metadata")
        if "mvt_version" in info and not (directory / "command.log").is_file():
            sources.append("incomplete-run-metadata")
        if "mvt_version" in info and "date" not in info:
            sources.append("incomplete-run-metadata")
    if "incomplete-run-metadata" in sources:
        warnings.append("MVT run metadata is incomplete; result is a summary of the supplied files only.")
    if not alerts_path.is_file() and "mvt_version" in (info or {}) and (directory / "command.log").is_file():
        sources.append("command.log")
    if alerts_path.is_file() and info is None:
        warnings.append("MVT run metadata is missing; the results cannot confirm scan completion.")
    warnings.extend(_coverage_warnings(directory, info, alerts_path, sources))
    androidqf_coverage = None
    if scan_meta and scan_meta.get("acquisition") == "androidqf":
        saved_coverage = scan_meta.get("androidqf_coverage")
        if isinstance(saved_coverage, dict):
            androidqf_coverage = _sanitize_androidqf_snapshot(saved_coverage)
        else:
            warnings.append("AndroidQF coverage snapshot is unavailable; acquisition status and artifacts cannot be verified by summarize.")
    if androidqf_coverage:
        if androidqf_coverage["intrusion_logs"] != "collected":
            warnings.append("Android Intrusion Logs were not included in the acquisition; intrusion-log IOC checks were unavailable.")
        if androidqf_coverage["acquisition_completion"] == "partial":
            warnings.append("AndroidQF acquisition metadata reports partial or failed module outcomes; inspect module_results in the report.")
        elif androidqf_coverage["acquisition_completion"] != "complete":
            warnings.append("AndroidQF acquisition completion could not be verified from its log or metadata.")
    if scan_meta and scan_meta.get("indicator_status") in {"missing", "failed", "partial"}:
        warnings.append("Public indicator coverage was missing or incomplete for this scan.")
    unique: dict[str, dict[str, Any]] = {}
    for row in findings:
        canonical = dict(row)
        canonical.pop("_source_file", None)
        unique.setdefault(json.dumps(canonical, sort_keys=True, separators=(",", ":"), default=str), row)
    findings = list(unique.values())



    indicator_counts: dict[str, int] = {}
    module_counts: dict[str, int] = {}
    unattributed = 0
    for row in findings:
        label = _indicator_label(row)
        if label:
            indicator_counts[label] = indicator_counts.get(label, 0) + 1
        else:
            module = row.get("module")
            if isinstance(module, str) and module.strip():
                module_counts[module.strip()] = module_counts.get(module.strip(), 0) + 1
            else:
                unattributed += 1

    indicator_matches = sum(indicator_counts.values())
    heuristic_matches = sum(module_counts.values()) + unattributed
    repetitive_mounts = _repetitive_mount_summary(findings)
    info_iocs = info.get("ioc_files", []) if info else []
    ioc_collections = []
    if isinstance(info_iocs, list):
        for item in info_iocs:
            if not isinstance(item, str) or not item.strip():
                continue
            basename = item.replace("\\", "/").rsplit("/", 1)[-1]
            if basename and basename not in ioc_collections:
                ioc_collections.append(basename)
    if indicator_matches:
        assessment = "indicator_match_found"
        indicator_word = "one" if indicator_matches == 1 else str(indicator_matches)
        summary = (
            f"MVT found potential spyware-related evidence, including {indicator_word} public spyware indicator match. "
            "This may show attempted targeting; it does not prove successful infection or active spyware."
        )
    elif heuristic_matches:
        assessment = "heuristics_need_review"
        summary = (
            f"MVT reported {heuristic_matches} heuristic findings, but no public spyware-indicator matches were found. "
            "Some alerts may result from normal settings, device customization, or artifacts needing context; this is not an infection diagnosis."
        )
    elif warnings:
        assessment = "limited_no_match"
        summary = "No known spyware matches were found in the readable results, but scan coverage is limited. This does not prove the phone is clean."
    else:
        assessment = "no_known_matches"
        summary = "No known spyware matches were found in the MVT results provided. This does not prove the phone is clean."

    is_synthetic_fixture = (
        isinstance(scan_meta, dict)
        and scan_meta.get("test_fixture") == "synthetic_published_trace_regression"
    )
    original_status = "evidence_found" if findings else "no_known_matches"
    report = {
        "status": original_status,
        "device_evidence_status": original_status,
        "overall_assessment": assessment,
        "device_evidence_assessment": assessment,
        "synthetic_test_fixture": is_synthetic_fixture,
        "indicator_match_found": bool(indicator_matches),
        "plain_summary": summary,
        "finding_count": len(findings),
        "indicator_match_count": indicator_matches,
        "heuristic_alert_count": heuristic_matches,
        "heuristic_alert_word": {1: "one", 2: "two", 3: "three", 4: "four", 5: "five"}.get(heuristic_matches, str(heuristic_matches)),
        "module_alert_counts": dict(sorted(module_counts.items())),
        "repetitive_mounts": repetitive_mounts,
        "family_counts": dict(sorted(indicator_counts.items())),
        "indicator_counts": dict(sorted(indicator_counts.items())),
        "families": sorted(indicator_counts),
        "unattributed_finding_count": unattributed,
        "source": ", ".join(dict.fromkeys(sources)) or None,
        "coverage_level": "limited" if warnings else "results_present",
        "coverage_warnings": warnings,
        "coverage": {
            "detected_files": [p.name for p in detected_files],
            "alerts_file_present": alerts_path.is_file(),
            "mvt_info_present": info is not None,
            "ioc_collections": ioc_collections,
            "indicator_status": scan_meta.get("indicator_status") if scan_meta else None,
            "indicator_collections": scan_meta.get("indicator_collections", []) if scan_meta else [],
            "indicator_updated_at": scan_meta.get("indicator_updated_at") if scan_meta else None,
            "test_fixture": scan_meta.get("test_fixture") if scan_meta and is_synthetic_fixture else None,
            "androidqf": androidqf_coverage,
            "mvt_metadata": {
                **({key: info[key] for key in ("version", "platform", "start_time", "end_time") if isinstance(info.get(key), (str, int, float, bool))} if info else {}),
                "mvt_version": info.get("mvt_version") if info else None,
                "date": info.get("date") if info else None,
            },
        },
        "findings": [{"severity": row.get("level") or row.get("severity")} for row in findings if isinstance(row.get("level") or row.get("severity"), str)],
        "limitations": [
            "This summarizes MVT artifacts; it does not independently inspect the phone.",
            "Public indicators and available artifacts do not cover every spyware family or attack.",
            "A match is an investigative lead, not proof of successful infection or active infection.",
            "A potential match does not prove successful infection.",
            "No matches do not prove the device is clean; evidence may be missing, erased, unsupported, or not publicly known.",
        ],
    }
    return _apply_synthetic_fixture_disclaimer(report)


def _apply_synthetic_fixture_disclaimer(report: dict[str, Any]) -> dict[str, Any]:
    if report.get("synthetic_test_fixture") is True:
        disclaimer = "Synthetic test fixture—not an assessment of a real device. "
        summary = report.get("plain_summary")
        if isinstance(summary, str) and not summary.startswith(disclaimer):
            report["plain_summary"] = disclaimer + summary
        report["status"] = "synthetic_test_fixture"
        report["overall_assessment"] = "synthetic_test_fixture"
    return report


def render_text(report: dict[str, Any]) -> str:
    _apply_synthetic_fixture_disclaimer(report)
    lines = ["Pegasus Hunter — MVT findings summary", "", report["plain_summary"]]
    if report.get("status") == "synthetic_test_fixture":
        lines.append("Synthetic test fixture: this is not an assessment of a real device.")
    if report["indicator_match_count"]:
        indicator_word = "one" if report["indicator_match_count"] == 1 else str(report["indicator_match_count"])
        lines.append(f"{indicator_word.capitalize()} public spyware indicator match(es) found.")
        lines.append("These are potential leads, not confirmation of infection.")
        lines.append("This does not by itself prove infection.")
        if report["indicator_counts"]:
            lines.append("Indicator collection labels (association only):")
            for name, count in report["indicator_counts"].items():
                lines.append(f"  {name}: {count}")
    if report["heuristic_alert_count"]:
        count = report["heuristic_alert_count"]
        count_word = report.get("heuristic_alert_word", {1: "one", 2: "two", 3: "three", 4: "four", 5: "five"}.get(count, str(count)))
        prefix = "additional " if report["indicator_match_count"] else ""
        lines.append(f"{count_word} {prefix}heuristic findings (not IOC matches)")
        for module, count in report["module_alert_counts"].items():
            lines.append(f"  {module}: {count}")
    if report.get("repetitive_mounts"):
        repeated = report["repetitive_mounts"]
        lines.append(
            f"Mounts: {repeated['repeated_noatime_count']} repeated noatime alerts and "
            f"{repeated['read_write_mount_count']} distinct read-write mount alert(s) to review."
        )
        for item in repeated["patterns"]:
            lines.append(f"  {item['pattern']}: {item['count']} repeated alerts")
        if repeated["read_write_mount_count"]:
            lines.append(f"  Distinct read-write mount alerts to review: {repeated['read_write_mount_count']}")
            lines.append(f"  This acquisition included {repeated['read_write_mount_count']} distinct read-write mount alerts for expert review.")
            lines.append("  Rooted or custom-ROM devices can have system partitions mounted read-write.")
            lines.append("  These alerts indicate possible system modification, not a spyware-indicator match.")
            lines.append("  Confirm whether this matches the phone's intended setup; this is not proof that the alerts are harmless.")
    elif report["unattributed_finding_count"]:
        lines.append(f"Other findings without a named indicator: {report['unattributed_finding_count']}")
    lines.append("")
    lines.append(f"Coverage: {report['coverage_level'].replace('_', ' ')}")
    for warning in report["coverage_warnings"]:
        lines.append("Coverage warning: " + warning)
    if report["coverage"].get("indicator_status") == "complete":
        updated = report["coverage"].get("indicator_updated_at")
        lines.append("Public indicators used: complete cached set" + (f" (updated {updated})" if updated else ""))
    if report["coverage"].get("ioc_collections"):
        lines.append("MVT public IOC collections loaded: " + ", ".join(report["coverage"]["ioc_collections"]))
    aqf = report["coverage"].get("androidqf")
    if aqf:
        lines.append("Android acquisition details:")
        lines.append("  Acquisition completion: " + aqf["acquisition_completion"])
        if aqf["acquisition_completion"] == "complete":
            lines.append("  AndroidQF metadata/logs report its collected modules completed; this does not establish device cleanliness.")
        if aqf.get("acquisition_metadata_present") and aqf.get("module_results"):
            module_results = [
                item for item in aqf.get("module_results", [])
                if isinstance(item, dict) and isinstance(item.get("status"), str)
            ]
            completed = sum(1 for item in module_results if item.get("status") == "completed")
            incomplete = sum(1 for item in module_results if item.get("status") in {"partial", "failed"})
            lines.append(f"  AndroidQF modules: {completed} completed, {incomplete} partial/failed.")
        lines.append("  Intrusion Logs: " + aqf["intrusion_logs"])
        lines.append("  Dumpsys included: " + ("yes" if aqf["dumpsys_present"] else "no"))
        lines.append("  Process list included: " + ("yes" if aqf["process_list_present"] else "no"))
        lines.append("  Services list included: " + ("yes" if aqf["services_list_present"] else "no"))
        if aqf["intrusion_logs"] == "collected":
            lines.append("  Intrusion Log files: " + str(aqf["intrusion_log_file_count"]))
        lines.append("  Bugreport included: " + ("yes" if aqf["bugreport_present"] else "no"))
        lines.append("  SMS/app backup included: " + ("yes" if aqf["backup_present"] else "no"))
        lines.append("  Backup size (bytes): " + str(aqf["backup_size_bytes"]))
        for limitation in aqf["limitations"]:
            lines.append("  Scope note: " + limitation)
    lines.extend([
        "",
        "No known matches do not prove the phone is clean, and public indicators only cover published threats.",
    ])
    if report["overall_assessment"] in {"indicator_match_found", "heuristics_need_review"}:
        lines.append("Next step: preserve the original results and ask a mobile-forensics specialist to review them.")
    elif report["overall_assessment"] == "limited_no_match":
        lines.append("Next step: do not rely on this incomplete result. Check the warnings or ask an expert.")
    return "\n".join(lines)
