# Pegasus Hunter

Pegasus Hunter is a beginner-oriented, privacy-conscious front end for Amnesty International's Mobile Verification Toolkit (MVT). This first working command-line version helps people run MVT on an existing supported backup/export and turns MVT's forensic output into cautious plain English. It is not a standalone malware scanner, antivirus, or proof that a phone is infected or safe.

This release:

- Guides an iOS or Android saved-backup scan with `pegasushunter wizard`.
- Runs installed MVT on iOS backups/filesystem dumps, Android SMS backups, and AndroidQF acquisition directories or ZIP archives.
- Snapshots safe AndroidQF artifact availability and module outcomes from the original directory/ZIP before analysis, retaining that coverage for later summaries. Pegasus Hunter does not collect from a live phone; use the official AndroidQF tool first. See `STEP_BY_STEP.md` for the consent-based workflow.
- Explains common Android read-write system-mount alerts as possible system modification—not a spyware indicator match—and asks the user to compare them with the intended rooted/custom-ROM setup. It does not dismiss them as harmless.
- Downloads a curated set of public MVT-compatible STIX indicator collections only when explicitly requested with `update-indicators`. Review the catalog and source provenance in `pegasushunter/indicators.py` before relying on those feeds.
- Includes Pegasus and other published spyware/stalkerware campaigns, recording source, URL, update time, and indicator counts.
- Validates downloaded STIX bundles before replacing cache files. Scans revalidate cached STIX content and fail closed on malformed bundles; incomplete cache coverage is reported.
- Passes local STIX bundles to MVT, disables its optional shortened-URL lookups during scans, and records which indicator set was used.
- Explains evidence versus no known matches without calling an indicator match a confirmed infection or a no-match result proof of safety.
- Does not upload backup contents. Backups and MVT outputs can contain highly sensitive personal records; keep them private.

## What the result means

“Potential spyware-related evidence” is an investigative lead, not proof that spyware successfully infected the phone or is active now. A threat name in a report identifies an indicator's campaign association, not a confirmed diagnosis.

“No known matches” means no relevant matches appeared in the readable MVT results using the supplied public indicators and available forensic artifacts. It does not prove the phone is clean. Public indicators are incomplete, and evidence can be missing, erased, unsupported, or unavailable to a backup-based scan.

MVT describes itself as a consensual forensic tool for technologists and investigators and warns that public indicators cannot establish that a device is clean. See:
- https://docs.mvt.re/en/stable/introduction/
- https://docs.mvt.re/en/stable/iocs/
- https://github.com/mvt-project/mvt-indicators

Only examine devices you own or have permission to examine. If you may be a high-risk target or results show suspicious evidence, preserve the original data and seek qualified mobile-forensics help.

## Requirements and install

Python 3.11+. Install Pegasus Hunter in a virtual environment. The `scanner` extra installs the pinned MVT version used for development, or install MVT separately using its official instructions. The CLI finds MVT on `PATH` or in the active Python environment.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[scanner,dev]'
python -m pytest -q
```

## Guided use

Read the detailed first-scan walkthrough in [`STEP_BY_STEP.md`](STEP_BY_STEP.md). It covers MVT installation, backup choices, safe decryption, indicator updates, the wizard, results, and limitations.

```sh
pegasushunter wizard
```

The wizard asks which platform and existing input you have, where to save results, whether to update public indicators, and whether to start the local scan. It does not access a connected phone. For iOS, encrypted-backup decryption is not part of the first wizard; prepare a decrypted working backup using MVT's documented workflow. Never type a backup password into Pegasus Hunter.

Update the public indicator cache (requires internet access):

```sh
pegasushunter update-indicators
```

The default cache location is `~/.pegasushunter/indicators`. A custom cache path is supported:

```sh
pegasushunter update-indicators --cache /path/to/indicator-cache
```

The updater reports complete, partial, or failed status. A partial or failed cache is not accepted by the wizard; direct scans can proceed with explicit warnings about missing or incomplete coverage. It downloads indicator bundles only; it does not send phone data.

Direct scans of existing device data:

```sh
pegasushunter scan ios /path/to/decrypted/ios-backup --output /path/to/new-results --indicator-cache ~/.pegasushunter/indicators
pegasushunter scan ios /path/to/full/filesystem-dump --acquisition filesystem --output /path/to/new-results --indicator-cache ~/.pegasushunter/indicators
pegasushunter scan android /path/to/android-backup.ab --output /path/to/new-results --indicator-cache ~/.pegasushunter/indicators
pegasushunter scan android /path/to/androidqf-acquisition.zip --acquisition androidqf --output /path/to/new-results --indicator-cache ~/.pegasushunter/indicators
```

The direct scan command defaults to `~/.pegasushunter/indicators` and warns when a complete cache is unavailable. Custom STIX files can be added with repeated `--ioc /path/to/custom.stix2`. Results must go to a new or empty folder outside the input.

Summarize an MVT results folder without rescanning. For Pegasus Hunter scans, the saved sanitized source snapshot is used instead of reopening MVT's `target_path`; legacy output lacking the snapshot is reported as unverified coverage:

```sh
pegasushunter summarize /path/to/mvt-results
pegasushunter summarize /path/to/mvt-results --format json
```

## Current limits

MVT recommends AndroidQF as the separate Android collection tool, followed by `mvt-android check-androidqf`. Pegasus Hunter analyzes an existing acquisition directory or ZIP archive; it does not acquire from a live phone. It snapshots the original acquisition's safe artifact facts and `acquisition.json` module outcomes before analysis, then preserves that snapshot in reports; summaries never reopen the target path. It cannot independently attest acquisition integrity. Intrusion Logs are optional and may be absent. Its output identifies those coverage gaps and provides additional context for read-write mount alerts. This CLI prototype has not been validated against independent known-clean and known-compromised corpora or on iOS hardware; do not use it as a forensic attestation tool.

## Development

```sh
python -m pytest -q
python -m pegasushunter --help
ruff check pegasushunter tests
pyright
python -m build
```

The default tests use local fixtures. To explicitly verify that every curated indicator URL is reachable and still contains a valid STIX bundle, run:

```sh
PEGASUSHUNTER_TEST_LIVE_INDICATORS=1 python -m pytest -q tests/test_indicators.py::test_indicator_catalog_urls_are_live_and_parseable
```

CI also exercises the installed MVT AndroidQF command against a synthetic ZIP (no device data) after installing the `scanner` extra:

```sh
PEGASUSHUNTER_TEST_MVT_INTEGRATION=1 python -m pytest -q tests/test_cli.py::test_real_mvt_androidqf_zip_smoke
```

Keep collection consensual, data local by default, and every result explicit about evidence and limits.
