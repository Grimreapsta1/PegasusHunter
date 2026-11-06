# Pegasus Hunter: step-by-step first scan

This guide is for the Kali/Linux machine where Pegasus Hunter is installed. Commands below assume the project is at `/home/kali/Projects/PegasusHunter`. The scan examines an existing backup/export; it does not inspect a live phone directly.

Safety first: only scan a device you own or have permission to examine. Do not upload or casually share the backup or results; they may contain private messages, identifiers, contacts, and other personal data. Public indicator matches are clues, not proof of infection. No matches are not proof the phone is safe.

## 1. Open a terminal and enter the project

```sh
cd /home/kali/Projects/PegasusHunter
```

## 2. Activate Pegasus Hunter's virtual environment

```sh
source .venv/bin/activate
```

If that says the environment does not exist, create it and install Pegasus Hunter plus its scanner extra:

```sh
python3 -m venv .venv
```

```sh
.venv/bin/python -m pip install -e '.[scanner]'
```

Activate the newly created environment before using the bare `pegasushunter` and `mvt-*` commands below:

```sh
source .venv/bin/activate
```

Check that the commands are available:

```sh
pegasushunter --help
```

```sh
mvt-ios --help
```

```sh
mvt-android --help
```

AndroidQF is a separate collector; Pegasus Hunter does not install or run it. Download it only from the official release page linked in step 5.

If an MVT command is missing, see MVT's installation instructions: https://docs.mvt.re/en/stable/install/ . On Linux MVT recommends a Python 3.11+ environment; follow its prerequisites for your distribution. Avoid installing Python packages into Kali's system Python. If the `scanner` extra was not installed, with this project's environment active you can run `python -m pip install mvt`.

## 3. Make an iPhone backup (skip to step 4 for Android)

On macOS, connect the iPhone, open Finder, select the phone, choose “Back up all of the data on your iPhone to this Mac,” enable “Encrypt local backup,” then select “Back Up Now.” Keep the backup password private and safe. MVT reports that encrypted backups include additional useful records. Apple's encrypted backup feature is operated in Finder; this computer must be the one that holds the backup.

On Windows, use Apple's supported iTunes/Apple Devices backup workflow. MVT documents backup locations under `%USERPROFILE%\Apple\MobileSync\` or `%USERPROFILE%\AppData\Roaming\Apple Computer\MobileSync\`. This Pegasus Hunter project is currently developed/tested on Linux; Windows-native use isn't verified.

For MVT-compatible backups made with `pymobiledevice3`, see MVT's guide: https://docs.mvt.re/en/stable/ios/backup/pymobiledevice3/ . Don’t put a real backup password in a shell command: command arguments can be saved in shell history or visible to other local processes.

Copy the backup folder onto the Linux computer using a private, access-controlled method. Do not copy it into the Pegasus Hunter project folder or a cloud/shared folder. The backup is usually a directory containing `Manifest.db` and `Info.plist`.

## 4. Decrypt an encrypted iPhone backup

MVT cannot analyze an encrypted backup as-is. In the terminal, set paths for your real backup and a new private decrypted-output folder. Replace the example path only with the path to your backup:

```sh
BACKUP="$HOME/path/to/iphone-backup"
```

```sh
DECRYPTED="$HOME/phone-check/decrypted-iphone-backup"
```

Make the parent folder if needed:

```sh
mkdir -p "$HOME/phone-check"
```

Run MVT's decrypt command; it will prompt for the backup password instead of putting it in shell history:

```sh
mvt-ios decrypt-backup -d "$DECRYPTED" "$BACKUP"
```

If the backup is unencrypted, skip this step and use its folder as the scan input. Do not guess or share forgotten passwords. Keep decrypted data private and remove it securely when you no longer need it, accounting for your storage/backup policy.

## 5. Make an Android backup or AndroidQF acquisition (skip if checking iPhone)

MVT's `mvt-android check-backup` focuses on SMS in Android backups; it is not a full Android spyware detector. Recent Android versions may not support local ADB backups, and apps can exclude data. Treat this source as narrow.

If your phone and Android platform tools still support ADB backup, connect and authorize your own phone, then run:

```sh
adb backup -nocompress com.android.providers.telephony
```

Follow any on-device prompt. The resulting `backup.ab` is typically in the current directory. If unsupported or refused, do not interpret that as a clean result. MVT's Android backup guide: https://docs.mvt.re/en/stable/android/backup/ .

For broader Android diagnostics, use the official AndroidQF acquisition workflow on a phone you own or are authorized to examine. This is a separate, live-device collection step—not a Pegasus Hunter command. Connect the phone over USB, enable USB debugging, and approve the host-key prompt on the phone only if you are the owner or have explicit consent. Download AndroidQF from its official releases page and follow its README prompts; the collector writes a ZIP archive, with output controlled by `-output` (default: current directory). The archive may contain highly sensitive bugreports, settings, package/process/service lists, logs, and SMS/app data. Save it in private storage; do not put it in the project, a shared directory, or cloud storage.

AndroidQF archives include `acquisition.json`, which records module statuses (`completed`, `partial`, `failed`), and `command.log`. Prefer these over inferring success from the presence of some artifacts. A finalized ZIP can still contain partial module results; check the per-module outcomes. Do not assume that having a `command.log` alone means collection completed.

Android Intrusion Logs are an optional AndroidQF artifact. Their availability depends on device support and Android's Advanced Protection Mode/Intrusion Logging; AndroidQF prompts whether to collect them, and collection may require on-device interaction. If the phone is not compatible, or the user skips the prompt, the scan cannot check those events. Absence is not an all-clear.

Official collector instructions and archive format:
- https://github.com/mvt-project/androidqf
- https://github.com/mvt-project/androidqf/releases/latest
- https://github.com/mvt-project/androidqf/blob/main/docs/acquisition-archives.md
- https://docs.mvt.re/en/latest/android/methodology/
- https://docs.mvt.re/en/latest/android/intrusion_logs/
- https://github.com/mvt-project/androidqf/blob/main/README.md#unattended-acquisitions

Before scanning, inspect the archive listing and `acquisition.json` metadata without modifying the original. AndroidQF records per-module outcomes as `completed`, `partial`, or `failed`; a finalized archive can still have incomplete modules. MVT 2026.11.2 accepts the AndroidQF ZIP archive directly, so extraction is optional; if extracting, preserve its directory structure and store it privately. Pegasus Hunter analyzes the saved acquisition; it does not start or control AndroidQF collection.

With the project environment active, run MVT through Pegasus Hunter:

```sh
pegasushunter scan android "$HOME/phone-check/androidqf.zip" --acquisition androidqf --output "$HOME/phone-check/androidqf-results" --indicator-cache "$HOME/.pegasushunter/indicators"
```

Choose a new results directory outside the acquisition. Pegasus Hunter reads the original acquisition log, artifact inventory, and ZIP `acquisition.json` module outcomes before analysis, storing only a sanitized coverage snapshot in its scan metadata. Later summaries use that snapshot rather than following an MVT target path. If it reports `partial`, inspect module results; if it reports `unverified`, check AndroidQF's own output/status. Missing `acquisition.json` may leave completion unverified even if a command log exists. Never treat a few present files as proof that every requested collection succeeded. The scan turns off MVT's optional network lookups; the device data stays local.

## 6. Update Pegasus Hunter's public indicators

This downloads STIX indicator bundles from their public sources to your computer. It does not upload your backup. You need internet access for this step:

```sh
pegasushunter update-indicators
```

Wait for JSON output with `"status": "complete"`. If it says `partial` or `failed`, do not scan based on that update; read the listed failed sources and try again later. The currently curated feeds represent published threats, not every spyware family or private intelligence.

## 7. Run the guided scan

```sh
pegasushunter wizard
```

Answer the prompts:

1. Choose `1` for iPhone/iPad or `2` for Android.
2. For iOS, choose backup or filesystem export. For Android, choose SMS backup or an existing AndroidQF acquisition directory/ZIP; MVT scans are limited to the artifacts actually collected.
3. Enter the path to your existing backup/export.
4. Choose a new output folder path, such as `$HOME/phone-check/results-2026-11-05`. The date is an example; choose a name that does not already exist or contain files.
5. Answer `y` to update the public indicators, or `n` to use an already complete cache. If you choose `n` and no complete cache exists, the wizard stops without scanning.
6. Review the local-scan/privacy confirmation and answer `y` only if the selected input is the device you are authorized to examine.

The scan runs MVT on your saved data. Keep the terminal output and result folder private. If Pegasus Hunter reports a failure or limited coverage, it will not present that as an all-clear.

## 8. Read the result

The wizard prints the plain-English assessment. To print it again later, use the actual output folder you chose:

```sh
pegasushunter summarize "$HOME/phone-check/results-2026-11-05"
```

For structured JSON output:

```sh
pegasushunter summarize "$HOME/phone-check/results-2026-11-05" --format json
```

If it says potential evidence was found, preserve the original backup and all MVT output and consult a qualified mobile-forensics specialist. Don’t delete evidence or reset the phone before getting advice if an investigation may matter. If it says “no known matches,” remember that it does not prove the device is clean. If the report says “limited,” don’t rely on it as reassurance.

## 9. If this is an urgent/high-risk concern

A self-run backup scan is not a substitute for expert help. Preserve the phone and its state as much as practical; don’t factory-reset it, jailbreak it, install random “spyware detector” apps, or send backup data to unknown services. Contact a trusted digital-security professional. MVT documentation points civil-society users to Amnesty Security Lab and Access Now's Digital Security Helpline: https://securitylab.amnesty.org/get-help/ and https://www.accessnow.org/help/ .

## Scope caveat

This version interprets actual MVT AndroidQF output, reports limited acquisition coverage, and groups repeated mount-option noise. It does not automatically decide whether read-write mounts are expected for a particular ROM or root setup. Even when results show no public indicator match, they are not proof that the phone is clean. Review the original report and, for expert review, the original MVT JSON data.
