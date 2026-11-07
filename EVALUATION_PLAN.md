Evaluation plan: Pegasus Hunter
Status: local planning aid; not a forensic validation report

Purpose

Evaluate Pegasus Hunter's parsing and reporting behavior without claiming that it detects real-world Pegasus infections. The existing MVT AndroidQF and iOS backup tests are appropriate for exercising compatibility and fixtures; they are not a labeled sensitivity/specificity corpus.

Evaluation phases

1. Synthetic regression scenarios
   - Run the repo's MVT integration test against a minimal synthetic AndroidQF ZIP.
   - Run the new `published_trace_synthetic` fixture test. It checks cautious wording, JSON/text disclaimers and local-path redaction.
   - Add synthetic positives and negatives for each report behavior that matters: single/multiple indicator matches, heuristic-only alerts, missing/partial acquisition coverage, malformed metadata, and routine missing-artifact logs.
   - Label every generated fixture `synthetic`; never count these as confirmed compromised or benign devices.

2. Upstream integration fixtures
   - Inspect the public MVT tests under `tests/android_androidqf` and `tests/ios_backup` and identify which fixture data/license terms permit reuse.
   - Prefer generating tiny, privacy-scrubbed fixtures in Pegasus Hunter tests from MVT's fixture schemas rather than importing entire upstream test trees.
   - Record the MVT version and exact fixture provenance. Do not copy test data or alter licenses until the upstream terms are checked.
   - Verify the scan command/output/report vertical path against these fixtures; this establishes compatibility, not detection accuracy.

3. Independent known-compromised material
   - Do not download or redistribute raw victim backups from reports. Public Pegasus reports expose forensic traces and case summaries, not a general public raw-phone corpus. Case-specific traces can seed a synthetic test only when each derived value is clearly fictionalized and labeled as simulated.
   - Ask Citizen Lab about a consented research collaboration or a sanitized evaluation sample; do not assume backups they reviewed are downloadable.
   - Ask Amnesty Security Lab about research collaboration only if there is a suitable research/civil-society basis; its public support channels are not general developer support, and it can decline requests.
   - Request an agreed, minimal artifact set or supervised evaluation—not a person's raw phone backup. Obtain consent and redistribution terms in writing before any transfer.
   - Treat a sample as a positive label only when a qualified independent examiner supplies defensible ground truth and the chain/provenance are documented. A published IOC hit alone is not ground truth for a whole device.

4. Known-benign samples
   - Use only devices/accounts whose owners explicitly consent and who understand what the collection contains. For a project not yet enrolled in formal research, ask the owners to provide only the minimal synthetic/public test data, not their full personal backups.
   - Record scope, OS/build, acquisition method, date, tool versions, and known custom/rooted state; do not publish raw records.
   - A no-match result on one device is not proof that it is benign; label it “no known compromise evidence in this acquisition” unless independently characterized.

5. Scoring and report
   - Predefine case-level expected findings and scoring before examining outputs.
   - Report per-case: input scope and availability, expected indicators/artifacts, observed results, false positives, misses, and limitations.
   - Separate parser/report correctness from true-world detection accuracy. Do not claim rates from tiny or non-random samples.
   - Preserve raw samples in controlled storage; publish only synthetic, reviewed, non-identifying derived fixtures with permission.

7. Public indicator catalogue
   - Compare the curated collection URLs against MVT's official `mvt-indicators/indicators.yaml`; an opt-in live test now asserts exact URL-set parity.
   - The current comparison covers 19 of 19 upstream indexed collections. It verifies catalogue coverage only, not device evidence or whether each artifact is relevant to every platform.
   - Keep the README explicit that public IOCs are incomplete, collected from published research, may miss recent or non-public traces, and cannot prove a device clean. Attribute each collection to its listed source and preserve its upstream references/license terms.
   - Refreshing the catalogue means reviewing the official index and supported platform relevance, updating `COLLECTIONS`, and running both the parity check and live STIX validation; do not silently claim that the list is perpetually current.


Current blockers to stronger claims

- No authorized, independently labeled known-compromised sample is available in this project.
- No representative independently verified benign corpus is available.
- No iOS hardware validation is recorded.
- Passing MVT fixtures and CI do not establish forensic validity or detection rates.
- The report produced from this folder is marked `synthetic_test_fixture` in JSON status/assessment and carries a disclaimer in plain_summary/text; it is not device evidence.

Synthetic report fields:

| Field | Meaning | Use |
|---|---|---|
| `synthetic_test_fixture` | Boolean caution marker only; not a verified claim about where the data came from. | Treat as a warning; it is editable metadata, not cryptographic provenance. |
| `device_evidence_status` / `device_evidence_assessment` | Underlying MVT result and interpretation before the synthetic label is applied. | Use these for the finding interpretation; this report is still not independently validated evidence. |


Contact drafts

A. Citizen Lab — inquiries@citizenlab.ca
Subject: Inquiry about consented mobile-forensics evaluation data

Hello Citizen Lab,

I maintain Pegasus Hunter, a private, early-stage front end for MVT. I’m planning an evaluation of its interpretation/reporting against independently confirmed mobile-forensics cases. I read your public peer review of Amnesty International’s Pegasus methodology and understand you reviewed backups supplied for that investigation. I am not assuming those backups are public or available for reuse.

I understand you do not provide technical assistance to individual members of the public; I am writing only to ask whether there is an appropriate research collaboration, consented/sanitized evaluation sample, or protocol you recommend. I do not need raw personal backups; a supervised evaluation or minimal non-identifying artifact set would be preferable. I would agree to your consent, security, retention, and non-redistribution requirements before receiving any data.

If this is outside your current scope, a referral to a suitable public or research resource would be appreciated. I can send a short protocol and repository details if useful.

Best,
Paul

B. Amnesty International Security Lab — share@amnesty.tech
Subject: Research inquiry: consented evaluation of an MVT front end

Hello Amnesty Security Lab,

I maintain Pegasus Hunter, a private prototype that wraps MVT for local scanning and cautious report summaries. I am trying to establish an ethical evaluation method and do not want victim data or raw backups without explicit permission and a secure, agreed process.

If appropriate for your remit, could you advise whether a research collaboration, supervised evaluation, or minimal sanitized artifact sample is possible? I understand you may not provide general developer support and may be unable to respond. I would follow any consent, security, retention, and non-redistribution requirements and would not publish case details or derived artifacts without approval.

If this is not suitable, please feel free to decline or direct me to a more appropriate research channel.

Best,
Paul

C. MVT maintainers — use the repository's public issue/maintainer channel
Subject: Recommended upstream test fixtures for AndroidQF/iOS integration testing

Hello MVT maintainers,

I maintain Pegasus Hunter, a small MVT front end. We have an opt-in test that runs `mvt-android check-androidqf` on a synthetic ZIP and local regression fixtures for cautious reporting. I’m looking to test integration compatibility—not claim spyware detection accuracy.

Could you point me to the currently supported, redistributable AndroidQF and iOS backup test fixtures, their applicable licenses, and any recommended public command-level tests for downstream wrappers? I will not redistribute private acquisitions and will preserve upstream attribution and licensing requirements.

Thanks,
Paul

Pre-send review

- Replace “Paul” with the identity/contact details you want to use, if needed.
- Add your affiliation only if accurate; do not imply you represent a lab or civil-society organization.
- Include the private repository URL only if you want to share it and the recipient is authorized to access it.
- Do not attach device data, serials, screenshots, backups, logs, or MVT result folders to first-contact emails.
- The drafts are not sent.
