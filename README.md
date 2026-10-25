# SentinelBaseline

**Capture. Compare. Verify.**

SentinelBaseline is a PowerShell toolkit for Windows infrastructure inventory, selected security-posture assessment, configuration baseline comparison, and evidence-integrity tracking.

It is designed to help authorized administrators and security practitioners establish a point-in-time view of a Windows system, preserve a versioned snapshot, compare a later assessment against that snapshot, and record integrity metadata for generated artifacts.

> **Important:** SentinelBaseline is an assessment aid—not a penetration-testing tool, complete compliance auditor, or forensic acquisition platform. Local hashes and logs cannot prove that a compromised endpoint or privileged local user has not manipulated the evidence.

## Features

- **System inventory:** host, operating system, firmware, CPU, memory, disks, volumes, and GPU.
- **Security posture indicators:** Secure Boot, TPM, Microsoft Defender, Windows Firewall profiles, UAC, RDP, SMBv1, BitLocker, and selected PowerShell logging policy values.
- **Limited CIS-aligned checks:** a small set of configuration indicators, not a complete CIS Benchmark audit.
- **Network inventory:** adapters, IPv4 addresses, DNS servers, routes, TCP listeners, and UDP endpoints.
- **Device discovery:** removable devices, USB storage, smart-card devices, and portable-device indicators.
- **Reports:** timestamped CSV and readable TXT output.
- **Versioned snapshots:** JSON records with collection metadata and assessment rows.
- **Baseline comparison:** identifies added, removed, and changed records against a selected prior snapshot.
- **Integrity manifest:** SHA-256 hashes for generated artifacts and the script when available.
- **Local evidence trail:** hash-linked JSONL records intended to improve traceability.

Windows 11 readiness testing is intentionally excluded.

## Requirements

- A supported Windows system with PowerShell.
- Administrator execution is recommended for broader collection coverage.
- Availability and completeness of individual fields depend on Windows version, hardware, permissions, and installed cmdlets/modules.

## Quick start

Open PowerShell in the directory containing the script.

### Capture a snapshot

```powershell
.\SentinelBaseline.ps1
```

The default mode is `Capture`. Review the output paths printed by the script. Reports are written beside the script; evidence artifacts are stored in the `Evidence` directory.

### Compare with an earlier snapshot

```powershell
.\SentinelBaseline.ps1 `
  -Mode Compare `
  -BaselinePath ".\Evidence\YOUR-BASELINE.snapshot.json"
```

Replace the example path with the actual snapshot path from a prior run.

Comparison results depend on the identifiers and fields available in the snapshots. Volatile values—such as timestamps, network state, and listener information—may legitimately differ between runs.

## Output overview

Depending on the selected mode and successful collection, the tool may produce:

- `COMPUTER-TIMESTAMP.csv` — structured assessment rows.
- `COMPUTER-TIMESTAMP.txt` — readable report grouped by section.
- `Evidence\COMPUTER-TIMESTAMP.snapshot.json` — versioned snapshot and collection metadata.
- `Evidence\COMPUTER-TIMESTAMP.manifest.json` — SHA-256 hashes and run metadata.
- `Evidence\chain-of-custody.jsonl` — local hash-linked event records.

The CSV report uses the fields `Section`, `Item`, `Value`, `Status`, and `Details`.

## Interpreting results

- A missing or `Unknown` value does **not** mean that a control is secure.
- CIS-labelled checks are limited indicators. A pass does not establish compliance with an entire benchmark.
- The Event Log capacity figure is an estimate, not a measured future growth rate or a retention guarantee.
- Review the output and validate the script on representative systems before relying on it operationally.

## Evidence integrity: what it does and does not mean

SHA-256 manifests can help detect file changes when the manifest itself is trusted. A local hash-linked log can improve traceability, but neither mechanism is tamper-proof against a privileged user or compromised endpoint that can modify files and regenerate hashes.

For stronger evidence handling, use independently administered access-controlled storage, protected signing keys, documented collection and transfer procedures, and separate verification of each artifact and custody record.

## Safety and privacy

Run SentinelBaseline only on systems you own or are explicitly authorized to assess.

Reports and snapshots may contain sensitive information, including hostnames, domain names, hardware serial numbers, MAC/IP addresses, routes, listening ports, device identifiers, removable-media details, and security settings. Do not publish real organizational output. Use synthetic or thoroughly redacted examples.

## Known limitations

- This is a system inventory and preliminary security-posture assessment aid, not a full vulnerability assessment, penetration test, forensic acquisition tool, or compliance certification.
- Some collection commands may be unavailable on particular Windows versions or without elevated permissions.
- Review unknown/blank values and error handling before production use.
- Test capture, comparison, malformed or missing baseline files, and integrity verification in an approved test environment.

## Attribution and license

SentinelBaseline is distributed under the **SentinelBaseline Attribution-Required License** in [`LICENSE`](LICENSE). You must retain the copyright and license notices and provide visible attribution when downloading, using, sharing, redistributing, or modifying the project, as specified by the license.

Suggested attribution:

> SentinelBaseline by Hussain Raza Naqvi — https://github.com/hussainraza110/SentinelBaseline

Replace the placeholder with the canonical repository URL when linking from another site or project. Modified versions must clearly identify that they have been modified and must not imply that the original author endorses the changes.

This is a custom license, not an OSI-approved open-source license. Review it before adopting the project in commercial, employer, or other third-party environments.
