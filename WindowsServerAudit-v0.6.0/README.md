# Focused Windows Server security audit — 0.6.0

This release targets your examples on an **already potentially compromised server with no clean reference**. It produces a short findings report and keeps raw collections in separate evidence files.

## Run

Extract the package, open **64-bit Windows PowerShell 5.1 as administrator**, change to the extracted directory, and run:

```powershell
.\Invoke-WindowsServerAudit.ps1
```

Supports Windows Server 2016, 2019, 2022 and 2025, including domain controllers. No additional PowerShell modules are installed. Scripts are unsigned; follow your organization's download/signing policy.

The existing short role/port setup remains. Version 0.5 answer files are compatible:

```powershell
.\Invoke-WindowsServerAudit.ps1 -ConfigPath 'C:\Audit\ServerIntent.json' -NonInteractive
```

No clean baseline or service-by-service configuration is required. Port answers provide context for connections/listeners associated with running script leads; they do not generate a long independent port-anomaly list.

## What generates findings

| Target | Evidence and limits |
| --- | --- |
| Firewall off | Explicit disabled profile states or a stopped/paused Windows Defender Firewall service; grouped into one finding |
| Domain reversible encryption | Reads the current computer's domain password-properties flag; matching fine-grained password policies; matching user-account flags |
| Defender exclusions | Groups visible configured exclusions into one finding with exact values; broad drive/type exclusions get higher priority |
| Defender protection | Flags disabled real-time/antivirus protection when Defender explicitly reports active Normal mode; passive mode is not assumed malicious |
| Known threat reports | Existing Microsoft Defender Antivirus records marked active; inactive history is not called active compromise |
| Suspicious scheduled tasks | Enabled tasks invoking general-purpose runtimes, cron-like schedulers, custom script locations/commands, or specific suspicious command patterns |
| Running scripts | Python, JavaScript and other runtimes; PowerShell with script/command arguments; Windows command/script hosts; cron-like processes |
| Stronger execution/persistence clues | Download-and-execute text, encoded PowerShell, Windows-like program names in unexpected directories, signature hash mismatches, or selected combinations of path/permission/network evidence |
| Possible keyboard capture | Referenced text combining keyboard-capture interfaces/callbacks with capture/logging patterns; explicitly a static lead |
| Database execution features | Local Microsoft Structured Query Language (SQL) Server instances with operating-system command execution or automation features enabled |

**Normal firewall rule breadth is no longer a finding.** Ordinary service startup differences, inherited directory permissions, unsigned files, network connections and unfamiliar names do not generate prominent findings on their own. Direct service configuration grants to broad principals can still merit investigation; these permission checks do not calculate complete effective access for every identity.

Running interpreters are review leads because you explicitly want to see them, not because Python or PowerShell is inherently malicious. Identical worker command lines are grouped, the audit's own process is excluded, and stronger persistence/process findings suppress overlapping simple runtime leads. Disabled tasks stay in supporting evidence. Common Windows maintenance task locations reduce weak custom-script leads, but do not suppress stronger command or keyboard-capture indicators.

## Domain policy checks

Directory reads use the current Windows identity against the assessed computer's domain. They can run from a domain member as well as a domain controller when directory access is available. They do not edit policy, reset passwords, request credentials, read password material or enumerate every domain computer.

The three checks cover:

- Domain `pwdProperties` containing flag value 16.
- Visible password-settings objects with reversible encryption enabled.
- Visible user accounts with account-control flag value 128.

The latter two searches return at most 1000 entries each and report truncation. Policy assignment groups and each user's resultant policy are not expanded. Directory permissions can limit visibility. An enabled setting does not prove which existing passwords were stored reversibly; the report describes the observed configuration. Local account password policy on a standalone server is outside these domain checks.

## Beacons and keyloggers

This audit cannot reliably identify every beacon or compiled/memory-only keylogger from a configuration snapshot. It can surface active antivirus threat reports, referenced script code containing keyboard-capture patterns, suspicious persistence and related process connections.

A script with a delay/network loop is not labeled a confirmed beacon. Such code can be ordinary monitoring. A single keyboard interface name can be a legitimate hotkey implementation. Static text may contain comments/examples; inspect the code and use endpoint detection and response tooling for validation. Referenced script reads are bounded to small files; remote/reparse paths are skipped. Encoded commands are recognized but not decoded or executed.

## Report layout

Open the run folder's **index.html** in Microsoft Edge or another browser permitting local JavaScript.

It contains only:

1. Prioritized findings and running-script review leads.
2. Expandable evidence and the next verification step for each finding.
3. A compact, collapsed list of collection limits.

There is **no embedded inventory, raw serialized data, baseline table, complete file listing or duplicate artifact-card section**. Search, category, priority and reset controls remain. Long observations are truncated for display only; full values remain in evidence files. If scripts are blocked, every finding stays readable and a notice explains why filtering is unavailable. Zero selected findings does not establish that the machine is clean.

`ExampleReport.html` is a **synthetic preview**, not a scan of your computer.

## Separate outputs

Each run creates a new `ServerTriage-<computer>-<timestamp>` folder:

- `index.html`: the short report.
- `ServerIntent.json`: reusable setup answers.
- `Evidence/Coverage.txt`: readable collection status and failures.
- `Evidence/DomainSecurity.json`: exact visible domain findings.
- `Evidence/DefenderSecurity.json`: antivirus mode and existing threat records.
- `Evidence/DefenderVisibleExclusions.json`: visible configured exclusions.
- Other `Evidence/*.json` files: full processes, connections, task/service/startup definitions, file facts, assessments and selected findings.

JavaScript Object Notation (JSON) is used for those separate machine-readable files, not embedded dumps in the report. Protect the output: existing commands or database jobs can contain internal identifiers or secrets.

## Read-only behavior and coverage

No remediation, service changes, firewall changes, account changes, antivirus scans or logging changes occur. Commands found in evidence are never executed. Existing antivirus records are read; event-log timeline analysis is not included. Normal audit reads can themselves create operating-system/security telemetry.

Service/task/startup and Windows Management Instrumentation (WMI) persistence collection remains. Referenced files can receive hashes, signatures, permission checks and small script-text inspection. Windows trust/revocation checks may use ordinary network access. No complete disk/memory scan, injected-code detection, kernel investigation, nested group expansion, comprehensive application configuration audit, software vulnerability matching or compliance certification is provided.

Database reads use the current Windows identity through local shared memory, fixed metadata queries and timeouts. Application table contents are not read. Missing permissions, stopped instances or encrypted definitions are coverage gaps. Use `-SkipSql` to skip these reads. Remote, container, LocalDB and clustered instances are not comprehensively discovered.

Optional legacy snapshot flags remain available, but this workflow does not require a reference or certify a captured baseline as clean.

## Validation

Executed here: static lexical/source checks, the report's actual JavaScript against 11 document-fixture test groups, example-profile checks and archive integrity checks.

**Not executed here:** PowerShell parsing/runtime, live Windows collectors, domain queries and the PowerShell fixture suite. Full browser rendering also remains unverified because the environment blocks browser startup. Pilot the updated audit before relying on its findings.

On Windows, run the dependency-free fixtures with:

```powershell
.\Test-Triage.ps1
```

They cover firewall-off grouping, normal-rule suppression, reversible-encryption findings, grouped exclusions, active/inactive threat distinction, passive antivirus mode, runtime grouping, task selection, association boundaries, weak-signal suppression and absence of raw report dumps.

Developer filter checks require Node.js only:

```text
node Tests/Test-ReportFilters.cjs
```

An optional Playwright/Chromium browser test is included separately. Template fixtures do not execute PowerShell string interpolation or Windows collection.

## References

- [Store passwords using reversible encryption](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption)
- [Domain password-properties flags](https://learn.microsoft.com/en-us/windows/win32/adschema/a-pwdproperties)
- [User account-control flags](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties)
- [Fine-grained reversible-encryption attribute](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-passwordreversibleencryptionenabled)
- [Microsoft Defender threat records](https://learn.microsoft.com/en-us/powershell/module/defender/get-mpthreat)
- [Server antivirus exclusions and visibility](https://learn.microsoft.com/en-us/defender-endpoint/configure-server-exclusions-microsoft-defender-antivirus)
