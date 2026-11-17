# Windows Server triage — 0.4.0

A local, read-only PowerShell audit that asks what the server should do, then produces one HTML report with prioritized investigation leads and requirement mismatches. Supports Windows Server 2016, 2019, 2022 and 2025, including domain controllers, member servers and standalone servers.

This is the focused redesign discussed for finding Red Team implants. The report distinguishes suspicious artifacts, operator requirement violations, review items and checks that could not be assessed. Scores order the evidence; they are not probabilities or malware verdicts. Neither zero findings nor an apparently trusted signature establishes that a host is clean.

## First run

1. Extract the ZIP to a local folder on the server.
2. Open **64-bit Windows PowerShell 5.1 as administrator** and change to that folder.
3. Run:

```powershell
.\Invoke-WindowsServerAudit.ps1
```

If Windows has marked the downloaded files as blocked, review their contents and use File Properties → Unblock on the files you reviewed. Follow your organization's script-signing policy; this package is unsigned.

The wizard shows detected OS, role and candidate services. You supply:

- Intended roles and required services, including expected state, startup mode and account when known.
- Expected inbound TCP/UDP ports, allowed source IPs/CIDRs, and whether a listener is required now.
- Approved direct Administrators members by qualified name or SID.
- Approved management tool names, custom task paths and visible Defender exclusions.
- Whether local firewall rules must apply for each Domain, Private and Public profile.
- Approved SQL sysadmin login names. This initial profile uses one list across all local instances.
- Optional exception annotations and an optional compatible baseline.

**Enter means unknown.** For lists, `none` explicitly means none; after entering a list, confirm whether it is complete. An incomplete list does not make every other entry unauthorized. Selecting a discovered service requires an explicit choice; discovery never approves it. Management tool names and exception annotations do not suppress findings. Review the summary and confirm before the remaining scan starts. An initial process/network capture occurs before the questions to preserve some early evidence.

For your firewall example, answer **y** when asked whether local firewall rules must apply on Domain. An observed effective value of False then becomes a requirement violation. The script records the active profile context and policy source. It does not change GPOs or firewall settings.

## Outputs and repeat runs

Each run creates a new `ServerTriage-<computer>-<timestamp>` folder in the current directory:

| Output | Purpose |
| --- | --- |
| `index.html` | Searchable findings, artifact evidence, file facts, coverage and intended configuration |
| `ServerIntent.json` | Your reusable answers |
| `Evidence/*.json` | Process/network captures, execution entries, firewall, direct administrators, visible exclusions, SQL metadata, file facts, findings and coverage |
| `Evidence/TriageSnapshot.json` | Selected persistence command/account and referenced-file hash snapshot |

Open `index.html` locally in a browser. The HTML is self-contained and makes no external requests. Evidence is escaped for HTML display.

Reuse your saved answers interactively:

```powershell
.\Invoke-WindowsServerAudit.ps1 -ConfigPath 'C:\Audit\Saved\ServerIntent.json'
```

For an unattended run with a reviewed profile:

```powershell
.\Invoke-WindowsServerAudit.ps1 -ConfigPath 'C:\Audit\Saved\ServerIntent.json' -NonInteractive -OutputDirectory 'C:\Audit\Run-002'
```

The output directory must not already exist. It is the only location where this script deliberately writes files. Reports can contain internal addresses, usernames, script contents and SQL job command text, including embedded secrets if a job already contains them. Store reports accordingly.

`ServerIntent.example.json` shows the schema with all approvals unknown. It is a format example, not a security baseline. Prefer generating your first real profile with the wizard. Review host-specific paths and local identities before reusing a profile elsewhere.

## What is inspected

| Area | Evidence and checks |
| --- | --- |
| Running processes and network | Initial/current process command lines, executable paths, parents, TCP connections and TCP/UDP listeners |
| Services | Image paths, accounts, state/start mode, ServiceDll where readable, service DACLs and required-service mismatches |
| Scheduled tasks | Actions, arguments, working directories, principal, selected trigger/settings metadata, custom task approvals |
| Startup | Machine Run/RunOnce in both registry views, loaded user Run/RunOnce, common/current-user Startup folders, selected Windows PowerShell profiles |
| WMI persistence | CommandLineEventConsumer, ActiveScriptEventConsumer, filters and bindings in root/subscription |
| Referenced files | SHA-256, Authenticode status, file/parent ACLs, small script text patterns, unusual locations and Windows-like names outside normal directories |
| Administrators | Direct built-in Administrators membership versus your approved list; SID lookup on domain controllers |
| Firewall | Effective profiles, local-rule merging, disabled protection, shields-up mode, enabled inbound rule scopes and listeners versus intended ports |
| Defender | Visible configured exclusions versus approvals |
| SQL Server | Local Database Engine instances/versions, direct sysadmin membership, selected sensitive configuration, SQL Agent job steps and master startup procedures |

Examples of corroborating signals include an executable in a public user directory, potentially dangerous broad-principal permissions, encoded PowerShell, text resembling download-and-execute behavior, SYSTEM context and an associated process with established connections. Legitimate administration can produce these signals; the report shows why an entry was flagged and the next verification step.

Service/file ACL checks inspect broad allow ACEs, inheritance and deny ambiguity. They do **not** calculate full effective permissions for an arbitrary user or expand all nested groups. Unquoted service paths are leads; exploitability is not established. Process association uses PIDs and paths and can be affected by PID reuse and non-atomic collection. WMI binding association is explicitly marked as candidate name matching.

Only ordinary fixed local drive paths are inspected for referenced file contents. UNC/device targets, mapped/network/removable drives and reparse-point paths are skipped. Files can change during collection, so path checks are not an atomic security boundary. Commands found in evidence are never run. Script files are read as text, never dot-sourced. Some Windows trust/revocation operations may use normal operating-system network behavior.

SQL checks use the current Windows identity through **local shared memory**, fixed SELECT statements, short connection/query timeouts and no application table reads. No SQL credentials are requested or stored. Windows elevation does not grant SQL permissions. Missing permissions, disabled shared-memory access, stopped instances or unavailable/encrypted definitions are reported as gaps. Each query runs independently so denied job access does not prevent a readable startup-procedure check. This release targets ordinary local Database Engine service instances; remote, container, LocalDB and clustered instances are not fully covered. Use `-SkipSql` to skip SQL metadata queries.

## Optional baseline

No baseline is chosen automatically. Without one, intent checks and artifact triage still run.

After independently establishing a reviewed reference, capture a snapshot with:

```powershell
.\Invoke-WindowsServerAudit.ps1 -CaptureBaseline
```

This performs the regular audit and also writes `Baseline.json`. The flag does not certify cleanliness. Supply that file's full path in the wizard or edit `BaselinePath` in your intent profile.

Comparison is limited to selected non-process execution-entry command/account changes, additions/removals when collection coverage supports them, and hashes of referenced files. It is not an entire-computer configuration comparison. Server year, role, SKU and build must match; `-AllowBaselineBuildMismatch` explicitly permits a build mismatch and records a review finding. Updates and host-specific differences can explain changes. **Earlier v0.3 snapshots are incompatible** and produce a clear not-assessed finding.

## Boundaries

The audit does not remediate, install tools, start services, change logging or scan remote hosts. Event-log timeline analysis is not included. It does not provide comprehensive registry/file coverage, memory or kernel forensics, nested group expansion, COM handler resolution, all-user profile coverage, application allowlisting analysis, software vulnerability/CVE matching or full CIS/STIG certification. Microsoft task paths are excluded only from the custom task approval-list comparison; their execution artifacts still receive behavioral checks.

Firewall scope comparisons are candidate reviews, not effective packet-policy simulation or external reachability tests. Application/service conditions, block rules, interfaces, IPsec, dynamic scopes and upstream controls require separate validation. A candidate CIDR must fit inside one approved CIDR; adjacent approved ranges are not merged. `Get-MpPreference` can omit automatic/hidden exclusions. Missing evidence is recorded and must not be read as a pass.

This focused release replaces the previous CIS-heavy report workflow. It does not bundle the old benchmark catalogs, bulk default-deviation list or CVE results.

## Validation

**This package has not been executed on Windows or parsed by the PowerShell runtime in the build environment.** Available checks here were static lexical/source checks, example JSON validation and ZIP integrity. Treat the first server run as a pilot and review the coverage section.

A dependency-free fixture suite is included:

```powershell
.\Test-Triage.ps1
```

It uses the PowerShell parser to check the main script, loads function definitions without executing the audit entry point, and tests unknown versus none, partial approvals, input validation, address/port matching, ACL uncertainty, path correlation, firewall merging, scoring, baseline coverage and HTML escaping. These fixtures **have not been run here**. They do not substitute for Windows collector/SQL integration testing.

If the pilot fails, preserve the error text and the partially written output directory. Never use `iwr ... | iex` for this interactive script; download, review and invoke the local `.ps1` file so its prompts and parameters work normally.

## Reference documentation

- [Windows service security and access rights](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)
- [Win32_Service](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-service)
- [Get-NetFirewallProfile](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile)
- [Get-NetTCPConnection](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-nettcpconnection)
- [Get-ScheduledTask](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/get-scheduledtask)
- [SQL Agent job steps](https://learn.microsoft.com/en-us/sql/relational-databases/system-tables/dbo-sysjobsteps-transact-sql)
