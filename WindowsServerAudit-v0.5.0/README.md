# Windows Server triage 0.5.0

A read-only local PowerShell audit for Windows Server 2016, 2019, 2022 and 2025. This release simplifies setup, automatically selects service expectations, adds an explicit Windows firewall reference, and replaces report filtering.

## Run

Extract the package. Open **64-bit Windows PowerShell 5.1 as administrator**, change to the extracted folder, and run:

```powershell
.\Invoke-WindowsServerAudit.ps1
```

If Windows blocks downloaded scripts, review their contents and follow your organization's script-signing/download policy. No installation or additional PowerShell modules are required for the main audit. The package is unsigned.

Setup asks only:

1. Is this intended to be a domain controller? The detected role is the suggested answer.
2. What other roles should it serve? Choose websites, Microsoft Structured Query Language (SQL) Server databases, file sharing, Domain Name System (DNS), or Remote Desktop Services. Detected installed services are suggested candidates, not proof that a role is authorized.
3. Which inbound ports should listen?
4. Which outbound **remote destination** ports are allowed?
5. Confirm the answers.

No per-service names, account names, startup modes, administrator lists, task lists or antivirus-exclusion lists are requested. Generated labels expand common abbreviations. Exact commands, paths and raw evidence retain their original values.

## Port answers

Use `TCP:443,UDP:53` or ranges such as `TCP:5000-5010`. Transmission Control Protocol (TCP) and User Datagram Protocol (UDP) are spelled out in the setup.

| Answer | Inbound listening ports | Outbound remote destination ports |
| --- | --- | --- |
| Enter | Use essential Windows and selected-role ports as an allowed-if-present reference | Allow all destination ports, matching the Windows starting default |
| Explicit list | Include the declared workload ports plus the built-in Windows/role reference; review other listeners | Review possible outbound connections outside that list |
| `none` | Expect no non-loopback listeners, including Windows listeners | Expect no non-loopback outbound connections |
| `unknown` | Inventory without deciding which listeners are expected | Inventory without a destination-port comparison |

The role reference does not require every default port to be listening. Explicitly supplied inbound ports are expected to have a listener in the current capture; a range requires at least one matching listener. If a named database instance uses a custom/dynamic port, enter that port or its approved range. Existing local loopback listeners are not treated as externally exposed. The essential Windows reference includes common remote-management, file-sharing, address-assignment, time and name-resolution client endpoints. Dynamic high-numbered datagram sockets without destination information are informational because they may be temporary outbound sockets.

An outbound connection has a local source port and a remote destination port. The script compares the **remote** port to your answer. It does not treat temporary local source ports as unexpected services. The endpoint table does not prove which side initiated a connection, so the audit excludes connections with a matching same-process local listener and labels the remaining candidates as **possible** outbound connections. Datagram endpoint inventory has no remote destination ports, so outbound datagram policy remains not assessed. No connections are opened to test reachability.

## Service assumptions

The reference is intentionally focused:

| Role | Expected services |
| --- | --- |
| Windows core | Windows Event Log; Windows Defender Firewall; Base Filtering Engine; Remote Procedure Call; Task Scheduler; Windows Management Instrumentation |
| Domain controller | Active Directory Domain Services; Kerberos Key Distribution Center; Net Logon; Active Directory Web Services; Server/file-sharing service |
| Websites | World Wide Web Publishing Service and Windows Process Activation Service |
| Name resolution | Domain Name System Server |
| File sharing | Server/file-sharing service |
| Remote desktops | Remote Desktop Services |
| Databases | Discovered local Microsoft Structured Query Language Server Database Engine instances |

Core and selected-role services normally should be running. The report lists accepted startup modes and expected accounts where stable. Manual and automatic startup are both accepted for Windows Process Activation Service. Custom database accounts are permitted; a stopped SQL Server Agent is not automatically a problem because job scheduling can be intentionally unused. Third-party security tools and optional services have deployment-specific requirements.

A running website/database service outside an explicitly complete role selection is a review item. An unfamiliar service is not automatically assumed to need disabling. All collected services still receive command/path/permission checks. These assumptions are not a complete inventory of every Windows service and cannot identify every authorized application.

## Firewall reference

For Domain, Private and Public profiles, the Windows starting reference is:

| Setting | Reference |
| --- | --- |
| Firewall enabled | True |
| Unmatched inbound traffic | Block |
| Unmatched outbound traffic | Allow |
| Inbound allow rules accepted | True |
| Local firewall rules merged | True |

Normal outbound allowance and ordinary scoped inbound rules are not labeled abnormal. When a provider returns `NotConfigured`, the script attempts a read-only native effective-policy lookup for supported settings. A value it cannot resolve remains **unknown**, rather than being guessed from the defaults.

Central policy may intentionally disable local rule merging or inbound allow rules. Those differences are **Information**, not automatic security failures. The report explains that local application rules may be ignored. Disabled firewall profiles, unmatched inbound traffic allowed by default, and candidate inbound allow rules with no program/service/protocol/port/source restriction still merit review. Other rule conditions, explicit block rules, interfaces and upstream firewalls can change effective exposure.

These are settings defaults, not a universal list of every firewall rule. Installed roles, applications, Windows builds and organizational policies change that rule inventory. The report includes both the reference and observed settings, and saves `Evidence/ReferenceDefaults.json`.

## Report and filtering

Each run creates a new `ServerTriage-<computer>-<timestamp>` folder containing:

- `index.html`: findings, artifact evidence, firewall reference/comparison, automatic service expectations, file facts and coverage.
- `ServerIntent.json`: the four saved setup answers and metadata.
- `Evidence/*.json`: exact collected evidence, findings and selected snapshots.

Open the saved `index.html` in **Microsoft Edge** or another browser that permits local JavaScript. Search, category and priority filters work together and apply to both finding rows and artifact cards. There is a reset button, visible count and no-match message. The initial view shows actionable findings; choose **All categories** or **Information** to include policy context and collection gaps in the findings table. Coverage and reference tables remain visible independently.

The script uses older JavaScript syntax and explicitly changes row/card display to improve compatibility. If JavaScript is blocked, the controls remain disabled and a message explains why; every finding stays readable. The report is self-contained and does not fetch external resources.

`ExampleReport.html` is a **synthetic filter demonstration**, not a scan of your server.

## Repeat runs

```powershell
.\Invoke-WindowsServerAudit.ps1 -ConfigPath 'C:\Audit\ServerIntent.json' -NonInteractive -OutputDirectory 'C:\Audit\Run-002'
```

The output directory must not exist. You can adjust the simple saved profile; `ServerIntent.example.json` illustrates a website role with a custom inbound port.

**Version 0.4 profiles are not silently reused.** Run without `-ConfigPath` to create a simplified version 2 profile. This avoids carrying forward the detailed answers you wanted removed.

An optional selected persistence/file snapshot can still be written with `-CaptureBaseline`. To compare a reviewed reference later, set `BaselinePath` in the saved profile. No clean baseline is selected or certified automatically. Compatible selected triage snapshots from version 0.4 remain usable; older configuration snapshots are incompatible. The comparison covers selected execution command/account fields and referenced-file hashes, not an entire computer configuration. Server year, role, edition and build must match unless `-AllowBaselineBuildMismatch` explicitly permits a build difference.

## Other collection and boundaries

The existing audit still collects process/network captures; service definitions and permissions; scheduled-task actions; machine and loaded-user startup registry entries; selected Startup folders and PowerShell profiles; Windows Management Instrumentation (WMI) persistence consumers; direct administrator membership; visible Microsoft Defender Antivirus exclusions; and local database metadata, jobs and startup procedures.

SQL Server metadata reads use the current Windows identity through local shared memory, with fixed read-only queries and timeouts. Permissions, stopped services, encrypted definitions or disabled shared-memory access can limit results. `-SkipSql` skips these queries. Remote/container/clustered instances and LocalDB are not comprehensively discovered. No application table contents or database passwords are requested.

Referenced local files may be hashed, checked for Authenticode signatures, inspected for broad permissions and read as text for simple behavior patterns. Ordinary fixed drives only; remote/mapped/removable/reparse-point paths are skipped. Permission signals do not calculate complete effective access for every identity. Path checks and process associations are not atomic and can be affected by changes during collection. Signature validation can use normal Windows trust/revocation behavior.

The script never executes a command found in evidence, starts/stops services, changes firewall rules, changes accounts, enables logging or remediates. Its deliberate file writes are report/evidence outputs. Results are investigation leads, not compromise verdicts. Event-log timelines, full memory/kernel analysis, complete registry/file monitoring, nested group expansion, comprehensive application configuration analysis, software vulnerability matching, and Center for Internet Security (CIS) or Security Technical Implementation Guide (STIG) certification are outside this focused release.

Reports can contain internal addresses, usernames, scripts and database job command text, including secrets if already embedded in those commands. Protect the output folder.

## Validation

Executed in the build environment:

- Static lexical/source checks and example-profile checks.
- Eleven JavaScript filter fixture groups: search events, category, priority, combinations, reset, counts, empty state, artifact cards, escaped evidence, and absent newer JavaScript helper functions.
- Archive integrity checks.

A full Chromium browser launch was blocked by the environment, so **browser rendering was not verified**. No PowerShell runtime is installed here, so **the updated PowerShell script, its fixture suite and Windows collectors have not been executed**. Please pilot this on a server before relying on its findings.

On Windows, run the dependency-free PowerShell fixtures:

```powershell
.\Test-Triage.ps1
```

They parse the script and test role references, normal firewall defaults, unknown settings, managed-policy information, port input, outbound direction handling, permission uncertainty, baseline coverage and HTML escaping. They import function definitions without running the scan entry point.

Developer JavaScript logic checks require Node.js only:

```text
node Tests/Test-ReportFilters.cjs
```

`Tests/Test-ReportBrowser.cjs` provides an additional browser test for environments with Playwright and Chromium installed. Set `CHROMIUM_PATH` if needed. Fixture templates are extracted from the PowerShell source, but do not exercise PowerShell string interpolation or Windows collection.

## References

- [Windows Firewall overview and default inbound/outbound behavior](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/)
- [Windows firewall profile settings](https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile)
- [Firewall profile policy defaults](https://learn.microsoft.com/en-us/windows/client-management/mdm/firewall-csp)
- [Windows service guidance](https://learn.microsoft.com/en-us/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server)
- [Internet Information Services architecture and service accounts](https://learn.microsoft.com/en-us/iis/get-started/introduction-to-iis/introduction-to-iis-architecture)
- [Database service accounts and deployment-specific choices](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions)
