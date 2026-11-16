# Windows Server security auditor — version 0.3.0

This is a first implementation with **partial automated coverage**, not a complete
CIS compliance assessment or a replacement for a validated vulnerability scanner.
It runs locally and audits configuration without applying remediation.

The standalone PowerShell script contains its benchmark catalog. No additional
PowerShell modules, benchmark PDFs, SQL client utilities, or agents are required
on the assessed machine. The separate JSON catalog is a readable reference copy;
editing that copy does not change the embedded script catalog.

## Run

1. Copy `Invoke-WindowsServerAudit.ps1` to the server.
2. Open **64-bit Windows PowerShell 5.1 as administrator**.
3. Change to the directory containing the script and run:

```powershell
.\Invoke-WindowsServerAudit.ps1
```

A new `ServerAudit-COMPUTERNAME-TIMESTAMP` directory is created in the current
directory. Open its `index.html` in a browser. For Server Core, copy the complete
report directory to an administrator workstation and open the HTML there.
Normal organizational script signing and execution policies still apply; this
script does not change or bypass them. PowerShell 7 has not been validated.

To choose an output location, supply a **new** directory:

```powershell
.\Invoke-WindowsServerAudit.ps1 -OutputDirectory 'C:\AuditReports\FirstRun'
```

Select individual profiles or skip specific collection stages:

```powershell
.\Invoke-WindowsServerAudit.ps1 -Profiles Level1,Level2
.\Invoke-WindowsServerAudit.ps1 -SkipOnline
.\Invoke-WindowsServerAudit.ps1 -SkipSqlQueries
```

An NVD API key is optional. To supply one for the current PowerShell process:

```powershell
$env:NVD_API_KEY = Read-Host 'NVD API key'
.\Invoke-WindowsServerAudit.ps1
Remove-Item Env:\NVD_API_KEY
```

API keys are sent in the NVD request header and are not deliberately written to
reports. NVD requests are spaced at 6.5 seconds without a key or 0.7 seconds with
a key. Shared public IP quotas may still cause requests to fail. Failures appear
as unavailable assessments, with diagnostic messages. There are no automatic
module installations or service starts.

## Reports

| File | Purpose |
|---|---|
| `index.html` | Links, coverage notes, up to 30 configuration failures, selected SQL concerns, and supplemental firewall observations |
| `Level1.html` | Applicable Level 1 recommendations |
| `Level2.html` | Applicable Level 1 and Level 2 recommendations together |
| `STIG.html` | Applicable STIG recommendations from the supplied STIG edition |
| `NextGeneration.html` | Optional advanced profile, assessed separately from Level 1/2 |
| `ConfigurationChanges.html` | Documented default differences, trusted-snapshot differences, collection gaps and investigation leads |
| `Firewall.html` | Effective firewall settings, local rule merging, environment requirements, and rule health |
| `SQLServer.html` | Per-instance SQL version/build evidence and selected metadata observations |
| `Software.html` | Potential CVE matches, KEV context, lookup failures, and software coverage limitations |
| `Inventory.html` | Machine-wide installed software registry inventory |
| `Evidence/` | Machine, policy, service, firewall, listening port, hotfix, SQL, CVE response, and diagnostic evidence |

Reports are self-contained, support search/status filtering, and make no network
requests when opened. HTML encodes all machine-supplied values. Evidence includes
host details, service identities and paths, and database names. Store it with the
same access controls you use for other server assessment reports.

## Windows assessment coverage

- Detects Windows Server 2016, 2019, 2022, and 2025 using known base build numbers.
- Distinguishes domain controller, domain member server, and standalone server.
- Selects the benchmark edition matching that OS and role context.
- Includes a catalog of recommendations from the supplied PDFs, with benchmark
  versions, PDF page references, and source SHA256 hashes.
- Automates a conservative subset: unambiguous single registry DWORD comparisons
  and selected account/password/lockout policy comparisons.
- Exports merged security policy with `secedit /export`; it does not apply it.
- Saves effective firewall policy, listening TCP ports, services and hotfixes.
- Shows disabled effective firewall profiles as supplemental findings. It does
  not test external network reachability or infer internet exposure.
- Uses source-specific expectations. It does not reuse one OS's values for a
  different OS or substitute standard CIS recommendations for STIG requirements.
- Recommendations with alternate STIG values in their description/audit text
  remain for review rather than using the standard value automatically.

The catalog is a transcription of supplied content, not an independently
validated CIS-certified assessment. See the generated coverage table below for
the precise number of implemented comparisons in each document. Check counts
vary by selected role and profile. Source pages are physical PDF page numbers,
which can differ from the printed page label.

**Missing source editions:** no standalone editions were supplied for 2016/2019;
no 2025 STIG edition was supplied. STIG domain documents are not substituted for
standalone systems. These combinations produce an unavailable report.

### Status meanings

| Status | Meaning |
|---|---|
| `Fail` | An implemented comparison found a mismatch, or a supplemental check found a disabled firewall profile |
| `Pass` | The implemented comparison matched the expected value; this is not a claim that every runtime dependency was verified |
| `Review` | Missing/ambiguous evidence, a contextual SQL observation, or a potential CVE candidate needs validation |
| `Manual` | The benchmark marks the recommendation as requiring human assessment |
| `NotImplemented` | Cataloged recommendation or assessment capability has no evaluator in this release |
| `Error` | A check or evidence collector failed |
| `Unavailable` | Benchmark, permissions, service, or external data prevented assessment |
| `Info` | Inventory or coverage information, not a compliance determination |

An absent registry value is **Review**, because its effective default and
conditional applicability have not been verified. A failed read is never Pass.
No complete compliance percentage is calculated. Priority labels are transparent
engineering triage categories based on control topics, not severities assigned
by CIS and not CVSS scores. They do not establish actual exposure.

Account policy checks concern the exported default policy. Fine-grained domain
password policies for individual users/groups are outside this release's scope.
GPO delivery/enforcement, user rights, audit subcategories, complex multi-value
checks, most service conditions, and manual business requirements need further
evaluators or human review. A registry match alone does not prove runtime state.

## Firewall operational checks added in 0.2.0

The four CIS audits retain their benchmark expectations. A separate `Firewall.html`
report evaluates effective policy and explicit environment requirements.

**The default environment requirement is that Domain-profile local firewall rules
must be allowed to merge.** This reflects the requested environment, not a
universal CIS recommendation. To change the requirement, run:

```powershell
.\Invoke-WindowsServerAudit.ps1 -RequireLocalFirewallRules Domain,Private
```

To disable the custom merging requirement while retaining firewall observations:

```powershell
.\Invoke-WindowsServerAudit.ps1 -RequireLocalFirewallRules @()
```

New read-only checks and evidence:

- Effective `AllowLocalFirewallRules`, `AllowLocalIPsecRules`, and
  `AllowInboundRules`, plus firewall defaults and disabled-interface aliases.
- Current network categories by interface; multiple adapters are retained.
- A mismatch when a specified profile explicitly rejects required local rules.
- Review when local rule merging is disabled on other profiles, since central
  management may intentionally require that configuration.
- Enabled local rules scoped to each profile, with counts marked as unknown if
  collection fails. Counts do not establish actual traffic failures.
- Disabled firewall profiles and permissive default inbound actions, prioritized
  higher when a matching network category is reported on a current interface.
- Review when inbound allow rules are ignored by shields-up mode.
- Review for domain-joined hosts with no reported domain-authenticated network.
- Review of enabled ActiveStore rules reporting Error or Degraded primary status.
- Rule policy sources when `Get-NetFirewallRule -TracePolicyStore` can retrieve
  them. The source GPO of an individual profile setting is **not** attributed.

Findings remain supplemental and separate from CIS. A profile can pass a CIS
requirement yet conflict with an environment requirement. `NotConfigured`/missing
merge values remain Review when merging is required; this release does not infer
an effective True value from an unresolved default. Local Group Policy rules are distinct from PersistentStore rules and may still
apply when local merging is disabled. No network reachability,
complete packet-filter simulation, third-party firewall analysis or discovery of
arbitrary unknown misconfigurations is performed.

The report overview includes failures and actionable review findings. Evidence
adds `NetworkProfiles.json`, `LocalFirewallRules.json`,
`EffectiveFirewallRules.json`, `FirewallFindings.json`, and
`RequiredLocalFirewallRuleProfiles.json`.

`Test-FirewallChecks.ps1` is provided to parse the main script and run 13 pure
fixture scenarios, including multi-adapter profiles, explicit versus missing
values, failed evidence collection, and configurable expectations. It loads only
the finding functions and does not query or change the machine's firewall.
These tests have not been executed here because PowerShell is unavailable.

```powershell
.\Test-FirewallChecks.ps1
```

## Configuration changes added in 0.3.0

The normal audit now produces `ConfigurationChanges.html`. Run the script normally
for documented default comparisons and current investigation leads:

```powershell
.\Invoke-WindowsServerAudit.ps1
```

There are three explicitly labeled reference types:

| Reference | Purpose |
|---|---|
| Documented Windows defaults | 16 curated comparisons: four effective firewall settings for each of three profiles, plus NTLM minimum client/server session security, EnableLUA and LimitBlankPasswordUse |
| User-selected compatible snapshot | Added, removed and changed configuration compared with a reference you have established as clean |
| Current observation/pattern | Visible Defender exclusions and execution entries referencing encoded PowerShell or potentially unusual locations, without asserting historical changes |

The four CIS reports and the custom firewall requirements remain separate. A
change can be legitimate hardening, an approved application change, policy from
central management, or an investigation lead. **No finding establishes a red-team
plant or compromise.** The code neither executes observed commands nor decodes
and runs encoded strings.

### Capture a reference

On a **trusted clean server**, preferably the same clean template/build as the
machine you will assess, run:

```powershell
.\Invoke-WindowsServerAudit.ps1 -CaptureBaseline -BaselineLabel 'Clean server template' -OutputDirectory 'C:\AuditReports\CleanReference'
```

The output directory must be new. Capture mode writes `Baseline.json`, a SHA256
sidecar, current evidence, `ConfigurationChanges.html`, and a capture overview.
It stops before the CIS, SQL and online CVE stages. Review collection errors and
coverage before accepting the reference. The script does not certify cleanliness.

Copy `Baseline.json` through a trusted route to the machine being assessed:

```powershell
.\Invoke-WindowsServerAudit.ps1 -BaselinePath 'C:\AuditReferences\Baseline.json'
```

For an optional integrity pin, supply the SHA256 value recorded separately from a
trusted source:

```powershell
.\Invoke-WindowsServerAudit.ps1 -BaselinePath 'C:\AuditReferences\Baseline.json' -BaselineSha256 '<64-character trusted SHA256>'
```

The placeholder above must be replaced with the actual hash. The importer hashes
and parses the same bytes, treats the baseline solely as data, and rejects a
mismatching pin. A hash file stored beside a baseline does not by itself prove
that either file is authentic. Protect the reference independently from the
assessed machine.

By default, **OS year, server role, edition SKU, architecture, and full build must
match**. A different build prevents reference comparison. For an explicitly
reviewed build difference:

```powershell
.\Invoke-WindowsServerAudit.ps1 -BaselinePath 'C:\AuditReferences\Baseline.json' -AllowBaselineBuildMismatch
```

The report discloses the override; software updates can explain many changes.
Different OS years, roles, editions or architectures are still rejected.
Different current-user SIDs cause only the user-scoped collection comparison to
be skipped. Machine-name prefixes in local service accounts, task principal names,
and local administrator names are normalized where identified; domain identities,
paths, local principal SIDs in task definitions and software-dependent differences
can still produce legitimate changes.

### Captured configuration

| Area | Included comparison data |
|---|---|
| Security registry | Values addressed by implemented registry rules in the matching standard benchmark edition, plus curated default targets; explicit presence, type and value |
| Security policy | Numeric values in the merged secedit security policy export |
| Services | Startup mode, delayed-start registry state, account, image command line and ServiceDll registry state |
| Scheduled tasks | Task identity, actions, triggers, principal and settings; no last-run/next-run result timestamps or running state |
| Startup entries | Machine/current-user Run and RunOnce entries in both registry views; regular files immediately in common/current-user Startup folders, hashed up to 16 MiB with hidden/system/read-only flags |
| Administrators | Direct members of the built-in Administrators group; on a DC, direct members of domain Builtin Administrators read through LDAP |
| Defender exclusions | Visible path/process/extension/IP exclusions returned by Get-MpPreference |
| Firewall profiles | Effective profile settings from ActiveStore |
| Firewall rules | Rule configuration and port, address, application, service, interface, interface-type and security filters |

The normal audit always saves `Evidence/ConfigurationSnapshot.json`, which can
also be selected as a later reference if its cleanliness is independently
established. Snapshots can contain command-line arguments, identifiers and other
sensitive configuration; they are not uploaded by the script.

For each difference the report provides before/after values, evidence, category,
reference source/hash, priority and top-level changed field names. Service,
task, startup, administrator and exclusion differences receive higher triage
priority. They remain **Review**, not a malicious/unauthorized verdict. Matching
entries are not repeated as change findings. Recorded tasks can differ in trigger
start dates across clean installations, and firewall rule identities/filter values
can differ legitimately across machines. Capturing from the same template limits
such noise.

### Coverage and reliability

- Unreadable collectors/items are recorded as unavailable, rather than interpreted
  as missing configuration. Additions require reference enumeration to have
  completed, and removals require current enumeration to have completed.
- Defender can hide exclusions and add automatic server-role exclusions. Empty
  visible output does not establish no effective exclusions. Differences in
  visible exclusions are labeled newly visible, and removals are not inferred.
- Local Administrators membership is direct only. Nested memberships, other
  privileged groups and local account creation outside that group are not covered.
  DC LDAP membership visibility and localized/renamed group paths may limit reads.
- Startup collection covers the machine and the account running the audit;
  unloaded/other users, startup subdirectories, reparse-point targets, WMI
  persistence, boot configuration and every other autorun mechanism are not covered.
  Startup shortcut contents are hashed, but their targets are not executed or
  separately resolved. Oversized or unreadable files are marked unavailable.
- Services/executables are **not** broadly hashed. Replacing a service executable
  in place while preserving its recorded configuration may escape this check.
- Registry default comparisons do not infer effective state from an absent value.
  Unmapped registry defaults are labeled as unavailable in the curated reference
  catalog; a snapshot comparison can still assess those values. CIS recommended
  values are never silently substituted for factory defaults.
- Neither exact GPO attribution for every setting nor complete policy-origin
  tracing is implemented. Available firewall rule source details are retained.
- Collection is a sequence of reads rather than an atomic machine snapshot.
  Concurrent updates or red-team changes can affect the evidence. Full firewall
  filter collection can add several minutes to a scan.

### Comparison tests

Two optional fixture suites parse the main script and load only the helper
functions needed for tests. They do not perform a live audit. Baseline import
fixtures create and clean up their own temporary JSON files.

```powershell
.\Test-FirewallChecks.ps1
.\Test-ConfigurationChanges.ps1
```

The configuration suite covers ordering/JSON round trips, changed/added/removed
entries, failed and partial collection, incompatible references, scope differences,
additional hardening, unresolved defaults, hidden exclusions, HTML encoding,
trusted-hash mismatch and invalid snapshots. **PowerShell and Windows execution
were not available in the development environment; these fixture suites have
not been run here.** Run them on a lab system before relying on the new comparison.

## Microsoft SQL Server scope

This release concerns **Microsoft SQL Server Database Engine versions and local
instances**, not PostgreSQL/MySQL or other database vendors.

- Enumerates both 64-bit and 32-bit SQL instance registry mappings and engine
  services, including default and named instances.
- Records setup build/edition when present; running instances are queried with
  the current Windows identity over local shared memory.
- Reads `SERVERPROPERTY` version, edition, product level, update level, and update
  KB reference. Each instance gets its own record.
- Reads selected `sys.configurations` settings plus user database trust/chaining
  flags from `sys.databases`. It does not read application table contents.
- A stopped engine is not started. Failed or denied queries are reported.
- Checks database metadata visibility and warns that inventory may be limited.

These are **supplemental SQL observations**. The uploaded Windows Server
benchmarks are not SQL Server benchmarks. Full SQL configuration assessment needs
the appropriate SQL Server CIS documents for the releases you use. The script
does not grant database permissions or change authentication. An administrator
should arrange the required metadata read access for the audit identity.

LocalDB, containers, remote SQL hosts, Analysis Services, and Reporting Services
are not covered by the engine-instance discovery in this release. Local shared
memory being unavailable can prevent queries even when another SQL transport
would work. Registry setup builds can be stale; reports identify the build source.

## Software and CVE scope

- Inventories machine-wide uninstall entries in both registry views.
- Looks up SQL Server CVE **release-family candidates** from NVD (SQL 2008/2008 R2
  through SQL 2025 when a version can be mapped).
- Looks up product/version candidates for supported Google Chrome, Mozilla
  Firefox, and 7-Zip uninstall entries.
- Checks candidate identifiers against a retrieved CISA KEV feed when available.
- Records source responses, lookup timestamps, failures and truncation.

**No CVE is marked as a confirmed vulnerability on this host.** SQL release-family
queries do not resolve CU/GDR fixed-build branches or component prerequisites.
An old CVE can therefore appear for a SQL instance that has already been patched.
Validate candidates against Microsoft advisories and installed builds. KEV means
the vulnerability is cataloged as exploited; it does not establish that this host
is affected. NVD/CISA data can be incomplete or unavailable.

Each unique product query returns at most `-MaxCvesPerProduct` results (default
200, maximum 1000). This release does not paginate beyond that page. When more
results exist, the report explicitly flags truncation. The first page is not
guaranteed to contain the newest or most severe findings. NVD results are cached
within a run so multiple instances of the same SQL release reuse the response.

**Windows missing-patch applicability is not implemented.** A hotfix list alone
does not resolve cumulative updates, supersedence, or CVE applicability. The
Windows build and hotfix inventory are saved for follow-up. There are no direct
configuration-to-CVE mappings in this release. Other installed products remain
inventory-only. Per-user apps, portable binaries, libraries, dependencies and
containers are outside the inventory coverage.

The script requests public data from `services.nvd.nist.gov` and `www.cisa.gov`.
Supported product identifiers/versions are sent to NVD; hostnames, SQL instance
names, database names and report files are not included in those requests.

## Audit behavior and validation

The script does not set registry values, apply GPOs/security templates, change
users/permissions, run SQL configuration commands, start/stop services, install
software or trigger MSI inventory repair. It writes report/evidence files and
performs normal configuration/SQL reads. Windows/SQL logs may record those reads.

Development validation checked catalog integrity, profile membership, source
references, data embedding and basic PowerShell lexical structure. **The script
has not been executed on Windows, and a PowerShell parser/runtime was unavailable
in the development environment.** These checks do not establish PowerShell
syntax or runtime correctness. Validate it on a representative lab server before
using its findings operationally.

## References

- [Microsoft: UAC settings and documented defaults](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/settings-and-configuration)
- [Microsoft: Run and RunOnce registry entries](https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys)
- [Microsoft: visible custom Defender exclusions](https://learn.microsoft.com/en-us/defender-endpoint/configure-exclusions-microsoft-defender-antivirus)

- The user-supplied CIS PDFs named in the catalog and coverage table below.
- [Microsoft: secedit export](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/secedit-export)
- [Microsoft: SQL instance registry mapping](https://learn.microsoft.com/en-us/sql/sql-server/install/file-locations-for-default-and-named-instances-of-sql-server)
- [Microsoft: SERVERPROPERTY](https://learn.microsoft.com/en-us/sql/t-sql/functions/serverproperty-transact-sql)
- [Microsoft: software inventory and Win32_Product considerations](https://learn.microsoft.com/en-us/powershell/scripting/samples/working-with-software-installations)
- [Microsoft: local firewall rule merging](https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile#-allowlocalfirewallrules)
- [Microsoft: firewall rule health and policy sources](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule)
- [Microsoft: effective firewall profiles](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile)
- [NVD API documentation](https://nvd.nist.gov/developers/vulnerabilities)
- [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

## Catalog coverage

The following table is generated from the embedded catalog. "Implemented" means
an evaluator exists; it does not predict how many checks will succeed on a host.

| Windows Server | Edition | Benchmark version | Catalog recommendations | Implemented comparisons |
|---|---|---|---:|---:|
| 2016 | Domain | 4.0.0 | 422 | 230 |
| 2016 | STIG | 3.0.0 | 521 | 230 |
| 2019 | Domain | 5.0.0 | 400 | 224 |
| 2019 | STIG | 3.0.0 | 528 | 235 |
| 2022 | Domain | 5.1.0 | 408 | 233 |
| 2022 | STIG | 2.0.0 | 540 | 244 |
| 2022 | Standalone | 2.0.0 | 342 | 199 |
| 2025 | Domain | 2.1.1 | 428 | 257 |
| 2025 | Standalone | 2.0.0 | 361 | 217 |
