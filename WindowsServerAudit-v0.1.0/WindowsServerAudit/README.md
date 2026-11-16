# Windows Server security auditor — version 0.1.0

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

- The user-supplied CIS PDFs named in the catalog and coverage table below.
- [Microsoft: secedit export](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/secedit-export)
- [Microsoft: SQL instance registry mapping](https://learn.microsoft.com/en-us/sql/sql-server/install/file-locations-for-default-and-named-instances-of-sql-server)
- [Microsoft: SERVERPROPERTY](https://learn.microsoft.com/en-us/sql/t-sql/functions/serverproperty-transact-sql)
- [Microsoft: software inventory and Win32_Product considerations](https://learn.microsoft.com/en-us/powershell/scripting/samples/working-with-software-installations)
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
