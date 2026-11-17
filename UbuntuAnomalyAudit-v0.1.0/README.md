# Ubuntu Anomaly Audit 0.1.0

A local, read-only security triage scanner for **Ubuntu 25.04 and 25.10**. It works on a potentially compromised machine without a clean baseline and produces a short, searchable report. Findings are investigation leads, not malware verdicts or a certificate that a host is clean.

## Run

Extract this package on the Ubuntu server, open a terminal in the extracted directory, and run:

```bash
sudo bash ./Invoke-UbuntuAudit.sh
```

The launcher uses `/usr/bin/python3` and Python's standard library. It does not install software, use additional Python packages, or require PowerShell.

There is one setup question: **Should this machine enforce a host firewall?**

- `required`: review absent local input filtering when all inventoried backends can be assessed.
- `external`: protection is intentionally provided outside this machine; the audit does not assess external rules.
- `unknown` or Enter: collect local firewall evidence without claiming a missing required policy.

For a repeat run without questions:

```bash
sudo bash ./Invoke-UbuntuAudit.sh --host-firewall required --non-interactive --output ./UbuntuAuditRun01
```

Use a new output directory each time. Its parent must already exist. The script detects the exact release automatically. Other Linux releases are rejected unless an explicit development compatibility flag is supplied.

The console prints the report path. Open that folder's **index.html** in a browser. The output directory is private (`0700`) and files are private (`0600`). When run with sudo they belong to root. Use your normal privileged file-transfer method, or give your account ownership of this specific report folder:

```bash
sudo chown -R "$(id -u):$(id -g)" ./UbuntuAuditRun01
```

That optional command changes the newly created output folder only. The scanner itself does not change ownership of existing system files.

## What differs from Windows

| Windows target | Ubuntu target |
| --- | --- |
| Scheduled tasks | Cron jobs and systemd timers/services |
| Services and registry startup entries | System service definitions, selected shell startup files, user service files and the global dynamic-loader preload file |
| Domain password-policy checks | Selected local administrative-account, administrator-command policy and Secure Shell (SSH) settings |
| Windows Defender configuration | AppArmor state/profile-disable entries, plus optional Microsoft Defender for Endpoint exclusions when installed |
| PowerShell/Python execution | Custom Python, shell, JavaScript and other runtime processes |
| Windows Firewall profiles | Uncomplicated Firewall (UFW), nftables and iptables evidence in the current network namespace |

Cron and Python are ordinary Ubuntu components. They are not flagged simply for existing. Package ownership can suppress a weak runtime-only lead, but it never suppresses stronger captured behavior patterns. **A package ownership record is not an integrity check** and the package database may itself be compromised.

Ubuntu's Uncomplicated Firewall is initially disabled by default, so that state alone is never treated as proof of missing protection. The script does not infer firewall protection from a service being running or stopped. It inspects available ruleset backends instead. Complex rules remain unknown rather than being classified as safe or unfiltered.

Both Ubuntu 25 releases have ended normal security support: 25.04 on January 15, 2026, and 25.10 on July 9, 2026. The report shows this lifecycle finding separately from persistence/script findings. It does not perform an upgrade.

## Selected findings

- Scheduled or persistent commands that pipe a download/decoded payload into a shell, contain shell/network redirection patterns, or point privileged execution at temporary payloads.
- Referenced script code combining keyboard/input-capture interfaces with capture or logging patterns. Comments, examples and legitimate software can match; inspect the code.
- A process executing an anonymous in-memory executable, a deleted temporary executable, or a temporary-directory program as root. Legitimate installation or instrumentation can explain these cases.
- Custom or unattributed script runtimes. Identical command lines are grouped; the audit's own process is excluded. Existing system automation with a declared package owner is not flagged solely as a runtime.
- Additional local accounts with user identifier zero, an explicit every-user/every-command administrative rule, and selected world-writable authentication/persistence files.
- Secure Shell settings that permit root password login or empty passwords. The global configuration is queried read-only; conditional `Match` blocks and complete authentication-module behavior are not evaluated.
- A nonempty global dynamic-loader preload configuration, explicitly disabled AppArmor kernel state, or entries in the AppArmor profile-disable directory. Approved security products/compatibility work can explain some of these findings.
- Visible Microsoft Defender for Endpoint exclusions, when the optional command-line client is installed and its exclusion output can be parsed. Its absence is not a security finding.

The script avoids reporting every service, every cron job, ordinary administrator-group/passwordless cloud-user rules, or every firewall rule as an anomaly.

## Report and separate evidence

`index.html` contains findings, expandable evidence/next checks and a collapsed coverage summary. Search, category, priority and reset filters are included. No full inventory or serialized evidence dump is embedded. If local JavaScript is disabled, all findings remain readable and the report explains why the filters have not started.

The run folder also contains:

| File | Content |
| --- | --- |
| `Coverage.txt` | Human-readable gaps, limits and missing tools |
| `Coverage.json` | Structured coverage records |
| `Findings.json` | Full finding observations, including text truncated in the report |
| `ProcessesInitial.json`, `ProcessesFinal.json` | Two bounded process snapshots |
| `ConnectionsInitial.json`, `ConnectionsFinal.json` | Connection/socket observations in the current network namespace |
| `Persistence.json` | Selected scheduling/startup records and signals |
| `FileFacts.json` | Bounded referenced-file hashes, permission mode bits and package attribution |
| `CommandEvidence.json` | Successful read-only utility output |
| `Host.json` | Operating system, collection time and the chosen firewall requirement |

JavaScript Object Notation (JSON) files are separate machine-readable evidence. Reports can contain usernames, internal addresses and secrets already embedded in command lines or configurations; protect the whole output folder.

`ExampleReport.html` is **synthetic** and does not represent a scanned computer.

## Read-only design

The scanner never runs commands found in evidence, sources shell profiles, imports observed scripts, installs packages, changes firewall rules, changes accounts, reloads services, starts antivirus scans or remediates. It does not read password hashes from `/etc/shadow` or collect process environment variables.

Known utility locations are used directly with argument arrays and no shell. Utilities and their resolved parent paths must be root-owned and not group/world writable according to mode bits. Only fixed read operations are invoked. Individual utility reads have a 20-second timeout and bounded output; timed-out collector subprocesses may be terminated. Observed processes are never terminated. Missing/unsafe/unavailable utilities are recorded as gaps.

Payload/configuration reads are bounded and skip symlinks, nonregular files and identified remote/automount paths. Special kernel process/network paths are read explicitly for observation. These checks are not atomic against concurrent file changes and do not independently verify a compromised kernel or utility. Normal reads may update access times or produce operating-system/security telemetry. Deliberate output writes go to the new report directory; the launcher disables Python bytecode-cache writes.

## Important limits

- This is a selected-pattern triage tool, not a full compliance, vulnerability, antivirus or integrity scanner.
- It does not reliably identify every beacon, compiled keylogger, injected process, rootkit or in-memory implant. Connections do not prove communication direction or periodic beaconing. No packets are captured.
- Only the current process and network namespaces are visible. A container run does not audit the whole host or other containers.
- Persistence collection covers loaded system service/timer metadata, selected cron directories, selected shell startup files and user unit files. It does not fully resolve user managers, enablement, dependency graphs, environment files, escaped unit paths, all startup mechanisms or application persistence. Inactive loaded services may still be inspected because timers/dependencies can activate them.
- Authentication checks are selected settings, not a full effective sudo/authentication-policy computation. Directory-provided accounts, remote-access keys, all conditional Secure Shell contexts and domain policies are not comprehensively assessed.
- Firewall absence is reported only for an explicitly required host firewall when the captured backends all support the narrow absent/empty-input-policy conclusion. Any unresolved backend prevents that conclusion. An observed filtering policy is not proof of correct protection. External firewalls, cloud policy, other namespaces and other kernel filtering mechanisms are outside the check.
- Input-capture patterns and suspicious shell text can be legitimate examples/automation. No clean reference means authorization still requires a reviewer.
- Referenced script reads/hashes are capped at 262,144 bytes; at most 3,000 referenced files, 2,000 loaded units and 4,096 process records per snapshot are selected. Command lines and descriptor/socket association are also bounded. File hashes use exact read bytes but do not cover every executable or the whole filesystem.
- Mode bits are inspected; complete effective filesystem access-control lists, executable capabilities and a full set-user-identifier file inventory are not computed.
- Event-log/history correlation, online threat-intelligence lookups, general package vulnerability matching, active antivirus threat-report integration and database-specific audits are not implemented in this initial Ubuntu version.
- Results depend on the data supplied by the potentially compromised operating system. Missing evidence is not a pass.

## Validation

Completed in the build environment:

- 26 Python unit tests covering normal-setting suppression, lifecycle dates, firewall uncertainty, package attribution behavior, process grouping, suspicious patterns, safe reads, exact hashes, protected outputs and bounded subprocess capture.
- Nine JavaScript document-fixture groups testing actual filter logic, combined controls, reset, count/no-match behavior and escaped evidence.
- Bash syntax checks and a limited, unprivileged end-to-end Linux smoke run on Debian 13, using explicit development flags.

**Not yet validated on a live Ubuntu 25.04/25.10 server with elevated privileges.** Systemd, firewall, Secure Shell and optional Defender integration were not exercised against a real Ubuntu deployment. The limited smoke environment skips unavailable or untrusted utilities. Full browser rendering remains unverified; JavaScript tests use a document fixture. Treat this as a pilot.

Run the Python tests without elevated privileges:

```bash
python3 -B -m unittest discover -s Tests -v
```

Optional developer filter checks require Node.js, which is not required for the audit:

```bash
node Tests/test_filters.cjs
```

The `--allow-other-linux` and `--allow-unprivileged` options exist for explicit compatibility/limited-visibility testing. They do not turn another distribution or an unprivileged run into validated Ubuntu coverage.

## Sources

- [Ubuntu firewall documentation](https://ubuntu.com/server/docs/firewalls/)
- [Ubuntu AppArmor documentation](https://ubuntu.com/server/docs/security-apparmor/)
- [System service unit lookup and override paths](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html)
- [Microsoft Defender for Endpoint Linux exclusions](https://learn.microsoft.com/en-us/defender-endpoint/linux-exclusions)
- [Ubuntu 25.04 end-of-life announcement](https://lists.ubuntu.com/archives/ubuntu-announce/2026-January/000320.html)
- [Ubuntu 25.10 end-of-life announcement](https://lists.ubuntu.com/archives/ubuntu-announce/2026-July/000325.html)
