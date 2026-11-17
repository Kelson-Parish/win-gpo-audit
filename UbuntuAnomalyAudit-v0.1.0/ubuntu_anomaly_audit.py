#!/usr/bin/env python3
"""Read-only, baseline-free Ubuntu 25 security triage. Standard library only."""
import sys
sys.dont_write_bytecode = True
import argparse
import datetime as dt
import hashlib
import html
import ipaddress
import json
import itertools
import selectors
import signal
import os
from pathlib import Path
import re
import shlex
import socket
import stat
import struct
import subprocess
import time

VERSION = "0.1.0"
READ_LIMIT = 262144
FILE_LIMIT = 3000
TOOLS = {
    "systemctl": ["/usr/bin/systemctl"],
    "nft": ["/usr/sbin/nft"],
    "iptables": ["/usr/sbin/iptables-save"],
    "ip6tables": ["/usr/sbin/ip6tables-save"],
    "iptables_legacy": ["/usr/sbin/iptables-legacy-save"],
    "ip6tables_legacy": ["/usr/sbin/ip6tables-legacy-save"],
    "ufw": ["/usr/sbin/ufw"],
    "sshd": ["/usr/sbin/sshd"],
    "dpkg": ["/usr/bin/dpkg-query"],
    "mdatp": ["/usr/bin/mdatp", "/opt/microsoft/mdatp/sbin/mdatp"],
}
TEMP_PATH = re.compile(r"^/(?:tmp|var/tmp|dev/shm)(?:/|$)")
SCRIPT_SUFFIXES = {".py", ".pyw", ".sh", ".bash", ".pl", ".rb", ".js", ".mjs", ".cjs", ".ps1"}


def parse_os_release(text):
    result = {}
    for line in text.splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            try:
                parts = shlex.split(value)
                result[key] = parts[0] if parts else ""
            except ValueError:
                result[key] = value.strip('"')
    return result


def finding(kind, priority, identity, title, observation, why, verify):
    return dict(kind=kind, priority=priority, identity=identity, title=title,
                observation=observation, why=why, verify=verify)


def behavior_signals(text):
    """Passive text patterns. Observed content is never imported or executed."""
    result = []
    if re.search(r"(?:\bcurl\b|\bwget\b)[^\n]{0,400}\|\s*(?:sudo\s+)?(?:ba)?sh\b", text, re.I):
        result.append("Download piped to a shell")
    if re.search(r"\b(?:base64\s+(?:-d|--decode)|openssl\s+enc\s+-d)[^\n]{0,300}\|\s*(?:ba)?sh\b", text, re.I):
        result.append("Decoded content piped to a shell")
    if re.search(r"/dev/(?:tcp|udp)/|\b(?:nc|ncat|netcat)\b[^\n]{0,150}\s-[a-z]*e\s+(?:/\w+/)?(?:ba)?sh\b", text, re.I):
        result.append("Shell/network redirection pattern")
    capture = re.search(r"keyboard\s*\.\s*Listener\s*\(|from\s+pynput(?:\.keyboard)?\s+import|\bevdev\.InputDevice\s*\(|\bXRecordCreateContext\s*\(", text, re.I)
    logging = re.search(r"on_press\s*=|read_loop\s*\(|open\(.{0,120}['\"][aw]['\"]|\.write\s*\(", text, re.I | re.S)
    if capture and logging:
        result.append("Keyboard/input-capture code patterns")
    if re.search(r"(?:^|\s)(?:LD_PRELOAD|LD_AUDIT)\s*=\s*['\"]?/(?:tmp|var/tmp|dev/shm)/", text):
        result.append("Temporary library injected through the dynamic loader")
    return result


def runtime(argv):
    if not argv:
        return ""
    name = Path(argv[0]).name
    if re.fullmatch(r"(?:python(?:\d+(?:\.\d+)*)?|pypy\d*)", name):
        return "Python"
    if name in {"node", "nodejs", "deno", "bun"}:
        return "JavaScript runtime"
    if name in {"perl", "ruby", "php", "lua", "pwsh"}:
        return "Script runtime"
    if name in {"sh", "bash", "dash", "zsh", "ksh"} and len(argv) > 1 and argv[1] not in {"-l", "--login"}:
        return "Shell script or command"
    return ""


def script_target(argv, cwd):
    """Conservative argument extraction; interpreter options are not evaluated."""
    if not argv:
        return None
    name = Path(argv[0]).name
    args = argv[1:]
    if name != "env" and not runtime(argv):
        if Path(argv[0]).suffix in SCRIPT_SUFFIXES:
            return str(Path(argv[0]) if argv[0].startswith("/") else Path(cwd or "/") / argv[0])
        return None
    if name == "env":
        args = [a for a in args if "=" not in a]
        return script_target(args, cwd) if args else None
    for i, value in enumerate(args):
        if value in {"-c", "-m", "-e", "--eval", "--command"}:
            return None
        if value.startswith("-"):
            continue
        if Path(value).suffix in SCRIPT_SUFFIXES or value.startswith("/"):
            return str(Path(value) if value.startswith("/") else Path(cwd or "/") / value)
    return None


def parse_ssh(text):
    return dict(line.split(None, 1) for line in text.splitlines() if len(line.split(None, 1)) == 2)


def ssh_findings(text):
    config = parse_ssh(text)
    output = []
    if config.get("permitrootlogin") == "yes" and config.get("passwordauthentication") == "yes":
        output.append(finding("SecurityWeakness", "High", "SecureShell:RootPassword", "Secure Shell permits root login with password authentication", "PermitRootLogin=yes; PasswordAuthentication=yes", "Effective global server settings permit a high-privilege password-authentication path; account/Pluggable Authentication Modules (PAM) conditions can still apply.", "Confirm approved remote-access policy. Conditional Match settings require separate assessment."))
    if config.get("permitemptypasswords") == "yes":
        output.append(finding("SecurityWeakness", "High", "SecureShell:EmptyPasswords", "Secure Shell permits empty passwords", "PermitEmptyPasswords=yes", "The effective global setting weakens authentication where other conditions permit it.", "Review authentication requirements and conditional settings."))
    return output


def nft_input_state(document):
    """False only for demonstrably empty/accept-only input hooks. None is unknown.
    True means potential filtering, not proof of correct rules or reachability.
    """
    entries = document.get("nftables")
    if not isinstance(entries, list):
        return None
    chains = {}
    rules = {}
    for entry in entries:
        if "chain" in entry:
            c = entry["chain"]
            chains[(c.get("family"), c.get("table"), c.get("name"))] = c
        if "rule" in entry:
            r = entry["rule"]
            rules.setdefault((r.get("family"), r.get("table"), r.get("chain")), []).append(r)
    relevant = [key for key, c in chains.items() if c.get("hook") == "input" and c.get("family") in {"ip", "ip6", "inet"}]
    if not relevant:
        return False
    for key in relevant:
        if chains[key].get("policy") == "drop":
            return True
        if chains[key].get("policy") not in {"accept", None}:
            return None
        if rules.get(key):
            return None  # jumps, maps, priorities and expressions require full evaluation
    return False


def iptables_input_state(text):
    in_filter = False
    saw_input = False
    for line in text.splitlines():
        if line.startswith("*"):
            in_filter = line == "*filter"
        if not in_filter:
            continue
        if line.startswith(":INPUT "):
            saw_input = True
            if line.split()[1] == "DROP":
                return True
            if line.split()[1] != "ACCEPT":
                return None
        if line.startswith("-A INPUT "):
            return None
    # An empty successful save has no legacy input filter table.
    return False if saw_input or not text.strip() or "*filter" not in text else None


def firewall_finding(required, states, ufw_status="unknown"):
    if required != "required":
        return []
    # Require all available backends to be read, including explicit legacy tools.
    if not states or any(value is None for value in states.values()):
        return []
    if any(value is True for value in states.values()):
        return []
    return [finding("SecurityWeakness", "High", "Firewall:NoInputPolicy", "No host input filtering was observed despite your requirement", "All successfully inventoried network-filter backends have absent or empty accept-policy input chains. Uncomplicated Firewall status: " + ufw_status, "This is evidence about local nftables/iptables input policy. Cloud security groups, external firewalls and other kernel filtering mechanisms are outside this check.", "Confirm the intended host protection and applicable backend. The audit does not enable or modify a firewall.")]


def release_findings(os_info, today):
    deadlines = {"25.04": dt.date(2026, 1, 15), "25.10": dt.date(2026, 7, 9)}
    version = os_info.get("VERSION_ID")
    if os_info.get("ID") == "ubuntu" and version in deadlines and today >= deadlines[version]:
        return [finding("SecurityWeakness", "High", "Ubuntu:Support", "This Ubuntu release is past its security-support period", "Ubuntu " + version + "; published support ended " + deadlines[version].isoformat(), "This release no longer receives normal Ubuntu security updates. This is a known lifecycle condition, not evidence of a Red Team implant.", "Plan an approved move to a supported release. No upgrade is performed.")]
    return []


class Audit:
    def __init__(self):
        self.coverage = []
        self.files = {}
        self.owners = {}
        self.findings = []
        self.artifacts = []
        self.commands = {}
        self.tool_cache = {}
        self.untrusted_mounts = []
        self.file_reads = 0
        try:
            for line in Path("/proc/mounts").read_text().splitlines():
                fields = line.split()
                if len(fields) >= 3 and (fields[2].startswith(("nfs", "fuse", "cifs")) or fields[2] in {"9p", "smb3", "autofs"}):
                    self.untrusted_mounts.append(fields[1].replace("\\040", " "))
        except OSError:
            self.gap("Mount inventory", "Cannot exclude all remote filesystem mounts.")

    def gap(self, name, detail, status="Unavailable"):
        self.coverage.append(dict(check=name, status=status, detail=str(detail)))

    def read(self, path, limit=READ_LIMIT, required=False, binary=False):
        """No devices/FIFOs/symlinks or known remote mounts. Bounded reads only."""
        p = Path(path)
        try:
            if not p.is_absolute() or ".." in p.parts:
                raise ValueError("ordinary absolute paths only")
            for mount in self.untrusted_mounts:
                if str(p) == mount or str(p).startswith(mount.rstrip("/") + "/"):
                    raise ValueError("remote/automount filesystem skipped")
            part = Path("/")
            for segment in p.parts[1:]:
                part /= segment
                if stat.S_ISLNK(os.lstat(part).st_mode):
                    raise ValueError("symlink path skipped")
            fd = os.open(str(p), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode):
                    raise ValueError("non-regular file skipped")
                with os.fdopen(fd, "rb", closefd=False) as stream:
                    data = stream.read(limit + 1)
                if len(data) > limit:
                    raise ValueError("file exceeds bounded read limit")
                return data if binary else data.decode("utf-8", errors="replace")
            finally:
                os.close(fd)
        except (OSError, ValueError) as exc:
            if required or not isinstance(exc, FileNotFoundError):
                self.gap("Read " + str(p), exc)
            return None

    def run(self, tool, args, limit=2 * 1024 * 1024, accepted=(0,)):
        """Fixed utilities only; time/output bounded, no shell or PATH lookup."""
        if tool not in self.tool_cache:
            executable = next((p for p in TOOLS[tool] if Path(p).exists()), None)
            try:
                if not executable:
                    raise ValueError("Optional read-only utility is not installed.")
                real = Path(executable).resolve(strict=True)
                for part in [real] + list(real.parents):
                    metadata = part.stat()
                    if metadata.st_uid != 0 or metadata.st_mode & 0o022:
                        raise ValueError("utility or parent is not root-owned and protected from group/world writes")
                self.tool_cache[tool] = executable
            except (OSError, ValueError) as exc:
                self.gap(tool, exc, "Not assessed"); self.tool_cache[tool] = None
        executable = self.tool_cache[tool]
        if not executable:
            return None
        process = None
        try:
            process = subprocess.Popen([executable] + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                shell=False, stdin=subprocess.DEVNULL, cwd="/", start_new_session=True,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "SYSTEMD_PAGER": "", "SYSTEMD_COLORS": "0"})
            buffers = {"out": bytearray(), "err": bytearray()}; total = 0; deadline = time.monotonic() + 20
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ, "out")
                selector.register(process.stderr, selectors.EVENT_READ, "err")
                while selector.get_map():
                    if time.monotonic() >= deadline:
                        raise ValueError("read-only utility exceeded 20-second timeout")
                    for key, _ in selector.select(timeout=0.2):
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            selector.unregister(key.fileobj); continue
                        total += len(chunk)
                        if total > limit:
                            raise ValueError("utility output exceeded capture limit")
                        buffers[key.data].extend(chunk)
            process.wait(timeout=max(0.1, deadline-time.monotonic()))
            if process.returncode not in accepted:
                raise ValueError("exit " + str(process.returncode) + ": " + buffers["err"][:4096].decode(errors="replace"))
            value = buffers["out"].decode(errors="replace")
            self.commands[tool + " " + " ".join(args)] = value
            return value
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            self.gap(tool, exc); return None
        finally:
            if process:
                if process.poll() is None:
                    try: os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                    process.wait()
                if process.stdout: process.stdout.close()
                if process.stderr: process.stderr.close()

    def package_owner(self, path):
        if path not in self.owners:
            value = self.run("dpkg", ["--search", "--", path], limit=32768, accepted=(0, 1))
            self.owners[path] = "; ".join(line for line in (value or "").splitlines() if ": " in line and line.split(": ", 1)[1] == path)
        return self.owners[path]

    def file_fact(self, path):
        if path in self.files:
            return self.files[path]
        fact = dict(path=path, sha256="", package="", signals=[], status="Unreadable")
        self.files[path] = fact
        self.file_reads += 1
        if self.file_reads > FILE_LIMIT:
            self.gap("Referenced files", "File inspection cap reached.", "Partial")
            return fact
        fact["package"] = self.package_owner(path)
        data = self.read(path, binary=True)
        if data is None:
            return fact
        try:
            info = os.stat(path, follow_symlinks=False)
            fact.update(status="Observed", uid=info.st_uid, gid=info.st_gid,
                        mode=oct(stat.S_IMODE(info.st_mode)), sha256=hashlib.sha256(data).hexdigest(),
                        signals=behavior_signals(data.decode("utf-8", errors="replace")))
            if info.st_mode & 0o002:
                fact["signals"].append("Referenced file is world-writable")
        except OSError as exc:
            self.gap(path, "File changed during inspection: " + str(exc), "Partial")
        return fact

    def safe_directory(self, path):
        p = Path(path)
        try:
            if not p.is_absolute() or ".." in p.parts: return False
            for mount in self.untrusted_mounts:
                if str(p) == mount or str(p).startswith(mount.rstrip("/") + "/"): return False
            part = Path("/")
            for segment in p.parts[1:]:
                part /= segment
                if stat.S_ISLNK(os.lstat(part).st_mode): return False
            return p.is_dir()
        except OSError:
            return False

    def unit_files(self, directory):
        stack = [Path(directory)]; count = 0
        while stack and count < FILE_LIMIT:
            current = stack.pop()
            if not self.safe_directory(current): continue
            try:
                with os.scandir(current) as entries:
                    for entry in itertools.islice(entries, FILE_LIMIT-count):
                        count += 1
                        if entry.is_dir(follow_symlinks=False): stack.append(Path(entry.path))
                        elif entry.is_file(follow_symlinks=False) and Path(entry.name).suffix in {".service", ".timer", ".conf"}:
                            yield Path(entry.path)
            except OSError as exc: self.gap(str(current), exc)


    def analyze_artifact(self, identity, kind, command, source, cwd="/", privileged=False, inspect_paths=True):
        signals = behavior_signals(command)
        try:
            argv = shlex.split(command, comments=False)
        except ValueError:
            argv = []
        target = script_target(argv, cwd)
        if privileged and ((argv and TEMP_PATH.match(argv[0])) or re.search(r"(?:^|\n)\s*(?:exec\s+|nohup\s+)?/(?:tmp|var/tmp|dev/shm)/", command)):
            signals.append("Privileged persistence executes a temporary-directory payload")
        if inspect_paths and not target:
            candidates = re.findall(r"(/[A-Za-z0-9_./@+\-]+\.(?:py|sh|pl|rb|js))\b", command)
            if candidates: target = candidates[0]
        if inspect_paths and target:
            fact = self.file_fact(target)
            signals.extend(fact["signals"])
            if TEMP_PATH.match(target) and privileged:
                signals.append("Privileged persistence references a temporary-directory payload")
        record = dict(identity=identity, kind=kind, command=command, source=source, target=target,
                      privileged=privileged, signals=sorted(set(signals)))
        self.artifacts.append(record)
        if record["signals"]:
            strong = any(s != "Referenced file is world-writable" for s in record["signals"])
            if strong or privileged:
                self.findings.append(finding("Persistence", "High" if privileged else "Medium", identity,
                                             "Persistence or scheduled command has specific suspicious evidence", command,
                                             "; ".join(record["signals"]) + ". Static text may contain legitimate examples or approved automation.",
                                             "Inspect " + source + " and the exact payload. Do not run the observed command to investigate."))

    def collect_persistence(self):
        paths = []
        for directory in ["/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly", "/var/spool/cron/crontabs"]:
            try:
                if self.safe_directory(directory):
                    paths += [(p, "cron" if directory.endswith(("cron.d", "crontabs")) else "cron-script") for p in itertools.islice(Path(directory).iterdir(), FILE_LIMIT) if not p.name.startswith(".")]
            except FileNotFoundError:
                pass
            except OSError as exc:
                self.gap(directory, exc)
        paths += [(Path(p), "cron" if p.endswith("crontab") else "startup") for p in ["/etc/crontab", "/etc/rc.local", "/etc/profile"] if os.path.lexists(p)]
        # Loaded system units include packaged files, administrator overrides and transient fragments.
        units = self.run("systemctl", ["list-units", "--all", "--type=service", "--type=timer", "--no-legend", "--no-pager", "--plain"])
        if units is not None:
            names = [line.split()[0] for line in units.splitlines() if line.split() and re.fullmatch(r"[A-Za-z0-9_@.\\:\-]+\.(?:service|timer)", line.split()[0])]
            properties = "Id,FragmentPath,DropInPaths,ExecStart,ExecStartPre,ExecStartPost,User,ActiveState,UnitFileState,LoadState"
            for start in range(0, min(len(names), 2000), 50):
                data = self.run("systemctl", ["show", "--no-pager", "--property=" + properties, "--"] + names[start:start + 50])
                if data is None:
                    continue
                for block in data.split("\n\n"):
                    fields = dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
                    identity = fields.get("Id", "unknown")
                    if fields.get("LoadState") != "loaded":
                        continue  # inactive services can still be triggered by enabled timers/dependencies
                    privileged = fields.get("User", "") in {"", "root", "0"}
                    for field in ["ExecStart", "ExecStartPre", "ExecStartPost"]:
                        for match in re.finditer(r"argv\[\]=(.*?)(?: ;|$)", fields.get(field, "")):
                            self.analyze_artifact("systemd:" + identity + ":" + field, "systemd", match.group(1), fields.get("FragmentPath") or identity, privileged=privileged)
                    for value in [fields.get("FragmentPath", "")] + fields.get("DropInPaths", "").split():
                        if value:
                            paths.append((Path(value), "unit-definition"))
            if len(names) > 2000:
                self.gap("System service units", "Unit cap reached.", "Partial")
        # Read user persistence files without logging in as other users or executing their shells.
        passwd = self.read("/etc/passwd", required=True) or ""
        for line in passwd.splitlines():
            parts = line.split(":")
            if len(parts) != 7 or not parts[5].startswith("/"):
                continue
            home = Path(parts[5])
            if not self.safe_directory(home): continue
            for tail in [".profile", ".bashrc", ".bash_profile", ".zshrc"]:
                path = home / tail
                if os.path.lexists(path):
                    paths.append((path, "root-startup" if parts[2] == "0" else "user-startup"))
            user_units = home / ".config/systemd/user"
            paths.extend((path, "root-user-unit" if parts[2] == "0" else "user-unit") for path in self.unit_files(user_units))
            if len(paths) >= FILE_LIMIT: break
        if len(paths) > FILE_LIMIT: self.gap("Persistence files", "File cap reached.", "Partial")
        for path, kind in list(dict.fromkeys(paths))[:FILE_LIMIT]:
            text = self.read(str(path))
            if text is None:
                continue
            try: info = path.stat(follow_symlinks=False)
            except OSError as exc:
                self.gap(str(path), exc, "Partial"); continue
            if kind == "cron":
                for number, line in enumerate(text.splitlines(), 1):
                    clean = line.strip()
                    if not clean or clean.startswith("#") or re.match(r"^[A-Za-z_]\w*=", clean):
                        continue
                    if str(path) == "/etc/crontab" or str(path).startswith("/etc/cron.d/"):
                        parts = clean.split(None, 2 if clean.startswith("@") else 6)
                        if len(parts) != (3 if clean.startswith("@") else 7):
                            self.gap(str(path), "Unparsed cron line " + str(number), "Partial"); continue
                        account, command = parts[-2], parts[-1]
                        privileged = account in {"root", "0"}
                    else:
                        parts = clean.split(None, 1 if clean.startswith("@") else 5)
                        if len(parts) != (2 if clean.startswith("@") else 6):
                            self.gap(str(path), "Unparsed user cron line " + str(number), "Partial"); continue
                        command = parts[-1]; privileged = path.name == "root"
                    self.analyze_artifact(str(path) + ":" + str(number), kind, command, str(path), privileged=privileged, inspect_paths=False)
                    # Absolute script targets in cron commands are inspected passively.
                    for target in re.findall(r"(/[A-Za-z0-9_./@+\-]+\.(?:py|sh|pl|rb|js))\b", command):
                        fact = self.file_fact(target)
                        if fact["signals"] or (TEMP_PATH.match(target) and privileged):
                            self.findings.append(finding("Persistence", "High" if privileged else "Medium", str(path) + ":payload:" + target, "Scheduled command references a risky script payload", target, "; ".join(fact["signals"]) or "A root-account schedule references a temporary script.", "Inspect the schedule, effective job account and referenced script; file ownership alone does not prove execution as root."))
            else:
                code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith(("#", ";")))
                self.analyze_artifact(str(path), kind, code, str(path), privileged=(info.st_uid == 0 and kind not in {"user-startup", "user-unit"}), inspect_paths=False)
            if info.st_mode & 0o002:
                self.findings.append(finding("SecurityWeakness", "High", "Writable:" + str(path), "A persistence configuration is world-writable", str(path), "Mode bits permit any local user to modify this file; daemon permission checks may refuse it rather than execute it.", "Inspect ownership, permissions and the consuming service. Effective access-control lists are not calculated."))
        self.gap("Persistence scope", "Loaded system units, selected cron/startup files and user unit files only. User managers, enablement, generated units, environment files, containers and all persistence mechanisms are not fully resolved.", "Partial")

    def collect_processes(self, cap=4096):
        result = []; fd_budget = 50000
        for directory in Path("/proc").iterdir():
            if not directory.name.isdigit():
                continue
            if len(result) >= cap:
                self.gap("Processes", "Process cap reached.", "Partial"); break
            try:
                with (directory / "cmdline").open("rb") as stream: raw = stream.read(16384)
                argv = [part.decode(errors="replace") for part in raw.split(b"\0") if part]
                if not argv:
                    continue
                with (directory / "status").open() as stream: status = stream.read(65536)
                uid_fields = re.search(r"^Uid:\s+(\d+)\s+(\d+)", status, re.M)
                real_uid = int(uid_fields.group(1)); uid = int(uid_fields.group(2))
                parent = int(re.search(r"^PPid:\s+(\d+)", status, re.M).group(1))
                try: exe = os.readlink(directory / "exe")
                except OSError: exe = ""
                try: cwd = os.readlink(directory / "cwd")
                except OSError: cwd = ""
                sockets = []
                try:
                    for fd in itertools.islice((directory / "fd").iterdir(), min(2048, fd_budget)):
                        fd_budget -= 1
                        try:
                            link = os.readlink(fd)
                            if link.startswith("socket:["):
                                sockets.append(link[8:-1])
                        except OSError:
                            pass
                except OSError:
                    pass
                result.append(dict(pid=int(directory.name), parent=parent, uid=uid, real_uid=real_uid, exe=exe, cwd=cwd, argv=argv, sockets=sockets))
            except (OSError, ValueError, AttributeError):
                continue  # races/protected processes summarized as an explicit coverage limit
        if fd_budget <= 0: self.gap("Socket association", "Global descriptor inspection cap reached.", "Partial")
        self.gap("Process visibility", "Snapshots can miss short-lived/protected processes; file-descriptor lists are capped and process identifiers can be reused. Only the current process/network namespaces are visible.", "Partial")
        return result

    def collect_network(self):
        connections = []
        for protocol in ["tcp", "tcp6", "udp", "udp6"]:
            # /proc/net is a deliberate kernel symlink. Open the explicit current
            # process namespace path instead, never a path found in observed commands.
            try:
                with Path("/proc/self/net/" + protocol).open() as stream: text = stream.read(2 * 1024 * 1024)
            except OSError as exc:
                self.gap("Network " + protocol, exc); continue
            for line in text.splitlines()[1:]:
                fields = line.split()
                if len(fields) < 10:
                    continue
                try:
                    def endpoint(value):
                        address, port = value.split(":")
                        data = b"".join(struct.pack("<I", int(address[i:i+8], 16)) for i in range(0, len(address), 8))
                        return socket.inet_ntop(socket.AF_INET6 if len(data) == 16 else socket.AF_INET, data), int(port, 16)
                    local, local_port = endpoint(fields[1]); remote, remote_port = endpoint(fields[2])
                    connections.append(dict(protocol=protocol, local=local, local_port=local_port, remote=remote, remote_port=remote_port, state=fields[3], inode=fields[9]))
                except (ValueError, OSError):
                    continue
        return connections

    def analyze_processes(self, processes, connections):
        groups = {}
        for process in processes:
            if process["pid"] == os.getpid():
                continue
            command = shlex.join(process["argv"])
            signals = behavior_signals(command)
            target = script_target(process["argv"], process["cwd"])
            fact = self.file_fact(target) if target else None
            if fact:
                signals.extend(fact["signals"])
            if process["exe"].startswith("/memfd:") or (" (deleted)" in process["exe"] and TEMP_PATH.match(process["exe"])):
                signals.append("Process executes an anonymous or deleted temporary executable")
            if process["uid"] == 0 and TEMP_PATH.match(process["exe"]):
                signals.append("Root process executes a temporary-directory program")
            run = runtime(process["argv"])
            # Ubuntu itself runs Python/shell automation. Package ownership
            # suppresses weak runtime-only leads, never stronger code evidence.
            custom = bool(run and (not fact or not fact.get("package")))
            if run == "Shell script or command" and "-c" not in process["argv"] and not target:
                custom = False
            if not signals and not custom:
                continue
            key = command
            entry = groups.setdefault(key, dict(command=command, processes=[], signals=set(), runtime=run, target=target))
            entry["processes"].append(process); entry["signals"].update(signals)
        for entry in groups.values():
            pids = [p["pid"] for p in entry["processes"]]
            inodes = {s for p in entry["processes"] for s in p["sockets"]}
            peers = sorted({c["remote"] + ":" + str(c["remote_port"]) for c in connections if c["inode"] in inodes and c["state"] == "01" and c["protocol"].startswith("tcp") and not ipaddress.ip_address(c["remote"]).is_loopback})
            evidence = ("; ".join(sorted(entry["signals"])) + ". " if entry["signals"] else "Custom/unattributed script runtime needs approval context. ")
            evidence += "Process identifiers: " + ", ".join(map(str, pids)) + ". "
            if peers:
                evidence += "Associated established peers: " + ", ".join(peers) + ". Connection direction and beaconing are not established. "
            self.findings.append(finding("ThreatEvidence" if entry["signals"] else "RunningScript", "High" if entry["signals"] else "Medium", "Process:" + ",".join(map(str, pids)), "Running process has specific suspicious evidence" if entry["signals"] else "Custom script runtime is running - confirm its purpose", entry["command"], evidence, "Inspect the exact script, account and parent process. A package ownership record does not prove integrity, and an unattributed script can be legitimate application code."))

    def collect_security(self, os_info, host_firewall):
        self.findings.extend(release_findings(os_info, dt.date.today()))
        passwd = self.read("/etc/passwd", required=True) or ""
        extra = [line.split(":")[0] for line in passwd.splitlines() if len(line.split(":")) == 7 and line.split(":")[2] == "0" and line.split(":")[0] != "root"]
        if extra:
            self.findings.append(finding("SecurityWeakness", "High", "Accounts:RootEquivalent", "Additional local root-equivalent accounts exist", ", ".join(extra), "These local accounts have user identifier zero. This is an observed privilege assignment, not proof of who created it.", "Confirm approval and account ownership. Directory-provided accounts are not enumerated."))
        critical = ["/etc/passwd", "/etc/group", "/etc/sudoers", "/etc/ssh/sshd_config"]
        try: critical += [str(p) for p in Path("/etc/sudoers.d").iterdir() if not p.name.startswith(".")]
        except OSError: pass
        for path in critical:
            if not os.path.lexists(path): continue
            try:
                metadata = os.lstat(path)
                if stat.S_ISLNK(metadata.st_mode):
                    self.gap(path, "Symlink configuration path not assessed.", "Partial"); continue
                if metadata.st_mode & 0o002:
                    self.findings.append(finding("SecurityWeakness", "High", "Writable:" + path, "Critical authentication configuration is world-writable", path, "Any local user can modify mode-bit writable content; consuming tools may reject unsafe permissions.", "Review exact ownership, permissions and configuration validity."))
                if path.startswith("/etc/sudoers"):
                    text = self.read(path) or ""
                    if re.search(r"^\s*ALL\s+ALL\s*=\s*\([^)]*\)\s*(?:NOPASSWD:\s*)?ALL\s*(?:#.*)?$", text, re.M):
                        self.findings.append(finding("SecurityWeakness", "High", "Sudo:AllUsers:" + path, "Administrative-command policy grants every user full command privileges", path, "An explicit ALL-users/ALL-commands rule was observed. Ordinary administrator-group rules and cloud-image passwordless users are not flagged just for existing.", "Validate included policy and effective permissions with approved administrative tools."))
            except OSError as exc: self.gap(path, exc)
        preload = self.read("/etc/ld.so.preload")
        if preload and any(line.strip() and not line.lstrip().startswith("#") for line in preload.splitlines()):
            self.findings.append(finding("Persistence", "Medium", "Loader:GlobalPreload", "Global dynamic-loader preloading is configured", preload.strip(), "This can be legitimate instrumentation or security software; it is also a high-impact persistence location.", "Identify every library and its approved package/vendor. Referenced libraries are not loaded by this audit."))
        apparmor = self.read("/sys/module/apparmor/parameters/enabled")
        if os_info.get("ID") == "ubuntu" and apparmor and apparmor.strip() == "N":
            self.findings.append(finding("SecurityWeakness", "High", "AppArmor:Disabled", "AppArmor is explicitly disabled in the kernel", "Kernel module parameter: N", "AppArmor is normally loaded by Ubuntu. Container/host policy scope needs validation.", "Confirm kernel security configuration and approved exceptions."))
        elif apparmor is None:
            self.gap("AppArmor", "Kernel state could not be read; no disabled-state assumption was made.", "Not assessed")
        disabled_profiles = Path("/etc/apparmor.d/disable")
        if self.safe_directory(disabled_profiles):
            try:
                names = sorted(p.name for p in itertools.islice(disabled_profiles.iterdir(), 1000) if not p.name.startswith("."))
                if names:
                    self.findings.append(finding("SecurityWeakness", "Medium", "AppArmor:DisabledProfiles", "AppArmor profiles are explicitly disabled", ", ".join(names[:20]), "Entries exist in the profile-disable directory. Vendor compatibility or approved exceptions can explain them.", "Review the named profiles and effective kernel enforcement. Presence of an entry is not proof of compromise."))
            except OSError as exc: self.gap("AppArmor disabled profiles", exc)
        ssh = self.run("sshd", ["-T"])
        if ssh is not None: self.findings.extend(ssh_findings(ssh))
        self.gap("Secure Shell conditional policy", "The read-only global configuration test does not evaluate every conditional Match context or authentication-module decision.", "Partial")
        states = {}
        nft = self.run("nft", ["-j", "list", "ruleset"])
        if nft is not None:
            try: states["nftables"] = nft_input_state(json.loads(nft))
            except (ValueError, TypeError): states["nftables"] = None
        else: states["nftables"] = None
        for name in ["iptables", "ip6tables"]:
            value = self.run(name, [])
            states[name] = iptables_input_state(value) if value is not None else None
        for name in ["iptables_legacy", "ip6tables_legacy"]:
            if any(Path(p).exists() for p in TOOLS[name]):
                value = self.run(name, [])
                states[name] = iptables_input_state(value) if value is not None else None
        ufw = self.run("ufw", ["status"])
        ufw_state = "active" if ufw and re.search(r"^Status: active\s*$", ufw, re.M) else "inactive" if ufw and "Status: inactive" in ufw else "unknown"
        self.findings.extend(firewall_finding(host_firewall, states, ufw_state))
        self.gap("Firewall scope", "Uncomplicated Firewall inactivity alone is never treated as no firewall. Complex rules, external filtering and other namespaces are not fully evaluated. Backend states: " + str(states), "Partial")
        if any(Path(p).exists() for p in TOOLS["mdatp"]):
            raw = self.run("mdatp", ["exclusion", "list", "--output", "json"])
            if raw is not None:
                try:
                    value = json.loads(raw)
                    exclusions = value if isinstance(value, list) else value.get("exclusions") if isinstance(value, dict) else None
                    if not isinstance(exclusions, list): raise ValueError("unrecognized exclusion schema")
                    if exclusions:
                        self.findings.append(finding("SecurityWeakness", "Medium", "Defender:Exclusions", "Microsoft Defender for Endpoint has configured exclusions", "; ".join(e if isinstance(e, str) else ", ".join(str(k)+"="+str(v) for k, v in e.items() if not isinstance(v, (dict, list))) if isinstance(e, dict) else "Unrecognized entry; see separate evidence" for e in exclusions[:12]), "Visible exclusions can be legitimate; complete command output is saved separately.", "Review exact exclusion paths, types and scope. No exclusion was changed."))
                except (ValueError, TypeError) as exc: self.gap("Defender exclusions", exc, "Partial")
        else:
            self.gap("Antivirus integration", "Microsoft Defender for Endpoint command-line client is not installed. Ubuntu does not require this product by default; no antivirus-presence failure is inferred.", "Not applicable")

    def save(self, name, value):
        target = self.output / name
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, ensure_ascii=True)
            stream.write("\n")


FILTER_JS = r"""
(function () {
'use strict';
var q=document.getElementById('query'), k=document.getElementById('kind'), p=document.getElementById('priority');
var rows=document.querySelectorAll('#results tbody tr[data-kind]');
function filter(){var i,r,n=0,s=q.value.toLowerCase().replace(/^\s+|\s+$/g,'');
for(i=0;i<rows.length;i+=1){r=rows[i];var show=(!k.value||r.getAttribute('data-kind')===k.value)&&(!p.value||r.getAttribute('data-priority')===p.value)&&(r.textContent||r.innerText||'').toLowerCase().indexOf(s)!==-1;r.style.display=show?'table-row':'none';if(show){n+=1;}}
document.getElementById('count').innerHTML='Showing '+n+' of '+rows.length+' findings';document.getElementById('empty').style.display=n?'none':'block';}
q.disabled=false;k.disabled=false;p.disabled=false;document.getElementById('reset').disabled=false;
q.addEventListener('input',filter);q.addEventListener('keyup',filter);k.addEventListener('change',filter);p.addEventListener('change',filter);
document.getElementById('reset').addEventListener('click',function(){q.value='';k.value='';p.value='';filter();});
document.getElementById('filterWarning').style.display='none';filter();
}());
"""


def render_report(host, findings, coverage):
    esc = lambda value: html.escape(str(value), quote=True)
    ranks = {"High": 0, "Medium": 1, "Low": 2}
    labels = {"SecurityWeakness": "Security weakness", "Persistence": "Persistence to investigate", "RunningScript": "Running script to review", "ThreatEvidence": "Threat evidence to validate"}
    rows = []
    for item in sorted(findings, key=lambda x: (ranks[x["priority"]], x["kind"], x["identity"])):
        observation = item["observation"]
        if len(observation) > 2200: observation = observation[:2200] + " ... [full observation saved separately]"
        rows.append('<tr data-kind="{kind}" data-priority="{priority}"><td><b>{priority}</b><br>{label}</td><td><b>{title}</b><br><small>{identity}</small></td><td><code>{observation}</code><details><summary>Evidence and next check</summary><p>{why}</p><p><b>Verify:</b> {verify}</p></details></td></tr>'.format(**{k: esc(v) for k, v in item.items() if k != "observation"}, label=esc(labels[item["kind"]]), observation=esc(observation)))
    gaps = "".join("<li>" + esc(c["check"] + ": " + c["detail"]) + "</li>" for c in coverage[:12])
    return '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'none'"><title>Ubuntu focused findings</title><style>
body{font:15px/1.5 Arial,sans-serif;margin:0;background:#f3f4f6;color:#263444}header{padding:22px 5%;background:#7d2f15;color:white}main{padding:18px 5%}table{border-collapse:collapse;width:100%;background:white}th,td{padding:12px;border-bottom:1px solid #d8dfe5;text-align:left;vertical-align:top;word-break:break-word}th{background:#e2e8ed}tr[data-priority=High]{border-left:4px solid #b62e36}code{white-space:pre-wrap;word-break:break-word}details{margin-top:12px}summary{cursor:pointer}input,select,button{padding:8px;margin:5px}.notice{background:#fff4d9;padding:12px}#empty{display:none}.scroll{overflow-x:auto}</style></head><body><header><h1>Ubuntu focused security findings</h1><p>''' + esc(host) + " | read-only audit " + VERSION + '''</p></header><main><p class="notice">Investigation leads on a potentially compromised machine. Script runtimes, cron and system services can be legitimate. No clean baseline is required; no finding certifies malware or a clean host.</p><p id="filterWarning">Filters have not started. If this stays visible, allow local JavaScript in your browser. All findings remain readable.</p><noscript>JavaScript is disabled; all findings are displayed.</noscript><label>Search <input id="query" disabled></label><label>Category <select id="kind" disabled><option value="">All findings</option><option value="SecurityWeakness">Security weaknesses</option><option value="Persistence">Persistence</option><option value="RunningScript">Running scripts</option><option value="ThreatEvidence">Threat evidence</option></select></label><label>Priority <select id="priority" disabled><option value="">All priorities</option><option>High</option><option>Medium</option><option>Low</option></select></label><button id="reset" disabled>Reset filters</button><p id="count"></p><p id="empty">No selected findings. This does not establish that the machine is clean.</p><div class="scroll"><table id="results"><thead><tr><th>Priority / category</th><th>Finding</th><th>Observation and verification</th></tr></thead><tbody>''' + "".join(rows) + '''</tbody></table></div><details><summary>Scan limits and coverage (''' + str(len(coverage)) + ''')</summary><p>No memory/kernel scan, traffic capture, complete persistence coverage, event-log timeline or general vulnerability scan is performed. Only the current namespaces are visible. Package ownership does not verify file integrity. Missing permissions and missing tools remain coverage gaps.</p><ul>''' + gaps + '''</ul><p>Full evidence and readable Coverage.txt are saved separately. No raw inventory or serialized data is embedded here.</p></details></main><script>''' + FILTER_JS + "</script></body></html>"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--host-firewall", choices=["required", "external", "unknown"])
    parser.add_argument("--non-interactive", action="store_true")
    parser.add_argument("--allow-other-linux", action="store_true", help="development/compatibility testing only")
    parser.add_argument("--allow-unprivileged", action="store_true", help="development/limited visibility only")
    args = parser.parse_args(argv)
    if sys.platform != "linux": parser.error("Run locally on Ubuntu Linux.")
    os_info = parse_os_release(Path("/etc/os-release").read_text())
    if (os_info.get("ID") != "ubuntu" or os_info.get("VERSION_ID") not in {"25.04", "25.10"}) and not args.allow_other_linux:
        parser.error("This release targets Ubuntu 25.04 and 25.10. Use --allow-other-linux only for explicit compatibility testing.")
    if os.geteuid() and not args.allow_unprivileged: parser.error("Run with sudo for system visibility.")
    firewall = args.host_firewall
    if firewall is None:
        if args.non_interactive: firewall = "unknown"
        else:
            print("Should this machine enforce a HOST firewall? Cloud/network firewalls are separate.")
            answer = input("Enter required, external, or unknown [Enter=unknown]: ").strip().lower()
            if answer not in {"", "required", "external", "unknown"}: parser.error("Invalid firewall answer.")
            firewall = answer or "unknown"
    output = args.output or Path.cwd() / ("UbuntuTriage-" + time.strftime("%Y%m%d-%H%M%S") + "-" + os.urandom(3).hex())
    output = output.absolute()
    try:
        output.mkdir(mode=0o700, parents=False, exist_ok=False)
    except OSError as exc:
        parser.error("Choose a new report directory beneath an existing parent: " + str(exc))
    audit = Audit(); audit.output = output
    if os.geteuid(): audit.gap("Privileges", "Unprivileged run: system visibility is incomplete.", "Partial")
    if os_info.get("ID") != "ubuntu": audit.gap("Compatibility", "Explicit non-Ubuntu development run. This is not Ubuntu integration validation.", "Partial")
    print("Collecting processes, persistence and focused security settings. No remediation will occur.")
    initial = audit.collect_processes()
    connections = audit.collect_network()
    audit.collect_security(os_info, firewall)
    audit.collect_persistence()
    current = audit.collect_processes()
    current_connections = audit.collect_network()
    audit.analyze_processes(current, current_connections)
    # Stable deduplication preserves distinct findings and avoids repeated unit/cron references.
    unique = {}
    for item in audit.findings: unique[(item["identity"], item["observation"])] = item
    audit.findings = list(unique.values())
    for name, value in [("Findings.json", audit.findings), ("Coverage.json", audit.coverage), ("ProcessesInitial.json", initial), ("ProcessesFinal.json", current), ("ConnectionsInitial.json", connections), ("ConnectionsFinal.json", current_connections), ("Persistence.json", audit.artifacts), ("FileFacts.json", list(audit.files.values())), ("CommandEvidence.json", audit.commands), ("Host.json", dict(os_release=os_info, host=socket.gethostname(), host_firewall_requirement=firewall, collected_utc=dt.datetime.now(dt.timezone.utc).isoformat()))]:
        audit.save(name, value)
    fd = os.open(output / "Coverage.txt", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write("\n".join(c["check"] + " | " + c["status"] + " | " + c["detail"] for c in audit.coverage) + "\n")
    fd = os.open(output / "index.html", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream: stream.write(render_report(socket.gethostname(), audit.findings, audit.coverage))
    print("Report: " + str(output / "index.html"))
    print(str(len(audit.findings)) + " findings; " + str(len(audit.coverage)) + " coverage notes. No findings does not establish a clean host.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
