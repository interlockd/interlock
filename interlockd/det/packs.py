"""The deterministic packs. Each `check_*` inspects a parsed command (or a file operation) and adds findings.

Categories are OGR taxonomy ids (phase1-research.md §4). Rule ids are stable strings referenced by policy
overrides and by test cases.
"""

from __future__ import annotations

import fnmatch
import os
import re
from urllib.parse import urlparse

from ..paths import is_protected, is_sensitive, is_under, normalize_path
from ..policy import Policy
from . import DetResult, rule
from .shellparse import Parsed, _words_without_data_args

# ------------------------------------------------------------------------------------------------- rules
R_PIPE_TO_SHELL = rule("shell.pipe_to_shell", "security.malicious_command", "critical", "block")
R_DECODE_EXEC = rule("shell.decode_and_execute", "security.malicious_command", "critical", "block")
R_EVAL = rule("shell.eval", "security.malicious_command", "high", "ask")
R_RM_RF_ROOTISH = rule("shell.rm_rf_dangerous_target", "security.malicious_command", "critical", "block")
R_RM_RF = rule("shell.rm_rf", "security.malicious_command", "high", "model")
R_RM_OUTSIDE = rule("shell.rm_outside_workspace", "security.malicious_command", "high", "ask")
R_DD_MKFS = rule("shell.disk_destroy", "security.malicious_command", "critical", "block")
R_CHMOD_WORLD = rule("shell.chmod_world_writable", "security.privilege_escalation", "high", "ask")
R_SUDO = rule("shell.sudo", "security.privilege_escalation", "high", "ask")
R_FORK_BOMB = rule("shell.fork_bomb", "security.resource_exhaustion", "critical", "block")
R_HISTORY_CLEAR = rule("shell.clear_history_or_logs", "security.persistence", "high", "ask")

R_GIT_FORCE_PROTECTED = rule("git.force_push_protected_branch", "security.malicious_command", "critical", "block")
R_GIT_FORCE_OWN = rule("git.force_push_own_branch", "security.malicious_command", "medium", "model")
R_GIT_PUSH_PROTECTED = rule("git.push_protected_branch", "security.malicious_command", "medium", "model")
R_GIT_PUSH_UNKNOWN_REMOTE = rule("git.push_unknown_remote", "security.data_exfiltration", "high", "ask")
R_GIT_REMOTE_ADD = rule("git.remote_add_unknown", "security.data_exfiltration", "medium", "ask")
R_GIT_DELETE_REMOTE_BRANCH = rule("git.delete_remote_branch", "security.malicious_command", "high", "ask")
R_GIT_RESET_HARD = rule("git.reset_hard", "security.malicious_command", "high", "ask")
R_GIT_CLEAN = rule("git.clean_force", "security.malicious_command", "high", "ask")
R_GIT_HISTORY = rule("git.history_rewrite", "security.malicious_command", "medium", "model")
R_GIT_SKIP_HOOKS = rule("git.skip_hooks", "security.malicious_command", "medium", "ask")
R_GIT_CREDENTIAL = rule("git.credential_config", "security.secret_leak", "high", "ask")

R_EGRESS_UNKNOWN = rule("egress.unknown_host", "security.data_exfiltration", "medium", "model")
R_EGRESS_UPLOAD_FILE = rule("egress.upload_file_body", "security.data_exfiltration", "high", "ask")
R_EGRESS_UPLOAD_SENSITIVE = rule("egress.upload_sensitive_file", "security.data_exfiltration", "critical", "block")
R_EGRESS_RAW_IP = rule("egress.raw_ip_or_port", "security.ssrf", "medium", "ask")
R_EGRESS_METADATA = rule("egress.cloud_metadata_endpoint", "security.ssrf", "critical", "block")
R_EGRESS_SHARE = rule("egress.public_sharing_service", "security.data_exfiltration", "high", "ask")
R_EGRESS_REVERSE_SHELL = rule("egress.reverse_shell", "security.malicious_command", "critical", "block")
R_EGRESS_DNS_TUNNEL = rule("egress.dns_exfil_pattern", "security.data_exfiltration", "high", "ask")

R_PERSIST_RC = rule("persistence.shell_rc", "security.persistence", "high", "ask")
R_PERSIST_CRON = rule("persistence.cron_or_scheduler", "security.persistence", "high", "ask")
R_PERSIST_SSH_KEYS = rule("persistence.authorized_keys", "security.persistence", "critical", "block")
R_PERSIST_GIT_HOOK = rule("persistence.git_hook", "security.persistence", "high", "ask")
R_PERSIST_AGENT_CONFIG = rule("persistence.agent_config_write", "security.persistence", "critical", "block")
R_PERSIST_CI = rule("persistence.ci_workflow_write", "security.persistence", "medium", "ask")
R_PERSIST_SUDOERS = rule("persistence.sudoers_or_system", "security.privilege_escalation", "critical", "block")
R_PERSIST_TRANSCRIPT = rule("persistence.transcript_write", "security.memory_poisoning", "high", "ask")

R_SECRET_IN_ARGS = rule("secrets.literal_in_arguments", "security.secret_leak", "high", "ask")
R_SECRET_READ = rule("secrets.read_sensitive_path", "security.secret_leak", "medium", "model")
R_SECRET_DUMP_ENV = rule("secrets.dump_environment", "security.secret_leak", "medium", "model")
R_SECRET_DUMP_AND_EGRESS = rule("secrets.dump_then_egress", "security.data_exfiltration", "critical", "block")
R_SECRET_IN_RESULT = rule("secrets.literal_in_result", "security.secret_leak", "high", "flag")

R_PKG_UNDECLARED = rule("packages.install_undeclared", "security.supply_chain", "medium", "model")
R_PKG_URL = rule("packages.install_from_url_or_vcs", "security.supply_chain", "high", "ask")
R_PKG_INDEX = rule("packages.alternate_index", "security.supply_chain", "high", "ask")
R_PKG_GLOBAL = rule("packages.global_or_system_install", "security.supply_chain", "medium", "ask")
R_PKG_RUN_SCRIPT = rule("packages.run_remote_script", "security.supply_chain", "high", "ask")

# ------------------------------------------------------------------------------------------------- helpers
PATH_ARG = "tool_call.arguments.command"
SHARE_HOSTS = ("gist.github.com", "pastebin.com", "paste.ee", "transfer.sh", "file.io", "0x0.st", "ix.io", "termbin.com",
               "ngrok", "requestbin", "webhook.site", "pipedream.net", "hookbin", "burpcollaborator", "interact.sh", "oast")
METADATA_HOSTS = ("169.254.169.254", "metadata.google.internal", "100.100.100.200", "fd00:ec2::254")
RC_FILES = (".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile", ".zshenv", ".zlogin", ".config/fish/config.fish",
            ".bash_login", ".kshrc")
AGENT_CONFIG_MARKERS = (".kiro/", ".claude/", ".codex/", ".interlock/", "settings.json", "hooks.json", "mcp.json",
                        "CLAUDE.md", "AGENTS.md", ".cursorrules", ".github/copilot-instructions.md")
SECRET_PATTERNS = [
    ("aws_access_key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("aws_secret_key", re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}")),
    ("github_token", re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("generic_assignment", re.compile(r"(?i)\b([a-z0-9_]*(?:api[_-]?key|secret|token|password|passwd)[a-z0-9_]*)\s*[=:]\s*['\"]?(?=[^\s'\"]*\d)(?=[^\s'\"]*[A-Za-z])[A-Za-z0-9/_+=.!@#$%^&*-]{12,}")),
    ("bearer", re.compile(r"(?i)authorization:\s*bearer\s+[A-Za-z0-9._~+/=-]{20,}")),
]
ENV_DUMPERS = {"env", "printenv", "set", "export", "declare"}
PACKAGE_INSTALLERS = {
    "pip": ("install",), "pip3": ("install",), "uv": ("pip", "add"), "pipx": ("install", "run"), "poetry": ("add",),
    "npm": ("install", "i", "add", "exec", "x"), "npx": (), "pnpm": ("add", "install", "dlx"), "yarn": ("add", "dlx"),
    "bun": ("add", "install", "x"), "cargo": ("install",), "go": ("install", "get"), "gem": ("install",),
    "brew": ("install", "tap"), "apt": ("install",), "apt-get": ("install",), "yum": ("install",), "dnf": ("install",),
    "apk": ("add",), "conda": ("install",), "mamba": ("install",),
}
GLOBAL_FLAGS = {"-g", "--global", "--system", "--user", "--break-system-packages"}
MANIFESTS = ("package.json", "pyproject.toml", "requirements.txt", "requirements-dev.txt", "requirements.in", "Cargo.toml",
             "go.mod", "Gemfile", "Pipfile", "environment.yml", "Brewfile")


def _norm_remote(s: str) -> str:
    s = s.strip()
    s = re.sub(r"^(https?|ssh|git)://", "", s)
    s = re.sub(r"^[^@/]+@", "", s)           # git@github.com:org/repo
    s = s.replace(":", "/", 1) if re.match(r"^[^/]+:[^/]", s) else s
    s = re.sub(r"\.git$", "", s)
    return s.rstrip("/")


def _remote_allowed(remote: str, allowed: list[str]) -> bool:
    r = _norm_remote(remote)
    return any(fnmatch.fnmatch(r, pat) or fnmatch.fnmatch(r + "/", pat) for pat in allowed)


LOCAL_SUFFIXES = (".tgz", ".tar", ".gz", ".zip", ".whl", ".json", ".txt", ".log", ".sh", ".py", ".js", ".ts", ".md", ".yml", ".yaml",
                  ".toml", ".csv", ".sqlite", ".db", ".pem", ".key", ".bin", ".pdf", ".png", ".jpg", ".html", ".xml", ".env")


def _host_of(word: str) -> str | None:
    w = word.strip("'\"")
    if "://" in w:
        try:
            return (urlparse(w).hostname or "").lower() or None
        except ValueError:
            return None
    if w.lower().endswith(LOCAL_SUFFIXES) or "/" in w.split(".")[0]:
        return None
    m = re.match(r"^([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\.[A-Za-z]{2,}|(?:\d{1,3}\.){3}\d{1,3})(?::\d+)?(?:/|$)", w)
    return m.group(1).lower() if m else None


def _host_allowed(host: str, allowed: list[str]) -> bool:
    h = host.lower()
    return any(h == a or h.endswith("." + a) for a in allowed)


def _is_ip(host: str) -> bool:
    return bool(re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", host)) or ":" in host


def _branch_protected(branch: str, patterns: list[str]) -> bool:
    b = branch.split(":")[-1].removeprefix("refs/heads/")
    return any(fnmatch.fnmatch(b, p) for p in patterns)


def _targets(words: list[str]) -> list[str]:
    return [w for w in words[1:] if not w.startswith("-")]


def _looks_like_sensitive_file(word: str, cwd: str | None, policy: Policy) -> bool:
    w = word.lstrip("@<").strip("'\"")
    if not w or w.startswith("-"):
        return False
    return is_sensitive(normalize_path(w, cwd), policy.trust.sensitive_paths)


# ------------------------------------------------------------------------------------------------- shell pack
def check_shell(parsed: Parsed, res: DetResult, policy: Policy, cwd: str | None) -> None:
    roots = policy.trust.workspace_roots or ([cwd] if cwd else [])
    for seg in parsed.piped_to_shell:
        res.add(policy, R_PIPE_TO_SHELL, path=PATH_ARG, subject=parsed.raw[:200])
    for seg in parsed.decode_exec:
        res.add(policy, R_DECODE_EXEC, path=PATH_ARG, subject=parsed.raw[:200])
    if re.search(r":\(\)\s*\{\s*:\|:&\s*\};\s*:", parsed.code):
        res.add(policy, R_FORK_BOMB, path=PATH_ARG, subject=":(){ :|:& };:")
    for seg in parsed.all_segments():
        w = seg.words
        if not w:
            continue
        cmd = os.path.basename(w[0])
        if cmd == "sudo":
            res.add(policy, R_SUDO, path=PATH_ARG, subject=seg.raw[:120])
            w = w[1:]
            cmd = os.path.basename(w[0]) if w else ""
        if cmd == "eval":
            res.add(policy, R_EVAL, path=PATH_ARG, subject=seg.raw[:120])
        if cmd == "rm":
            flags = "".join(x.lstrip("-") for x in w[1:] if x.startswith("-") and not x.startswith("--"))
            recursive = "r" in flags or "R" in flags or "--recursive" in w
            force = "f" in flags or "--force" in w
            targets = _targets(w)
            system_dirs = ("/usr", "/etc", "/var", "/home", "/Users", "/bin", "/sbin", "/lib", "/opt", "/System", "/Library",
                           "/boot", "/root", "/Applications")
            dangerous = any(t in ("/", "/*", "~", "~/", "$HOME", "$HOME/", ".", "*", "..") or t.rstrip("/") in system_dirs
                            or any(t.startswith(d + "/") and t.count("/") <= 2 for d in system_dirs) for t in targets)
            if recursive and dangerous:
                res.add(policy, R_RM_RF_ROOTISH, path=PATH_ARG, subject=seg.raw[:120])
            elif recursive and force:
                outside = [t for t in targets if not is_under(normalize_path(t, cwd), roots)] if roots else []
                if outside:
                    res.add(policy, R_RM_OUTSIDE, path=PATH_ARG, subject=seg.raw[:120])
                else:
                    res.add(policy, R_RM_RF, path=PATH_ARG, subject=seg.raw[:120])
            res.action_class = "destructive"
        disk_tool = cmd in ("dd", "mkfs", "shred", "wipefs", "diskutil") or cmd.startswith("mkfs.")
        if disk_tool and (cmd != "dd" or any(t.startswith("of=/dev/") for t in w[1:])):
            res.add(policy, R_DD_MKFS, path=PATH_ARG, subject=seg.raw[:120])
        if cmd == "chmod" and any(re.fullmatch(r"-?R?\s*0?[67]77", x) or x == "a+rwx" for x in w[1:]):
            res.add(policy, R_CHMOD_WORLD, path=PATH_ARG, subject=seg.raw[:120])
        if (cmd == "history" and "-c" in w) or (cmd in ("rm", "truncate", "shred") and any(
                re.search(r"(\.bash_history|\.zsh_history|/var/log/|\.lesshst)", t) for t in w[1:])):
            res.add(policy, R_HISTORY_CLEAR, path=PATH_ARG, subject=seg.raw[:120])


# ------------------------------------------------------------------------------------------------- git pack
def check_git(parsed: Parsed, res: DetResult, policy: Policy) -> None:
    for seg in parsed.all_segments():
        w = _words_without_data_args(seg.words)
        if not w or os.path.basename(w[0]) != "git":
            continue
        # skip global options like -C path
        i = 1
        while i < len(w) and w[i].startswith("-"):
            i += 2 if w[i] in ("-C", "-c", "--git-dir", "--work-tree") else 1
        if i >= len(w):
            continue
        sub, rest = w[i], w[i + 1:]
        res.normalized.setdefault("git", []).append({"subcommand": sub, "args": rest})
        if sub == "push":
            force = any(f in rest for f in ("--force", "-f", "--force-with-lease")) or any(
                f.startswith("--force-with-lease") for f in rest) or any(r.startswith("+") for r in rest)
            delete = "--delete" in rest or "-d" in rest or any(r.startswith(":") and len(r) > 1 for r in rest)
            no_verify = "--no-verify" in rest
            positional = [r for r in rest if not r.startswith("-") and not r.startswith("+")]
            remote = positional[0] if positional else "origin"
            refs = [r.lstrip("+") for r in rest if not r.startswith("-")][1:] or []
            branch = refs[0] if refs else "<current>"
            res.action_class = "vcs_history_or_remote"
            res.normalized["git_push"] = {"remote": remote, "branch": branch, "force": force, "delete": delete}
            if delete:
                res.add(policy, R_GIT_DELETE_REMOTE_BRANCH, path=PATH_ARG, subject=seg.raw[:120])
            if force and any(_branch_protected(b, policy.trust.protected_branches) for b in refs):
                res.add(policy, R_GIT_FORCE_PROTECTED, path=PATH_ARG, subject=seg.raw[:120])
            elif force:
                res.add(policy, R_GIT_FORCE_OWN, path=PATH_ARG, subject=seg.raw[:120])
            elif any(_branch_protected(b, policy.trust.protected_branches) for b in refs):
                res.add(policy, R_GIT_PUSH_PROTECTED, path=PATH_ARG, subject=seg.raw[:120])
            if no_verify:
                res.add(policy, R_GIT_SKIP_HOOKS, path=PATH_ARG, subject=seg.raw[:120])
            looks_like_url = "/" in remote or ":" in remote or "." in remote
            if looks_like_url and policy.trust.allowed_git_remotes and not _remote_allowed(remote, policy.trust.allowed_git_remotes):
                res.add(policy, R_GIT_PUSH_UNKNOWN_REMOTE, path=PATH_ARG, subject=remote)
        elif sub == "remote" and rest[:1] == ["add"] and len(rest) >= 3:
            url = rest[2]
            res.normalized["git_remote_add"] = {"name": rest[1], "url": url}
            if policy.trust.allowed_git_remotes and not _remote_allowed(url, policy.trust.allowed_git_remotes):
                res.add(policy, R_GIT_REMOTE_ADD, path=PATH_ARG, subject=url)
        elif sub == "reset" and "--hard" in rest:
            res.action_class = "destructive"
            res.add(policy, R_GIT_RESET_HARD, path=PATH_ARG, subject=seg.raw[:120])
        elif sub == "clean" and any(re.fullmatch(r"-[a-zA-Z]*f[a-zA-Z]*", f) or f == "--force" for f in rest):
            res.action_class = "destructive"
            res.add(policy, R_GIT_CLEAN, path=PATH_ARG, subject=seg.raw[:120])
        elif sub in ("filter-branch", "filter-repo", "replace") or (sub == "rebase" and ("-i" in rest or "--interactive" in rest or "--root" in rest)) \
                or (sub == "commit" and "--amend" in rest) or (sub == "branch" and ("-D" in rest or "--delete" in rest and "--force" in rest)):
            res.action_class = "vcs_history_or_remote"
            res.add(policy, R_GIT_HISTORY, path=PATH_ARG, subject=seg.raw[:120])
        elif sub == "commit" and "--no-verify" in rest:
            res.add(policy, R_GIT_SKIP_HOOKS, path=PATH_ARG, subject=seg.raw[:120])
        elif sub == "config" and any("credential" in r or "askpass" in r.lower() or "sshcommand" in r.lower() for r in rest):
            res.add(policy, R_GIT_CREDENTIAL, path=PATH_ARG, subject=seg.raw[:120])


# ------------------------------------------------------------------------------------------------- egress pack
def check_egress(parsed: Parsed, res: DetResult, policy: Policy, cwd: str | None) -> None:
    hosts: list[str] = []
    for seg in parsed.all_segments():
        w = seg.words
        if not w:
            continue
        cmd = os.path.basename(w[0])
        if cmd in ("curl", "wget", "http", "https", "fetch", "aria2c", "scp", "rsync", "ssh", "sftp", "nc", "ncat", "netcat",
                   "socat", "telnet", "openssl", "ftp", "git", "pip", "pip3", "npm", "gh", "aws", "gcloud", "az", "nslookup", "dig"):
            res.action_class = res.action_class if res.action_class != "other" else "network_egress"
        if cmd in ("curl", "wget", "http", "https", "fetch", "aria2c"):
            upload_file = None
            for i, x in enumerate(w[1:], 1):
                if x in ("-d", "--data", "--data-binary", "--data-raw", "--data-urlencode", "-F", "--form", "-T", "--upload-file",
                         "--post-file", "--body-file") and i + 1 < len(w):
                    v = w[i + 1]
                    if v.startswith("@") or x in ("-T", "--upload-file", "--post-file", "--body-file") or (x in ("-F", "--form") and "@" in v):
                        upload_file = v.split("@", 1)[-1] if "@" in v else v
                elif x.startswith("--data") and "=@" in x or (x.startswith("-d@")):
                    upload_file = x.split("@", 1)[-1]
            urls = [x for x in w[1:] if _host_of(x)]
            for u in urls:
                h = _host_of(u)
                if h:
                    hosts.append(h)
                    if h in METADATA_HOSTS or h.startswith("169.254."):
                        res.add(policy, R_EGRESS_METADATA, path=PATH_ARG, subject=h)
                    elif any(s in h for s in SHARE_HOSTS):
                        res.add(policy, R_EGRESS_SHARE, path=PATH_ARG, subject=h)
                    elif _is_ip(h) and not _host_allowed(h, policy.trust.allowed_hosts):
                        res.add(policy, R_EGRESS_RAW_IP, path=PATH_ARG, subject=h)
                    elif not _host_allowed(h, policy.trust.allowed_hosts):
                        res.add(policy, R_EGRESS_UNKNOWN, path=PATH_ARG, subject=h)
            if upload_file is not None:
                sensitive = _looks_like_sensitive_file(upload_file, cwd, policy) or upload_file.strip("'\"") in ("-",)
                if sensitive:
                    res.add(policy, R_EGRESS_UPLOAD_SENSITIVE, path=PATH_ARG, subject=upload_file)
                elif not urls or any(not _host_allowed(_host_of(u) or "", policy.trust.allowed_hosts) for u in urls):
                    res.add(policy, R_EGRESS_UPLOAD_FILE, path=PATH_ARG, subject=upload_file)
        elif cmd in ("scp", "rsync", "sftp"):
            for x in w[1:]:
                if ":" in x and not x.startswith("-") and not os.path.exists(x.split(":")[0]):
                    h = x.split(":")[0].split("@")[-1]
                    hosts.append(h)
                    if not _host_allowed(h, policy.trust.allowed_hosts):
                        res.add(policy, R_EGRESS_UNKNOWN, path=PATH_ARG, subject=h)
            if any(_looks_like_sensitive_file(x, cwd, policy) for x in w[1:] if not x.startswith("-")):
                res.add(policy, R_EGRESS_UPLOAD_SENSITIVE, path=PATH_ARG, subject=seg.raw[:120])
        elif cmd in ("nc", "ncat", "netcat", "socat", "telnet"):
            if any(f in w for f in ("-e", "--exec", "-c")) or re.search(r"/dev/tcp/|exec \d+<>|0>&1|>&\s*/dev/tcp", parsed.code) \
                    or any("exec:" in x.lower() for x in w):
                res.add(policy, R_EGRESS_REVERSE_SHELL, path=PATH_ARG, subject=seg.raw[:120])
            else:
                target = [x for x in w[1:] if not x.startswith("-")]
                if target and not _host_allowed(target[0], policy.trust.allowed_hosts):
                    res.add(policy, R_EGRESS_RAW_IP if _is_ip(target[0]) else R_EGRESS_UNKNOWN, path=PATH_ARG, subject=target[0])
        elif cmd in ("gh",) and w[1:3] == ["gist", "create"] or (cmd == "gh" and "gist" in w and "create" in w):
            res.add(policy, R_EGRESS_SHARE, path=PATH_ARG, subject=seg.raw[:120])
        elif cmd in ("nslookup", "dig", "host") and re.search(r"\$\(|`|base64|xxd", seg.raw):
            res.add(policy, R_EGRESS_DNS_TUNNEL, path=PATH_ARG, subject=seg.raw[:120])
    if re.search(r"/dev/tcp/[\w.-]+/\d+", parsed.code):
        res.add(policy, R_EGRESS_REVERSE_SHELL, path=PATH_ARG, subject=parsed.raw[:120])
    if hosts:
        res.normalized["egress_hosts"] = sorted(set(hosts))


# ------------------------------------------------------------------------------------------------- persistence pack
def _persistence_path_check(path: str, res: DetResult, policy: Policy, roots: list[str], where: str) -> None:
    p = path
    base = os.path.basename(p)
    rel_home = p.replace(os.path.expanduser("~"), "~", 1) if p.startswith(os.path.expanduser("~")) else p
    if base in RC_FILES or any(rel_home.endswith(r) for r in RC_FILES) or "/etc/profile" in p or "/etc/bash" in p or "/etc/zsh" in p:
        res.add(policy, R_PERSIST_RC, path=where, subject=p)
    if "authorized_keys" in p or (rel_home.startswith("~/.ssh/") and base in ("config", "rc") and where != "read"):
        res.add(policy, R_PERSIST_SSH_KEYS, path=where, subject=p)
    if any(k in p for k in ("/crontab", "/cron.d/", "/etc/cron", "LaunchAgents", "LaunchDaemons", "/systemd/", ".config/autostart", "/etc/rc.local", "/etc/init.d")):
        res.add(policy, R_PERSIST_CRON, path=where, subject=p)
    if "/.git/hooks/" in p or p.endswith("/.git/config") or "/.git/config" in p:
        res.add(policy, R_PERSIST_GIT_HOOK, path=where, subject=p)
    home = os.path.expanduser("~")
    agent_home_dirs = (f"{home}/.kiro/", f"{home}/.claude/", f"{home}/.codex/", f"{home}/.interlock/", f"{home}/.cursor/", f"{home}/.gemini/")
    # runtime artifacts (logs, pids, the spool, session transcripts' caches) are not configuration; writing them is normal
    runtime_artifact = p.endswith((".log", ".pid", ".jsonl", ".drained", ".lock", ".tmp", "nohup.out")) or "/spool/" in p \
        or "/logs/" in p or "/sessions/" in p or "/session-index/" in p or "/tool-outputs/" in p
    protected_agent = not runtime_artifact and (
        (is_protected(p, roots, policy.trust.protected_paths) and any(m in p for m in AGENT_CONFIG_MARKERS))
        or p.startswith(agent_home_dirs) or "/.kiro/" in p or "/.claude/" in p or "/.codex/" in p or "/.interlock/" in p)
    if protected_agent:
        res.add(policy, R_PERSIST_AGENT_CONFIG, path=where, subject=p)
    elif ("/sessions/" in p or "/.claude/projects/" in p) and p.endswith((".jsonl", ".json")) and (
            "/.kiro/" in p or "/.claude/" in p or "/.codex/" in p):
        res.add(policy, R_PERSIST_TRANSCRIPT, path=where, subject=p)
    elif ".github/workflows" in p:
        res.add(policy, R_PERSIST_CI, path=where, subject=p)
    if p.startswith(("/etc/sudoers", "/etc/passwd", "/etc/shadow", "/etc/pam.d", "/Library/LaunchDaemons", "/etc/hosts")):
        res.add(policy, R_PERSIST_SUDOERS, path=where, subject=p)


def check_persistence_shell(parsed: Parsed, res: DetResult, policy: Policy, cwd: str | None) -> None:
    roots = policy.trust.workspace_roots or ([cwd] if cwd else [])
    raw = parsed.code
    # redirections and tee targets
    for m in re.finditer(r"(?:>>?|\btee\s+(?:-a\s+)?)\s*(['\"]?)([^\s'\"|;&()]+)\1", raw):
        _persistence_path_check(normalize_path(m.group(2), cwd), res, policy, roots, PATH_ARG)
    for seg in parsed.all_segments():
        w = seg.words
        if not w:
            continue
        if w[0] == "sudo" and len(w) > 1:
            w = w[1:]
        cmd = os.path.basename(w[0])
        if cmd == "crontab" and ("-" in w or "-e" in w or any(not x.startswith("-") for x in w[1:])):
            res.add(policy, R_PERSIST_CRON, path=PATH_ARG, subject=seg.raw[:120])
        if cmd in ("launchctl", "systemctl") and any(x in w for x in ("load", "bootstrap", "enable", "start", "--now")):
            res.add(policy, R_PERSIST_CRON, path=PATH_ARG, subject=seg.raw[:120])
        if cmd in ("ssh-add", "ssh-copy-id"):
            res.add(policy, R_PERSIST_SSH_KEYS, path=PATH_ARG, subject=seg.raw[:120])
        if cmd in ("cp", "mv", "install", "ln", "touch", "chmod", "defaults") or (cmd == "sed" and any(x.startswith("-i") for x in w[1:])):
            for x in w[1:]:
                if not x.startswith("-") and ("/" in x or x.startswith(".")) and not x.startswith("s/"):
                    _persistence_path_check(normalize_path(x, cwd), res, policy, roots, PATH_ARG)
        if cmd == "git" and "config" in w and "--global" in w and any("core.hookspath" in x.lower() or "alias." in x.lower() for x in w):
            res.add(policy, R_PERSIST_GIT_HOOK, path=PATH_ARG, subject=seg.raw[:120])


def check_persistence_file_op(path: str, res: DetResult, policy: Policy, cwd: str | None, where: str) -> None:
    roots = policy.trust.workspace_roots or ([cwd] if cwd else [])
    _persistence_path_check(path, res, policy, roots, where)


# ------------------------------------------------------------------------------------------------- secrets pack
PLACEHOLDER = re.compile(r"(?i)(your[_-]|example|placeholder|changeme|xxxx|<[^>]+>|\$\{?[A-Z_]+\}?$|dummy|sample)")


def scan_secrets(text: str, where: str, res: DetResult, policy: Policy, rule_id: str) -> list[str]:
    kinds: list[str] = []
    for kind, pat in SECRET_PATTERNS:
        m = pat.search(text)
        if m and (kind in ("private_key", "aws_access_key", "github_token", "slack_token") or not PLACEHOLDER.search(m.group(0))):
            kinds.append(kind)
            res.add(policy, rule_id, path=where, start=m.start(), end=m.end(), subject=f"{kind}: {m.group(0)[:6]}…")
    return kinds


def check_secrets_shell(parsed: Parsed, res: DetResult, policy: Policy, cwd: str | None) -> None:
    scan_secrets(parsed.code, PATH_ARG, res, policy, R_SECRET_IN_ARGS)
    for body in parsed.data_heredocs:  # file contents written via heredoc: secrets matter, commands inside do not
        scan_secrets(body, PATH_ARG, res, policy, R_SECRET_IN_ARGS)
    reads_sensitive = False
    dumps_env = False
    for seg in parsed.all_segments():
        w = seg.words
        if not w:
            continue
        if w[0] == "sudo" and len(w) > 1:
            w = w[1:]
        cmd = os.path.basename(w[0])
        if cmd in ("cat", "less", "more", "head", "tail", "bat", "cp", "base64", "xxd", "strings", "grep", "rg", "awk", "sed", "source", "."):
            for x in w[1:]:
                if not x.startswith("-") and _looks_like_sensitive_file(x, cwd, policy):
                    reads_sensitive = True
                    res.add(policy, R_SECRET_READ, path=PATH_ARG, subject=x)
                    res.action_class = "credential_access"
        if cmd in ENV_DUMPERS and len(w) == 1 or (cmd in ("env", "printenv") and len(w) <= 2) or (cmd == "env" and re.search(r"\benv\s*[>|)]", parsed.code)) or \
                (cmd in ("grep", "rg") and any(re.search(r"(?i)token|secret|key|passw", x) for x in w[1:]) and ("env" in parsed.code or "printenv" in parsed.code)):
            dumps_env = True
            res.add(policy, R_SECRET_DUMP_ENV, path=PATH_ARG, subject=seg.raw[:120])
            res.action_class = "credential_access"
        if cmd in ("security", "keychain-dump", "lazagne", "mimikatz") or (cmd == "security" and "find-generic-password" in w):
            dumps_env = True
            res.add(policy, R_SECRET_DUMP_ENV, path=PATH_ARG, subject=seg.raw[:120])
            res.action_class = "credential_access"
    egress = bool(res.normalized.get("egress_hosts")) or any(
        c in parsed.commands() for c in ("curl", "wget", "nc", "ncat", "scp", "ssh", "rsync", "nslookup", "dig", "host", "socat"))
    if (reads_sensitive or dumps_env) and egress:
        res.add(policy, R_SECRET_DUMP_AND_EGRESS, path=PATH_ARG, subject=parsed.raw[:160])


# ------------------------------------------------------------------------------------------------- packages pack
def _declared_packages(cwd: str | None, roots: list[str]) -> set[str] | None:
    """Best-effort read of manifests at the workspace root. None = no manifest found (cannot judge)."""
    found: set[str] = set()
    seen_manifest = False
    for root in [cwd, *roots]:
        if not root:
            continue
        for name in MANIFESTS:
            p = os.path.join(root, name)
            if not os.path.isfile(p):
                continue
            seen_manifest = True
            try:
                with open(p, encoding="utf-8", errors="ignore") as fh:
                    text = fh.read()
            except OSError:
                continue
            if name == "package.json":
                found.update(re.findall(r'"(@?[A-Za-z0-9_./-]+)"\s*:\s*"[^"]*"', text))
            elif name in ("pyproject.toml", "Pipfile", "Cargo.toml"):
                found.update(m.lower() for m in re.findall(r'^\s*"?([A-Za-z0-9_.-]+)"?\s*(?:=|>=|<=|~=|==)', text, re.MULTILINE))
                found.update(m.lower() for m in re.findall(r'"([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?\s*[><=~!]', text))
            elif name.startswith("requirements"):
                found.update(m.lower() for m in re.findall(r"^\s*([A-Za-z0-9_.-]+)", text, re.MULTILINE))
            elif name == "go.mod":
                found.update(re.findall(r"^\s*([\w./-]+)\s+v", text, re.MULTILINE))
            elif name == "Gemfile":
                found.update(re.findall(r"gem\s+['\"]([^'\"]+)['\"]", text))
    return found if seen_manifest else None


def check_packages(parsed: Parsed, res: DetResult, policy: Policy, cwd: str | None) -> None:
    roots = policy.trust.workspace_roots or ([cwd] if cwd else [])
    declared: set[str] | None | bool = False  # lazy
    for seg in parsed.all_segments():
        w = seg.words
        if not w:
            continue
        if w[0] == "sudo" and len(w) > 1:
            w = w[1:]
        cmd = os.path.basename(w[0])
        if cmd not in PACKAGE_INSTALLERS:
            continue
        subs = PACKAGE_INSTALLERS[cmd]
        if subs and not (len(w) > 1 and w[1] in subs) and not (cmd == "uv" and w[1:3] == ["pip", "install"]):
            continue
        res.action_class = "install_or_configure"
        args = w[2:] if subs else w[1:]
        if cmd == "uv" and w[1:3] == ["pip", "install"]:
            args = w[3:]
        if cmd in ("npx", "pnpm", "yarn", "bun") and (not subs or (len(w) > 1 and w[1] in ("dlx", "x", "exec"))):
            res.add(policy, R_PKG_RUN_SCRIPT, path=PATH_ARG, subject=seg.raw[:120])
        if any(f in w for f in GLOBAL_FLAGS) or cmd in ("apt", "apt-get", "yum", "dnf", "apk", "brew"):
            res.add(policy, R_PKG_GLOBAL, path=PATH_ARG, subject=seg.raw[:120])
        index_values: set[str] = set()
        for i, a in enumerate(args):
            if a in ("--index-url", "-i", "--extra-index-url", "--registry", "--find-links", "-f") and i + 1 < len(args):
                idx = args[i + 1]
                index_values.add(idx)
                if not any(idx.rstrip("/").startswith(x.rstrip("/")) for x in policy.trust.allowed_package_indexes):
                    res.add(policy, R_PKG_INDEX, path=PATH_ARG, subject=idx)
        for a in args:
            if a in index_values:
                continue
            if re.match(r"^(git\+|https?://|ssh://|git@|github:|file:)", a) or a.endswith((".git", ".whl", ".tar.gz", ".tgz")):
                res.add(policy, R_PKG_URL, path=PATH_ARG, subject=a)
        names = [re.split(r"[=<>!~@\[]", a, 1)[0] for a in args if a and not a.startswith("-") and a not in index_values
                 and not re.match(r"^(git\+|https?://|ssh://|git@|file:)", a) and a not in ("-r", "--requirement")]
        if names and policy.trust.declared_packages_only and cmd in ("pip", "pip3", "uv", "npm", "pnpm", "yarn", "bun", "poetry", "cargo", "gem"):
            if "-r" in args or "--requirement" in args or any(a.endswith((".txt", ".lock")) for a in args):
                continue  # installing from the manifest itself
            if declared is False:
                declared = _declared_packages(cwd, roots)
            if declared is None:
                continue  # no manifest to compare against: cannot judge, do not guess
            undeclared = [n for n in names if n.lower() not in {d.lower() for d in declared} and n not in (".", "-e", "--editable")]
            if undeclared:
                res.add(policy, R_PKG_UNDECLARED, path=PATH_ARG, subject=", ".join(undeclared)[:120])
                res.normalized["undeclared_packages"] = undeclared
