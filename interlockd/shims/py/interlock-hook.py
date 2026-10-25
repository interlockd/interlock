# Interlock hook shim in Python: the same contract and output as the POSIX sh shims (claude-code/interlock-hook.sh and
# kiro/interlock-hook.sh), for platforms without sh + curl (native Windows). Installers run it as
# `python -I -S interlock-hook.py [pre|post]`.
#
# Every agent tool call waits on this, so it imports only `os` and `socket` (interpreter start plus ~10 ms): no json
# (it pulls in re) and no urllib (it pulls in ssl). Like the sh shim, it reads the few fields it needs with plain
# string matching and speaks HTTP/1.1 to the local daemon itself; an https INTERLOCK_URL falls back to urllib.
#
# The daemon normalizes the payload and renders the exact reply each harness applies, so this shim only forwards and
# prints. An empty reply means "no opinion": the harness's own permission system stays in charge (Interlock never
# auto-approves). Cursor treats exit 0 with output that isn't permission JSON as a block, so "no opinion" there is a
# non-zero exit. Windsurf and Kiro block with exit 2 and a message on stderr; Kiro's PostToolUse is record-only.
#
# Install writes HARNESS: claude-code | codex | cursor | gemini-cli | copilot-cli | windsurf | antigravity | kiro.

import os
import socket
import sys

HARNESS = "__HARNESS__"
VERSION = "0.1.5"
HOME_DIR = os.environ.get("INTERLOCK_HOME") or os.path.join(os.path.expanduser("~"), ".interlock")
PRE_TIMEOUT = int(os.environ.get("INTERLOCK_PRE_TIMEOUT_MS") or 1500)
POST_TIMEOUT = int(os.environ.get("INTERLOCK_POST_TIMEOUT_MS") or 2500)
REFUSED = ("[interlock] This action was refused by a security policy and was NOT executed. You may pursue the user's "
           "goal by other legitimate means, but you MUST NOT retry this action in a disguised form.")
UNREACHABLE = ("[interlock] This action was NOT executed: the Interlock daemon is unreachable and this workspace fails "
               "closed. Start it with `interlock start`, then retry.")


def log_local(line):
    import time

    try:
        os.makedirs(HOME_DIR, exist_ok=True)
        with open(os.path.join(HOME_DIR, "hook.log"), "a", encoding="utf-8") as f:
            f.write(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) + " " + line + "\n")
    except OSError:
        pass


def out(text, stream=None):
    stream = stream or sys.stdout
    stream.buffer.write((text + "\n").encode("utf-8"))
    stream.flush()


def read(name):
    try:
        with open(os.path.join(HOME_DIR, name), encoding="utf-8") as f:
            return f.read()
    except OSError:
        return ""


def field(text, key):
    """The string value of `"key": "..."` (first occurrence, either spacing), as the sh shim reads it."""
    for pat in (f'"{key}":"', f'"{key}": "'):
        i = text.find(pat)
        if i >= 0:
            j = text.find('"', i + len(pat))
            return text[i + len(pat):j] if j >= 0 else ""
    return ""


def jstr(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t") + '"'


def is_post_event(payload, arg):
    if arg in ("pre", "post"):
        return arg == "post"
    if HARNESS == "cursor":
        return any(k in payload for k in ("postToolUse", "afterShellExecution", "afterMCPExecution"))
    if HARNESS == "gemini-cli":
        return "AfterTool" in payload
    if HARNESS == "windsurf":
        return '"agent_action_name":"post_' in payload or '"agent_action_name": "post_' in payload
    return "PostToolUse" in payload or "postToolUse" in payload


def no_opinion(is_post):
    if HARNESS == "cursor" and not is_post:
        sys.exit(1)
    if HARNESS == "antigravity":            # a pre-tool decision is required; post-tool hooks return {}
        out('{"decision":"allow"}' if not is_post else "{}")
    sys.exit(0)


def fail_mode():
    env = os.environ.get("INTERLOCK_FAIL_MODE")
    if env in ("open", "closed"):
        return env
    text = read("fail-mode.json")
    i = text.find('"default"')
    rest = text[i + 9:].lstrip(" \t:") if i >= 0 else ""
    return "closed" if rest.startswith('"closed"') else "open"


def unreachable(payload, is_post, why):
    mode = fail_mode()
    log_local(f"unjudged harness={HARNESS} tool={field(payload, 'tool_name') or '?'} kind={'post' if is_post else 'pre'} "
              f"error={why} fail_mode={mode}")
    if is_post or mode != "closed":
        if HARNESS == "kiro":
            sys.exit(0)
        no_opinion(is_post)
    if HARNESS in ("kiro", "windsurf"):
        out(UNREACHABLE, sys.stderr)
        sys.exit(2)
    if HARNESS == "cursor":
        out(f'{{"permission":"deny","agent_message":"{UNREACHABLE}","user_message":"Interlock daemon unreachable (fail closed)"}}')
    elif HARNESS in ("gemini-cli", "antigravity"):
        out(f'{{"decision":"deny","reason":"{UNREACHABLE}"}}')
    elif HARNESS == "copilot-cli":
        out(f'{{"permissionDecision":"deny","permissionDecisionReason":"{UNREACHABLE}"}}')
    else:
        out('{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny",'
            f'"permissionDecisionReason":"{UNREACHABLE}"}}}}')
    sys.exit(0)


def post(base, path, token, body, timeout):
    """POST to the daemon; returns the reply text. Raises OSError on any transport error or HTTP status >= 400."""
    if not base.startswith("http://"):
        import urllib.request

        req = urllib.request.Request(base + path, data=body, method="POST",
                                     headers={"authorization": f"Bearer {token}", "content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="replace")
    hostport = base[7:].split("/", 1)[0]
    host, _, port = hostport.rpartition(":")
    host, port = (host or hostport).strip("[]"), int(port) if port.isdigit() else 80
    head = (f"POST {path} HTTP/1.1\r\nHost: {hostport}\r\nAuthorization: Bearer {token}\r\n"
            f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(head + body)
        chunks = []
        while data := s.recv(65536):
            chunks.append(data)
    raw = b"".join(chunks)
    status_line, _, rest = raw.partition(b"\r\n")
    parts = status_line.split()
    if len(parts) < 2 or not parts[1].isdigit() or int(parts[1]) >= 400:
        raise OSError(f"HTTP {status_line[:40]!r}")
    headers, _, payload = rest.partition(b"\r\n\r\n")
    if b"transfer-encoding: chunked" in headers.lower():
        decoded, buf = b"", payload
        while buf:
            size_line, _, buf = buf.partition(b"\r\n")
            size = int(size_line.split(b";")[0] or b"0", 16)
            if size == 0:
                break
            decoded, buf = decoded + buf[:size], buf[size + 2:]
        payload = decoded
    return payload.decode("utf-8", errors="replace")


def main():
    payload = sys.stdin.buffer.read().decode("utf-8", errors="replace")
    if not payload.strip():
        sys.exit(0)
    arg = sys.argv[1] if len(sys.argv) > 1 else ""
    is_post = is_post_event(payload, arg)
    token = read("token").strip()
    if not token:
        log_local(f"inert: no token at {os.path.join(HOME_DIR, 'token')}")
        sys.exit(0) if HARNESS == "kiro" else no_opinion(is_post)
    if os.environ.get("INTERLOCK_URL"):
        base = os.environ["INTERLOCK_URL"].rstrip("/")
    else:
        base = "http://" + (field(read("daemon.json"), "listen") or "127.0.0.1:7391")

    fmt = {"cursor": "cursor", "gemini-cli": "gemini-cli", "copilot-cli": "copilot-cli", "antigravity": "antigravity",
           "windsurf": "text", "kiro": "text"}.get(HARNESS, "claude-code")
    if HARNESS == "kiro":
        adapter = f'{{"name":"kiro","version":{jstr(VERSION)}}}'
    else:
        event = jstr("post" if is_post else "pre")
        adapter = f'{{"name":{jstr(HARNESS)},"version":{jstr(VERSION)},"event":{event},"cwd":{jstr(os.getcwd())}}}'
    body = ('{"adapter":' + adapter + ',"payload":' + payload + "}").encode("utf-8")
    try:
        reply = post(base, f"/interlock/v1/hooks/{HARNESS}?format={fmt}", token, body,
                     (POST_TIMEOUT if is_post else PRE_TIMEOUT) / 1000).strip()
    except (OSError, ValueError) as e:
        unreachable(payload, is_post, type(e).__name__)

    if HARNESS == "kiro":
        if not reply:
            unreachable(payload, is_post, "empty reply")
        if is_post:                                    # record-only on Kiro
            sys.exit(0)
        first, _, notice = reply.partition("\n")
        disposition, mode = (first.split() + ["", ""])[:2]
        if mode != "shadow" and disposition in ("block", "ask"):
            out(notice.strip() or REFUSED, sys.stderr)
            sys.exit(2)
        sys.exit(0)
    if HARNESS == "windsurf":
        first, _, notice = reply.partition("\n")
        disposition, mode = (first.split() + ["", ""])[:2]
        if mode == "enforce" and disposition in ("block", "ask"):
            out(notice.strip(), sys.stderr)
            sys.exit(2)
        sys.exit(0)
    if not reply:
        no_opinion(is_post)
    out(reply)
    sys.exit(0)


main()
