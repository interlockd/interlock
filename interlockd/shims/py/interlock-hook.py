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
# A reply is applied only when it carries exactly one X-Interlock-Identity header equal to <Home>/identity (written
# by this home's daemon at start): any other process answering on the address is not trusted. When the call cannot
# be judged, the outcome is classified (classify()) and a fail mode chosen (select_fail_mode()):
#   tamper token_rejected   the process at the address answered 401/403 to this home's token
#   tamper daemon_identity  a reply without, with several, or with a wrong identity header
#   tamper daemon_lost      the daemon is unreachable and no valid <Home>/stop-marker.json explains it
#   unjudged ...            an operator stop or restart (stop marker), another HTTP error, an empty Kiro reply
# Tamper causes use fail-mode.json's `tamper` (closed when missing or invalid), the others its `default`;
# INTERLOCK_FAIL_MODE=closed tightens both and no other value loosens either.
#
# Install writes HARNESS: claude-code | codex | cursor | gemini-cli | copilot-cli | windsurf | antigravity | kiro.

import os
import socket
import sys

HARNESS = "__HARNESS__"
VERSION = "0.2.0"
HOME_DIR = os.environ.get("INTERLOCK_HOME") or os.path.join(os.path.expanduser("~"), ".interlock")
PRE_TIMEOUT = int(os.environ.get("INTERLOCK_PRE_TIMEOUT_MS") or 1500)
POST_TIMEOUT = int(os.environ.get("INTERLOCK_POST_TIMEOUT_MS") or 2500)
MAX_STATE_BYTES = 64 * 1024              # a larger state file is treated as absent (Requirement 12.4)
IDENTITY_HEADER = "x-interlock-identity"
TAMPER_CAUSES = ("token_rejected", "daemon_identity", "daemon_lost")
REFUSED = ("[interlock] This action was refused by a security policy and was NOT executed. You may pursue the user's "
           "goal by other legitimate means, but you MUST NOT retry this action in a disguised form.")
UNREACHABLE = ("[interlock] This action was NOT executed: the Interlock daemon is unreachable and this workspace fails "
               "closed. Start it with `interlock start`, then retry.")


def log_local(line):
    """Append one timestamped line to <Home>/hook.log; False when it cannot be written."""
    import time

    try:
        os.makedirs(HOME_DIR, exist_ok=True)
        with open(os.path.join(HOME_DIR, "hook.log"), "a", encoding="utf-8") as f:
            f.write(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) + " " + line + "\n")
        return True
    except OSError:
        return False


def out(text, stream=None):
    stream = stream or sys.stdout
    stream.buffer.write((text + "\n").encode("utf-8"))
    stream.flush()


def read(name):
    """The text of <Home>/name; "" when absent, unreadable or larger than MAX_STATE_BYTES."""
    try:
        with open(os.path.join(HOME_DIR, name), encoding="utf-8", errors="replace") as f:
            text = f.read(MAX_STATE_BYTES + 1)
    except OSError:
        return ""
    return "" if len(text) > MAX_STATE_BYTES else text


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


# ---- pure classification (exercised directly by the property tests) ------------------------------------------------

def _mode_value(text, key):
    """`open` or `closed` when `text` has `"key": "open|closed"` (any spacing around the colon), else None."""
    i = text.find(f'"{key}"')
    if i < 0:
        return None
    rest = text[i + len(key) + 2:].lstrip(" \t\r\n")
    if not rest.startswith(":"):
        return None
    rest = rest[1:].lstrip(" \t\r\n")
    for mode in ("closed", "open"):
        if rest.startswith(f'"{mode}"'):
            return mode
    return None


def select_fail_mode(cause, env, fail_mode_text):
    """The fail mode for a call that cannot be judged because of `cause`. `env` is INTERLOCK_FAIL_MODE (None when
    unset) and `fail_mode_text` the content of fail-mode.json ("" when absent). `closed` from the environment
    tightens both modes; any other environment value is ignored. A tamper cause uses the file's `tamper` value and
    `closed` when it is missing or invalid; every other cause uses `default` and `open` when it is missing. A file
    that is not a single JSON object (truncated, empty) counts as absent."""
    if env == "closed":
        return "closed"
    text = (fail_mode_text or "").strip()
    if not (text.startswith("{") and text.endswith("}")):
        fail_mode_text = ""
    if cause in TAMPER_CAUSES or cause == "enforcement_point":
        return _mode_value(fail_mode_text, "tamper") or "closed"
    return _mode_value(fail_mode_text, "default") or "open"


def _int_field(text, key):
    """The integer value of `"key": <digits>` (either spacing); None when absent or not an integer."""
    for pat in (f'"{key}":', f'"{key}": '):
        i = text.find(pat)
        if i >= 0:
            rest = text[i + len(pat):].lstrip(" ")
            digits = ""
            for ch in rest:
                if not ch.isdigit() or not ch.isascii():
                    break
                digits += ch
            return int(digits) if digits else None
    return None


def marker_state(marker_text, now):
    """`operator_stopped` (valid marker without expiry), `restarting` (valid marker whose expires_epoch is later than
    `now`) or None (absent, unparseable, missing action or written_at, malformed or past expiry)."""
    text = (marker_text or "").strip()
    if not (text.startswith("{") and text.endswith("}")):
        return None
    if not field(text, "action") or not field(text, "written_at"):
        return None
    if '"expires_epoch"' not in text and '"expires_at"' not in text:
        return "operator_stopped"
    expires = _int_field(text, "expires_epoch")
    return "restarting" if expires is not None and now < expires else None


def classify(connected, status=0, identity_values=(), expected="", marker_text=None, now=0):
    """The outcome of one hook call as (outcome, detail):
      ("apply", "")                      a verified reply: render it as today
      ("tamper", <cause>)                token_rejected | daemon_identity | daemon_lost
      ("unjudged", <why>)                operator_stopped | restarting | http_<status>
    `connected` is False when daemon.json is absent (and no INTERLOCK_URL), the connection was refused or timed out,
    or the reply was malformed; the stop marker is consulted only then. `identity_values` are the received
    X-Interlock-Identity header values and `expected` the content of <Home>/identity."""
    if not connected:
        state = marker_state(marker_text, now)
        return ("unjudged", state) if state else ("tamper", "daemon_lost")
    if status in (401, 403):
        return "tamper", "token_rejected"
    if status >= 400:
        return "unjudged", f"http_{status}"
    values = list(identity_values)
    if not expected or len(values) != 1 or values[0] != expected:
        return "tamper", "daemon_identity"
    return "apply", ""


def tamper_message(cause, addr, home):
    """The refusal text for a tamper cause: exactly one cause keyword and the command that repairs it."""
    if cause == "token_rejected":
        return (f"[interlock] This action was NOT executed: the process at {addr} rejected this hook's token "
                "(token_rejected). Run `interlock doctor`.")
    if cause == "daemon_identity":
        return (f"[interlock] This action was NOT executed: the process answering at {addr} is not this home's "
                "Interlock daemon (daemon_identity). Run `interlock doctor`.")
    return (f"[interlock] This action was NOT executed: Interlock daemon stopped unexpectedly (daemon_lost). "
            f"Home: {home}. Run `interlock doctor`, then `interlock start`.")


# ---- harness output -----------------------------------------------------------------------------------------------

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
    if HARNESS == "kiro":
        sys.exit(0)
    if HARNESS == "cursor" and not is_post:
        sys.exit(1)
    if HARNESS == "antigravity":            # a pre-tool decision is required; post-tool hooks return {}
        out('{"decision":"allow"}' if not is_post else "{}")
    sys.exit(0)


def refuse(message, user_message):
    """Refuse a pre-tool call through the harness's fail-closed channel (the one a policy block uses)."""
    if HARNESS in ("kiro", "windsurf"):
        out(message, sys.stderr)
        sys.exit(2)
    m = jstr(message)
    if HARNESS == "cursor":
        out(f'{{"permission":"deny","agent_message":{m},"user_message":{jstr(user_message)}}}')
    elif HARNESS in ("gemini-cli", "antigravity"):
        out(f'{{"decision":"deny","reason":{m}}}')
    elif HARNESS == "copilot-cli":
        out(f'{{"permissionDecision":"deny","permissionDecisionReason":{m}}}')
    else:
        out('{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny",'
            f'"permissionDecisionReason":{m}}}}}')
    sys.exit(0)


def _context(payload, is_post, addr):
    return f"harness={HARNESS} tool={field(payload, 'tool_name') or '?'} kind={'post' if is_post else 'pre'} addr={addr}"


def unjudged(payload, is_post, why, addr):
    mode = select_fail_mode(why, os.environ.get("INTERLOCK_FAIL_MODE"), read("fail-mode.json"))
    log_local(f"unjudged why={why} {_context(payload, is_post, addr)} fail_mode={mode}")
    if is_post or mode != "closed":
        no_opinion(is_post)
    refuse(UNREACHABLE, "Interlock daemon unreachable (fail closed)")


def tamper(payload, is_post, cause, addr, status):
    mode = select_fail_mode(cause, os.environ.get("INTERLOCK_FAIL_MODE"), read("fail-mode.json"))
    if not log_local(f"tamper {cause} {_context(payload, is_post, addr)} status={status} fail_mode={mode}"):
        out(f"[interlock] could not write {os.path.join(HOME_DIR, 'hook.log')}", sys.stderr)
    if is_post or mode != "closed":         # post-tool: the action already ran, the contracts offer no refusal
        no_opinion(is_post)
    refuse(tamper_message(cause, addr, HOME_DIR), "Interlock refused this action: protection check failed")


# ---- transport ----------------------------------------------------------------------------------------------------

def _headers(pairs):
    """Header (name, value) pairs as a dict of lower-cased name -> list of values, in order received."""
    hdrs = {}
    for k, v in pairs:
        hdrs.setdefault(k.strip().lower(), []).append(v.strip(" \t"))
    return hdrs


def post(base, path, token, body, timeout, unix_path=None):
    """POST to the daemon (over the Unix socket `unix_path` when given); returns (status, headers, reply text) for
    any HTTP status. Raises OSError or ValueError on a transport error (refused, timeout) or a malformed reply."""
    if not unix_path and not base.startswith("http://"):
        import urllib.error
        import urllib.request

        req = urllib.request.Request(base + path, data=body, method="POST",
                                     headers={"authorization": f"Bearer {token}", "content-type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, _headers(r.headers.items()), r.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, _headers(e.headers.items() if e.headers else []), ""
    hostport = base[7:].split("/", 1)[0]
    host, _, port = hostport.rpartition(":")
    host, port = (host or hostport).strip("[]"), int(port) if port.isdigit() else 80
    head = (f"POST {path} HTTP/1.1\r\nHost: {hostport}\r\nAuthorization: Bearer {token}\r\n"
            f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
    if unix_path:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect(unix_path)
        except BaseException:
            s.close()
            raise
    else:
        s = socket.create_connection((host, port), timeout=timeout)
    with s:
        s.settimeout(timeout)
        s.sendall(head + body)
        chunks = []
        while data := s.recv(65536):
            chunks.append(data)
    raw = b"".join(chunks)
    while True:
        block, sep, raw = raw.partition(b"\r\n\r\n")
        lines = block.split(b"\r\n")
        parts = lines[0].split()
        if not sep or len(parts) < 2 or not parts[0].startswith(b"HTTP/") or len(parts[1]) != 3 \
                or not parts[1].isdigit():
            raise ValueError("malformed reply")
        status = int(parts[1])
        if not 100 <= status < 200:          # skip interim responses (100 Continue)
            break
    hdrs = _headers(line.decode("latin-1").partition(":")[::2] for line in lines[1:] if b":" in line)
    payload = raw
    if "chunked" in ",".join(hdrs.get("transfer-encoding", [])).lower():
        decoded, buf = b"", payload
        while buf:
            size_line, _, buf = buf.partition(b"\r\n")
            size = int(size_line.split(b";")[0] or b"0", 16)
            if size == 0:
                break
            decoded, buf = decoded + buf[:size], buf[size + 2:]
        payload = decoded
    return status, hdrs, payload.decode("utf-8", errors="replace")


def main():
    payload = sys.stdin.buffer.read().decode("utf-8", errors="replace")
    if not payload.strip():
        sys.exit(0)
    arg = sys.argv[1] if len(sys.argv) > 1 else ""
    is_post = is_post_event(payload, arg)
    token = read("token").strip()
    if not token:
        log_local(f"inert: no token at {os.path.join(HOME_DIR, 'token')}")
        no_opinion(is_post)
    url = os.environ.get("INTERLOCK_URL")
    daemon_json = read("daemon.json")
    sock = None
    if url:
        base = addr = url.rstrip("/")
    else:
        base = addr = "http://" + (field(daemon_json, "listen") or "127.0.0.1:7391")
        # prefer the daemon's Unix socket (mode 0600: only this user can connect), as the sh shim does
        path = os.path.join(HOME_DIR, "interlockd.sock")
        try:
            if os.name != "nt" and hasattr(socket, "AF_UNIX") and os.stat(path).st_mode & 0o170000 == 0o140000:
                sock, base, addr = path, "http://localhost", "unix:" + path
        except OSError:
            pass

    fmt = {"cursor": "cursor", "gemini-cli": "gemini-cli", "copilot-cli": "copilot-cli", "antigravity": "antigravity",
           "windsurf": "text", "kiro": "text"}.get(HARNESS, "claude-code")
    shim = jstr(os.path.abspath(__file__))
    if HARNESS == "kiro":
        adapter = f'{{"name":"kiro","version":{jstr(VERSION)},"shim":{shim}}}'
    else:
        event = jstr("post" if is_post else "pre")
        adapter = (f'{{"name":{jstr(HARNESS)},"version":{jstr(VERSION)},"event":{event},"cwd":{jstr(os.getcwd())},'
                   f'"shim":{shim}}}')
    body = ('{"adapter":' + adapter + ',"payload":' + payload + "}").encode("utf-8")
    connected, status, headers, reply = False, 0, {}, ""
    if url or daemon_json:                   # no daemon.json: no daemon has been started for this home
        try:
            status, headers, reply = post(base, f"/interlock/v1/hooks/{HARNESS}?format={fmt}", token, body,
                                          (POST_TIMEOUT if is_post else PRE_TIMEOUT) / 1000, sock)
            connected = True
        except (OSError, ValueError):
            pass
    if connected:
        outcome, detail = classify(True, status, headers.get(IDENTITY_HEADER, []), read("identity").strip())
    else:
        import time

        outcome, detail = classify(False, marker_text=read("stop-marker.json"), now=int(time.time()))
    if outcome == "tamper":
        tamper(payload, is_post, detail, addr, status if connected else "-")
    elif outcome == "unjudged":
        unjudged(payload, is_post, detail, addr)
    reply = reply.strip()

    if HARNESS == "kiro":
        if not reply:
            unjudged(payload, is_post, "empty_reply", addr)
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


if __name__ == "__main__":
    main()
