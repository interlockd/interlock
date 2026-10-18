"""Shell command decomposition: segments, words, pipes, heredocs, interpreter one-liners, decode-and-exec.

This is a pragmatic tokenizer, not a full POSIX grammar. It must never raise: any input yields a list of
segments, each a list of words, and the raw text is always available to the packs as a fallback.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
import shlex
from dataclasses import dataclass, field

CONTROL = re.compile(r"(\|\||&&|;|\||\n)")
INTERPRETERS = {
    "bash": ("-c",), "sh": ("-c",), "zsh": ("-c",), "dash": ("-c",), "ksh": ("-c",),
    "python": ("-c",), "python3": ("-c",), "python2": ("-c",), "node": ("-e", "--eval", "-p"), "ruby": ("-e",),
    "perl": ("-e", "-E"), "php": ("-r",), "osascript": ("-e",),
}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish"}
B64 = re.compile(r"^[A-Za-z0-9+/=_-]{16,}$")


@dataclass
class Segment:
    raw: str
    words: list[str]
    heredoc: str | None = None
    inner: list[Segment] = field(default_factory=list)   # programs passed to interpreters, decoded payloads

    @property
    def cmd(self) -> str:
        return self.words[0] if self.words else ""

    def flat(self) -> list[Segment]:
        out = [self]
        for s in self.inner:
            out.extend(s.flat())
        return out


@dataclass
class Parsed:
    raw: str
    segments: list[Segment]
    piped_to_shell: list[Segment] = field(default_factory=list)   # "curl … | sh" style
    decode_exec: list[Segment] = field(default_factory=list)      # "echo … | base64 -d | sh"
    data_heredocs: list[str] = field(default_factory=list)        # heredoc bodies written to files, not executed
    code: str = ""                                                 # the command text with data heredocs removed

    def all_segments(self) -> list[Segment]:
        out: list[Segment] = []
        for s in self.segments:
            out.extend(s.flat())
        return out

    def commands(self) -> list[str]:
        return [s.cmd for s in self.all_segments() if s.cmd]


def _strip_env_prefix(words: list[str]) -> list[str]:
    i = 0
    while i < len(words) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", words[i]):
        i += 1
    if i < len(words) and words[i] in ("env", "sudo", "doas", "command", "exec", "nohup", "time", "nice", "xargs"):
        # keep sudo visible to the privilege pack; a bare `env` (no following command) is a dump, keep it too
        if words[i] == "sudo" or (words[i] == "env" and (i + 1 >= len(words) or words[i + 1].startswith((">", "|")))):
            return words[i:]
        return _strip_env_prefix(words[i + 1:]) if i + 1 < len(words) else words[i:]
    return words[i:]


HEREDOC_OPEN = re.compile(r"<<-?\s*(['\"]?)(\w+)\1")


def split_heredocs(text: str) -> tuple[str, list[tuple[str, str]]]:
    """Return (text with every heredoc body removed, [(consumer_line, body), ...]) in order of appearance.

    The consumer line is the command line carrying the `<<TAG` operator; the body runs from the next line to
    the matching terminator. An unterminated heredoc runs to the end of the text.
    """
    out_lines: list[str] = []
    docs: list[tuple[str, str]] = []
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        m = HEREDOC_OPEN.search(line)
        if not m:
            out_lines.append(line)
            i += 1
            continue
        tag = m.group(2)
        body: list[str] = []
        j = i + 1
        while j < len(lines) and lines[j].strip() != tag:
            body.append(lines[j])
            j += 1
        docs.append((line, "\n".join(body)))
        out_lines.append(line)
        i = j + 1
    return "\n".join(out_lines), docs


def _split_heredoc(text: str) -> tuple[str, str | None]:
    """Compatibility shim: (code text, first heredoc body or None)."""
    code, docs = split_heredocs(text)
    return code, (docs[0][1] if docs else None)


def _words(raw: str) -> list[str]:
    try:
        return shlex.split(raw, posix=True)
    except ValueError:
        # unbalanced quotes (a heredoc fragment, a truncated message): fall back to whitespace words
        return raw.split()


def _balanced_substitutions(chunk: str) -> list[str]:
    """Contents of $( … ), ( … ) and ` … ` with balanced nesting. Single quotes make everything literal;
    inside double quotes $( ) and backticks still substitute (as in a real shell)."""
    out: list[str] = []
    i, in_single, in_double = 0, False, False
    while i < len(chunk):
        ch = chunk[i]
        if in_single:
            if ch == "'":
                in_single = False
            i += 1
            continue
        if ch == "\\" and in_double and i + 1 < len(chunk):
            i += 2
            continue
        if ch == "'" and not in_double:
            in_single = True
            i += 1
            continue
        if ch == '"':
            in_double = not in_double
            i += 1
            continue
        if chunk.startswith("$(", i) or (ch == "(" and not in_double and (i == 0 or chunk[i - 1] in " \t;&|")):
            start = i + 2 if chunk.startswith("$(", i) else i + 1
            depth, j = 1, start
            while j < len(chunk) and depth:
                if chunk[j] == "(":
                    depth += 1
                elif chunk[j] == ")":
                    depth -= 1
                j += 1
            if depth == 0:
                out.append(chunk[start:j - 1])
                i = j
                continue
        if ch == "`":
            j = chunk.find("`", i + 1)
            if j > i:
                out.append(chunk[i + 1:j])
                i = j + 1
                continue
        i += 1
    return out


def _segments(text: str, depth: int = 0) -> list[Segment]:
    if depth > 5:
        return []
    code, docs = split_heredocs(text)
    heredoc = docs[0][1] if docs else None
    segs: list[Segment] = []
    for chunk in _split_top_level(code, ("||", "&&", ";", "\n")):
        # a pipeline is several commands; each piece is its own segment
        for piece in _pipeline_pieces_raw(chunk):
            words = _strip_env_prefix(_words(piece))
            # strip a stray leading "(" from a subshell piece so the command name is clean
            if words and words[0].startswith("(") and len(words[0]) > 1:
                words[0] = words[0][1:]
            seg = Segment(raw=piece, words=words, heredoc=heredoc if not segs else None)
            for inner in _balanced_substitutions(piece):
                if inner.strip():
                    seg.inner.extend(_segments(inner, depth + 1))
            if words and os.path.basename(words[0]) in INTERPRETERS:
                flags = INTERPRETERS[os.path.basename(words[0])]
                for i, w in enumerate(words[1:], 1):
                    if w in flags and i + 1 < len(words):
                        program = words[i + 1]
                        if os.path.basename(words[0]) in SHELLS:
                            seg.inner.extend(_segments(program, depth + 1))
                        else:
                            for inner in exec_literals(program):
                                seg.inner.extend(_segments(inner, depth + 1))
                        break
            segs.append(seg)
    for consumer, body in docs:
        kind = _heredoc_kind(consumer)
        if kind == "shell":
            segs.extend(_segments(body, depth + 1))
        elif kind == "interpreter":
            for inner in exec_literals(body):
                segs.extend(_segments(inner, depth + 1))
    return segs


def _pipeline_pieces_raw(text: str) -> list[str]:
    pieces = _split_top_level(text.replace("||", "\x00"), ("|",))
    return [p.replace("\x00", "||") for p in pieces]


FETCHERS = {"curl", "wget", "fetch", "http", "https", "aria2c"}
DECODERS = {"base64", "openssl", "xxd", "gzip", "gunzip", "zcat", "python3", "python", "perl", "rev", "tr", "uudecode"}


def _pipeline_pieces(text: str) -> list[list[str]]:
    """Split one chain-free command on single '|' (outside quotes/parens) into word lists."""
    pieces = _split_top_level(text.replace("||", "\x00"), ("|",))
    return [_strip_env_prefix(_words(p.replace("\x00", "||"))) for p in pieces]


DATA_ARG_FLAGS = {"git": ("-m", "--message", "-F", "--file"), "gh": ("--body", "--title", "-b", "-t", "--notes", "-m"),
                  "hg": ("-m",), "svn": ("-m",), "sed": (), "grep": (), "rg": (), "awk": (), "echo": (), "printf": ()}
DATA_ONLY_COMMANDS = {"echo", "printf", "grep", "rg", "awk", "sed", "test", "[", "expr"}


def _words_without_data_args(words: list[str]) -> list[str]:
    """Drop message bodies (git commit -m "…"), echo/printf text, and pattern arguments from a word list."""
    if not words:
        return words
    cmd = os.path.basename(words[0])
    if cmd in DATA_ONLY_COMMANDS:
        return words[:1]
    flags = DATA_ARG_FLAGS.get(cmd)
    if not flags:
        return words
    out, skip = [], False
    for w in words:
        if skip:
            skip = False
            continue
        if w in flags:
            out.append(w)
            skip = True
            continue
        if any(w.startswith(f + "=") for f in flags if f.startswith("--")) or (cmd == "git" and len(w) > 2 and w.startswith("-m") and not w.startswith("--")):
            out.append(w.split("=", 1)[0])
            continue
        out.append(w)
    return out


def _is_shell(words: list[str]) -> bool:
    if not words:
        return False
    w = words
    if w[0] == "sudo" and len(w) > 1:
        w = w[1:]
    return os.path.basename(w[0]) in SHELLS


def _analyze_pipelines(chunk: str, parsed: Parsed) -> None:
    pieces = _pipeline_pieces(chunk)
    if len(pieces) < 2 or not _is_shell(pieces[-1]):
        return
    first = pieces[0]
    # the fetcher is usually word 0, but cron lines ("0 3 * * * curl …") and env prefixes put it later
    fetch_at = next((i for i, w in enumerate(first) if os.path.basename(w) in FETCHERS), None)
    if fetch_at is not None:
        parsed.piped_to_shell.append(Segment(raw=chunk, words=first[fetch_at:]))
    decoders = [p for p in pieces[1:-1] if p and os.path.basename(p[0]) in DECODERS]
    if decoders:
        parsed.decode_exec.append(Segment(raw=chunk, words=decoders[0]))
        for w in first:
            if B64.match(w):
                try:
                    decoded = base64.b64decode(w + "=" * (-len(w) % 4)).decode("utf-8", "ignore")
                except (ValueError, binascii.Error):
                    continue
                if decoded.strip():
                    parsed.segments.extend(_segments(decoded))


def _split_top_level(text: str, seps: tuple[str, ...]) -> list[str]:
    """Split on separators that are outside quotes and parentheses."""
    out, buf, i, depth, quote = [], [], 0, 0, None
    while i < len(text):
        ch = text[i]
        if quote:
            buf.append(ch)
            if ch == "\\" and i + 1 < len(text) and quote == '"':
                buf.append(text[i + 1]); i += 2; continue
            if ch == quote:
                quote = None
            i += 1; continue
        if ch in ("'", '"', "`"):
            quote = ch; buf.append(ch); i += 1; continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        if depth == 0:
            matched = next((s for s in seps if text.startswith(s, i)), None)
            if matched:
                out.append("".join(buf)); buf = []; i += len(matched); continue
        buf.append(ch); i += 1
    out.append("".join(buf))
    return [c.strip() for c in out if c.strip()]


EXEC_CALL = re.compile(
    r"(?:os\.system|os\.popen|subprocess\.(?:run|call|check_output|check_call|Popen)|commands\.getoutput|"
    r"execSync|exec|spawn|spawnSync|execFile|system|popen|shell_exec|passthru|backticks|Runtime\.getRuntime\(\)\.exec|"
    r"os\.exec\w*|eval)\s*\(\s*(?:\[\s*)?(?:f?r?['\"])((?:[^'\"\\]|\\.)*)['\"]"
)


def exec_literals(program: str) -> list[str]:
    """String literals passed to exec-like calls inside an interpreter program (os.system('…'), execSync("…")).

    Other string literals are data: a Python file that *mentions* `rm -rf /` in a docstring or a test fixture
    is not a command to run it. This is what keeps editing security code from tripping the gate.
    """
    out = []
    for m in EXEC_CALL.finditer(program):
        lit = m.group(1).strip()
        if lit:
            out.append(lit)
    return out


def _consumer_words(consumer_line: str) -> list[str]:
    head = consumer_line.split("\n", 1)[0]
    idx = head.find("<<")
    if idx < 0:
        return []
    after = re.sub(r"^<<-?\s*['\"]?\w+['\"]?", "", head[idx:]).strip()
    if after.startswith("|"):  # `cat <<EOF | bash`: the text after the operator names the real consumer
        tail_pieces = _pipeline_pieces_raw(after.lstrip("|").strip())
        words = _strip_env_prefix(_words(tail_pieces[-1])) if tail_pieces else []
    else:
        chunks = _split_top_level(head[:idx], ("||", "&&", ";", "\n"))
        pieces = _pipeline_pieces_raw(chunks[-1]) if chunks else []
        words = _strip_env_prefix(_words(pieces[-1])) if pieces else []
    if words and words[0] == "sudo" and len(words) > 1:
        words = words[1:]
    return words


def _heredoc_kind(consumer_line: str) -> str:
    """'shell' when a shell consumes the heredoc, 'interpreter' for python/node/etc., else 'data' (a file write)."""
    words = _consumer_words(consumer_line)
    if not words:
        return "data"
    cmd = os.path.basename(words[0])
    if cmd in SHELLS:
        return "shell"
    if cmd in INTERPRETERS:
        return "interpreter"
    return "data"


def _heredoc_is_code(consumer_line: str) -> bool:
    return _heredoc_kind(consumer_line) != "data"


def _chain_chunks(text: str) -> list[str]:
    code, docs = split_heredocs(text)
    chunks = _split_top_level(code, ("||", "&&", ";", "\n"))
    for consumer, body in docs:
        kind = _heredoc_kind(consumer)
        if kind == "shell":
            chunks.extend(_chain_chunks(body))
        elif kind == "interpreter":
            for inner in exec_literals(body):
                chunks.extend(_chain_chunks(inner))
    return chunks


def _scan_text_for_pipelines(text: str, parsed: Parsed, depth: int = 0) -> None:
    if depth > 4 or not text.strip():
        return
    for chunk in _chain_chunks(text):
        _analyze_pipelines(chunk, parsed)
        # each pipeline piece may itself carry a quoted command (echo '… | bash' inside a subshell)
        for piece in _pipeline_pieces_raw(chunk):
            pw = _strip_env_prefix(_words(piece))
            if pw and os.path.basename(pw[0]) in INTERPRETERS and os.path.basename(pw[0]) not in SHELLS:
                continue  # interpreter programs are handled through exec_literals above
            # echo/printf text is data, unless this chunk persists it (crontab, tee, >> redirect) or evals it
            if pw and os.path.basename(pw[0]) in DATA_ONLY_COMMANDS and not re.search(r"\bcrontab\b|\btee\b|>>?\s*\S|\beval\b", chunk):
                continue
            if pw and os.path.basename(pw[0]) not in DATA_ONLY_COMMANDS and os.path.basename(pw[0]) in DATA_ARG_FLAGS \
                    and len(_words_without_data_args(pw)) < len(pw):
                continue  # git commit -m "…" / gh pr --body "…": the message is data; the git pack reads git's own argv
            for q in re.findall(r"'([^']*)'|\"((?:[^\"\\\\]|\\\\.)*)\"", piece):
                for inner in q:
                    if inner and ("|" in inner or ";" in inner or "&&" in inner) and inner != text:
                        _scan_text_for_pipelines(inner.lstrip("!"), parsed, depth + 1)
        # subshells / substitutions / backticks
        for inner in _balanced_substitutions(chunk):
            if inner.strip():
                _scan_text_for_pipelines(inner, parsed, depth + 1)
        # interpreter one-liners and any quoted string that itself looks like a command
        words = _strip_env_prefix(_words(chunk))
        if words and os.path.basename(words[0]) in INTERPRETERS:
            flags = INTERPRETERS[os.path.basename(words[0])]
            for i, w in enumerate(words[1:], 1):
                if w in flags and i + 1 < len(words):
                    program = words[i + 1]
                    if os.path.basename(words[0]) in SHELLS:
                        _scan_text_for_pipelines(program, parsed, depth + 1)
                    else:
                        for inner in exec_literals(program):
                            _scan_text_for_pipelines(inner, parsed, depth + 1)
                    break



def parse(command: str) -> Parsed:
    text = command if isinstance(command, str) else str(command)
    code, docs = split_heredocs(text)
    parsed = Parsed(raw=text, segments=_segments(text))
    code_docs: list[str] = []
    for consumer, body in docs:
        kind = _heredoc_kind(consumer)
        if kind == "shell":
            code_docs.append(body)
        elif kind == "interpreter":
            code_docs.extend(exec_literals(body))
        else:
            parsed.data_heredocs.append(body)
    parsed.code = code + ("\n" + "\n".join(code_docs) if code_docs else "")
    _scan_text_for_pipelines(code, parsed)
    for doc in code_docs:
        _scan_text_for_pipelines(doc, parsed)
    return parsed


