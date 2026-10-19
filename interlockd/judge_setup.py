"""`interlock judge install | status | remove`: run the optional judge model locally with one command.

The judge (Strands Decider 2B, Apache-2.0 open weights: a LoRA on Qwen3.5-2B) answers narrow questions for ambiguous
calls: "did the user ask for this?" for rules routed to `model`, "does this tool result carry injected instructions?"
on results, "did the user just confirm?" for agents without a native ask. `install` creates a private environment in
~/.interlock/judge, installs the `strands-decider` server there, downloads the weights (about 5 GB with the base
model), and adds a `judge.primary` block to your policy so the daemon starts and supervises the server. Nothing is
sent anywhere: the model runs on this machine (Apple GPU, CUDA, or CPU).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

PACKAGE = "strands-decider==0.1.0"
CHECKPOINT = "StrandsAgents/strands-decider-2B-hobson-v21"
DEFAULT_PORT = 8017


def venv_dir(home: Path) -> Path:
    return home / "judge"


def server_exe(home: Path) -> Path:
    return venv_dir(home) / "bin" / "strands-decider"


def install_env(home: Path, log=print) -> Path:
    """Create the private environment and install the server. Prefers uv; falls back to venv + pip."""
    d = venv_dir(home)
    py = d / "bin" / "python"
    uv = shutil.which("uv")
    if not py.exists():
        log(f"creating {d}")
        if uv:
            subprocess.run([uv, "venv", "-q", "--python", "3.12", str(d)], check=True)
        else:
            subprocess.run([sys.executable, "-m", "venv", str(d)], check=True)
    log(f"installing {PACKAGE} (PyTorch included; a few minutes the first time)")
    if uv:
        subprocess.run([uv, "pip", "install", "-q", "--python", str(py), PACKAGE], check=True)
    else:
        subprocess.run([str(py), "-m", "pip", "install", "-q", PACKAGE], check=True)
    return server_exe(home)


def download(home: Path, checkpoint: str = CHECKPOINT, log=print) -> None:
    """Fetch the adapter and its base model into the Hugging Face cache, so the first start is not a 5 GB download."""
    py = venv_dir(home) / "bin" / "python"
    code = (
        "import json, sys\n"
        "from huggingface_hub import snapshot_download\n"
        "p = snapshot_download(sys.argv[1])\n"
        "base = json.load(open(p + '/strands_decider_config.json')).get('base_model')\n"
        "print('base model:', base)\n"
        "base and snapshot_download(base)\n"
    )
    log(f"downloading {checkpoint} and its base model")
    subprocess.run([str(py), "-c", code, checkpoint], check=True)


def judge_block(home: Path, port: int, checkpoint: str = CHECKPOINT) -> str:
    cmd = [str(server_exe(home)), "serve", checkpoint, "--port", str(port)]
    return ("  primary:                                    # added by `interlock judge install`\n"
            "    type: strands_decider\n"
            f"    base_url: http://127.0.0.1:{port}\n"
            f"    local_command: {json.dumps(cmd)}\n")


def configure(policy_path: Path, home: Path, port: int) -> str:
    """Add `judge.primary` to the policy file, keeping everything else (comments included). Returns what happened."""
    text = policy_path.read_text() if policy_path.exists() else ""
    if re.search(r"^\s{2}primary:", text, re.MULTILINE):
        return "unchanged: the policy already has judge.primary (edit it by hand, or `interlock judge remove` first)"
    block = judge_block(home, port)
    m = re.search(r"^judge:\s*$", text, re.MULTILINE)
    if m:
        text = text[: m.end()] + "\n" + block + text[m.end() + 1:]
    else:
        text = text.rstrip("\n") + "\n\njudge:\n" + block
    policy_path.write_text(text)
    return f"added judge.primary to {policy_path}"


def unconfigure(policy_path: Path) -> bool:
    if not policy_path.exists():
        return False
    text = policy_path.read_text()
    new = re.sub(r"^  primary:\s+# added by `interlock judge install`\n(?:    .*\n)+", "", text, flags=re.MULTILINE)
    if new != text:
        policy_path.write_text(new)
    return new != text


def health(base_url: str) -> dict | None:
    try:
        with urllib.request.urlopen(f"{base_url.rstrip('/')}/health", timeout=3) as r:
            return json.load(r)
    except Exception:  # noqa: BLE001
        return None


def remove(home: Path) -> bool:
    d = venv_dir(home)
    if d.exists():
        shutil.rmtree(d)
        return True
    return False


def disk_free_gb(path: Path) -> float:
    st = os.statvfs(path if path.exists() else path.parent)
    return st.f_bavail * st.f_frsize / 1e9
