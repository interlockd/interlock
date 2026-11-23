import json

import pytest
from conftest import POST_BASH, PRE_BASH, PRE_READ
from shim_stub import CURRENT_SHIMS, HAVE_SH, Reply, ShimHome, StubDaemon, install_shim, run_shim

from interlockd.normalize.kiro import normalize_kiro


def test_pre_action_fields():
    ev = normalize_kiro(PRE_BASH, agent_id="kiro-test")
    assert ev.kind == "pre_action"
    assert ev.adapter.name == "kiro"
    assert ev.identity.agent_type == "kiro" and ev.identity.agent_id == "kiro-test"
    assert ev.identity.agent_workspace == "proj"
    assert ev.session_hint == "sess_test-0001"
    assert ev.tool_call.name == "execute_bash"
    assert ev.tool_call.arguments["command"] == "git status --short"
    assert ev.context.cwd == "/ws/proj"
    assert ev.context.user_messages is None  # Kiro sends none; the daemon fills them
    assert ev.result is None
    assert ev.capabilities.ask is False and ev.capabilities.rewrite is False


def test_post_action_result_and_exit_code():
    ev = normalize_kiro(POST_BASH)
    assert ev.kind == "post_action"
    assert ev.result is not None
    assert ev.result.content.startswith("Output:")
    assert ev.result.evidence == {"exit_code": 0}


def test_non_dict_tool_input_is_wrapped():
    ev = normalize_kiro({**PRE_READ, "tool_input": "raw"})
    assert ev.tool_call.arguments == {"value": "raw"}


def test_default_agent_id_when_unset():
    ev = normalize_kiro(PRE_READ)
    assert ev.identity.agent_id.startswith("kiro-")


@pytest.mark.skipif(not HAVE_SH, reason="needs sh and curl")
def test_kiro_sh_shim_request_normalizes_like_the_raw_payload():
    """The Kiro sh shim forwards the payload unchanged next to an adapter block that now carries its own path
    (hook-tamper-detection Req 5.10); the daemon normalizes the payload alone, so the event is the same."""
    home = ShimHome.create()
    try:
        with StubDaemon(Reply(status=200, body="allow enforce 0\n\n", identity=[home.identity])) as stub:
            home.write_daemon_json(stub.listen)
            shim = install_shim(CURRENT_SHIMS / "kiro" / "interlock-hook.sh", "kiro", home)
            for payload in (PRE_BASH, POST_BASH):
                stub.clear()
                assert run_shim(shim, json.dumps(payload), home).returncode == 0
                body = stub.requests[0].json()
                assert body["payload"] == payload
                assert body["adapter"] == {"name": "kiro", "version": body["adapter"]["version"], "shim": str(shim)}
                got, want = normalize_kiro(body["payload"]), normalize_kiro(payload)
                assert (got.kind, got.tool_call.name, got.tool_call.arguments, got.context.cwd, got.session_hint) == (
                    want.kind, want.tool_call.name, want.tool_call.arguments, want.context.cwd, want.session_hint)
    finally:
        home.cleanup()
