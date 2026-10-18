from conftest import POST_BASH, PRE_BASH, PRE_READ

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
