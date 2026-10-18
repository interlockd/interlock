from conftest import SESSION

from interlockd.transcript.kiro import KiroTranscript


def test_user_messages_and_meta(kiro_sessions):
    t = KiroTranscript(kiro_sessions)
    msgs = t.user_messages(SESSION, n=3)
    assert [m.text for m in msgs] == ["first instruction", "clean up the PR"]
    assert [m.n for m in msgs] == [-2, -1]
    assert t.turn_count(SESSION) == 2
    assert t.session_meta(SESSION)["autopilot"] is True


def test_unknown_session_is_none(kiro_sessions):
    t = KiroTranscript(kiro_sessions)
    assert t.user_messages("nope") is None
    assert t.session_meta("nope") == {}


def test_incremental_read_picks_up_appends_and_partial_lines(kiro_sessions):
    import json

    t = KiroTranscript(kiro_sessions)
    assert t.turn_count(SESSION) == 2
    path = kiro_sessions / "wshash" / SESSION / "messages.jsonl"
    with open(path, "a") as f:
        f.write(json.dumps({"id": "5", "payload": {"type": "user", "content": "third"}}) + "\n")
        f.write('{"id": "6", "payload": {"type": "user", "content": "partial')  # no newline yet
    assert [m.text for m in t.user_messages(SESSION, n=2)] == ["clean up the PR", "third"]
    with open(path, "a") as f:
        f.write(' line"}}\n')
    assert t.user_messages(SESSION, n=1)[0].text == "partial line"
    assert t.turn_count(SESSION) == 4


def test_interaction_answers_count_as_user_messages(kiro_sessions):
    import json

    path = kiro_sessions / "wshash" / SESSION / "messages.jsonl"
    with open(path, "a") as f:
        f.write(json.dumps({"id": "7", "payload": {"type": "pending_interaction", "interactionType": "user_input", "question": "May I?"}}) + "\n")
        f.write(json.dumps({"id": "8", "payload": {"type": "interaction_resolved", "outcome": "answered", "selectedOption": "Yes, append it"}}) + "\n")
        f.write(json.dumps({"id": "9", "payload": {"type": "interaction_resolved", "outcome": "dismissed"}}) + "\n")
    t = KiroTranscript(kiro_sessions)
    assert t.user_messages(SESSION, 1)[0].text == "[answer] Yes, append it"
