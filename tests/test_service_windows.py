"""The Windows service backend (winrun): a per-user Run-key entry starts the daemon at sign-in. The registry is faked
here; the Windows CI job exercises the real one."""

from __future__ import annotations

import subprocess

from interlockd.service import ServiceManager


class FakeRunKey:
    def __init__(self):
        self.values: dict[str, str] = {}

    def get(self, name):
        return self.values.get(name)

    def set(self, name, value):
        self.values[name] = value

    def delete(self, name):
        self.values.pop(name, None)


def _svc(tmp_path, reg):
    return ServiceManager(tmp_path / "ih", backend="winrun", python=str(tmp_path / "python.exe"), run_key=reg,
                          runner=lambda cmd: subprocess.CompletedProcess(cmd, 0, "", ""))


def test_install_writes_a_sign_in_entry_and_uninstall_removes_it(tmp_path):
    reg = FakeRunKey()
    svc = _svc(tmp_path, reg)
    assert not svc.status().installed
    svc.install()
    cmd = reg.values[svc.label]
    assert "-m interlockd --home" in cmd and str(tmp_path / "ih") in cmd and cmd.endswith("start --backend process")
    st = svc.status()
    assert st.installed and st.backend == "winrun" and st.detail.endswith(svc.label)
    svc.uninstall()
    assert svc.label not in reg.values and not svc.status().installed


def test_uses_pythonw_when_it_is_next_to_python(tmp_path):
    (tmp_path / "pythonw.exe").write_text("", encoding="utf-8")
    reg = FakeRunKey()
    _svc(tmp_path, reg).install()
    assert next(iter(reg.values.values())).startswith(str(tmp_path / "pythonw.exe"))


def test_one_entry_per_interlock_home(tmp_path):
    reg = FakeRunKey()
    a = ServiceManager(tmp_path / "a", backend="winrun", run_key=reg)
    b = ServiceManager(tmp_path / "b", backend="winrun", run_key=reg)
    a.install(); b.install()
    assert len(reg.values) == 2 and a.label != b.label


def test_stop_treats_a_process_that_is_already_exiting_as_stopped(tmp_path, monkeypatch):
    """On Windows, terminating a process that is already exiting (the daemon once its venv launcher has gone) raises
    PermissionError ("access is denied"); stop() must not fail on it (it flaked `interlock stop` on CI)."""
    from interlockd import service

    svc = ServiceManager(tmp_path / "ih", backend="process", python="python")
    svc.pid_path.parent.mkdir(parents=True, exist_ok=True)
    svc.pid_path.write_text("4242", encoding="utf-8")
    alive = {"n": 0}

    def fake_alive(pid):
        alive["n"] += 1
        return alive["n"] == 1                 # alive when checked, gone right after

    def denied(pid, sig):
        raise PermissionError(5, "Access is denied")
    monkeypatch.setattr(ServiceManager, "_alive", staticmethod(fake_alive))
    monkeypatch.setattr(service, "_win_is_python", lambda pid: True, raising=False)
    monkeypatch.setattr(service.os, "kill", denied)
    svc.stop()
    assert not svc.pid_path.exists()
