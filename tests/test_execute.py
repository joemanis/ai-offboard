from __future__ import annotations

from offboard.connectors.mock import MockConnector
from offboard.execute import Executor
from offboard.scan import run_scan


def test_executor_simulates_on_mock():
    connector = MockConnector()
    executor = Executor(connector)
    assert executor._simulated
    outcome = executor.execute("block_signin", "stale@example.com")
    assert outcome["status"] == "ok"
    assert outcome.get("simulated") is True


def test_executor_unknown_action():
    executor = Executor(MockConnector())
    outcome = executor.execute("frobnicate", "x@example.com")
    assert outcome["status"] == "unknown_action"


def test_remediation_parses_to_action():
    from offboard.cli import _remediation_to_action

    assert _remediation_to_action("Disable the account to remove residual access.") == "block_signin"
    assert _remediation_to_action("Revoke tokens/SSO sessions.") == "revoke_token"
    assert _remediation_to_action("Review the assigned role scope.") is None  # manual step


def test_execute_on_mock_plan_flow(monkeypatch, tmp_path):
    """The full execute loop on a mock connector produces audit-log rows."""
    from offboard import store

    monkeypatch.setattr(store, "DB_PATH", str(tmp_path / "execute.db"))
    connector = MockConnector()
    result = run_scan(connector, "demo")
    assert len(result.findings) >= 3

    # Simulate what the CLI does: plan steps -> execute -> log
    from offboard.cli import _remediation_to_action

    executor = Executor(connector)
    executed = 0
    for f in result.findings:
        for step in f.remediation:
            action = _remediation_to_action(step)
            if action:
                outcome = executor.execute(action, f.subject)
                store.log_execution("demo", action, f.subject, outcome["status"])
                executed += 1
    assert executed > 0
    assert len(store.list_executions()) == executed