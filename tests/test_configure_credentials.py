"""Tests for the permission report of `configure_credentials.py --verify`."""

import configure_credentials
import pytest

EDITOR = {"incidents:write", "risks:write", "tags:read"}


def test_an_editor_passes_every_requirement(capsys):
    required = configure_credentials.requirements("incident,risk,tags")
    assert configure_credentials.report_permissions(EDITOR, required) == 0
    assert "MISSING" not in capsys.readouterr().out


def test_without_require_one_usable_action_passes(capsys):
    assert configure_credentials.report_permissions({"risks:write", "tags:read"}) == 0
    output = capsys.readouterr().out
    assert "adversarial_incident  MISSING  (incidents:write)" in output
    assert "adversarial_risk      ready    (risks:write)" in output


def test_require_fails_a_risk_editor_for_the_incident_action(capsys):
    """A Risk Editor cannot run the incident action that the alerts use."""
    required = configure_credentials.requirements("incident")
    assert configure_credentials.report_permissions({"risks:write", "tags:read"}, required) == 1
    assert "lacks what --require names: incident" in capsys.readouterr().err


def test_require_tags_needs_tags_read(capsys):
    required = configure_credentials.requirements("risk,tags")
    assert configure_credentials.report_permissions({"risks:write"}, required) == 1
    assert "tags" in capsys.readouterr().err


def test_a_viewer_can_run_no_action(capsys):
    assert configure_credentials.report_permissions({"incidents:read", "risks:read"}) == 1
    assert "can run no alert action" in capsys.readouterr().err


def test_an_unknown_requirement_is_rejected():
    with pytest.raises(ValueError):
        configure_credentials.requirements("incident,ticket")
    assert configure_credentials.main(["--verify", "--require", "ticket"]) == 2
