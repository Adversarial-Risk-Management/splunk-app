"""Tests for the exit code that an alert action returns.

Splunk shows the exit code in the log and in the message
"Alert script returned error code N", so each failure needs its own code. Both
actions use the same codes, so each test runs against both.
"""

import adversarial_alert as alert
import adversarial_incident
import adversarial_risk
import pytest
from adversarial_api import ApiError, TransportError
from conftest import FakeClient, Stdin

# Each case holds the action module, the settings that the action needs, and
# the identifier that the API answers with.
ACTIONS = [
    pytest.param(
        adversarial_incident,
        {"severity": "auto", "status": "New", "source": "SIEM"},
        "INC-00042",
        id="incident",
    ),
    pytest.param(
        adversarial_risk,
        {"iru": "auto", "status": "New", "source": "Attack Surface Monitoring"},
        "RSK-00042",
        id="risk",
    ),
]


def payload(settings, **configuration):
    """A payload that carries its own credentials, so no Splunk call is needed."""
    config = {
        "title": "Splunk alert: test",
        "fields": "host",
        "add_comment": "0",
        "info_severity": "4",
        "info_trigger_time": "1755600000",
        "base_url": "https://api.example.test/api",
        "client_id": "arm_sa_example",
        "client_secret": "arm_sk_example",
    }
    config.update(settings)
    config.update(configuration)
    # No session key, so the action does not read the Splunk secret store.
    return {
        "search_name": "test",
        "results_link": "http://splunk:8000/results",
        "result": {"host": "host-01"},
        "configuration": config,
    }


@pytest.mark.parametrize("action,settings,identifier", ACTIONS)
def test_a_created_record_returns_zero(client, action, settings, identifier):
    assert action.send(payload(settings)) == alert.OK
    assert FakeClient.instances[0].records[0]["title"] == "Splunk alert: test"


@pytest.mark.parametrize("action,settings,identifier", ACTIONS)
def test_an_empty_title_returns_the_validation_code(client, action, settings, identifier):
    assert action.send(payload(settings, title="")) == alert.EXIT_VALIDATION_FAILED


@pytest.mark.parametrize("action,settings,identifier", ACTIONS)
def test_missing_credentials_return_the_validation_code(client, action, settings, identifier):
    data = payload(settings, client_id="", client_secret="")
    assert action.send(data) == alert.EXIT_VALIDATION_FAILED


@pytest.mark.parametrize("action,settings,identifier", ACTIONS)
@pytest.mark.parametrize("status", [401, 403])
def test_a_rejected_credential_returns_the_authentication_code(
    client, action, settings, identifier, status
):
    client["create_error"] = ApiError(status, '{"error":"invalid_client"}', "url")
    assert action.send(payload(settings)) == alert.EXIT_AUTH_FAILED


@pytest.mark.parametrize("action,settings,identifier", ACTIONS)
def test_a_rejected_record_returns_the_api_code(client, action, settings, identifier):
    """The API answers 400 when, for example, the source name is unknown."""
    client["create_error"] = ApiError(400, '{"errors":{"source":["unknown"]}}', "url")
    assert action.send(payload(settings)) == alert.EXIT_API_REJECTED


@pytest.mark.parametrize("action,settings,identifier", ACTIONS)
def test_an_unreachable_api_returns_the_network_code(client, action, settings, identifier):
    client["create_error"] = TransportError("name resolution failed")
    assert action.send(payload(settings)) == alert.EXIT_NOT_REACHABLE


@pytest.mark.parametrize("action,settings,identifier", ACTIONS)
def test_a_failed_comment_still_reports_success(client, action, settings, identifier):
    """The record exists, so the alert action must not report a failure."""
    client["comment_error"] = TransportError("timeout")
    assert action.send(payload(settings, add_comment="1")) == alert.OK


@pytest.mark.parametrize("action,settings,identifier", ACTIONS)
def test_the_comment_uses_the_identifier_from_the_api(client, action, settings, identifier):
    action.send(payload(settings, add_comment="1"))
    assert FakeClient.instances[0].comments[0][0] == identifier


@pytest.mark.parametrize("action,settings,identifier", ACTIONS)
def test_no_comment_is_added_when_the_setting_is_off(client, action, settings, identifier):
    action.send(payload(settings, add_comment="0"))
    assert FakeClient.instances[0].comments == []


# -- the entry point ---------------------------------------------------------


@pytest.mark.parametrize("action,settings,identifier", ACTIONS)
def test_main_rejects_a_payload_that_is_not_json(monkeypatch, action, settings, identifier):
    monkeypatch.setattr("sys.argv", ["action.py", "--execute"])
    monkeypatch.setattr("sys.stdin", Stdin("not json"))
    assert action.main() == alert.EXIT_VALIDATION_FAILED


@pytest.mark.parametrize("action,settings,identifier", ACTIONS)
def test_main_needs_the_execute_argument(monkeypatch, action, settings, identifier):
    monkeypatch.setattr("sys.argv", ["action.py"])
    assert action.main() == alert.EXIT_UNEXPECTED


@pytest.mark.parametrize("action,settings,identifier", ACTIONS)
def test_main_returns_the_unexpected_code_after_an_unhandled_error(
    monkeypatch, action, settings, identifier
):
    monkeypatch.setattr("sys.argv", ["action.py", "--execute"])
    monkeypatch.setattr("sys.stdin", Stdin("{}"))
    monkeypatch.setattr(action, "send", _raise)
    assert action.main() == alert.EXIT_UNEXPECTED


def _raise(_payload):
    raise RuntimeError("something unexpected")
