"""Tests for the way the incident action maps a Splunk payload to an incident."""

import adversarial_incident as action
import pytest


def payload(**configuration):
    """Build a payload like the one Splunk writes to standard input."""
    config = {
        "title": "Splunk alert: Brute force",
        "description": "",
        "severity": "",
        "status": "New",
        "source": "SIEM",
        "fields": "",
        "add_comment": "1",
        "info_severity": "3",
        "info_trigger_time": "1755600000",
    }
    config.update(configuration)
    return {
        "search_name": "Brute force",
        "sid": "scheduler__admin__search__RMD5abc_at_1755600000_1",
        "server_host": "splunk-demo",
        "results_link": "http://splunk-demo:8000/app/search/@go?sid=1",
        "result": {"host": "auth-gateway-01", "failed_logins": "137"},
        "configuration": config,
    }


# -- the severity ------------------------------------------------------------


@pytest.mark.parametrize(
    "splunk_severity,expected",
    [("1", "SEV-5"), ("2", "SEV-5"), ("3", "SEV-4"), ("4", "SEV-3"), ("5", "SEV-2"), ("6", "SEV-1")],
)
def test_auto_maps_the_splunk_level_to_a_severity(splunk_severity, expected):
    data = payload(severity="auto", info_severity=splunk_severity)
    assert action.severity_of(data) == expected


def test_the_severity_stays_empty_by_default():
    """The platform then assigns the severity with AI Suggest Score."""
    assert action.severity_of(payload()) is None


def test_auto_gives_no_severity_for_an_ad_hoc_search():
    data = payload(severity="auto", info_severity="$alert.severity$")
    assert action.severity_of(data) is None


def test_an_explicit_severity_wins_over_the_mapping():
    assert action.severity_of(payload(severity="SEV-1", info_severity="2")) == "SEV-1"


# -- the request body --------------------------------------------------------


def test_the_incident_body_carries_every_field_the_api_needs():
    incident = action.build_incident(
        payload(severity="auto", severity_reasoning="Active attack.")
    )
    assert incident["title"] == "Splunk alert: Brute force"
    assert incident["severity"] == "SEV-4"
    assert incident["status"] == "New"
    assert incident["source"] == "SIEM"
    assert incident["detected_date"] == "2025-08-19T10:40:00Z"
    assert incident["severity_reasoning"] == "Active attack."


def test_the_incident_body_omits_an_empty_field():
    incident = action.build_incident(payload())
    assert "severity" not in incident
    assert "severity_reasoning" not in incident


def test_the_comment_names_the_severity_of_the_incident():
    data = payload(severity="SEV-2")
    comment = action.build_comment(data, action.build_incident(data))
    assert "Severity from Splunk: SEV-2" in comment


def test_the_comment_says_when_the_platform_must_score_the_incident():
    data = payload()
    comment = action.build_comment(data, action.build_incident(data))
    assert "AI Suggest Score" in comment


# -- validation --------------------------------------------------------------


def test_validation_accepts_a_complete_payload():
    assert action.validate(payload()) == []


def test_validation_accepts_an_empty_severity():
    assert action.validate(payload(severity="")) == []


def test_validation_rejects_an_empty_title():
    assert "title" in action.validate(payload(title=""))[0]


def test_validation_rejects_an_unknown_severity_or_status():
    assert action.validate(payload(severity="critical"))
    assert action.validate(payload(status="Open"))
