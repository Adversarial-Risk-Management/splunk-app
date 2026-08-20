"""Tests for the way the risk action maps a Splunk payload to a risk."""

import adversarial_risk as action
import pytest


def payload(**configuration):
    """Build a payload like the one Splunk writes to standard input.

    The result holds one row, because a posture search aggregates the whole
    condition into one risk.
    """
    config = {
        "title": "Endpoint agent missing on 7 endpoints",
        "description": "",
        "type": "Control Deficiency",
        "source": "Attack Surface Monitoring",
        "status": "New",
        "iru": "",
        "likelihood": "",
        "impact": "",
        "likelihood_reason": "",
        "impact_reason": "",
        "remediation_task": "",
        "control_statement": "",
        "fields": "",
        "add_comment": "1",
        "info_severity": "4",
        "info_trigger_time": "1755600000",
    }
    config.update(configuration)
    return {
        "search_name": "Endpoint agent coverage",
        "sid": "scheduler__admin__adversarial__RMD5abc_at_1755600000_1",
        "server_host": "splunk-demo",
        "results_link": "http://splunk-demo:8000/app/search/@go?sid=1",
        "result": {
            "hosts": "7",
            "host_list": ["lt-eng-0114", "lt-fin-0042", "srv-build-03"],
            "business_units": "Engineering, Finance",
        },
        "configuration": config,
    }


# -- the initially reported urgency ------------------------------------------


@pytest.mark.parametrize(
    "splunk_severity,expected",
    [("1", "Info"), ("2", "Info"), ("3", "Low"), ("4", "Medium"), ("5", "High"), ("6", "Critical")],
)
def test_auto_maps_the_splunk_level_to_an_urgency(splunk_severity, expected):
    data = payload(iru="auto", info_severity=splunk_severity)
    assert action.urgency_of(data) == expected


def test_the_urgency_stays_empty_by_default():
    assert action.urgency_of(payload()) is None


def test_an_explicit_urgency_wins_over_the_mapping():
    assert action.urgency_of(payload(iru="Critical", info_severity="3")) == "Critical"


# -- the request body --------------------------------------------------------


def test_the_risk_body_carries_every_field_the_api_needs():
    risk = action.build_risk(payload(iru="auto"))
    assert risk["title"] == "Endpoint agent missing on 7 endpoints"
    assert risk["type"] == "Control Deficiency"
    assert risk["source"] == "Attack Surface Monitoring"
    assert risk["status"] == "New"
    assert risk["initially_reported_urgency"] == "Medium"
    # Splunk found the condition when the alert fired. The platform counts the
    # SLA from this date.
    assert risk["discovered_date"] == "2025-08-19T10:40:00Z"


def test_the_score_stays_out_of_the_body_by_default():
    """AI Suggest Score then assigns the likelihood and the impact."""
    risk = action.build_risk(payload())
    assert "likelihood" not in risk
    assert "impact" not in risk
    assert "initially_reported_urgency" not in risk


def test_a_score_from_the_alert_reaches_the_body():
    risk = action.build_risk(
        payload(
            likelihood="Probable",
            impact="High",
            likelihood_reason="The hosts are on the internet.",
            impact_reason="The hosts hold customer data.",
        )
    )
    assert risk["likelihood"] == "Probable"
    assert risk["impact"] == "High"
    assert risk["likelihood_reasoning"] == "The hosts are on the internet."
    assert risk["impact_reasoning"] == "The hosts hold customer data."


def test_the_remediation_fields_reach_the_body():
    risk = action.build_risk(
        payload(remediation_task="Install the agent.", control_statement="The build image checks.")
    )
    assert risk["remediation_task"] == "Install the agent."
    assert risk["control_statement"] == "The build image checks."


def test_the_action_leaves_the_dates_and_the_threat_objectives_to_the_platform():
    risk = action.build_risk(payload())
    for field in ("due_date", "expected_date", "closed_date", "threat_objectives"):
        assert field not in risk


def test_the_description_lists_every_affected_host():
    risk = action.build_risk(payload(fields="hosts,host_list"))
    assert "- hosts: 7" in risk["description"]
    assert "lt-eng-0114, lt-fin-0042, srv-build-03" in risk["description"]


def test_the_comment_names_the_score_of_the_risk():
    data = payload(iru="High", likelihood="Probable", impact="High")
    comment = action.build_comment(data, action.build_risk(data))
    assert "Initially reported urgency: High" in comment
    assert "Likelihood: Probable. Impact: High." in comment


def test_the_comment_says_when_the_platform_must_score_the_risk():
    data = payload()
    comment = action.build_comment(data, action.build_risk(data))
    assert "AI Suggest Score" in comment


# -- validation --------------------------------------------------------------


def test_validation_accepts_a_complete_payload():
    assert action.validate(payload()) == []


def test_validation_accepts_an_empty_score():
    assert action.validate(payload(likelihood="", impact="", iru="")) == []


def test_validation_rejects_an_empty_title():
    assert "title" in action.validate(payload(title=""))[0]


@pytest.mark.parametrize(
    "setting",
    [
        {"likelihood": "Very Likely"},
        {"impact": "Critical"},
        {"iru": "SEV-1"},
        {"status": "In Progress"},
        {"type": "Third Party"},
    ],
)
def test_validation_rejects_a_value_that_the_api_does_not_hold(setting):
    """The risk enums differ from the incident enums, so each one has a check."""
    assert action.validate(payload(**setting))
