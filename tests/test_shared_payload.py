"""Tests for the payload code that both alert actions use."""

import adversarial_alert as alert
import pytest


def payload(**configuration):
    """Build a payload like the one Splunk writes to standard input."""
    config = {
        "title": "Splunk alert: Brute force",
        "description": "",
        "fields": "",
        "add_comment": "1",
        "info_severity": "3",
        "info_trigger_time": "1755600000",
    }
    config.update(configuration)
    return {
        "app": "search",
        "owner": "admin",
        "search_name": "Brute force",
        "sid": "scheduler__admin__search__RMD5abc_at_1755600000_1",
        "server_host": "splunk-demo",
        "server_uri": "https://127.0.0.1:8089",
        "session_key": "session-key",
        "results_link": "http://splunk-demo:8000/app/search/@go?sid=1",
        "result": {
            "host": "auth-gateway-01",
            "source": "/var/log/auth.log",
            "sourcetype": "linux_secure",
            "src_ip": ["203.0.113.42", "203.0.113.43"],
            "failed_logins": "137",
        },
        "configuration": config,
    }


# -- the trigger time --------------------------------------------------------


def test_the_trigger_time_becomes_an_rfc_3339_timestamp():
    assert alert.trigger_time(payload()) == "2025-08-19T10:40:00Z"


def test_a_missing_trigger_time_uses_the_current_time():
    assert alert.trigger_time(payload(info_trigger_time="")).endswith("Z")


# -- the severity of the Splunk alert ----------------------------------------


def test_the_splunk_severity_is_a_number():
    assert alert.splunk_severity(payload(info_severity="5")) == 5


def test_an_ad_hoc_search_has_no_splunk_severity():
    """`sendalert` does not expand the $alert.severity$ token."""
    assert alert.splunk_severity(payload(info_severity="$alert.severity$")) is None
    assert alert.splunk_severity(payload(info_severity="")) is None


# -- a score setting ---------------------------------------------------------

TABLE = {3: "Low", 5: "High"}


def test_an_empty_score_setting_leaves_the_field_empty():
    """The platform then assigns the value with AI Suggest Score."""
    assert alert.scored_value(payload(score=""), "score", TABLE) is None


def test_auto_maps_the_splunk_severity():
    assert alert.scored_value(payload(score="auto", info_severity="5"), "score", TABLE) == "High"


def test_auto_leaves_the_field_empty_without_a_splunk_severity():
    data = payload(score="auto", info_severity="$alert.severity$")
    assert alert.scored_value(data, "score", TABLE) is None


def test_a_named_value_goes_to_the_api_as_it_is():
    assert alert.scored_value(payload(score="Severe"), "score", TABLE) == "Severe"


# -- the result fields -------------------------------------------------------


def test_selected_fields_keeps_the_order_of_the_setting():
    fields = alert.selected_fields(payload(fields="sourcetype, host"))
    assert fields == [("sourcetype", "linux_secure"), ("host", "auth-gateway-01")]


def test_selected_fields_expands_a_wildcard():
    fields = dict(alert.selected_fields(payload(fields="s*")))
    assert set(fields) == {"source", "sourcetype", "src_ip"}


def test_selected_fields_joins_a_multi_value_field():
    """A `values()` result must name every asset, not only the first."""
    fields = dict(alert.selected_fields(payload(fields="src_ip")))
    assert fields["src_ip"] == "203.0.113.42, 203.0.113.43"


def test_a_long_multi_value_field_is_shortened():
    hosts = ["host-%03d" % index for index in range(50)]
    data = payload(fields="hosts")
    data["result"]["hosts"] = hosts
    value = dict(alert.selected_fields(data))["hosts"]
    assert value.endswith(", and 30 more")
    assert value.count("host-") == alert.MAX_FIELD_VALUES


def test_selected_fields_is_empty_when_the_setting_is_empty():
    assert alert.selected_fields(payload(fields="")) == []


# -- the description ---------------------------------------------------------


def test_the_description_holds_the_context_and_the_results_link():
    description = alert.build_description(payload(description="Investigate now.", fields="host"))
    assert description.startswith("Investigate now.")
    assert "Search: Brute force" in description
    assert "Trigger time: 2025-08-19T10:40:00Z" in description
    assert "http://splunk-demo:8000/app/search/@go?sid=1" in description
    assert "- host: auth-gateway-01" in description


def test_the_description_names_an_ad_hoc_search():
    data = payload()
    del data["search_name"]
    assert "Search: ad-hoc search" in alert.build_description(data)


def test_a_long_description_is_truncated():
    description = alert.build_description(payload(description="x" * 20000))
    assert len(description) <= alert.MAX_DESCRIPTION_CHARS + len("\n[truncated]")
    assert description.endswith("[truncated]")


# -- the comment -------------------------------------------------------------


def test_the_comment_links_back_to_splunk():
    comment = alert.build_comment(payload(), "adversarial_incident", ["Extra line."])
    assert "adversarial_incident" in comment
    assert "http://splunk-demo:8000/app/search/@go?sid=1" in comment
    assert "Brute force" in comment
    assert comment.endswith("Extra line.")


@pytest.mark.parametrize("setting,expected", [("1", True), ("0", False), ("", True)])
def test_the_comment_setting_defaults_to_on(setting, expected):
    assert alert.wants_comment(payload(add_comment=setting)) is expected


# -- validation --------------------------------------------------------------


def test_common_problems_accepts_a_complete_payload():
    assert alert.common_problems(payload()) == []


def test_common_problems_rejects_an_empty_title():
    assert "title" in alert.common_problems(payload(title=""))[0]


def test_common_problems_rejects_a_payload_without_a_configuration():
    assert alert.common_problems({}) == ["The payload has no `configuration` object."]


def test_check_choice_accepts_an_empty_setting():
    assert alert.check_choice(payload(status=""), "status", ("New",)) == []


def test_check_choice_rejects_an_unknown_value_and_names_the_valid_ones():
    problems = alert.check_choice(payload(status="Open"), "status", ("New", "Closed"))
    assert problems and "New, Closed" in problems[0]


def test_check_choice_accepts_auto_only_when_the_setting_allows_it():
    assert alert.check_choice(payload(score="auto"), "score", ("High",), allow_auto=True) == []
    assert alert.check_choice(payload(score="auto"), "score", ("High",))
