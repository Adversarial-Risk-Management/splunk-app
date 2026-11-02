"""Tests for the "Records" setting: one record, or one record for each result."""

import csv
import gzip

import adversarial_alert as alert
import adversarial_incident
import adversarial_risk
import pytest
from adversarial_api import ApiError
from conftest import FakeClient

ACTIONS = [
    pytest.param(adversarial_incident, id="incident"),
    pytest.param(adversarial_risk, id="risk"),
]

ROWS = [
    {"dest": "gw-01", "failed_logins": "137", "user": ["alice", "bob"]},
    {"dest": "gw-02", "failed_logins": "64", "user": "carol"},
    {"dest": "gw-03", "failed_logins": "21", "user": "dave"},
]


def write_results(path, rows):
    """Write a results file in the format of Splunk: gzip CSV with `__mv_` columns."""
    names = []
    for row in rows:
        for name in row:
            if name not in names:
                names.append(name)
    header = []
    for name in names:
        header += [name, "__mv_" + name]
    with gzip.open(path, "wt", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(header)
        for row in rows:
            cells = []
            for name in names:
                value = row.get(name, "")
                if isinstance(value, list):
                    encoded = ";".join("$%s$" % item.replace("$", "$$") for item in value)
                    cells += ["\n".join(value), encoded]
                else:
                    cells += [value, ""]
            writer.writerow(cells)
    return str(path)


def payload(results_file=None, **configuration):
    config = {
        "title": "Brute force on {{row.dest}}",
        "description": "{{row.failed_logins}} failed logins",
        "fields": "dest,user",
        "add_comment": "1",
        "info_severity": "4",
        "info_trigger_time": "1755600000",
        "base_url": "https://api.example.test/api",
        "client_id": "arm_sa_example",
        "client_secret": "arm_sk_example",
    }
    config.update(configuration)
    data = {
        "search_name": "Brute force",
        "results_link": "http://splunk:8000/results",
        "result": dict(ROWS[0]),
        "configuration": config,
    }
    if results_file:
        data["results_file"] = results_file
    return data


# -- the results file --------------------------------------------------------


def test_read_results_decodes_multi_value_fields(tmp_path):
    path = write_results(tmp_path / "results.csv.gz", ROWS)
    rows = alert.read_results(path)
    assert [row["dest"] for row in rows] == ["gw-01", "gw-02", "gw-03"]
    assert rows[0]["user"] == ["alice", "bob"]
    assert rows[1]["user"] == "carol"
    assert all(not name.startswith("__mv_") for name in rows[0])


def test_multi_value_keeps_a_dollar_sign():
    assert alert.multi_value("$a$$b$;$c$") == ["a$b", "c"]


# -- the row tokens ----------------------------------------------------------


def test_a_row_token_takes_the_field_of_the_row():
    assert alert.expand_row_tokens("Host {{row.dest}}", ROWS[1]) == "Host gw-02"


def test_a_row_token_joins_a_multi_value_field():
    assert alert.expand_row_tokens("{{row.user}}", ROWS[0]) == "alice, bob"


def test_a_row_token_for_a_missing_field_is_empty():
    assert alert.expand_row_tokens("[{{row.nothing}}]", ROWS[0]) == "[]"


def test_a_row_token_accepts_spaces_inside_the_braces():
    assert alert.expand_row_tokens("{{ row.dest }}", ROWS[2]) == "gw-03"


def test_other_text_stays_as_it_is():
    text = '{"key": "{{other}}"} costs $5'
    assert alert.expand_row_tokens(text, ROWS[0]) == text


# -- one mode ----------------------------------------------------------------


@pytest.mark.parametrize("action", ACTIONS)
def test_one_mode_creates_one_record_from_the_first_result(client, action, tmp_path):
    path = write_results(tmp_path / "results.csv.gz", ROWS)
    assert action.send(payload(path)) == alert.OK
    records = FakeClient.instances[0].records
    assert len(records) == 1
    assert records[0]["title"] == "Brute force on gw-01"
    assert "First result:" in records[0]["description"]


# -- each mode ---------------------------------------------------------------


@pytest.mark.parametrize("action", ACTIONS)
def test_each_mode_creates_one_record_for_each_result(client, action, tmp_path):
    path = write_results(tmp_path / "results.csv.gz", ROWS)
    assert action.send(payload(path, records="each")) == alert.OK
    fake = FakeClient.instances[0]
    assert [r["title"] for r in fake.records] == [
        "Brute force on gw-01",
        "Brute force on gw-02",
        "Brute force on gw-03",
    ]
    assert fake.records[1]["description"].startswith("64 failed logins")
    assert "Result 2 of 3:\n- dest: gw-02\n- user: carol" in fake.records[1]["description"]
    assert len(fake.comments) == 3


@pytest.mark.parametrize("action", ACTIONS)
def test_each_mode_stops_at_the_limit(client, action, tmp_path):
    path = write_results(tmp_path / "results.csv.gz", ROWS)
    assert action.send(payload(path, records="each", max_records="2")) == alert.OK
    records = FakeClient.instances[0].records
    assert [r["title"] for r in records] == ["Brute force on gw-01", "Brute force on gw-02"]
    assert "Result 2 of 3:" in records[1]["description"]


@pytest.mark.parametrize("action", ACTIONS)
def test_each_mode_with_zero_has_no_limit(client, action, tmp_path):
    rows = [{"dest": "gw-%02d" % n, "failed_logins": "1", "user": "u"} for n in range(40)]
    path = write_results(tmp_path / "results.csv.gz", rows)
    assert action.send(payload(path, records="each", max_records="0")) == alert.OK
    records = FakeClient.instances[0].records
    assert len(records) == 40
    assert "Result 40 of 40:" in records[-1]["description"]


@pytest.mark.parametrize("action", ACTIONS)
def test_each_mode_uses_the_default_limit_of_25(client, action, tmp_path):
    rows = [{"dest": "gw-%02d" % n, "failed_logins": "1", "user": "u"} for n in range(30)]
    path = write_results(tmp_path / "results.csv.gz", rows)
    assert action.send(payload(path, records="each")) == alert.OK
    assert len(FakeClient.instances[0].records) == 25


@pytest.mark.parametrize("action", ACTIONS)
def test_a_rate_limit_stops_the_run_with_a_clear_message(client, action, tmp_path, capsys):
    client["create_error"] = ApiError(429, "Too Many Requests", "url")
    path = write_results(tmp_path / "results.csv.gz", ROWS)
    assert action.send(payload(path, records="each", max_records="0")) == alert.EXIT_API_REJECTED
    assert "limited the request rate" in capsys.readouterr().err


@pytest.mark.parametrize("action", ACTIONS)
def test_each_mode_without_a_results_file_uses_the_first_result(client, action):
    assert action.send(payload(records="each")) == alert.OK
    records = FakeClient.instances[0].records
    assert [r["title"] for r in records] == ["Brute force on gw-01"]


@pytest.mark.parametrize("action", ACTIONS)
def test_each_mode_stops_at_the_first_failure(client, action, tmp_path):
    client["create_error"] = ApiError(422, '{"error":"unknown source"}', "url")
    path = write_results(tmp_path / "results.csv.gz", ROWS)
    assert action.send(payload(path, records="each")) == alert.EXIT_API_REJECTED


@pytest.mark.parametrize("action", ACTIONS)
def test_each_mode_uses_one_client_for_all_records(client, action, tmp_path):
    """One token exchange covers all the records of one alert firing."""
    path = write_results(tmp_path / "results.csv.gz", ROWS)
    action.send(payload(path, records="each"))
    assert len(FakeClient.instances) == 1


# -- validation --------------------------------------------------------------


@pytest.mark.parametrize("action", ACTIONS)
@pytest.mark.parametrize(
    "settings",
    [{"records": "all"}, {"max_records": "-1"}, {"max_records": "many"}],
)
def test_a_bad_records_setting_returns_the_validation_code(client, action, settings):
    assert action.send(payload(**settings)) == alert.EXIT_VALIDATION_FAILED
    assert FakeClient.instances == []


def test_the_records_setting_ignores_case_and_space():
    assert alert.records_mode(payload(records=" Each ")) == alert.RECORDS_EACH
