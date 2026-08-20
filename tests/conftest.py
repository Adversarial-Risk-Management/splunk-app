"""Test helpers that the two alert actions share."""

import adversarial_alert as alert
import pytest


class FakeClient:
    """Stands in for AdversarialClient and records the calls of an action."""

    instances = []

    def __init__(self, base_url, client_id, client_secret, cache=None, log=None):
        self.base_url = base_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.token_source = "client_credentials"
        # Every record that the action created, and every comment it added.
        self.records = []
        self.comments = []
        self.create_error = None
        self.comment_error = None
        FakeClient.instances.append(self)

    def create_incident(self, incident):
        return self._create(
            incident, {"id": "INC-00042", "severity": incident.get("severity")}
        )

    def create_risk(self, risk):
        # POST /v1/risks answers with a risk register entry.
        return self._create(
            risk,
            {
                "risk": {
                    "id": "RSK-00042",
                    "urgency": "Medium",
                    "due_date": "2026-11-15T00:00:00Z",
                }
            },
        )

    def _create(self, record, answer):
        if self.create_error:
            raise self.create_error
        self.records.append(record)
        return answer

    def add_incident_comment(self, identifier, text):
        return self._comment(identifier, text)

    def add_risk_comment(self, identifier, text):
        return self._comment(identifier, text)

    def _comment(self, identifier, text):
        if self.comment_error:
            raise self.comment_error
        self.comments.append((identifier, text))
        return {"id": "1"}


@pytest.fixture
def client(monkeypatch):
    """Install FakeClient in place of the API client.

    The fixture returns a dictionary. Put `create_error` or `comment_error` in
    it to make the next call fail.
    """
    FakeClient.instances = []
    planned = {}

    def factory(*args, **kwargs):
        instance = FakeClient(*args, **kwargs)
        instance.create_error = planned.get("create_error")
        instance.comment_error = planned.get("comment_error")
        return instance

    monkeypatch.setattr(alert, "AdversarialClient", factory)
    return planned


class Stdin:
    """Stands in for sys.stdin, which carries the Splunk payload."""

    def __init__(self, text):
        self._text = text

    def read(self):
        return self._text
