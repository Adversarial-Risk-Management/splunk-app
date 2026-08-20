"""Tests for the OAuth token cache, the refresh grant and the retry rule."""

import json
import time
import urllib.parse

import pytest
from adversarial_api import AdversarialClient, ApiError, MemoryTokenCache, TransportError

BASE_URL = "https://api.example.test/api"
CLIENT_ID = "arm_sa_example"
CLIENT_SECRET = "arm_sk_example"


class FakeApi:
    """Stands in for the HTTP layer and records every request."""

    def __init__(self, responses=None):
        self.calls = []
        # Map of (method, path) to a response, or to an exception to raise.
        self.responses = responses or {}

    def install(self, client):
        client._request = self.request  # noqa: SLF001 - the test replaces the transport
        return client

    def request(self, method, url, body=None, headers=None):
        path = url[len(BASE_URL):]
        fields = {}
        if body and (headers or {}).get("Content-Type", "").startswith(
            "application/x-www-form-urlencoded"
        ):
            fields = {k: v[0] for k, v in urllib.parse.parse_qs(body.decode()).items()}
        elif body:
            fields = json.loads(body.decode())
        self.calls.append({"method": method, "path": path, "fields": fields, "headers": headers or {}})

        outcome = self.responses.get((method, path), {})
        if isinstance(outcome, list):
            outcome = outcome.pop(0) if outcome else {}
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def grants(self):
        """Return the grant type of every token request, in order."""
        return [
            call["fields"].get("grant_type")
            for call in self.calls
            if call["path"] == "/v1/oauth/token"
        ]


def token_pair(access="access-1", refresh="refresh-1", expires_in=900):
    return {
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "Bearer",
        "expires_in": expires_in,
        "scope": "incidents:read incidents:write",
    }


def build_client(fake, cache=None):
    client = AdversarialClient(BASE_URL, CLIENT_ID, CLIENT_SECRET, cache=cache or MemoryTokenCache())
    return fake.install(client)


def test_an_empty_cache_uses_the_client_credentials_grant():
    fake = FakeApi({("POST", "/v1/oauth/token"): token_pair()})
    client = build_client(fake)

    assert client.access_token() == "access-1"
    assert client.token_source == "client_credentials"
    assert fake.grants() == ["client_credentials"]
    sent = fake.calls[0]["fields"]
    assert sent["client_id"] == CLIENT_ID
    assert sent["client_secret"] == CLIENT_SECRET


def test_a_fresh_cached_token_needs_no_request():
    cache = MemoryTokenCache()
    cache.save({"access_token": "cached", "refresh_token": "r", "expires_at": time.time() + 600})
    fake = FakeApi()
    client = build_client(fake, cache)

    assert client.access_token() == "cached"
    assert client.token_source == "cache"
    assert fake.calls == []


def test_a_token_inside_the_refresh_margin_is_refreshed():
    """A token with less than 60 seconds left is replaced before it is used."""
    cache = MemoryTokenCache()
    cache.save({"access_token": "old", "refresh_token": "refresh-1", "expires_at": time.time() + 30})
    fake = FakeApi({("POST", "/v1/oauth/token"): token_pair(access="access-2", refresh="refresh-2")})
    client = build_client(fake, cache)

    assert client.access_token() == "access-2"
    assert client.token_source == "refresh_token"

    sent = fake.calls[0]["fields"]
    assert sent["grant_type"] == "refresh_token"
    assert sent["refresh_token"] == "refresh-1"
    # A service account is a confidential client, so the grant carries the
    # credentials as well as the refresh token.
    assert sent["client_id"] == CLIENT_ID
    assert sent["client_secret"] == CLIENT_SECRET
    # The rotated pair replaces the old one in the cache.
    assert cache.load()["refresh_token"] == "refresh-2"


def test_the_cache_records_an_absolute_expiry_time():
    fake = FakeApi({("POST", "/v1/oauth/token"): token_pair(expires_in=900)})
    cache = MemoryTokenCache()
    build_client(fake, cache).access_token()

    remaining = cache.load()["expires_at"] - time.time()
    assert 880 < remaining <= 900


@pytest.mark.parametrize(
    "failure",
    [
        ApiError(400, '{"error":"invalid_grant"}', BASE_URL),
        ApiError(401, '{"error":"invalid_client"}', BASE_URL),
        TransportError("connection reset"),
    ],
)
def test_a_failed_refresh_falls_back_to_the_client_credentials_grant(failure):
    cache = MemoryTokenCache()
    cache.save({"access_token": "old", "refresh_token": "expired", "expires_at": time.time() - 10})
    fake = FakeApi({("POST", "/v1/oauth/token"): [failure, token_pair(access="access-3")]})
    client = build_client(fake, cache)

    assert client.access_token() == "access-3"
    assert client.token_source == "client_credentials"
    assert fake.grants() == ["refresh_token", "client_credentials"]


def test_an_expired_token_without_a_refresh_token_uses_the_credentials():
    cache = MemoryTokenCache()
    cache.save({"access_token": "old", "expires_at": time.time() - 10})
    fake = FakeApi({("POST", "/v1/oauth/token"): token_pair()})
    client = build_client(fake, cache)

    client.access_token()
    assert fake.grants() == ["client_credentials"]


def test_force_new_ignores_a_fresh_cached_token():
    cache = MemoryTokenCache()
    cache.save({"access_token": "cached", "expires_at": time.time() + 600})
    fake = FakeApi({("POST", "/v1/oauth/token"): token_pair(access="access-4")})
    client = build_client(fake, cache)

    assert client.access_token(force_new=True) == "access-4"


def test_a_broken_cache_does_not_stop_the_token_request():
    class BrokenCache:
        def load(self):
            raise OSError("the secret store is not readable")

        def save(self, state):
            raise OSError("the secret store is not writable")

    fake = FakeApi({("POST", "/v1/oauth/token"): token_pair()})
    client = build_client(fake, BrokenCache())

    assert client.access_token() == "access-1"


def test_create_incident_sends_a_bearer_token_and_returns_the_incident():
    fake = FakeApi(
        {
            ("POST", "/v1/oauth/token"): token_pair(),
            ("POST", "/v1/incidents"): {"id": "INC-00007", "severity": "SEV-2"},
        }
    )
    client = build_client(fake)

    created = client.create_incident({"title": "Test"})
    assert created["id"] == "INC-00007"

    incident_call = fake.calls[-1]
    assert incident_call["headers"]["Authorization"] == "Bearer access-1"
    assert incident_call["headers"]["Content-Type"] == "application/json"
    assert incident_call["fields"] == {"title": "Test"}


def test_a_401_on_the_api_call_triggers_one_retry_with_a_new_token():
    fake = FakeApi(
        {
            ("POST", "/v1/oauth/token"): [token_pair(), token_pair(access="access-5")],
            ("POST", "/v1/incidents"): [
                ApiError(401, '{"error":"expired"}', BASE_URL),
                {"id": "INC-00008"},
            ],
        }
    )
    client = build_client(fake)

    assert client.create_incident({"title": "Test"})["id"] == "INC-00008"
    assert fake.grants() == ["client_credentials", "client_credentials"]
    assert fake.calls[-1]["headers"]["Authorization"] == "Bearer access-5"


def test_a_403_is_not_retried():
    fake = FakeApi(
        {
            ("POST", "/v1/oauth/token"): token_pair(),
            ("POST", "/v1/incidents"): ApiError(403, '{"error":"forbidden"}', BASE_URL),
        }
    )
    client = build_client(fake)

    with pytest.raises(ApiError) as raised:
        client.create_incident({"title": "Test"})
    assert raised.value.status == 403
    assert fake.grants() == ["client_credentials"]


def test_create_risk_posts_to_the_risks_endpoint():
    fake = FakeApi(
        {
            ("POST", "/v1/oauth/token"): token_pair(),
            ("POST", "/v1/risks"): {"risk": {"id": "RSK-00011", "urgency": "Medium"}},
        }
    )
    client = build_client(fake)

    created = client.create_risk({"title": "Test", "type": "Control Deficiency"})
    assert created["risk"]["id"] == "RSK-00011"
    assert fake.calls[-1]["path"] == "/v1/risks"
    assert fake.calls[-1]["headers"]["Authorization"] == "Bearer access-1"


def test_add_incident_comment_uses_the_incident_id_in_the_path():
    fake = FakeApi(
        {
            ("POST", "/v1/oauth/token"): token_pair(),
            ("POST", "/v1/incidents/INC-00009/comments"): {"id": "1"},
        }
    )
    client = build_client(fake)

    client.add_incident_comment("INC-00009", "Look at the Splunk results.")
    assert fake.calls[-1]["path"] == "/v1/incidents/INC-00009/comments"
    assert fake.calls[-1]["fields"] == {"value": "Look at the Splunk results."}


def test_add_risk_comment_uses_the_risk_id_in_the_path():
    """Both record types take the same comment body."""
    fake = FakeApi(
        {
            ("POST", "/v1/oauth/token"): token_pair(),
            ("POST", "/v1/risks/RSK-00011/comments"): {"id": "1"},
        }
    )
    client = build_client(fake)

    client.add_risk_comment("RSK-00011", "Look at the Splunk results.")
    assert fake.calls[-1]["path"] == "/v1/risks/RSK-00011/comments"
    assert fake.calls[-1]["fields"] == {"value": "Look at the Splunk results."}
