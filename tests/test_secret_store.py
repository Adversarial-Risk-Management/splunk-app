"""Tests for the secret store layout and the settings that an alert reads.

`FakeSplunkd` stands in for the `storage/passwords` endpoint of splunkd, so the
tests run the real `SplunkRest` code against it.
"""

import json
import urllib.parse

import adversarial_alert as alert
import configure_credentials
import pytest
from conftest import FakeClient
from splunk_rest import SecretStoreTokenCache, SplunkRest, SplunkRestError

BASE_URL = "https://api.example.test/api"


class FakeSplunkd:
    """An in-memory `storage/passwords` collection for the `adversarial` app."""

    PATH = "/servicesNS/nobody/adversarial/storage/passwords"

    def __init__(self):
        # Map of "<realm>:<user>:" to the stored text.
        self.entries = {}

    def install(self, rest):
        rest._call = self.call  # noqa: SLF001 - the test replaces the transport
        return rest

    def call(self, method, path, fields=None):
        base, _, _ = path.partition("?")
        if base == self.PATH:
            if method == "GET":
                return {"entry": [self._entry(name) for name in sorted(self.entries)]}
            name = "%s:%s:" % (fields["realm"], fields["name"])
            if name in self.entries:
                raise SplunkRestError("POST %s returned HTTP 409: exists" % path)
            self.entries[name] = fields["password"]
            return {}
        name = urllib.parse.unquote(base[len(self.PATH) + 1:])
        if name not in self.entries:
            raise SplunkRestError("%s %s returned HTTP 404: not found" % (method, path))
        if method == "GET":
            return {"entry": [self._entry(name)]}
        if method == "DELETE":
            del self.entries[name]
            return {}
        self.entries[name] = fields["password"]
        return {}

    def _entry(self, name):
        realm, username, _ = name.split(":")
        return {"content": {"realm": realm, "username": username,
                            "clear_password": self.entries[name]}}


@pytest.fixture
def splunkd(monkeypatch):
    """Make every SplunkRest that the action builds talk to one FakeSplunkd."""
    fake = FakeSplunkd()

    def factory(server_uri, session_key=None, app="adversarial"):
        return fake.install(SplunkRest(server_uri, session_key, app))

    monkeypatch.setattr(alert, "SplunkRest", factory)
    return fake


def rest_for(fake):
    return fake.install(SplunkRest("https://127.0.0.1:8089", "key"))


def payload(**configuration):
    """A payload from Splunk, with a session key and no credentials."""
    config = {"title": "Splunk alert: test", "add_comment": "0", "info_trigger_time": "1"}
    config.update(configuration)
    return {
        "server_uri": "https://127.0.0.1:8089",
        "session_key": "key",
        "result": {},
        "configuration": config,
    }


# -- the layout ---------------------------------------------------------------


def test_the_config_entry_holds_no_secret():
    fake = FakeSplunkd()
    rest = rest_for(fake)
    rest.write_client_secret("arm_sa_a", "arm_sk_a")
    rest.write_config(BASE_URL, "arm_sa_a")

    assert json.loads(fake.entries["adversarial:config:"]) == {
        "base_url": BASE_URL,
        "client_id": "arm_sa_a",
    }
    assert fake.entries["adversarial:secret_arm_sa_a:"] == "arm_sk_a"
    assert rest.read_client_secret("arm_sa_a") == "arm_sk_a"


def test_a_secret_from_version_1_0_still_works():
    fake = FakeSplunkd()
    fake.entries["adversarial:config:"] = json.dumps(
        {"base_url": BASE_URL, "client_id": "arm_sa_a", "client_secret": "arm_sk_old"}
    )
    rest = rest_for(fake)
    assert rest.read_client_secret("arm_sa_a") == "arm_sk_old"
    # The old combined secret belongs only to the client ID next to it.
    assert rest.read_client_secret("arm_sa_b") is None


def test_a_new_secret_drops_the_cached_token_of_that_client():
    fake = FakeSplunkd()
    rest = rest_for(fake)
    SecretStoreTokenCache(rest, "arm_sa_a").save({"access_token": "a"})
    SecretStoreTokenCache(rest, "arm_sa_b").save({"access_token": "b"})

    rest.write_client_secret("arm_sa_a", "arm_sk_new")

    assert SecretStoreTokenCache(rest, "arm_sa_a").load() is None
    assert SecretStoreTokenCache(rest, "arm_sa_b").load() == {"access_token": "b"}


def test_clear_token_caches_removes_every_pair_and_the_old_one():
    fake = FakeSplunkd()
    rest = rest_for(fake)
    rest.write_client_secret("arm_sa_a", "arm_sk_a")
    SecretStoreTokenCache(rest, "arm_sa_a").save({"access_token": "a"})
    fake.entries["adversarial:token_cache:"] = "{}"

    assert rest.clear_token_caches() == 2
    assert list(fake.entries) == ["adversarial:secret_arm_sa_a:"]
    assert rest.stored_client_ids() == ["arm_sa_a"]


# -- the settings of an alert -------------------------------------------------


def store_default(fake, client_id="arm_sa_a", secret="arm_sk_a"):
    rest = rest_for(fake)
    rest.write_client_secret(client_id, secret)
    rest.write_config(BASE_URL, client_id)


def test_an_alert_uses_the_stored_default_account(splunkd):
    store_default(splunkd)
    settings, _ = alert.load_settings(payload())
    assert settings == {"base_url": BASE_URL, "client_id": "arm_sa_a",
                        "client_secret": "arm_sk_a"}


def test_an_overriding_client_id_uses_its_own_secret(splunkd):
    store_default(splunkd)
    rest_for(splunkd).write_client_secret("arm_sa_b", "arm_sk_b")

    settings, _ = alert.load_settings(payload(client_id="arm_sa_b"))
    assert (settings["client_id"], settings["client_secret"]) == ("arm_sa_b", "arm_sk_b")


def test_an_overriding_client_id_without_a_secret_fails_validation(splunkd, client):
    """Version 1.0 paired the override with the secret of the default account."""
    store_default(splunkd)
    adversarial_incident = __import__("adversarial_incident")

    code = adversarial_incident.send(payload(client_id="arm_sa_b", source="SIEM"))

    assert code == alert.EXIT_VALIDATION_FAILED
    assert FakeClient.instances == []


def test_each_client_gets_its_own_token_cache(splunkd, client):
    store_default(splunkd)
    rest_for(splunkd).write_client_secret("arm_sa_b", "arm_sk_b")

    default, _ = alert.connect(payload())
    other, _ = alert.connect(payload(client_id="arm_sa_b"))

    assert default.cache.username == "token_arm_sa_a"
    assert other.cache.username == "token_arm_sa_b"


# -- configure_credentials.py -------------------------------------------------


def options(*argv):
    return configure_credentials.parse_arguments(list(argv) + ["--splunk-password", "x"])


def test_the_script_stores_the_default_account_without_a_combined_secret():
    fake = FakeSplunkd()
    fake.entries["adversarial:token_cache:"] = "{}"
    rest = rest_for(fake)
    code = configure_credentials.run(rest, options(
        "--base-url", BASE_URL, "--client-id", "arm_sa_a", "--client-secret", "arm_sk_a"))

    assert code == 0
    assert "client_secret" not in json.loads(fake.entries["adversarial:config:"])
    assert fake.entries["adversarial:secret_arm_sa_a:"] == "arm_sk_a"
    assert "adversarial:token_cache:" not in fake.entries


def test_add_client_keeps_the_default_account():
    fake = FakeSplunkd()
    store_default(fake)
    code = configure_credentials.run(rest_for(fake), options(
        "--add-client", "--client-id", "arm_sa_b", "--client-secret", "arm_sk_b"))

    assert code == 0
    assert json.loads(fake.entries["adversarial:config:"])["client_id"] == "arm_sa_a"
    assert fake.entries["adversarial:secret_arm_sa_b:"] == "arm_sk_b"


def test_remove_client_deletes_its_secret_and_token():
    fake = FakeSplunkd()
    rest = rest_for(fake)
    rest.write_client_secret("arm_sa_b", "arm_sk_b")
    SecretStoreTokenCache(rest, "arm_sa_b").save({"access_token": "b"})

    assert configure_credentials.run(rest, options("--remove-client", "arm_sa_b")) == 0
    assert fake.entries == {}


def test_show_never_prints_a_secret(capsys):
    fake = FakeSplunkd()
    store_default(fake)
    assert configure_credentials.run(rest_for(fake), options("--show")) == 0
    output = capsys.readouterr().out
    assert "arm_sa_a" in output
    assert "arm_sk_a" not in output


def test_a_refused_store_request_gives_a_message_and_not_a_traceback(monkeypatch, capsys):
    def refuse(_options):
        rest = SplunkRest("https://127.0.0.1:8089", "key")

        def call(method, path, fields=None):
            raise SplunkRestError("GET %s returned HTTP 403: forbidden" % path)

        rest._call = call  # noqa: SLF001
        return rest

    monkeypatch.setattr(configure_credentials, "connect", refuse)
    assert configure_credentials.main(["--show", "--splunk-password", "x"]) == 1
    assert "refused" in capsys.readouterr().err
