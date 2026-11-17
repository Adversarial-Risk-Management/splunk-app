"""Tests for the proxy setting.

The HTTP tests start real servers on 127.0.0.1: a proxy that records each
request, and a fake API or splunkd behind it. They show where each request
goes, not only which objects the code builds.
"""

import base64
import http.server
import json
import threading

import adversarial_alert as alert
import configure_credentials
import pytest
from adversarial_api import (
    AdversarialClient,
    ProxyError,
    check_proxy_url,
    proxy_with_credentials,
)
from splunk_rest import SplunkRest
from test_secret_store import FakeSplunkd, options, payload, rest_for, splunkd  # noqa: F401

TOKEN = {"access_token": "a", "refresh_token": "r", "expires_in": 900, "token_type": "Bearer"}


class Recorder:
    """A threaded HTTP server that records requests and answers with a handler."""

    def __init__(self, answer):
        recorder = self
        self.requests = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _handle(self):
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    self.rfile.read(length)
                recorder.requests.append(
                    {"method": self.command, "path": self.path, "headers": dict(self.headers)}
                )
                status, body = answer(self)
                data = json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_CONNECT = _handle

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = "http://127.0.0.1:%d" % self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def servers():
    started = []

    def start(answer):
        server = Recorder(answer)
        started.append(server)
        return server

    yield start
    for server in started:
        server.close()


# -- the proxy URL ------------------------------------------------------------


@pytest.mark.parametrize("url", ["http://proxy:3128", "https://proxy.example.com", "http://p:8080/"])
def test_a_valid_proxy_url_has_no_problem(url):
    assert check_proxy_url(url) is None


@pytest.mark.parametrize(
    "url",
    ["proxy:3128", "ftp://proxy", "http://user:pass@proxy:3128", "http://proxy:3128/path",
     "http://proxy:port", "http://"],
)
def test_a_bad_proxy_url_has_a_problem(url):
    assert check_proxy_url(url)


def test_the_credentials_go_into_the_url_with_escapes():
    url = proxy_with_credentials("http://proxy:3128", "dom\\user", "p@ss:w/rd")
    assert url == "http://dom%5Cuser:p%40ss%3Aw%2Frd@proxy:3128"


def test_no_user_gives_the_url_as_it_is():
    assert proxy_with_credentials("http://proxy:3128", "", "secret") == "http://proxy:3128"


# -- requests to the API ------------------------------------------------------


def test_a_token_request_goes_through_the_proxy_with_its_credentials(servers):
    proxy = servers(lambda handler: (200, TOKEN))
    client = AdversarialClient(
        "http://api.example.test/api", "arm_sa_a", "arm_sk_a",
        proxy=proxy_with_credentials(proxy.url, "splunk", "pw"),
    )

    assert client.access_token() == "a"

    request = proxy.requests[0]
    # A proxy gets the absolute URL of the target.
    assert request["path"] == "http://api.example.test/api/v1/oauth/token"
    expected = "Basic " + base64.b64encode(b"splunk:pw").decode("ascii")
    assert request["headers"]["Proxy-Authorization"] == expected


def test_an_https_api_url_opens_a_connect_tunnel(servers):
    # The test proxy refuses the tunnel, which is enough to see the CONNECT.
    proxy = servers(lambda handler: (502, {}))
    client = AdversarialClient("https://api.example.test/api", "arm_sa_a", "arm_sk_a",
                               proxy=proxy.url)

    with pytest.raises(ProxyError):
        client.access_token()

    assert proxy.requests[0]["method"] == "CONNECT"
    assert proxy.requests[0]["path"] == "api.example.test:443"


@pytest.mark.parametrize("status", [407, 401, 403, 502])
def test_a_refused_tunnel_is_a_proxy_error(servers, status):
    proxy = servers(lambda handler: (status, {}))
    client = AdversarialClient("https://api.example.test/api", "arm_sa_a", "arm_sk_a",
                               proxy=proxy.url)

    with pytest.raises(ProxyError, match="refused the tunnel .*%d" % status):
        client.access_token()


def test_a_refused_forward_request_is_a_proxy_error_and_not_a_token_error(servers):
    """Exit code 5 for the network path, not exit code 3 for the credentials."""
    proxy = servers(lambda handler: (407, {}))
    client = AdversarialClient("http://api.example.test/api", "arm_sa_a", "arm_sk_a",
                               proxy=proxy.url)

    with pytest.raises(ProxyError, match="407"):
        client.access_token()


def test_without_a_proxy_setting_the_environment_proxy_applies(servers, monkeypatch):
    proxy = servers(lambda handler: (200, TOKEN))
    monkeypatch.setenv("HTTP_PROXY", proxy.url)
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    client = AdversarialClient("http://api.example.test/api", "arm_sa_a", "arm_sk_a")

    assert client.access_token() == "a"
    assert proxy.requests[0]["path"] == "http://api.example.test/api/v1/oauth/token"


def test_requests_to_splunkd_never_use_a_proxy(servers, monkeypatch):
    proxy = servers(lambda handler: (502, {}))
    splunkd = servers(lambda handler: (200, {"entry": []}))
    monkeypatch.setenv("HTTP_PROXY", proxy.url)
    monkeypatch.setenv("HTTPS_PROXY", proxy.url)
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)

    SplunkRest(splunkd.url, "session-key").list_usernames()

    assert proxy.requests == []
    assert len(splunkd.requests) == 1


# -- the stored setting -------------------------------------------------------


def test_an_alert_uses_the_stored_proxy_with_its_password(splunkd):
    rest = rest_for(splunkd)
    rest.write_client_secret("arm_sa_a", "arm_sk_a")
    rest.write_proxy_password("pw")
    rest.write_config("https://api.example.test/api", "arm_sa_a",
                      "http://proxy:3128", "splunk")

    settings, _ = alert.load_settings(payload())

    assert settings["proxy_url"] == "http://proxy:3128"
    assert settings["proxy"] == "http://splunk:pw@proxy:3128"


def test_the_log_names_the_proxy_without_the_password(splunkd, client, capsys):
    rest = rest_for(splunkd)
    rest.write_client_secret("arm_sa_a", "arm_sk_a")
    rest.write_proxy_password("pw")
    rest.write_config("https://api.example.test/api", "arm_sa_a",
                      "http://proxy:3128", "splunk")

    created, code = alert.connect(payload())

    assert code == alert.OK
    assert created.proxy == "http://splunk:pw@proxy:3128"
    log = capsys.readouterr().err
    assert "through the proxy http://proxy:3128" in log
    assert "pw" not in log


def test_a_config_without_a_proxy_user_drops_the_password():
    fake = FakeSplunkd()
    rest = rest_for(fake)
    rest.write_proxy_password("pw")
    rest.write_config("https://api.example.test/api", "arm_sa_a", "http://proxy:3128")
    assert "adversarial:proxy_password:" not in fake.entries


# -- configure_credentials.py -------------------------------------------------

API = ["--base-url", "https://api.example.test/api", "--client-id", "arm_sa_a",
       "--client-secret", "arm_sk_a"]


def stored(fake):
    return json.loads(fake.entries["adversarial:config:"])


def test_the_script_stores_a_proxy_with_the_settings():
    fake = FakeSplunkd()
    code = configure_credentials.run(rest_for(fake), options(
        *API, "--proxy-url", "http://proxy:3128", "--proxy-user", "splunk",
        "--proxy-password", "pw"))

    assert code == 0
    assert stored(fake)["proxy_url"] == "http://proxy:3128"
    assert stored(fake)["proxy_user"] == "splunk"
    assert fake.entries["adversarial:proxy_password:"] == "pw"


def test_proxy_options_alone_change_only_the_proxy():
    fake = FakeSplunkd()
    configure_credentials.run(rest_for(fake), options(*API))
    code = configure_credentials.run(rest_for(fake), options("--proxy-url", "http://proxy:3128"))

    assert code == 0
    assert stored(fake) == {"base_url": "https://api.example.test/api", "client_id": "arm_sa_a",
                            "proxy_url": "http://proxy:3128"}
    assert fake.entries["adversarial:secret_arm_sa_a:"] == "arm_sk_a"


def test_a_new_store_keeps_the_stored_proxy():
    fake = FakeSplunkd()
    configure_credentials.run(rest_for(fake), options(*API, "--proxy-url", "http://proxy:3128"))
    configure_credentials.run(rest_for(fake), options(*API))
    assert stored(fake)["proxy_url"] == "http://proxy:3128"


def test_no_proxy_removes_the_proxy_and_its_password():
    fake = FakeSplunkd()
    configure_credentials.run(rest_for(fake), options(
        *API, "--proxy-url", "http://proxy:3128", "--proxy-user", "splunk",
        "--proxy-password", "pw"))
    code = configure_credentials.run(rest_for(fake), options("--no-proxy"))

    assert code == 0
    assert "proxy_url" not in stored(fake)
    assert "adversarial:proxy_password:" not in fake.entries


def test_the_script_rejects_a_bad_proxy_url():
    fake = FakeSplunkd()
    code = configure_credentials.run(rest_for(fake), options(
        *API, "--proxy-url", "http://user:pw@proxy:3128"))
    assert code == 2
    assert "adversarial:config:" not in fake.entries


def test_a_proxy_user_needs_a_password():
    fake = FakeSplunkd()
    code = configure_credentials.run(rest_for(fake), options(
        *API, "--proxy-url", "http://proxy:3128", "--proxy-user", "splunk"))
    assert code == 2


def test_show_names_the_proxy_but_not_its_password(capsys):
    fake = FakeSplunkd()
    configure_credentials.run(rest_for(fake), options(
        *API, "--proxy-url", "http://proxy:3128", "--proxy-user", "splunk",
        "--proxy-password", "s3cret-pw"))
    capsys.readouterr()

    assert configure_credentials.run(rest_for(fake), options("--show")) == 0
    output = capsys.readouterr().out
    assert "http://proxy:3128" in output
    assert "splunk (password stored)" in output
    assert "s3cret-pw" not in output
