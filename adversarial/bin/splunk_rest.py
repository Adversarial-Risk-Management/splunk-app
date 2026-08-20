"""Access to the Splunk management API from an alert action.

Splunk gives an alert action a session key on standard input. The alert action
uses that key to read its configuration from the Splunk secret store
(`storage/passwords`), where Splunk keeps the value encrypted on disk.

The module uses only the Python standard library.
"""

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request

# The app owns one realm in the secret store. Two entries live in it:
#
#   config       the API URL, the client ID and the client secret
#   token_cache  the current OAuth token pair
#
# Keep colons out of realm and user names. Splunk builds the entry name as
# "<realm>:<user>:" and a colon inside either part needs an escape.
SECRET_REALM = "adversarial"
CONFIG_USERNAME = "config"
TOKEN_CACHE_USERNAME = "token_cache"

HTTP_TIMEOUT_SECONDS = 30


class SplunkRestError(Exception):
    """A request to the Splunk management API failed."""


class SplunkRest:
    """Small client for the endpoints that this app needs."""

    def __init__(self, server_uri, session_key=None, app="adversarial"):
        self.server_uri = server_uri.rstrip("/")
        self.session_key = session_key
        self.app = app
        # splunkd presents a self-signed certificate on the management port.
        # Verification is off for this local connection only. Requests to the
        # Adversarial API keep full certificate verification.
        self._ssl_context = ssl._create_unverified_context()

    # -- HTTP ------------------------------------------------------------

    def _call(self, method, path, fields=None):
        url = "%s/%s" % (self.server_uri, path.lstrip("/"))
        separator = "&" if "?" in url else "?"
        url += separator + "output_mode=json"
        body = urllib.parse.urlencode(fields).encode("utf-8") if fields else None
        request = urllib.request.Request(url, data=body, method=method)
        if self.session_key:
            request.add_header("Authorization", "Splunk " + self.session_key)
        try:
            with urllib.request.urlopen(
                request, timeout=HTTP_TIMEOUT_SECONDS, context=self._ssl_context
            ) as response:
                text = response.read().decode("utf-8")
                return json.loads(text) if text else {}
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", "replace")
            raise SplunkRestError(
                "%s %s returned HTTP %s: %s" % (method, url, error.code, detail[:300])
            ) from error
        except (urllib.error.URLError, OSError) as error:
            raise SplunkRestError("%s %s failed: %s" % (method, url, error)) from error

    def login(self, username, password):
        """Exchange a user name and a password for a session key.

        Only the command-line setup script uses this method. An alert action
        receives its session key from Splunk.
        """
        result = self._call(
            "POST", "/services/auth/login", {"username": username, "password": password}
        )
        self.session_key = result["sessionKey"]
        return self.session_key

    # -- Secret store ----------------------------------------------------

    def _passwords_path(self, username=None):
        # Entries live in the app namespace and belong to no single user, so
        # every alert owner in the org can read them.
        base = "/servicesNS/nobody/%s/storage/passwords" % urllib.parse.quote(self.app)
        if username is None:
            return base
        name = "%s:%s:" % (SECRET_REALM, username)
        return "%s/%s" % (base, urllib.parse.quote(name, safe=""))

    def read_secret(self, username):
        """Return the stored text for one entry, or None if it is absent."""
        try:
            result = self._call("GET", self._passwords_path(username))
        except SplunkRestError as error:
            if "HTTP 404" in str(error):
                return None
            raise
        entries = result.get("entry") or []
        if not entries:
            return None
        return entries[0].get("content", {}).get("clear_password")

    def write_secret(self, username, value):
        """Create or replace one entry."""
        # An update posts only the password. A create also needs the name and
        # the realm, so try the update first and fall back to the create.
        try:
            self._call("POST", self._passwords_path(username), {"password": value})
            return
        except SplunkRestError as error:
            if "HTTP 404" not in str(error):
                raise
        self._call(
            "POST",
            self._passwords_path(),
            {"name": username, "realm": SECRET_REALM, "password": value},
        )

    def delete_secret(self, username):
        """Remove one entry. A missing entry is not an error."""
        try:
            self._call("DELETE", self._passwords_path(username))
        except SplunkRestError as error:
            if "HTTP 404" not in str(error):
                raise

    # -- App configuration ------------------------------------------------

    def read_config(self):
        """Return the stored app configuration as a dictionary."""
        raw = self.read_secret(CONFIG_USERNAME)
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except ValueError:
            raise SplunkRestError("The stored configuration is not valid JSON.")

    def write_config(self, base_url, client_id, client_secret):
        """Store the API URL and the service account credentials."""
        self.write_secret(
            CONFIG_USERNAME,
            json.dumps(
                {
                    "base_url": base_url,
                    "client_id": client_id,
                    "client_secret": client_secret,
                }
            ),
        )


class SecretStoreTokenCache:
    """Token cache that keeps the OAuth pair in the Splunk secret store.

    Alert actions run as separate short-lived processes. A shared cache lets
    them re-use one access token for its full 15-minute life, and lets them
    use the refresh-token grant instead of the client secret.
    """

    def __init__(self, rest, log=None):
        self.rest = rest
        self.log = log or (lambda level, message: None)

    def load(self):
        raw = self.rest.read_secret(TOKEN_CACHE_USERNAME)
        if not raw:
            return None
        try:
            return json.loads(raw)
        except ValueError:
            self.log("WARN", "The token cache is not valid JSON. Ignoring it.")
            return None

    def save(self, state):
        self.rest.write_secret(TOKEN_CACHE_USERNAME, json.dumps(state))
