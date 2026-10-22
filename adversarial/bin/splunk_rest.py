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

# The app owns one realm in the secret store. These entries live in it:
#
#   config               the API URL and the default client ID, as JSON
#   secret_<client ID>   the client secret of one service account
#   token_<client ID>    the cached OAuth token pair of one service account
#
# The setup page reads only `config`, so the client secret never reaches the
# browser. Each service account has its own secret and its own token cache, so
# an alert that overrides the client ID uses the right secret and the right
# token.
#
# Keep colons out of realm and user names. Splunk builds the entry name as
# "<realm>:<user>:" and a colon inside either part needs an escape. A client ID
# holds only letters, digits and underscores.
SECRET_REALM = "adversarial"
CONFIG_USERNAME = "config"
SECRET_PREFIX = "secret_"
TOKEN_PREFIX = "token_"
# Version 1.0 of the app kept one token pair for every service account here.
LEGACY_TOKEN_CACHE_USERNAME = "token_cache"


def secret_username(client_id):
    return SECRET_PREFIX + client_id


def token_username(client_id):
    return TOKEN_PREFIX + client_id

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

    def list_usernames(self):
        """Return the user names of every entry in the app realm."""
        result = self._call("GET", self._passwords_path() + "?count=0")
        names = []
        for entry in result.get("entry") or []:
            content = entry.get("content") or {}
            if content.get("realm") == SECRET_REALM and content.get("username"):
                names.append(content["username"])
        return sorted(names)

    # -- App configuration ------------------------------------------------

    def read_config(self):
        """Return the stored API URL and default client ID as a dictionary.

        Version 1.0 of the app also kept the client secret in this entry. The
        method still returns it, so an install that has not saved its settings
        again keeps working.
        """
        raw = self.read_secret(CONFIG_USERNAME)
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except ValueError:
            raise SplunkRestError("The stored configuration is not valid JSON.")

    def write_config(self, base_url, client_id):
        """Store the API URL and the default client ID, without a secret."""
        self.write_secret(
            CONFIG_USERNAME, json.dumps({"base_url": base_url, "client_id": client_id})
        )

    def read_client_secret(self, client_id):
        """Return the stored secret of one service account, or None."""
        secret = self.read_secret(secret_username(client_id))
        if secret:
            return secret
        # Version 1.0 kept the secret of the default account in `config`.
        legacy = self.read_config()
        if legacy.get("client_id") == client_id:
            return legacy.get("client_secret") or None
        return None

    def write_client_secret(self, client_id, client_secret):
        """Store the secret of one service account and drop its cached token.

        A new secret can belong to a reset service account, so the old token
        pair must not stay in use.
        """
        self.write_secret(secret_username(client_id), client_secret)
        self.delete_secret(token_username(client_id))

    def delete_client(self, client_id):
        """Remove the secret and the cached token of one service account."""
        self.delete_secret(secret_username(client_id))
        self.delete_secret(token_username(client_id))

    def stored_client_ids(self):
        """Return the client IDs that have a stored secret."""
        return [
            name[len(SECRET_PREFIX):]
            for name in self.list_usernames()
            if name.startswith(SECRET_PREFIX)
        ]

    def clear_token_caches(self):
        """Remove every cached token pair. Returns the number removed."""
        names = [
            name
            for name in self.list_usernames()
            if name.startswith(TOKEN_PREFIX) or name == LEGACY_TOKEN_CACHE_USERNAME
        ]
        for name in names:
            self.delete_secret(name)
        return len(names)


class SecretStoreTokenCache:
    """Token cache that keeps the OAuth pair in the Splunk secret store.

    Alert actions run as separate short-lived processes. A shared cache lets
    them re-use one access token for its full 15-minute life, and lets them
    use the refresh-token grant instead of the client secret. Each service
    account has its own entry.
    """

    def __init__(self, rest, client_id, log=None):
        self.rest = rest
        self.username = token_username(client_id)
        self.log = log or (lambda level, message: None)

    def load(self):
        raw = self.rest.read_secret(self.username)
        if not raw:
            return None
        try:
            return json.loads(raw)
        except ValueError:
            self.log("WARN", "The token cache is not valid JSON. Ignoring it.")
            return None

    def save(self, state):
        self.rest.write_secret(self.username, json.dumps(state))
