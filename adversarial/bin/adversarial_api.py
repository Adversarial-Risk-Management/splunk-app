"""Client for the Adversarial REST API.

The client creates two kinds of record, `POST /v1/incidents` and
`POST /v1/risks`, and adds a comment to either one. It uses the OAuth 2.1
client-credentials grant of a credential service account. See
https://docs.adversarial.com/guides/service-accounts/api-access/

Token lifecycle
---------------
An access token is valid for 15 minutes. A refresh token is valid for 7 days.
The client keeps the pair in a cache so that many alerts share one token:

1. If the cached access token has more than 60 seconds left, use it.
2. If not, and a refresh token is in the cache, use the `refresh_token` grant.
   A service account is a confidential client, so this grant also sends the
   `client_id` and the `client_secret`.
3. If there is no refresh token, or the refresh fails, use the
   `client_credentials` grant.

The module uses only the Python standard library. You do not need to install
packages into Splunk.
"""

import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

# Refresh this many seconds before the access token expires. A proactive
# refresh is better than a retry after a 401.
REFRESH_MARGIN_SECONDS = 60

# Timeout for every HTTP request, in seconds. An alert action must not block a
# Splunk search process for a long time.
HTTP_TIMEOUT_SECONDS = 30


class ApiError(Exception):
    """The API returned a status code that the client cannot use."""

    def __init__(self, status, body, url):
        super().__init__("HTTP %s from %s: %s" % (status, url, body[:400]))
        self.status = status
        self.body = body
        self.url = url


class TransportError(Exception):
    """The request did not reach the API (DNS, TLS, connection, timeout)."""


class MemoryTokenCache:
    """Token cache that holds one token pair for the life of the process.

    `SecretStoreTokenCache` in `splunk_rest.py` keeps the pair in the Splunk
    secret store instead, so that separate alert runs share one token.
    """

    def __init__(self):
        self._state = None

    def load(self):
        return self._state

    def save(self, state):
        self._state = state


class AdversarialClient:
    """Minimal Adversarial API client with an OAuth token cache."""

    def __init__(self, base_url, client_id, client_secret, cache=None, log=None):
        # `base_url` includes the `/api` path element, for example
        # `https://api.adversarial.com/api`.
        self.base_url = base_url.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.cache = cache or MemoryTokenCache()
        self.log = log or (lambda level, message: None)
        # Records how the last token was obtained: "cache", "refresh_token" or
        # "client_credentials". The alert action writes this to the log.
        self.token_source = None

    # -- HTTP ------------------------------------------------------------

    def _request(self, method, url, body=None, headers=None):
        """Send one HTTP request and return the decoded JSON body."""
        request = urllib.request.Request(url, data=body, method=method)
        for name, value in (headers or {}).items():
            request.add_header(name, value)
        try:
            # The API uses a public certificate, so the default certificate
            # store applies. The client does not disable verification.
            with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
                text = response.read().decode("utf-8")
                return json.loads(text) if text else {}
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", "replace")
            raise ApiError(error.code, detail, url) from error
        except (urllib.error.URLError, ssl.SSLError, OSError) as error:
            raise TransportError("%s %s failed: %s" % (method, url, error)) from error

    def _post_form(self, path, fields):
        body = urllib.parse.urlencode(fields).encode("utf-8")
        return self._request(
            "POST",
            self.base_url + path,
            body=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    def _post_json(self, path, payload, token):
        body = json.dumps(payload).encode("utf-8")
        return self._request(
            "POST",
            self.base_url + path,
            body=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer " + token,
            },
        )

    # -- Tokens ----------------------------------------------------------

    def _store_pair(self, pair):
        """Put a token response into the cache with an absolute expiry time."""
        state = {
            "access_token": pair.get("access_token"),
            "refresh_token": pair.get("refresh_token"),
            "expires_at": time.time() + float(pair.get("expires_in", 900)),
            "scope": pair.get("scope"),
        }
        try:
            self.cache.save(state)
        except Exception as error:  # noqa: BLE001 - the cache is optional
            # A cache write failure must not stop the record from being
            # created. The next run then requests a new token.
            self.log("WARN", "Could not save the token cache: %s" % error)
        return state

    def _grant(self, fields):
        return self._post_form("/v1/oauth/token", fields)

    def access_token(self, force_new=False):
        """Return a usable access token, from the cache if possible."""
        cached = None
        if not force_new:
            try:
                cached = self.cache.load()
            except Exception as error:  # noqa: BLE001 - the cache is optional
                self.log("WARN", "Could not read the token cache: %s" % error)

        if cached and cached.get("access_token"):
            remaining = cached.get("expires_at", 0) - time.time()
            if remaining > REFRESH_MARGIN_SECONDS:
                self.token_source = "cache"
                self.log("INFO", "Using the cached access token, %d s left" % remaining)
                return cached["access_token"]

            if cached.get("refresh_token"):
                # Step 2: exchange the refresh token. A confidential client
                # must send its credentials on every token request.
                try:
                    pair = self._grant(
                        {
                            "grant_type": "refresh_token",
                            "refresh_token": cached["refresh_token"],
                            "client_id": self.client_id,
                            "client_secret": self.client_secret,
                        }
                    )
                    self.token_source = "refresh_token"
                    self.log("INFO", "Refreshed the access token with the refresh_token grant")
                    return self._store_pair(pair)["access_token"]
                except (ApiError, TransportError) as error:
                    # A refresh token expires after 7 days, and a secret reset
                    # makes it invalid at once. Both cases fall back to step 3.
                    self.log("WARN", "The refresh_token grant failed: %s" % error)

        # Step 3: full client-credentials exchange.
        pair = self._grant(
            {
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            }
        )
        self.token_source = "client_credentials"
        self.log("INFO", "Obtained a new access token with the client_credentials grant")
        return self._store_pair(pair)["access_token"]

    # -- Endpoints -------------------------------------------------------

    def _authenticated_post(self, path, payload):
        """POST as the service account, with one retry after a 401.

        A cached token can expire between the check and the call, or an
        administrator can disable and enable the service account. One retry
        with a new token keeps a single alert from failing for that reason.
        """
        token = self.access_token()
        try:
            return self._post_json(path, payload, token)
        except ApiError as error:
            if error.status != 401:
                raise
            self.log("WARN", "The API rejected the token. Requesting a new token.")
            token = self.access_token(force_new=True)
            return self._post_json(path, payload, token)

    def create_incident(self, incident):
        """Create an incident. Returns the new incident, including its ID."""
        return self._authenticated_post("/v1/incidents", incident)

    def create_risk(self, risk):
        """Create a risk. Returns a risk register entry.

        The answer holds the new risk in a `risk` object, together with the
        urgency and the due date that the platform derived from the score.
        """
        return self._authenticated_post("/v1/risks", risk)

    def add_incident_comment(self, incident_id, text):
        """Add a comment to an incident."""
        return self._add_comment("incidents", incident_id, text)

    def add_risk_comment(self, risk_id, text):
        """Add a comment to a risk."""
        return self._add_comment("risks", risk_id, text)

    def _add_comment(self, collection, identifier, text):
        """Add a comment. Both record types use the same request body."""
        path = "/v1/%s/%s/comments" % (collection, urllib.parse.quote(str(identifier)))
        return self._authenticated_post(path, {"value": text})
