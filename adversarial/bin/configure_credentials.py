#!/usr/bin/env python
"""Command-line setup for the Adversarial app.

The app needs the URL of your Adversarial API and the credentials of a
credential service account. The setup page in the app writes those values, and
this script does the same work from a shell. Use it for a scripted install.

Splunk keeps the values encrypted in the secret store.

Examples
--------
Store the settings:

    $SPLUNK_HOME/bin/splunk cmd python3 configure_credentials.py \\
        --base-url https://api.adversarial.com/api \\
        --client-id arm_sa_... --client-secret arm_sk_...

Show the stored settings, with the secret masked:

    $SPLUNK_HOME/bin/splunk cmd python3 configure_credentials.py --show

Check the credentials against the API, without creating an incident:

    $SPLUNK_HOME/bin/splunk cmd python3 configure_credentials.py --verify

The script reads the Splunk user name and password from the `--splunk-user` and
`--splunk-password` options, or from the SPLUNK_USERNAME and SPLUNK_PASSWORD
environment variables.
"""

import argparse
import getpass
import os
import sys

from adversarial_api import AdversarialClient, ApiError, TransportError
from splunk_rest import TOKEN_CACHE_USERNAME, SplunkRest, SplunkRestError

DEFAULT_MANAGEMENT_URI = "https://localhost:8089"


def mask(secret):
    """Show only the first characters of a secret."""
    if not secret:
        return "(not set)"
    return secret[:11] + "..." if len(secret) > 14 else "***"


def parse_arguments(argv):
    parser = argparse.ArgumentParser(
        description="Store or check the Adversarial API settings for this app."
    )
    parser.add_argument("--base-url", default=os.environ.get("ADVERSARIAL_BASE_URL"),
                        help="API base URL, for example https://api.adversarial.com/api")
    parser.add_argument("--client-id", default=os.environ.get("ADVERSARIAL_CLIENT_ID"),
                        help="Service account client ID (arm_sa_...)")
    parser.add_argument("--client-secret", default=os.environ.get("ADVERSARIAL_CLIENT_SECRET"),
                        help="Service account client secret (arm_sk_...)")
    parser.add_argument("--management-uri", default=DEFAULT_MANAGEMENT_URI,
                        help="Splunk management URI (default: %s)" % DEFAULT_MANAGEMENT_URI)
    parser.add_argument("--splunk-user", default=os.environ.get("SPLUNK_USERNAME", "admin"))
    parser.add_argument("--splunk-password", default=os.environ.get("SPLUNK_PASSWORD"))
    parser.add_argument("--show", action="store_true", help="Show the stored settings and exit.")
    parser.add_argument("--verify", action="store_true",
                        help="Request a token with the stored settings and exit.")
    parser.add_argument("--clear-token-cache", action="store_true",
                        help="Remove the cached OAuth token pair.")
    return parser.parse_args(argv)


def connect(options):
    """Log in to the Splunk management API and return a client."""
    password = options.splunk_password
    if not password:
        password = getpass.getpass("Password for Splunk user %s: " % options.splunk_user)
    rest = SplunkRest(options.management_uri)
    rest.login(options.splunk_user, password)
    return rest


def show(rest):
    config = rest.read_config()
    if not config:
        print("The app has no stored settings.")
        return 1
    print("base_url:      %s" % config.get("base_url"))
    print("client_id:     %s" % config.get("client_id"))
    print("client_secret: %s" % mask(config.get("client_secret")))
    cached = rest.read_secret(TOKEN_CACHE_USERNAME)
    print("token cache:   %s" % ("present" if cached else "empty"))
    return 0


def verify(rest):
    """Exchange the stored credentials for a token and read the identity."""
    config = rest.read_config()
    missing = [k for k in ("base_url", "client_id", "client_secret") if not config.get(k)]
    if missing:
        print("The app is not set up. Missing: %s" % ", ".join(missing), file=sys.stderr)
        return 1

    client = AdversarialClient(
        config["base_url"],
        config["client_id"],
        config["client_secret"],
        log=lambda level, message: print("%s %s" % (level, message)),
    )
    try:
        token = client.access_token(force_new=True)
    except (ApiError, TransportError) as error:
        print("The token request failed: %s" % error, file=sys.stderr)
        return 1

    # `GET /v1/users/me` shows which service account the token belongs to.
    identity = client._request(  # noqa: SLF001 - a check needs one plain GET
        "GET",
        config["base_url"].rstrip("/") + "/v1/users/me",
        headers={"Authorization": "Bearer " + token},
    )
    print("The credentials work. The service account is %s (%s)."
          % (identity.get("first_name"), identity.get("email")))
    return 0


def main(argv):
    options = parse_arguments(argv)
    try:
        rest = connect(options)
    except SplunkRestError as error:
        print("Could not log in to Splunk: %s" % error, file=sys.stderr)
        return 1

    if options.clear_token_cache:
        rest.delete_secret(TOKEN_CACHE_USERNAME)
        print("The token cache is empty.")
        return 0

    if options.show:
        return show(rest)

    if options.verify:
        return verify(rest)

    missing = [
        name
        for name, value in (
            ("--base-url", options.base_url),
            ("--client-id", options.client_id),
            ("--client-secret", options.client_secret),
        )
        if not value
    ]
    if missing:
        print("Give a value for: %s" % ", ".join(missing), file=sys.stderr)
        return 2

    rest.write_config(options.base_url, options.client_id, options.client_secret)
    # New credentials make an old token pair useless, so clear the cache.
    rest.delete_secret(TOKEN_CACHE_USERNAME)
    print("The settings are stored. Client ID: %s" % options.client_id)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
