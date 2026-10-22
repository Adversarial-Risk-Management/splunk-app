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

Store the secret of another service account. An alert then sends to it when
its `param.client_id` names that client ID:

    $SPLUNK_HOME/bin/splunk cmd python3 configure_credentials.py \\
        --add-client --client-id arm_sa_... --client-secret arm_sk_...

Show the stored settings. The script never prints a secret:

    $SPLUNK_HOME/bin/splunk cmd python3 configure_credentials.py --show

Check the credentials against the API, without creating a record. The check
names the roles of the service account and the alert actions it can run.
`--require` names the actions that must work, and the check fails without
them:

    $SPLUNK_HOME/bin/splunk cmd python3 configure_credentials.py --verify \\
        --require incident,risk,tags

The script reads the Splunk user name and password from the `--splunk-user` and
`--splunk-password` options, or from the SPLUNK_USERNAME and SPLUNK_PASSWORD
environment variables.
"""

import argparse
import getpass
import os
import sys

from adversarial_api import AdversarialClient, ApiError, TransportError
from splunk_rest import LEGACY_TOKEN_CACHE_USERNAME, SplunkRest, SplunkRestError

DEFAULT_MANAGEMENT_URI = "https://localhost:8089"

# What each alert action needs. The permission covers the create request and
# the follow-up comment. `tags` is the `param.tags` setting of either action.
REQUIREMENTS = {
    "incident": ("adversarial_incident", "incidents:write"),
    "risk": ("adversarial_risk", "risks:write"),
    "tags": ("param.tags", "tags:read"),
}


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
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--show", action="store_true", help="Show the stored settings and exit.")
    action.add_argument("--verify", action="store_true",
                        help="Request a token for the default client, or for --client-id, "
                             "and report what it may do.")
    action.add_argument("--add-client", action="store_true",
                        help="Store the secret of another service account, for alerts that "
                             "set param.client_id.")
    action.add_argument("--remove-client", metavar="CLIENT_ID",
                        help="Remove the stored secret and token of one service account.")
    action.add_argument("--clear-token-cache", action="store_true",
                        help="Remove every cached OAuth token pair.")
    parser.add_argument("--require", default="",
                        help="With --verify: a comma-separated list of %s that must work."
                             % ", ".join(sorted(REQUIREMENTS)))
    return parser.parse_args(argv)


def requirements(text):
    """Parse the --require list. Raises ValueError for an unknown name."""
    names = [name.strip().lower() for name in text.split(",") if name.strip()]
    unknown = [name for name in names if name not in REQUIREMENTS]
    if unknown:
        raise ValueError("Unknown --require value: %s. Use %s."
                         % (", ".join(unknown), ", ".join(sorted(REQUIREMENTS))))
    return names


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
    default = config.get("client_id")
    stored = rest.stored_client_ids()
    print("base_url:        %s" % config.get("base_url"))
    print("default client:  %s" % default)
    if "client_secret" in config:
        print("warning:         the secret sits in the old combined entry. Store the "
              "settings again to move it out.")
    print("stored secrets:  %s" % (", ".join(stored) or "(none)"))
    if default and default not in stored and "client_secret" not in config:
        print("warning:         the default client has no stored secret.")
    tokens = [name for name in rest.list_usernames() if name.startswith("token_")]
    print("token caches:    %d" % len(tokens))
    return 0


def verify(rest, options):
    """Exchange a stored secret for a token and report what the account may do."""
    config = rest.read_config()
    base_url = options.base_url or config.get("base_url")
    client_id = options.client_id or config.get("client_id")
    secret = rest.read_client_secret(client_id) if client_id else None
    missing = [name for name, value in (("base_url", base_url), ("client_id", client_id),
                                        ("client_secret", secret)) if not value]
    if missing:
        print("The app is not set up. Missing: %s" % ", ".join(missing), file=sys.stderr)
        return 1

    client = AdversarialClient(
        base_url, client_id, secret,
        log=lambda level, message: print("%s %s" % (level, message)),
    )
    try:
        token = client.access_token(force_new=True)
    except (ApiError, TransportError) as error:
        print("The token request failed: %s" % error, file=sys.stderr)
        return 1

    def get(path):
        return client._request(  # noqa: SLF001 - a check needs one plain GET
            "GET",
            base_url.rstrip("/") + path,
            headers={"Authorization": "Bearer " + token},
        )

    try:
        # `GET /v1/users/me` shows which service account the token belongs to.
        identity = get("/v1/users/me")
        # The effective permissions are the roles of the service account.
        granted = get("/v1/users/me/permissions")
    except (ApiError, TransportError) as error:
        print("The token works, but the identity check failed: %s" % error, file=sys.stderr)
        return 1
    print("The credentials work. The service account is %s (%s), client %s."
          % (identity.get("first_name"), identity.get("email"), client_id))
    print("Roles: %s" % (", ".join(granted.get("roles") or []) or "(none)"))
    return report_permissions(set(granted.get("permissions") or []),
                              requirements(options.require))


def report_permissions(granted, required=()):
    """Print what the service account may do.

    `required` names entries of REQUIREMENTS that must work. Returns 1 when one
    of them is missing. Without `required`, returns 1 only when the account can
    run no alert action.
    """
    for name in sorted(REQUIREMENTS):
        what, permission = REQUIREMENTS[name]
        state = "ready" if permission in granted else "MISSING"
        print("%-21s %-8s (%s)" % (what, state, permission))
    failed = [name for name in required if REQUIREMENTS[name][1] not in granted]
    if failed:
        print("The service account lacks what --require names: %s."
              % ", ".join(failed), file=sys.stderr)
        return 1
    actions = [name for name in ("incident", "risk") if REQUIREMENTS[name][1] in granted]
    if not actions:
        print("The service account can run no alert action. Give it the Incident Editor "
              "or the Risk Editor role.", file=sys.stderr)
        return 1
    return 0


def store(rest, options):
    """Store the default settings or, with --add-client, one more secret."""
    needed = [("--client-id", options.client_id), ("--client-secret", options.client_secret)]
    if not options.add_client:
        needed.insert(0, ("--base-url", options.base_url))
    missing = [name for name, value in needed if not value]
    if missing:
        print("Give a value for: %s" % ", ".join(missing), file=sys.stderr)
        return 2

    rest.write_client_secret(options.client_id, options.client_secret)
    if options.add_client:
        print("The secret of %s is stored. An alert uses it when param.client_id names it."
              % options.client_id)
        return 0
    rest.write_config(options.base_url, options.client_id)
    # Version 1.0 kept one token pair for every service account.
    rest.delete_secret(LEGACY_TOKEN_CACHE_USERNAME)
    print("The settings are stored. Default client ID: %s" % options.client_id)
    return 0


def run(rest, options):
    if options.clear_token_cache:
        print("Removed %d cached token pairs." % rest.clear_token_caches())
        return 0
    if options.remove_client:
        rest.delete_client(options.remove_client)
        print("Removed the secret and the cached token of %s." % options.remove_client)
        return 0
    if options.show:
        return show(rest)
    if options.verify:
        return verify(rest, options)
    return store(rest, options)


def main(argv):
    options = parse_arguments(argv)
    try:
        requirements(options.require)
    except ValueError as error:
        print(error, file=sys.stderr)
        return 2
    try:
        rest = connect(options)
    except SplunkRestError as error:
        print("Could not log in to Splunk: %s" % error, file=sys.stderr)
        return 1
    try:
        return run(rest, options)
    except SplunkRestError as error:
        # The Splunk user may lack the capability to read or write the store.
        print("The Splunk secret store refused the request: %s" % error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
