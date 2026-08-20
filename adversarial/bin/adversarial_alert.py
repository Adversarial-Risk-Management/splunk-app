"""Shared code for the Adversarial alert actions.

Two alert actions use this module:

    adversarial_incident.py     creates an incident
    adversarial_risk.py         creates a risk

Splunk starts an alert action with `--execute` and writes one JSON payload to
standard input. The payload holds the alert settings, the first search result,
and a session key for the Splunk management API. This module reads the payload,
builds the description, and calls the API. Each action script maps the payload
to the fields of one record type.

Which action to use
-------------------
An incident is an event: something happened, and a responder must act now. A
risk is a standing condition: a weakness that the organization must remediate
over time. A detection search creates an incident. A posture search creates a
risk.

One alert can use both actions. Splunk starts each action one time for each
alert firing, and the payload then holds the first result of the search. A
search that must report more than one row therefore aggregates the rows, or
sorts them so that the first row is the row that matters.

Scoring
-------
The platform scores a record with the AI Suggest Score feature. It reads the
title, the description and the comments, so the action always sends a full
description. The score fields stay empty by default:

    incident    severity                see param.severity
    risk        likelihood and impact   see param.likelihood, param.impact

A customer who has a useful value at the source can send it. See the field
guides:

    https://docs.adversarial.com/guides/incidents/incident-fields/
    https://docs.adversarial.com/guides/risks/risk-fields/

Exit codes
----------
0  The record was created.
2  The alert settings are not valid.
3  Authentication failed. Check the client ID and the client secret.
4  The API rejected the request. Check the source name.
5  The API was not reachable.
6  An unexpected error occurred.
"""

import datetime
import fnmatch
import json
import re
import sys
import traceback

from adversarial_api import AdversarialClient, ApiError, TransportError
from splunk_rest import SecretStoreTokenCache, SplunkRest, SplunkRestError

OK = 0
EXIT_VALIDATION_FAILED = 2
EXIT_AUTH_FAILED = 3
EXIT_API_REJECTED = 4
EXIT_NOT_REACHABLE = 5
EXIT_UNEXPECTED = 6

# Keep the description inside a size that reads well in the platform UI.
MAX_DESCRIPTION_CHARS = 6000

# Show at most this many values of a multi-value search field. A `values()`
# result can hold hundreds of names, which would fill the description.
MAX_FIELD_VALUES = 20

# The settings that the app needs before it can call the API.
REQUIRED_SETTINGS = ("base_url", "client_id", "client_secret")


def log(level, message):
    """Write one message to standard error, which Splunk collects."""
    sys.stderr.write("%s %s\n" % (level, message))
    sys.stderr.flush()


# ---------------------------------------------------------------- payload ----


def field_value(value):
    """Return one string for a search field.

    A multi-value field arrives as a list, for example from `values()` in the
    search. The function joins the values, because the description must name
    every affected asset.
    """
    if not isinstance(value, list):
        return value
    if len(value) <= MAX_FIELD_VALUES:
        return ", ".join(str(item) for item in value)
    shown = ", ".join(str(item) for item in value[:MAX_FIELD_VALUES])
    return "%s, and %d more" % (shown, len(value) - MAX_FIELD_VALUES)


def selected_fields(payload):
    """Return the result fields that the "Fields" setting selects.

    The setting is a comma-separated list of field names. A name can hold a
    wildcard, for example `src_*`. The order follows the setting.
    """
    result = payload.get("result") or {}
    setting = (payload["configuration"].get("fields") or "").strip()
    patterns = [p for p in re.split(r"\s*,\s*", setting) if p]
    chosen = []
    seen = set()
    for pattern in patterns:
        for name in result:
            if name not in seen and fnmatch.fnmatch(name, pattern):
                seen.add(name)
                chosen.append((name, field_value(result[name])))
    return chosen


def trigger_time(payload):
    """Return the alert trigger time as an RFC 3339 timestamp in UTC."""
    raw = payload["configuration"].get("info_trigger_time")
    try:
        moment = datetime.datetime.fromtimestamp(float(raw), datetime.timezone.utc)
    except (TypeError, ValueError):
        moment = datetime.datetime.now(datetime.timezone.utc)
    return moment.isoformat().replace("+00:00", "Z")


def splunk_severity(payload):
    """Return the severity level of the Splunk alert, or None.

    Splunk supplies the level through the `$alert.severity$` token: 1 debug,
    2 info, 3 warn, 4 error, 5 severe, 6 fatal. An ad-hoc `sendalert` search
    has no alert severity, so the token stays as it is and the function
    returns None.
    """
    try:
        return int(float(payload["configuration"].get("info_severity")))
    except (TypeError, ValueError):
        return None


def scored_value(payload, setting, from_alert_severity):
    """Return the value of a score setting, or None to leave the field empty.

    The setting takes three kinds of value:

    empty   The field stays empty, and AI Suggest Score assigns it.
    auto    The severity of the Splunk alert maps through
            `from_alert_severity`. An ad-hoc search has no alert severity, so
            the field stays empty.
    a name  The value goes to the API as it is, for example `SEV-2`.
    """
    value = (payload["configuration"].get(setting) or "").strip()
    if not value:
        return None
    if value.lower() != "auto":
        return value
    return from_alert_severity.get(splunk_severity(payload))


def build_description(payload):
    """Build the description from the alert settings and the first result.

    The description is the main input of AI Suggest Score, so it always holds
    the alert context and the fields that the "Fields" setting selects.
    """
    config = payload["configuration"]
    parts = []

    written = (config.get("description") or "").strip()
    if written:
        parts.append(written)

    context = ["Reported by Splunk."]
    if payload.get("search_name"):
        context.append("Search: %s" % payload["search_name"])
    else:
        context.append("Search: ad-hoc search")
    context.append("Trigger time: %s" % trigger_time(payload))
    if payload.get("server_host"):
        context.append("Splunk host: %s" % payload["server_host"])
    if payload.get("sid"):
        context.append("Search ID: %s" % payload["sid"])
    if payload.get("results_link"):
        context.append("Results: %s" % payload["results_link"])
    parts.append("\n".join(context))

    fields = selected_fields(payload)
    if fields:
        lines = ["First result:"]
        lines += ["- %s: %s" % (name, value) for name, value in fields]
        parts.append("\n".join(lines))

    description = "\n\n".join(parts)
    if len(description) > MAX_DESCRIPTION_CHARS:
        description = description[:MAX_DESCRIPTION_CHARS] + "\n[truncated]"
    return description


def build_comment(payload, action, extra=None):
    """Build the follow-up comment that links back to Splunk.

    The platform reads the comments of a record in AI Suggest Score, so the
    comment holds the alert name as well as the link.
    """
    lines = ["Created by the Splunk alert action `%s`." % action]
    if payload.get("search_name"):
        lines.append("Alert: %s" % payload["search_name"])
    if payload.get("results_link"):
        lines.append("Open the search results: %s" % payload["results_link"])
    lines += extra or []
    return "\n".join(lines)


def wants_comment(payload):
    """Whether the "Splunk link" setting asks for a comment."""
    return (payload["configuration"].get("add_comment") or "1") == "1"


# ------------------------------------------------------------ validation ----


def common_problems(payload):
    """Check the settings that both actions share.

    Returns a list of problems, empty when the settings are valid.
    """
    if "configuration" not in payload:
        return ["The payload has no `configuration` object."]
    if not (payload["configuration"].get("title") or "").strip():
        return ["The `title` setting is empty."]
    return []


def check_choice(payload, setting, valid, allow_auto=False):
    """Check one setting against a list of values. Returns a list of problems.

    An empty setting is always valid, because it leaves the field empty.
    """
    value = (payload["configuration"].get(setting) or "").strip()
    if not value:
        return []
    if allow_auto and value.lower() == "auto":
        return []
    if value in valid:
        return []
    names = list(valid)
    if allow_auto:
        names.insert(0, "auto")
    return ["The `%s` setting is `%s`. Use one of: %s." % (setting, value, ", ".join(names))]


# ------------------------------------------------------------ connection ----


def load_settings(payload):
    """Read the API URL and the credentials.

    The Splunk secret store holds the values that the setup page saved. The
    alert action can override each value, which lets one Splunk instance send
    records to more than one organization.
    """
    config = payload["configuration"]
    stored = {}
    rest = None

    session_key = payload.get("session_key")
    server_uri = payload.get("server_uri")
    if session_key and server_uri:
        rest = SplunkRest(server_uri, session_key)
        try:
            stored = rest.read_config()
        except SplunkRestError as error:
            # The alert owner may not hold the capability to read the store.
            # The alert still works if the settings carry the credentials.
            log("WARN", "Could not read the app configuration: %s" % error)

    settings = {
        "base_url": (config.get("base_url") or "").strip() or stored.get("base_url", ""),
        "client_id": (config.get("client_id") or "").strip() or stored.get("client_id", ""),
        "client_secret": (config.get("client_secret") or "").strip()
        or stored.get("client_secret", ""),
    }
    return settings, rest


def connect(payload):
    """Build the API client. Returns (client, exit_code).

    `client` is None when the app has no credentials. The token cache lives in
    the Splunk secret store, so separate alert runs share one access token.
    """
    settings, rest = load_settings(payload)
    missing = [name for name in REQUIRED_SETTINGS if not settings[name]]
    if missing:
        log(
            "FATAL",
            "The app is not set up. Missing: %s. Open the app and use the setup "
            "page, or run bin/configure_credentials.py." % ", ".join(missing),
        )
        return None, EXIT_VALIDATION_FAILED

    cache = SecretStoreTokenCache(rest, log) if rest else None
    client = AdversarialClient(
        settings["base_url"],
        settings["client_id"],
        settings["client_secret"],
        cache=cache,
        log=log,
    )
    return client, OK


# ---------------------------------------------------------------- sending ----


def submit(create, record, kind):
    """Send one record to the API. Returns (created, exit_code).

    `create` is the client method for the record type, for example
    `client.create_incident`. `created` is None when the call failed.
    """
    log("INFO", "Creating the %s: %s" % (kind, json.dumps(record)[:500]))
    try:
        return create(record), OK
    except ApiError as error:
        if error.status in (401, 403):
            log("FATAL", "The API refused the credentials: %s" % error)
            return None, EXIT_AUTH_FAILED
        log("FATAL", "The API rejected the %s: %s" % (kind, error))
        return None, EXIT_API_REJECTED
    except TransportError as error:
        log("FATAL", "The API was not reachable: %s" % error)
        return None, EXIT_NOT_REACHABLE


def comment(add, identifier, text):
    """Add the follow-up comment.

    The record exists at this point, so a comment failure is not fatal. The
    action writes a warning and reports success.
    """
    try:
        add(identifier, text)
        log("INFO", "Added the Splunk link as a comment on %s" % identifier)
    except (ApiError, TransportError) as error:
        log("WARN", "Could not add the comment to %s: %s" % (identifier, error))


def run(action, send):
    """Read the payload from standard input and call `send`.

    Returns the exit code of the action. Splunk writes the code to the log.
    """
    log("INFO", "Running the %s alert action" % action)
    if len(sys.argv) < 2 or sys.argv[1] != "--execute":
        log("FATAL", "Run this script with --execute. Splunk does that for you.")
        return EXIT_UNEXPECTED
    try:
        payload = json.loads(sys.stdin.read())
    except ValueError as error:
        log("FATAL", "The payload on standard input is not valid JSON: %s" % error)
        return EXIT_VALIDATION_FAILED

    try:
        return send(payload)
    except Exception:  # noqa: BLE001 - the exit code must stay predictable
        log("FATAL", "Unexpected error:")
        log("FATAL", traceback.format_exc())
        return EXIT_UNEXPECTED


def finish(code):
    """Write the last log line and stop with the exit code."""
    if code == OK:
        log("INFO", "The alert action finished")
    else:
        log("ERROR", "The alert action failed with exit code %d" % code)
    sys.exit(code)
