#!/usr/bin/env python3
"""Local development helper. It is not part of the Splunk app.

The script reads the Adversarial API and prints the result as text. The demo
script uses it to show the incidents and the risks that Splunk created.

    python3 dev/api_report.py whoami
    python3 dev/api_report.py sources          incident sources
    python3 dev/api_report.py risk-sources     risk sources, a separate list
    python3 dev/api_report.py latest 5         newest incidents
    python3 dev/api_report.py risks 5          newest risks
    python3 dev/api_report.py show INC-00007       or: show 7
    python3 dev/api_report.py show-risk RSK-00003 or: show-risk 3
    python3 dev/api_report.py count

The script reads ADVERSARIAL_BASE_URL, ADVERSARIAL_CLIENT_ID and
ADVERSARIAL_CLIENT_SECRET from the environment. It uses the client credentials
grant, so it shows what the service account can see.
"""

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT_SECONDS = 30


def fail(message):
    sys.stderr.write("error: %s\n" % message)
    raise SystemExit(1)


def setting(name):
    value = os.environ.get(name, "").strip()
    if not value:
        fail("the environment variable %s is empty" % name)
    return value


def token():
    """Get an access token with the client credentials grant."""
    body = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": setting("ADVERSARIAL_CLIENT_ID"),
        "client_secret": setting("ADVERSARIAL_CLIENT_SECRET"),
    }).encode("utf-8")
    request = urllib.request.Request(
        setting("ADVERSARIAL_BASE_URL") + "/v1/oauth/token",
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as answer:
            return json.loads(answer.read().decode("utf-8"))["access_token"]
    except urllib.error.HTTPError as error:
        fail("the token request failed: HTTP %d %s"
             % (error.code, error.read().decode("utf-8", "replace")[:300]))
    except urllib.error.URLError as error:
        fail("the API is not reachable: %s" % error.reason)


def get(path, access_token):
    request = urllib.request.Request(
        setting("ADVERSARIAL_BASE_URL") + path,
        headers={"Authorization": "Bearer " + access_token},
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as answer:
            return json.loads(answer.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        fail("GET %s failed: HTTP %d %s"
             % (path, error.code, error.read().decode("utf-8", "replace")[:300]))


def records(collection, key, access_token):
    """Read every record of one collection and put the newest first.

    The list endpoints answer with a wrapper for each row, for example
    `{"incident": {...}}` or `{"risk": {...}}`.
    """
    rows = []
    page = 1
    while True:
        answer = get("/v1/%s?page=%d&page_size=100" % (collection, page), access_token)
        results = answer.get("results", [])
        rows.extend(item.get(key, item) for item in results)
        pagination = answer.get("pagination") or {}
        if not results or not pagination.get("has_next"):
            break
        page += 1
    rows.sort(key=lambda item: item.get("created_date", ""), reverse=True)
    return rows


def incidents(access_token):
    return records("incidents", "incident", access_token)


def risks(access_token):
    return records("risks", "risk", access_token)


def person(value):
    if not isinstance(value, dict):
        return "-"
    return value.get("email") or value.get("first_name") or "-"


def command_whoami(access_token, _arguments):
    user = get("/v1/users/me", access_token)
    print("service account : %s" % person(user))
    print("name            : %s" % (user.get("first_name") or "-"))
    print("user id         : %s" % (user.get("id") or "-"))


def print_sources(collection, access_token):
    answer = get("/v1/%s/sources" % collection, access_token)
    values = answer.get("sources", answer if isinstance(answer, list) else [])
    for value in values:
        print(value.get("name") if isinstance(value, dict) else value)


def command_sources(access_token, _arguments):
    print_sources("incidents", access_token)


def command_risk_sources(access_token, _arguments):
    """The risk sources and the incident sources are separate lists."""
    print_sources("risks", access_token)


def command_count(access_token, _arguments):
    print(len(incidents(access_token)))


def command_latest(access_token, arguments):
    limit = int(arguments[0]) if arguments else 5
    rows = incidents(access_token)[:limit]
    if not rows:
        print("no incidents")
        return
    print("%-11s %-21s %-7s %-12s %-8s %s"
          % ("ID", "CREATED (UTC)", "SEV", "STATUS", "SOURCE", "TITLE"))
    for row in rows:
        print("%-11s %-21s %-7s %-12s %-8s %s" % (
            row.get("id", "-"),
            (row.get("created_date") or "")[:19].replace("T", " "),
            row.get("severity", "-"),
            row.get("status", "-"),
            row.get("source", "-"),
            row.get("title", "-")[:48],
        ))


def command_risks(access_token, arguments):
    limit = int(arguments[0]) if arguments else 5
    rows = risks(access_token)[:limit]
    if not rows:
        print("no risks")
        return
    print("%-11s %-21s %-9s %-18s %-26s %s"
          % ("ID", "CREATED (UTC)", "URGENCY", "STATUS", "SOURCE", "TITLE"))
    for row in rows:
        print("%-11s %-21s %-9s %-18s %-26s %s" % (
            row.get("id", "-"),
            (row.get("created_date") or "")[:19].replace("T", " "),
            row.get("urgency") or "-",
            row.get("status", "-"),
            (row.get("source") or "-")[:26],
            row.get("title", "-")[:40],
        ))


def path_id(identifier):
    """Return a record ID for a URL path.

    The API takes the display form, for example INC-00003 or RSK-00003, as
    well as the bare number 3. Both collections read the same forms, so the
    report sends what the caller gives and lets the API report a bad value.
    """
    value = (identifier or "").strip()
    if not value:
        fail("give a record ID")
    return urllib.parse.quote(value, safe="")


def print_description_and_comments(collection, identifier, row, access_token):
    print("description:")
    for line in (row.get("description") or "").splitlines():
        print("    %s" % line)
    comments = get("/v1/%s/%s/comments" % (collection, path_id(identifier)),
                   access_token)
    values = comments.get("comments", [])
    print("comments: %d" % len(values))
    for item in values:
        print("  - [%s] %s" % (person(item.get("user")),
                               (item.get("value") or "").replace("\n", " ")[:200]))


def command_show_risk(access_token, arguments):
    if not arguments:
        fail("give a risk ID, for example RSK-00003 or 3")
    identifier = arguments[0]
    answer = get("/v1/risks/%s" % path_id(identifier), access_token)
    row = answer.get("risk", answer)
    print("id                  : %s" % row.get("id"))
    print("title               : %s" % row.get("title"))
    print("type                : %s" % row.get("type"))
    print("status              : %s" % row.get("status"))
    print("source              : %s" % row.get("source"))
    print("initially reported  : %s" % (row.get("initially_reported_urgency") or "-"))
    # The platform derives the urgency from the likelihood and the impact, and
    # the due date from the urgency. All three stay empty until somebody, or AI
    # Suggest Score, assigns a score.
    print("likelihood          : %s" % (row.get("likelihood") or "-"))
    print("impact              : %s" % (row.get("impact") or "-"))
    print("urgency             : %s" % (row.get("urgency") or "-"))
    print("discovered          : %s" % row.get("discovered_date"))
    print("due                 : %s" % (row.get("due_date") or "-"))
    print("opened by           : %s" % person(row.get("opened_by")))
    print("remediation task    : %s" % (row.get("remediation_task") or "-"))
    print_description_and_comments("risks", identifier, row, access_token)


def command_show(access_token, arguments):
    if not arguments:
        fail("give an incident ID, for example INC-00007 or 7")
    identifier = arguments[0]
    answer = get("/v1/incidents/%s" % path_id(identifier), access_token)
    row = answer.get("incident", answer)
    print("id                : %s" % row.get("id"))
    print("title             : %s" % row.get("title"))
    print("severity          : %s" % row.get("severity"))
    print("status            : %s" % row.get("status"))
    print("source            : %s" % row.get("source"))
    print("detected          : %s" % row.get("detected_date"))
    print("opened by         : %s" % person(row.get("opened_by")))
    print("severity reasoning: %s" % (row.get("severity_reasoning") or "-"))
    print_description_and_comments("incidents", identifier, row, access_token)


COMMANDS = {
    "whoami": command_whoami,
    "sources": command_sources,
    "risk-sources": command_risk_sources,
    "count": command_count,
    "latest": command_latest,
    "risks": command_risks,
    "show": command_show,
    "show-risk": command_show_risk,
}


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        fail("use one of: %s" % ", ".join(sorted(COMMANDS)))
    COMMANDS[sys.argv[1]](token(), sys.argv[2:])


if __name__ == "__main__":
    main()
