#!/usr/bin/env python
"""Custom alert action: create an incident in the Adversarial platform.

Use this action when the alert detects an event: an intrusion attempt, a
policy violation, malware on a host. A responder must act now. For a standing
weakness, use `adversarial_risk.py` instead.

The action:

1. Reads the API URL and the service account credentials from the Splunk
   secret store.
2. Gets an OAuth access token. It re-uses a cached token, refreshes an expired
   token, or exchanges the client credentials. See `adversarial_api.py`.
3. Creates the incident with `POST /v1/incidents`.
4. Adds a comment that links back to the Splunk search results.

Field mapping
-------------
Alert setting          Incident field
---------------------  ------------------------------------------------------
param.title            title
param.description      description, with the alert context after it
param.severity         severity, empty for AI Suggest Score
param.severity_reason  severity_reasoning
param.status           status
param.source           source
(the trigger time)     detected_date

`adversarial_alert.py` holds the code that both actions share, and the exit
codes. To see the log messages of a run, search:

    index=_internal sourcetype=splunkd component=sendmodalert
    action="adversarial_incident"
"""

import adversarial_alert as alert
from adversarial_alert import EXIT_VALIDATION_FAILED, OK

ACTION = "adversarial_incident"

# The severity of a Splunk alert, from savedsearches.conf. Adversarial severity
# runs from SEV-5 (informational) to SEV-1 (critical). The action uses this
# table only when `param.severity` is `auto`.
SPLUNK_SEVERITY_TO_SEVERITY = {
    1: "SEV-5",  # debug
    2: "SEV-5",  # info
    3: "SEV-4",  # warn
    4: "SEV-3",  # error
    5: "SEV-2",  # severe
    6: "SEV-1",  # fatal
}

VALID_SEVERITIES = ("SEV-1", "SEV-2", "SEV-3", "SEV-4", "SEV-5")
VALID_STATUSES = ("New", "In Progress", "Review", "Closed")


def severity_of(payload):
    """Return the severity of the incident, or None to leave it empty.

    An empty severity is the default. The platform then assigns the severity
    with AI Suggest Score, which reads the title, the description and the
    comments. Set `param.severity` to `auto` to map the Splunk alert severity,
    or to a value such as `SEV-2` to force one.
    """
    return alert.scored_value(payload, "severity", SPLUNK_SEVERITY_TO_SEVERITY)


def build_incident(payload):
    """Build the request body for POST /v1/incidents."""
    config = payload["configuration"]
    incident = {
        "title": (config.get("title") or "").strip(),
        "description": alert.build_description(payload),
        "status": (config.get("status") or "New").strip(),
        "source": (config.get("source") or "SIEM").strip(),
        # The alert fired when Splunk detected the condition, so the trigger
        # time is the detection time.
        "detected_date": alert.trigger_time(payload),
    }

    # Send a field only when it holds a value. An absent severity tells the
    # platform to score the incident.
    severity = severity_of(payload)
    if severity:
        incident["severity"] = severity
    reasoning = (config.get("severity_reasoning") or "").strip()
    if reasoning:
        incident["severity_reasoning"] = reasoning
    return incident


def build_comment(payload, incident):
    """Build the follow-up comment that links back to Splunk."""
    extra = []
    if incident.get("severity"):
        extra.append("Severity from Splunk: %s" % incident["severity"])
    else:
        extra.append("The severity is empty, for AI Suggest Score.")
    return alert.build_comment(payload, ACTION, extra)


def validate(payload):
    """Check the payload. Returns a list of problems, empty when valid."""
    problems = alert.common_problems(payload)
    if problems:
        return problems
    problems += alert.check_choice(payload, "severity", VALID_SEVERITIES, allow_auto=True)
    problems += alert.check_choice(payload, "status", VALID_STATUSES)
    return problems


def send(payload):
    """Create the incident. Returns an exit code."""
    problems = validate(payload)
    if problems:
        for problem in problems:
            alert.log("FATAL", "Validation error: %s" % problem)
        return EXIT_VALIDATION_FAILED

    client, code = alert.connect(payload)
    if client is None:
        return code

    incident = build_incident(payload)
    created, code = alert.submit(client.create_incident, incident, "incident")
    if created is None:
        return code

    identifier = created.get("id", "unknown")
    alert.log(
        "INFO",
        "Created incident %s with severity %s. Token source: %s."
        % (identifier, created.get("severity"), client.token_source),
    )

    if alert.wants_comment(payload):
        alert.comment(client.add_incident_comment, identifier, build_comment(payload, incident))

    return OK


def main():
    return alert.run(ACTION, send)


if __name__ == "__main__":
    alert.finish(main())
