#!/usr/bin/env python
"""Custom alert action: create a risk in the Adversarial platform.

Use this action when the alert finds a standing condition: hosts without an
endpoint agent, accounts without MFA, a control that no longer works. The
organization remediates the condition over weeks, not minutes. For an event
that needs a responder now, use `adversarial_incident.py` instead.

A posture search therefore aggregates to one row. One row gives one risk for
the whole condition, not one risk for each host.

The action:

1. Reads the API URL and the service account credentials from the Splunk
   secret store.
2. Gets an OAuth access token. It re-uses a cached token, refreshes an expired
   token, or exchanges the client credentials. See `adversarial_api.py`.
3. Creates the risk with `POST /v1/risks`.
4. Adds a comment that links back to the Splunk search results.

Field mapping
-------------
Alert setting             Risk field
------------------------  ---------------------------------------------------
param.title               title
param.description         description, with the alert context after it
param.type                type
param.source              source
param.status              status
param.iru                 initially_reported_urgency
param.likelihood          likelihood, empty for AI Suggest Score
param.impact              impact, empty for AI Suggest Score
param.likelihood_reason   likelihood_reasoning
param.impact_reason       impact_reasoning
param.remediation_task    remediation_task
param.control_statement   control_statement
(the trigger time)        discovered_date

The platform derives the urgency of a risk from the likelihood and the impact,
and then the due date from the urgency. Both stay empty by default, so AI
Suggest Score assigns them. The action does not set the due date, the expected
date or the threat objectives: the platform owns the dates through the SLA, and
AI Suggest Score assigns the threat objectives.

`adversarial_alert.py` holds the code that both actions share, and the exit
codes. To see the log messages of a run, search:

    index=_internal sourcetype=splunkd component=sendmodalert
    action="adversarial_risk"
"""

import adversarial_alert as alert
from adversarial_alert import EXIT_VALIDATION_FAILED, OK

ACTION = "adversarial_risk"

# The severity of a Splunk alert, from savedsearches.conf. The initially
# reported urgency (IRU) holds the raw score of the reporting source, which is
# what a Splunk alert severity is. The action uses this table only when
# `param.iru` is `auto`.
SPLUNK_SEVERITY_TO_URGENCY = {
    1: "Info",      # debug
    2: "Info",      # info
    3: "Low",       # warn
    4: "Medium",    # error
    5: "High",      # severe
    6: "Critical",  # fatal
}

VALID_URGENCIES = ("Critical", "High", "Medium", "Low", "Info")
VALID_LIKELIHOODS = ("Remote", "Unlikely", "Possible", "Probable", "Imminent")
VALID_IMPACTS = ("Very Low", "Low", "Medium", "High", "Severe")
VALID_STATUSES = ("New", "Urgency Proposed", "Remediation", "Closure Proposed", "Closed")
VALID_TYPES = (
    "Code",
    "Configuration",
    "Control Deficiency",
    "Policy",
    "Procedural",
    "Vulnerability",
    "Third-party",
)

# Fields that the action copies from the settings when they hold a value.
OPTIONAL_TEXT = (
    ("type", "type"),
    ("likelihood_reason", "likelihood_reasoning"),
    ("impact_reason", "impact_reasoning"),
    ("remediation_task", "remediation_task"),
    ("control_statement", "control_statement"),
)


def urgency_of(payload):
    """Return the initially reported urgency, or None to leave it empty.

    The IRU is the score that the reporting source gave, so a customer who
    trusts the severity of the Splunk alert can map it with `auto`. AI Suggest
    Score reads the IRU when the title and the description hold too little
    detail.
    """
    return alert.scored_value(payload, "iru", SPLUNK_SEVERITY_TO_URGENCY)


def build_risk(payload):
    """Build the request body for POST /v1/risks."""
    config = payload["configuration"]
    risk = {
        "title": (config.get("title") or "").strip(),
        "description": alert.build_description(payload),
        "status": (config.get("status") or "New").strip(),
        "source": (config.get("source") or "Attack Surface Monitoring").strip(),
        # Splunk found the condition when the alert fired, so the trigger time
        # is the discovery time. The platform counts the SLA from this date.
        "discovered_date": alert.trigger_time(payload),
    }

    # Send a field only when it holds a value. An absent likelihood and impact
    # tell the platform to score the risk.
    for setting, field in OPTIONAL_TEXT:
        value = (config.get(setting) or "").strip()
        if value:
            risk[field] = value
    for setting, field in (("likelihood", "likelihood"), ("impact", "impact")):
        value = (config.get(setting) or "").strip()
        if value:
            risk[field] = value
    urgency = urgency_of(payload)
    if urgency:
        risk["initially_reported_urgency"] = urgency
    return risk


def build_comment(payload, risk):
    """Build the follow-up comment that links back to Splunk."""
    extra = []
    if risk.get("initially_reported_urgency"):
        extra.append("Initially reported urgency: %s"
                     % risk["initially_reported_urgency"])
    if risk.get("likelihood") or risk.get("impact"):
        extra.append("Likelihood: %s. Impact: %s."
                     % (risk.get("likelihood", "empty"), risk.get("impact", "empty")))
    else:
        extra.append("The likelihood and the impact are empty, for AI Suggest Score.")
    return alert.build_comment(payload, ACTION, extra)


def validate(payload):
    """Check the payload. Returns a list of problems, empty when valid."""
    problems = alert.common_problems(payload)
    if problems:
        return problems
    problems += alert.check_choice(payload, "iru", VALID_URGENCIES, allow_auto=True)
    problems += alert.check_choice(payload, "likelihood", VALID_LIKELIHOODS)
    problems += alert.check_choice(payload, "impact", VALID_IMPACTS)
    problems += alert.check_choice(payload, "status", VALID_STATUSES)
    problems += alert.check_choice(payload, "type", VALID_TYPES)
    return problems


def send(payload):
    """Create the risk. Returns an exit code."""
    problems = validate(payload)
    if problems:
        for problem in problems:
            alert.log("FATAL", "Validation error: %s" % problem)
        return EXIT_VALIDATION_FAILED

    client, code = alert.connect(payload)
    if client is None:
        return code

    risk = build_risk(payload)
    created, code = alert.submit(client.create_risk, risk, "risk")
    if created is None:
        return code

    # POST /v1/risks answers with a risk register entry, which holds the risk
    # in a `risk` object.
    record = created.get("risk") or created
    identifier = record.get("id", "unknown")
    # The urgency and the due date stay empty until the risk holds a likelihood
    # and an impact. The log names the score, so an operator can see whether
    # the platform must still assign it.
    alert.log(
        "INFO",
        "Created risk %s with urgency %s. Token source: %s."
        % (identifier, record.get("urgency") or "not yet assigned", client.token_source),
    )

    if alert.wants_comment(payload):
        alert.comment(client.add_risk_comment, identifier, build_comment(payload, risk))

    return OK


def main():
    return alert.run(ACTION, send)


if __name__ == "__main__":
    alert.finish(main())
