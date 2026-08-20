# Adversarial for Splunk

This Splunk app adds two custom alert actions. An alert action creates a record
in the Adversarial platform when a Splunk alert triggers.

| Alert action | Record |
| --- | --- |
| Create Adversarial incident | Incident |
| Create Adversarial risk | Risk |

The app is an example. Read the code and change it for your own environment.

## What the app does

1. A Splunk alert triggers.
2. Splunk starts the alert action and sends the alert data to it.
3. The alert action gets an OAuth access token for your credential service
   account.
4. The alert action creates an incident or a risk with the fields of the alert.
5. The alert action adds a comment. The comment holds a link to the Splunk
   search results.

## Which action to use

The two record types need a different search.

An incident is one event. A detection search finds the event, for example a
host with too many failed logins.

A risk is one condition. A posture search aggregates the rows into one row,
because the whole condition is one risk.

## One alert firing, one record

Splunk starts a custom alert action one time for each alert firing, and it
sends the first search result to it. It does not start the action one time for
each result. Write the search for that behaviour:

- Aggregate the rows if the whole result set is one record. A `stats` command
  with `values()` gives one row that names every asset.
- Sort the rows if the search keeps more than one row. The first row becomes
  the record, so `| sort - failed_logins` reports the worst host.
- Name the fields of that row in the **Fields** setting. The description then
  holds the values.

The comment holds a link to the search results, so a person reaches every row
from the record.

## Scoring

| Record | Score fields |
| --- | --- |
| Incident | Severity |
| Risk | Likelihood, Impact |

Set a score field only when the alert holds a value that you trust more than
the platform. A brute force detection is an example: the number of failed
logins is a reliable signal, so the example alert maps the Splunk alert
severity.

A risk holds one more field, **Initially reported urgency**. It is the raw
score of the reporting source.
 
The value `auto` maps the severity of the Splunk alert.

| Splunk alert severity | Incident severity | Risk initially reported urgency |
| --- | --- | --- |
| 1 (Debug) | SEV-5 | Info |
| 2 (Info) | SEV-5 | Info |
| 3 (Warning) | SEV-4 | Low |
| 4 (Error) | SEV-3 | Medium |
| 5 (Severe) | SEV-2 | High |
| 6 (Fatal) | SEV-1 | Critical |

The platform derives the urgency of a risk from the likelihood and the impact,
and the due date from the urgency. The urgency and the due date therefore stay
empty until the risk holds a likelihood and an impact.

The default view of the Risk Register filters on the urgency. A new risk with
no score therefore does not show in that view. Clear the filter, or use a view
with no urgency filter, to see the risks that need a score.

## Demo

`DEMO.md` holds the steps for a demo on a workstation, and a command line demo
script with scenarios for each part of the feature.

## What you need

- Splunk Enterprise 9.0 or later.
- A credential service account in your Adversarial organization. Give it the
  roles that it needs:
  - **Incident Editor** to create incidents.
  - **Risk Editor** to create risks.
  - Both roles, or **Editor**, to use both actions.
- Network access from the Splunk server to your Adversarial API.

The app uses only the Python standard library. You do not install packages.

## Install the app

The directory `adversarial/` in this repository is the app. Copy that one
directory into Splunk. It needs no build step, and it holds no dependency
outside the Python standard library.

**Copy the directory**

    cp -r adversarial $SPLUNK_HOME/etc/apps/
    $SPLUNK_HOME/bin/splunk restart

**Archive, for Splunk Web**

To make an archive for **Apps > Manage Apps > Install app from file**, run:

    dev/package.sh

The script writes `dist/adversarial.tar.gz`. The archive holds one top-level
directory, `adversarial`, which is what Splunk expects.

    tar -xzf dist/adversarial.tar.gz -C $SPLUNK_HOME/etc/apps/
    $SPLUNK_HOME/bin/splunk restart

The rest of this repository holds the tests, the documents and the demo
scripts. Splunk does not need them, and they stay out of the archive.

## Set up the credentials

Use the setup page or the command line. Splunk keeps the values encrypted in
the secret store. The client secret is never written to a configuration file.
Both actions read the same credentials.

**Setup page**

1. Open the **Adversarial** app.
2. Select **Setup**.
3. Type the API base URL, the client ID and the client secret.
4. Select **Save**.

**Command line**

    cd $SPLUNK_HOME/etc/apps/adversarial/bin
    $SPLUNK_HOME/bin/splunk cmd python3 configure_credentials.py \
        --base-url https://api.adversarial.com/api \
        --client-id arm_sa_... \
        --client-secret arm_sk_...

The script writes to the Splunk secret store, so it must sign in to Splunk. It
asks for the password of the `admin` user. To give the credentials in the
command, use `--splunk-user` and `--splunk-password`, or set `SPLUNK_USERNAME`
and `SPLUNK_PASSWORD` in the environment.

To check the credentials, use the `--verify` option. The check gets a token and
reads the service account identity. It does not create a record.

    $SPLUNK_HOME/bin/splunk cmd python3 configure_credentials.py --verify

## Add an alert action to an alert

1. Open a saved alert, or create one.
2. In **Trigger Actions**, select **Add Actions**.
3. Select **Create Adversarial incident** or **Create Adversarial risk**.
4. Complete the form.

One alert can hold both actions. Splunk starts each action one time for each
alert firing.

Splunk replaces a `$...$` token with a value from the alert. For example,
`$name$` becomes the name of the alert, and `$result.dest$` becomes the `dest`
field of the first search result.

**Create Adversarial incident**

| Field | Purpose |
| --- | --- |
| Title | The incident title. Default: `Splunk alert: $name$` |
| Description | Text at the start of the incident description |
| Severity | `auto`, or one of SEV-1 to SEV-5 |
| Severity reason | Why the severity is correct |
| Status | New, In Progress or Review |
| Source | The incident source. See "Source names" after the tables. |
| Fields | Field names from the first search result. Use a comma between names. A name can hold a wildcard, for example `src_*`. |
| Splunk link | Add a comment with a link to the search results |

**Create Adversarial risk**

| Field | Purpose |
| --- | --- |
| Title | The risk title. Default: `Splunk alert: $name$` |
| Description | Text at the start of the risk description |
| Type | Code, Configuration, Control Deficiency, Policy, Procedural, Vulnerability or Third-party |
| Source | The risk source. See "Source names" after the tables. |
| Status | New, Urgency Proposed or Remediation |
| Initially reported urgency | Empty, `auto`, or one of Critical, High, Medium, Low, Info |
| Likelihood | One of Remote, Unlikely, Possible, Probable, Imminent |
| Impact | One of Very Low, Low, Medium, High, Severe |
| Likelihood reason | Why the likelihood is correct |
| Impact reason | Why the impact is correct |
| Remediation task | What a person must do to close the risk |
| Control statement | The control that must hold |
| Fields | Field names from the first search result. Use a comma between names. A name can hold a wildcard, for example `src_*`. |
| Splunk link | Add a comment with a link to the search results |

The risk action does not send a due date, an expected date or a threat
objective. The platform owns the due date, and a threat objective needs a
person who knows the threat profile of the organization.

**Source names**

The source must be one of the sources of your organization. The two record
types hold two separate lists. To read them, open the Adversarial platform and
go to **Settings > Incidents** or **Settings > Risks**. A source name that the
platform does not hold gives exit code 4.

**More status values**

The forms hold the status values of a new record. The platform holds more, for
example `Closed`. To use one, start the action from a search with `sendalert`,
or write the value into `local/savedsearches.conf`.

## Example alerts

The app holds one example alert for each action. Both are disabled after an
install. Change the index and the source type to search your own data.

**Detection: an incident for the host above the threshold**

`Adversarial demo - brute force` counts failed logins for each host in the last
hour, and keeps a host with 20 or more:

    index=main sourcetype="demo:auth" outcome=failure
    | stats count AS failed_logins, latest(src_ip) AS src_ip,
            values(user) AS user, latest(app) AS app BY dest
    | where failed_logins >= 20
    | sort - failed_logins

The `sort` command puts the host with the most failed logins first, because the
incident holds the first row. The **Fields** setting names the fields of that
row, so the description holds the host, the source address, the user names and
the application.

**Posture: one risk for the whole condition**

`Adversarial demo - endpoint agent coverage` counts the endpoints that report
no endpoint agent, and keeps the count if it is 5 or more:

    index=main sourcetype="demo:posture" check="endpoint_baseline"
    | stats latest(agent_installed) AS agent_installed, latest(os) AS os,
            latest(business_unit) AS business_unit BY dest
    | where agent_installed="false"
    | stats count AS hosts, values(dest) AS host_list,
            values(os) AS os_list, values(business_unit) AS business_units
    | eval business_units=mvjoin(business_units, ", ")
    | where hosts >= 5

The second `stats` command gives one row, so the run creates one risk. The row
holds every affected host in `host_list`.

A multi-value field, for example `host_list`, arrives at the alert action as a
list. The description then names every host, up to 20 names.

**Suppression**

Both example alerts use the suppression settings of Splunk, because a condition
that stays true would otherwise create a record on every run:

    alert.suppress = 1
    alert.suppress.period = 24h

The detection suppresses a repeat for 24 hours, and the posture search for
7 days. Splunk holds the alert down for the whole period, and not for one host,
so a second host that crosses the threshold in the same period does not create
a record. Use a shorter period, or one alert for each group of assets, if your
environment needs a record for every host.

Splunk keys the suppression on a field value only for a per-result alert, which
is `alert.digest_mode = 0`. The example alerts keep the default digest mode, so
they do not use `alert.suppress.fields`.

## Use an alert action from a search

The `sendalert` command starts an alert action directly. Use it to test the
setup, because it needs no schedule and no data.

    | makeresults
    | eval dest="auth-gateway-01", failed_logins=137
    | sendalert adversarial_incident param.title="Test incident"
      param.source="SIEM" param.fields="dest,failed_logins"

    | makeresults
    | eval control="MFA on the VPN", exempt_users=48
    | sendalert adversarial_risk param.title="MFA exemption list holds 48 users"
      param.source="Attack Surface Monitoring" param.fields="control,exempt_users"

A `param.` name in the search is the same name as in the alert form. A name
that the search does not hold keeps the default value from
`default/alert_actions.conf`.

## Tokens

The Adversarial API uses OAuth 2.1. The alert action holds an access token and
a refresh token in the Splunk secret store, and shares them between alerts and
between both actions.

- The alert action reuses a valid access token.
- Less than 60 seconds before the token expires, the alert action uses the
  refresh token to get a new token.
- If the refresh fails, the alert action uses the client credentials again.
- If the API answers 401, the alert action gets a new token and sends the
  request one more time.

To remove the stored tokens, use this command. The next alert gets a new token.

    $SPLUNK_HOME/bin/splunk cmd python3 configure_credentials.py --clear-token-cache

## Exit codes

Splunk writes the exit code to the log. Each failure has its own code. Both
actions use the same codes.

| Code | Meaning |
| --- | --- |
| 0 | The alert action created the record. |
| 2 | A setting is missing or not valid. |
| 3 | The API refused the credentials. |
| 4 | The API refused the record. |
| 5 | The Splunk server cannot reach the API. |
| 6 | An unexpected error occurred. |

The alert action reports success if the record exists but the comment failed.
The record is the result, and the comment is extra.

## Find the log messages

Use this search.

    index=_internal sourcetype=splunkd component=sendmodalert
    action="adversarial_*"

## Troubleshooting

| Problem | Action |
| --- | --- |
| Exit code 2 | Read the log. It names the setting and the valid values. If the credentials are missing, open the setup page and store them again. |
| Exit code 3 | Check that the service account is active, and that it holds the role for the record type. Check that the client ID and the client secret are correct. |
| Exit code 4 | Check the source name. The source must exist in your organization. The risk sources and the incident sources are two separate lists. |
| Exit code 5 | Check that the Splunk server can reach the API URL. |

## Files

| Path | Purpose |
| --- | --- |
| `bin/adversarial_incident.py` | The incident alert action |
| `bin/adversarial_risk.py` | The risk alert action |
| `bin/adversarial_alert.py` | The parts that both actions share |
| `bin/adversarial_api.py` | The API client and the token logic |
| `bin/splunk_rest.py` | Access to the Splunk secret store |
| `bin/configure_credentials.py` | Setup from the command line |
| `default/app.conf` | The name, the version and the visibility of the app |
| `default/alert_actions.conf` | The alert actions and their default values |
| `default/data/ui/alerts/` | The alert forms |
| `default/savedsearches.conf` | The example alerts, disabled |
| `default/props.conf` | The source types of the sample data |
| `default/restmap.conf` | The save-time check of an alert |
| `default/data/ui/nav/default.xml` | The menu of the app |
| `default/data/ui/views/adversarial_setup.xml` | The setup page |
| `appserver/static/adversarial_setup.js` | The setup page logic |
| `appserver/static/adversarial_setup.css` | The setup page styles |
| `metadata/default.meta` | The read and write permissions of the app objects |
| `README/alert_actions.conf.spec` | The settings of the alert actions |
| `static/appIcon.png` | The app icon, in the app list |
| `static/appIcon_2x.png` | The same icon, for a high resolution screen |
| `static/appIconAlt.png` | The app icon, in the app rail |
| `static/appIconAlt_2x.png` | The same icon, for a high resolution screen |
| `appserver/static/appIcon.png` | The icon of the alert actions |

## Tests

The tests use [uv](https://docs.astral.sh/uv/).

    uv sync
    uv run pytest

The tests need no network access and no Splunk server.
