# Adversarial for Splunk

This Splunk app adds two
[custom alert actions](https://dev.splunk.com/enterprise/docs/devtools/customalertactions/).
An alert action creates a record in the Adversarial platform when a Splunk
alert triggers. Install the app on the search heads, because the search tier
runs alert actions.

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

## One record, or one record for each result

The **Incidents to create** and **Risks to create** settings (`param.records`)
select how many records one alert firing creates.

| Value | Result |
| --- | --- |
| `one` (form: **One incident per alert**) | One record from the first row of the search results. This is the default. |
| `each` (form: **One incident per result row**) | One record for each row of the search results, up to **Maximum incidents** or **Maximum risks** (`param.max_records`, default 25, `0` for no limit). |

Splunk can also start the action one time for each result. See "The Splunk
trigger" at the end of this section.

**One record from the first result**

With the trigger **Once**, Splunk starts a custom alert action one time for
each alert firing, and it sends the first search result to it. Write the search
for that behaviour:

- Aggregate the rows if the whole result set is one record. A `stats` command
  with `values()` gives one row that names every asset.
- Sort the rows if the search keeps more than one row. The first row becomes
  the record, so `| sort - failed_logins` reports the worst host.
- Name the fields of that row in the **Fields** setting. The description then
  holds the values.

**One record for each result**

The action reads the results file of the search, and creates one record for
each row. Use this value when each row is a separate event or condition, for
example one incident for each host above a threshold.

- Use a `{{row.<field>}}` token in a text setting, for example
  `Brute force on {{row.dest}}`. The action replaces the token with the field
  of the row that gives the record. Splunk replaces a `$result.<field>$` token
  before the action starts, always from the first result, so that token gives
  the same value in every record. Splunk replaces an unknown `$...$` token
  with an empty string, so the row token does not use `$`.
- The description names the row, for example `Result 2 of 5`.
- **Maximum incidents** or **Maximum risks** limits the records of one alert
  firing. The action creates records for the first rows and writes a warning
  for the other rows. Sort the search, so the rows that matter come first.
  Set `0` for no limit. Splunk still stops the action after `maxtime`
  (default 5 minutes), and the API limits the request rate of a service
  account. Each record takes two requests: the record and the comment.
- The action stops at the first failure. The records that it created before
  the failure stay.
- Use **Throttle** in the alert to stop a repeat. With the trigger **Once**,
  Splunk throttles the whole alert.

**The Splunk trigger**

A scheduled alert has a second way to get one record for each result: set the
trigger of the alert to **For each result** (`alert.digest_mode = 0`). Splunk
then starts the action one time for each row, and `$result.<field>$` takes the
value of that row. This trigger also gives **Throttle** by field value, for example
one record for each `dest` in 24 hours.

| | Trigger **For each result** | **One incident per result row** |
| --- | --- | --- |
| Scheduled alert | Yes | Yes |
| Manual run, `sendalert` search | No, Splunk does not start the action | Yes |
| Limit of records for one firing | No | **Maximum incidents**, **Maximum risks** |
| Throttle by field value | Yes | No |
| Starts of the action | One for each row | One |

Each start of the action with the trigger **For each result** gets a results
file that holds only its own row. The two ways therefore do not multiply: with
both, a run gives one record for each row.

The comment holds a link to the search results, so a person reaches every row
from the record.

## Scoring

| Record | Score fields |
| --- | --- |
| Incident | Severity |
| Risk | Likelihood, Impact |

A score setting takes one of these values:

| Value | Result | Settings |
| --- | --- | --- |
| Empty | The field stays empty. A person scores the record in the platform, for example with AI Suggest Score. This is the default. | Severity, Likelihood, Impact |
| `auto` | The severity of the Splunk alert maps to a value. See the table after this one. An ad-hoc `sendalert` search has no alert severity, so the field stays empty. | Severity, Initially reported urgency |
| A named value, for example `SEV-2` or `High` | The value goes to the platform as it is. | All |

The platform does not score a record that the API creates. A person runs AI
Suggest Score on one record or on many records, and accepts or changes the
proposed values. AI Suggest Score reads the title, the description and the
comments, so the action always sends a full description and adds a comment.
For a risk, it also reads the Initially Reported Urgency (IRU) and your Risk
Assessment Management Procedure (RAMP). For an incident, it also reads your
Cyber Incident Response Procedure (CIRP) and your Cybersecurity Policy.

Set a score field only when the alert holds a value that you trust. A brute
force detection is an example: the number of failed logins is a reliable
signal, so the example alert maps the Splunk alert severity.

A risk holds one more field, the **Initially Reported Urgency (IRU)**. It is
the raw score of the reporting source. AI Suggest Score uses it when the title
and the description hold too little detail.

The value `auto` maps the severity of the Splunk alert:

| Splunk alert severity | Incident severity | Risk initially reported urgency |
| --- | --- | --- |
| 1 (debug) | SEV-5 | Info |
| 2 (info) | SEV-5 | Info |
| 3 (warn) | SEV-4 | Low |
| 4 (error) | SEV-3 | Medium |
| 5 (severe) | SEV-2 | High |
| 6 (fatal) | SEV-1 | Critical |

The names are the `alert.severity` values of
[savedsearches.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.0/configuration-file-reference/10.0.10-configuration-file-reference/savedsearches.conf).

The platform derives the urgency of a risk from the likelihood and the impact.
The due date is the discovered date plus the SLA of that urgency, and a risk
with the urgency Info has no due date. The urgency and the due date therefore
stay empty until the risk holds a likelihood and an impact.

A register view can hide a record with no score. The default view of the
Incident Register shows open incidents at SEV-1 to SEV-3 only, so a new
incident with no severity does not show there. A risk view with an urgency
filter does not show a risk with no urgency. Use a view with no score filter to
find the records that need a score.

**Field reference**

The Adversarial documentation defines each value:

- [Incident fields](https://docs.adversarial.com/guides/incidents/incident-fields/)
  and [incident scoring](https://docs.adversarial.com/guides/incidents/scoring-and-response/)
- [Risk fields](https://docs.adversarial.com/guides/risks/risk-fields/)
  and [risk scoring](https://docs.adversarial.com/guides/risks/scoring-and-remediation/)
- [AI features](https://docs.adversarial.com/concepts/ai-features/), for AI
  Suggest Score
- [Incident FAQ](https://docs.adversarial.com/guides/incidents/faq/), for the
  default view of the Incident Register

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

  See [Service accounts](https://docs.adversarial.com/guides/service-accounts/),
  [API access](https://docs.adversarial.com/guides/service-accounts/api-access/)
  and [Managing roles](https://docs.adversarial.com/guides/roles/managing-roles/).
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

Use the setup page or the command line. The app keeps the values in the Splunk
secret store (`storage/passwords`). Splunk encrypts each secret and writes it
to `local/passwords.conf` of the app. No setting holds the secret in plain
text. See
[Store secrets](https://dev.splunk.com/enterprise/docs/developapps/manageknowledge/secretstorage/).
Both actions read the same credentials.

The app keeps these entries in the secret store, in the realm `adversarial`:

| Entry | Content |
| --- | --- |
| `config` | The API URL and the default client ID. No secret. |
| `secret_<client ID>` | The client secret of one service account. |
| `token_<client ID>` | The cached token pair of one service account. |

The setup page reads only `config`, so the client secret never reaches the
browser. An install of version 1.0 kept the secret inside `config`. The app
still reads it there, and the next save on the setup page, or with
`configure_credentials.py`, moves it into its own entry.

Only the `admin` and `sc_admin` roles can read or change these entries. To let
the alerts of another role use the actions, give that role the
`list_storage_passwords` and `edit_storage_passwords` capabilities, and add it
to the `[passwords]` stanza of `metadata/local.meta`. See
[Secret storage RBAC](https://dev.splunk.com/enterprise/docs/developapps/manageknowledge/secretstorage/secretstoragerbac/).

**Setup page**

1. Open the **Adversarial** app. The setup page is its only page.
2. Type the API base URL, the client ID and the client secret.
3. Select **Save**.

A save marks the app as configured (`is_configured = 1` in `local/app.conf`).
The command line does the same. Until then, a user who opens the app sees the
Splunk **App configuration** page, with a button to the setup page.

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

To check the credentials, use the `--verify` option. The check gets a token,
reads the service account identity and its roles, and names the alert actions
that the account can run. It does not create a record. `--require` names what
your alerts use, and the check fails when the account cannot do it:

    $SPLUNK_HOME/bin/splunk cmd python3 configure_credentials.py --verify \
        --require incident,risk,tags

| `--require` value | Permission |
| --- | --- |
| `incident` | `incidents:write`, for `adversarial_incident` |
| `risk` | `risks:write`, for `adversarial_risk` |
| `tags` | `tags:read`, for the **Tags** setting |

`--show` prints the stored settings. It never prints a secret.

**More than one organization**

An alert can send its records to another service account, for example in a
second organization. Store the secret of that account first:

    $SPLUNK_HOME/bin/splunk cmd python3 configure_credentials.py --add-client \
        --client-id arm_sa_... --client-secret arm_sk_...

Then set `param.client_id` of the alert to that client ID, and
`param.base_url` if the organization uses another API URL. Splunk keeps a saved
alert in plain text, so an alert never holds a secret. An alert that names a
client ID with no stored secret stops with exit code 2. To check that account,
run `--verify --client-id arm_sa_...`. To remove it, run
`--remove-client arm_sa_...`.

## Add an alert action to an alert

1. Open a saved alert, or create one.
2. In **Trigger Actions**, select **Add trigger actions** (**Add Actions** in Splunk 9).
3. Select **Create Adversarial incident** or **Create Adversarial risk**.
4. Complete the form.

One alert can hold both actions. Splunk starts each action one time for each
alert firing, or one time for each result with the trigger **For each result**.

Splunk replaces a `$...$` token with a value from the alert. For example,
`$name$` becomes the name of the alert, and `$result.dest$` becomes the `dest`
field of the first search result. The action replaces a `{{row.dest}}` token with
the `dest` field of the row that gives the record. See "One record, or one
record for each result".

**Create Adversarial incident**

| Field | Purpose |
| --- | --- |
| Title | The incident title. Default: `Splunk alert: $name$` |
| Description | Text at the start of the incident description |
| Severity | Empty, `auto`, or one of SEV-1 to SEV-5. See "Scoring". |
| Severity reason | Why the severity is correct |
| Status | New, In Progress or Review |
| Source | The incident source. See "Source names" after the tables. |
| Tags | Item tags, with a comma between tags. See "Tags" after the tables. |
| Fields | Field names from the search result. Use a comma between names. A name can hold a wildcard, for example `src_*`. |
| Incidents to create | **One incident per alert** (`one`) or **One incident per result row** (`each`). See "One record, or one record for each result". |
| Maximum incidents | The limit of incidents for one alert firing with **One incident per result row**. `0` means no limit. Default: 25 |
| Splunk link | Add a comment with a link to the search results |

**Create Adversarial risk**

| Field | Purpose |
| --- | --- |
| Title | The risk title. Default: `Splunk alert: $name$` |
| Description | Text at the start of the risk description |
| Type | Code, Configuration, Control Deficiency, Policy, Procedural, Vulnerability or Third-party |
| Source | The risk source. See "Source names" after the tables. |
| Tags | Item tags, with a comma between tags. See "Tags" after the tables. |
| Status | New, Urgency Proposed or Remediation |
| Initially reported urgency | Empty, `auto`, or one of Critical, High, Medium, Low, Info. See "Scoring". |
| Likelihood | Empty, or one of Remote, Unlikely, Possible, Probable, Imminent. See "Scoring". |
| Impact | Empty, or one of Very Low, Low, Medium, High, Severe. See "Scoring". |
| Likelihood reason | Why the likelihood is correct |
| Impact reason | Why the impact is correct |
| Remediation task | What a person must do to close the risk |
| Control statement | The control that must hold |
| Fields | Field names from the search result. Use a comma between names. A name can hold a wildcard, for example `src_*`. |
| Risks to create | **One risk per alert** (`one`) or **One risk per result row** (`each`). See "One record, or one record for each result". |
| Maximum risks | The limit of risks for one alert firing with **One risk per result row**. `0` means no limit. Default: 25 |
| Splunk link | Add a comment with a link to the search results |

The risk action does not send a due date, an expected date or a threat
objective. The platform owns the due date, and a threat objective needs a
person who knows the threat profile of the organization.

**Source names**

The source must be one of the sources of your organization. The two record
types hold two separate lists. To read them, open the Adversarial platform and
go to **Settings > Incidents** or **Settings > Risks**. A source name that the
platform does not hold gives exit code 4.

**Tags**

A tag must exist in your organization before an alert names it. Use the text
of the tag, or its UUID. The platform does not create a tag, and it rejects the
record if a tag is unknown, which gives exit code 4. The service account reads
the tags with the `tags:read` permission, which the editor roles hold.

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
    | eval user=mvjoin(user, ", ")
    | sort - failed_logins

The `sort` command puts the host with the most failed logins first, because the
incident holds the first row. The **Fields** setting names the fields of that
row, so the description holds the host, the source address, the user names and
the application. `mvjoin` turns the user names into one value, because a
`$result.user$` token gives only the first value of a multi-value field.

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

**Throttle**

Both example alerts use
[throttling](https://help.splunk.com/splunk-enterprise/alert-and-respond/alerting-manual/9.4/manage-alert-trigger-conditions-and-throttling/throttle-alerts),
also known as suppression, because a condition that stays true would otherwise
create a record on every run:

    alert.suppress = 1
    alert.suppress.period = 24h

The detection suppresses a repeat for 24 hours, and the posture search for
7 days. Splunk holds the alert down for the whole period, and not for one host,
so a second host that crosses the threshold in the same period does not create
a record. To get a record for every host, use the trigger **For each result**
and throttle by the `dest` field (`alert.suppress.fields = dest`). See "One
record, or one record for each result".

## Use an alert action from a search

The [`sendalert`](https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/search-commands/sendalert)
command starts an alert action directly. Use it to test the setup, because it
needs no schedule and no data. The user needs the `run_sendalert` capability.

Turn off **Preview** in the search bar before you run `sendalert`. With
preview on, Splunk can start the action more than one time, and each start
creates a record.

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
between both actions. Each service account has its own token pair, and a pair
records the API URL and the client ID that it belongs to. An alert never uses
the token of another account.

- The alert action reuses a valid access token.
- Less than 60 seconds before the token expires, the alert action uses the
  refresh token to get a new token.
- If the refresh fails, the alert action uses the client credentials again.
- If the API answers 401, the alert action gets a new token and sends the
  request one more time.

To remove every stored token pair, use this command. The next alert gets a new
token. A new secret for a client ID removes the pair of that client ID.

    $SPLUNK_HOME/bin/splunk cmd python3 configure_credentials.py --clear-token-cache

## Exit codes

Splunk writes the exit code to the log. Each failure has its own code. Both
actions use the same codes.

| Code | Meaning |
| --- | --- |
| 0 | The alert action created the record. |
| 2 | A setting is missing or not valid. |
| 3 | The API refused the credentials, or the address of the Splunk server is outside the IP allowlist. |
| 4 | The API refused the record. |
| 5 | The Splunk server cannot reach the API. |
| 6 | An unexpected error occurred. |
| 7 | The service account lacks a permission, or the API refused a cached token from an address outside the IP allowlist. |

The alert action reports success if the record exists but the comment failed.
The record is the result, and the comment is extra.

## Find the log messages

Splunk writes the output of a scheduled alert action to `splunkd.log`. Use this
search:

    index=_internal sourcetype=splunkd component=sendmodalert
    action="adversarial_*"

For a `sendalert` search, read `search.log` in the dispatch directory of the
search, or open **Job > Inspect Job**.

Splunk stops an alert action after `maxtime` (default 5 minutes). See
[alert_actions.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.0/configuration-file-reference/10.0.10-configuration-file-reference/alert_actions.conf).

## Troubleshooting

| Problem | Action |
| --- | --- |
| Exit code 2 | Read the log. It names the setting and the valid values. If the credentials are missing, open the setup page and store them again. |
| Exit code 2 and "no client secret" | The alert sets `param.client_id` to an account with no stored secret. Run `configure_credentials.py --add-client`. |
| Exit code 3 | The token endpoint refused the client ID or the secret. Check that both are correct, that the service account is not disabled or expired, and that the IP allowlist holds the address of the Splunk server. The API gives the same answer for each cause. |
| Exit code 4 | Check the source name and the tags. Both must exist in your organization. The risk sources and the incident sources are two separate lists. If the log says that the API limited the request rate, lower the maximum records or make the search return fewer rows. |
| Exit code 5 | Check that the Splunk server can reach the API URL. |
| Exit code 7 | The token is valid, but the account may not do the request. Give it the role for the record type, and `tags:read` if the alert sets tags. If the service account has an IP allowlist, add the address of the Splunk server. Run `--verify --require ...` to see what is missing. |

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
