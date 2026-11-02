#
# Settings of the Adversarial alert actions.
#
# Splunk reads this file to validate the settings of the app. Without it,
# `splunk btool check` reports each `param.*` setting as an invalid key.
#

[adversarial_incident]

param.base_url = <string>
* The base URL of the Adversarial API, for example
  https://api.adversarial.com/api
* Leave this setting empty to use the value from the setup page.
* Default: empty

param.client_id = <string>
* The client ID of a credential service account (arm_sa_...).
* Leave this setting empty to use the value from the setup page.
* Another client ID needs its secret in the Splunk secret store. Store it with
  `bin/configure_credentials.py --add-client`. Without it, the action stops
  with exit code 2.
* There is no `param.client_secret`. Splunk keeps a saved alert in plain text,
  so the client secret stays in the Splunk secret store.
* Default: empty

param.title = <string>
* The title of the incident. AI Suggest Score reads the title.
* Default: Splunk alert: $name$

param.description = <string>
* Text at the start of the incident description. The alert action adds the
  alert context and the search results link after this text.
* Default: empty

param.severity = <string>
* The severity of the incident: empty, auto, SEV-1, SEV-2, SEV-3, SEV-4 or
  SEV-5.
* Empty leaves the severity empty. A person scores the incident in the
  platform, for example with AI Suggest Score.
* `auto` maps the severity of the Splunk alert to an Adversarial severity.
* Default: empty

param.severity_reasoning = <string>
* Why the severity is correct.
* Default: empty

param.status = <string>
* The status of the incident: New, In Progress, Review or Closed.
* Default: New

param.source = <string>
* The source of the incident. The source must exist in your organization.
* Default: SIEM

param.tags = <string>
* Item tags for the incident, with a comma between tags. Each tag is the text
  of an existing item tag of your organization, or its UUID.
* The platform does not create a tag. An unknown tag makes the API reject the
  incident, which gives exit code 4.
* Default: empty

param.fields = <string>
* Field names from the search result, with a comma between names. The
  alert action adds each field to the description. A name can hold a wildcard,
  for example src_*.
* Default: host,source,sourcetype

param.add_comment = <boolean>
* Whether the alert action adds a comment with a link to the search results.
* Default: 1

param.records = <string>
* How many records one alert firing creates: one or each.
* one creates one record from the first search result.
* each creates one record for each search result, up to param.max_records.
  The action reads the results file of the search.
* A text setting can hold a {{row.<field>}} token. The action replaces it
  with the field of the row that gives the record. Splunk replaces a
  $result.<field>$ token from the first result only, so use {{row.<field>}}
  with each.
* A scheduled alert with the trigger "For each result"
  (alert.digest_mode = 0) starts the action one time for each result. Each
  start then gets one row, so one and each give the same records.
* Default: one

param.max_records = <integer>
* The maximum number of records for one alert firing when param.records is
  each. The action creates records for the first rows, and writes a warning
  for the rest.
* 0 means no limit. Splunk still stops the action after maxtime, and the API
  limits the request rate of the service account.
* Default: 25

param.info_severity = <string>
* The severity of the Splunk alert. Splunk supplies this value through the
  $alert.severity$ token. Do not change this setting.
* Default: $alert.severity$

param.info_trigger_time = <string>
* The time that the alert triggered, in epoch seconds. Splunk supplies this
  value through the $trigger_time$ token. Do not change this setting.
* Default: $trigger_time$


[adversarial_risk]

param.base_url = <string>
* The base URL of the Adversarial API, for example
  https://api.adversarial.com/api
* Leave this setting empty to use the value from the setup page.
* Default: empty

param.client_id = <string>
* The client ID of a credential service account (arm_sa_...).
* Leave this setting empty to use the value from the setup page.
* Another client ID needs its secret in the Splunk secret store. Store it with
  `bin/configure_credentials.py --add-client`. Without it, the action stops
  with exit code 2.
* Default: empty

param.title = <string>
* The title of the risk. AI Suggest Score reads the title.
* Default: Splunk alert: $name$

param.description = <string>
* Text at the start of the risk description. The alert action adds the alert
  context and the search results link after this text.
* Default: empty

param.type = <string>
* The type of the risk: Code, Configuration, Control Deficiency, Policy,
  Procedural, Vulnerability or Third-party.
* Empty gives Control Deficiency.
* Default: Control Deficiency

param.source = <string>
* The source of the risk. The source must exist in your organization. The risk
  sources and the incident sources are separate lists.
* Default: Attack Surface Monitoring

param.tags = <string>
* Item tags for the risk, with a comma between tags. Each tag is the text
  of an existing item tag of your organization, or its UUID.
* The platform does not create a tag. An unknown tag makes the API reject the
  risk, which gives exit code 4.
* Default: empty

param.status = <string>
* The status of the risk: New, Urgency Proposed, Remediation, Closure Proposed
  or Closed.
* Default: New

param.iru = <string>
* The Initially Reported Urgency (IRU): empty, auto, Critical, High, Medium, Low or
  Info.
* The field holds the raw score of the reporting source. AI Suggest Score uses
  it when the title and the description hold too little detail.
* `auto` maps the severity of the Splunk alert.
* Default: empty

param.likelihood = <string>
* The likelihood of the risk: empty, Remote, Unlikely, Possible, Probable or
  Imminent.
* Empty leaves the likelihood empty, for a person to score.
* Default: empty

param.impact = <string>
* The impact of the risk: empty, Very Low, Low, Medium, High or Severe.
* Empty leaves the impact empty, for a person to score.
* The platform derives the urgency from the likelihood and the impact. The due
  date is the discovered date plus the SLA of the urgency.
* Default: empty

param.likelihood_reason = <string>
* Why the likelihood is correct.
* Default: empty

param.impact_reason = <string>
* Why the impact is correct.
* Default: empty

param.remediation_task = <string>
* The actions that address the risk.
* Default: empty

param.control_statement = <string>
* The controls that are in place against the risk.
* Default: empty

param.fields = <string>
* Field names from the search result, with a comma between names. The
  alert action adds each field to the description. A name can hold a wildcard,
  for example src_*.
* Default: host,source,sourcetype

param.add_comment = <boolean>
* Whether the alert action adds a comment with a link to the search results.
* Default: 1

param.records = <string>
* How many records one alert firing creates: one or each.
* one creates one record from the first search result.
* each creates one record for each search result, up to param.max_records.
  The action reads the results file of the search.
* A text setting can hold a {{row.<field>}} token. The action replaces it
  with the field of the row that gives the record. Splunk replaces a
  $result.<field>$ token from the first result only, so use {{row.<field>}}
  with each.
* A scheduled alert with the trigger "For each result"
  (alert.digest_mode = 0) starts the action one time for each result. Each
  start then gets one row, so one and each give the same records.
* Default: one

param.max_records = <integer>
* The maximum number of records for one alert firing when param.records is
  each. The action creates records for the first rows, and writes a warning
  for the rest.
* 0 means no limit. Splunk still stops the action after maxtime, and the API
  limits the request rate of the service account.
* Default: 25

param.info_severity = <string>
* The severity of the Splunk alert. Splunk supplies this value through the
  $alert.severity$ token. Do not change this setting.
* Default: $alert.severity$

param.info_trigger_time = <string>
* The time that the alert triggered, in epoch seconds. Splunk supplies this
  value through the $trigger_time$ token. Do not change this setting.
* Default: $trigger_time$
