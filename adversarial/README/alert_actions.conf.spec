#
# Settings of the Adversarial alert actions.
#
# Splunk reads this file to validate the settings of the app. Without it,
# `splunk btool check` reports each `param.*` setting as an unknown key.
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
* There is no `param.client_secret`. Splunk keeps a saved alert in plain text,
  so the client secret stays in the Splunk secret store.
* Default: empty

param.title = <string>
* The title of the incident. The title is a key input of AI Suggest Score.
* Default: Splunk alert: $name$

param.description = <string>
* Text at the start of the incident description. The alert action adds the
  alert context and the search results link after this text.
* Default: empty

param.severity = <string>
* The severity of the incident: empty, auto, SEV-1, SEV-2, SEV-3, SEV-4 or
  SEV-5.
* Empty leaves the severity for AI Suggest Score.
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

param.fields = <string>
* Field names from the first search result, with a comma between names. The
  alert action adds each field to the description. A name can hold a wildcard,
  for example src_*.
* Default: host,source,sourcetype

param.add_comment = <boolean>
* Whether the alert action adds a comment with a link to the search results.
* Default: 1

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
* Default: empty

param.title = <string>
* The title of the risk. The title is a key input of AI Suggest Score.
* Default: Splunk alert: $name$

param.description = <string>
* Text at the start of the risk description. The alert action adds the alert
  context and the search results link after this text.
* Default: empty

param.type = <string>
* The category of the risk: Code, Configuration, Control Deficiency, Policy,
  Procedural, Vulnerability or Third-party.
* Empty gives Control Deficiency.
* Default: Control Deficiency

param.source = <string>
* The source of the risk. The source must exist in your organization. The risk
  sources and the incident sources are separate lists.
* Default: Attack Surface Monitoring

param.status = <string>
* The status of the risk: New, Urgency Proposed, Remediation, Closure Proposed
  or Closed.
* Default: New

param.iru = <string>
* The initially reported urgency: empty, auto, Critical, High, Medium, Low or
  Info.
* The field holds the raw score of the reporting source. AI Suggest Score reads
  it when the title and the description hold too little detail.
* `auto` maps the severity of the Splunk alert.
* Default: empty

param.likelihood = <string>
* The likelihood of the risk: empty, Remote, Unlikely, Possible, Probable or
  Imminent.
* Empty leaves the likelihood for AI Suggest Score.
* Default: empty

param.impact = <string>
* The impact of the risk: empty, Very Low, Low, Medium, High or Severe.
* Empty leaves the impact for AI Suggest Score.
* The platform derives the urgency from the likelihood and the impact, and the
  due date from the urgency.
* Default: empty

param.likelihood_reason = <string>
* Why the likelihood is correct.
* Default: empty

param.impact_reason = <string>
* Why the impact is correct.
* Default: empty

param.remediation_task = <string>
* The actions that address the risk. The audience is the wider organization.
* Default: empty

param.control_statement = <string>
* The controls that are in place against the risk.
* Default: empty

param.fields = <string>
* Field names from the first search result, with a comma between names. The
  alert action adds each field to the description. A name can hold a wildcard,
  for example src_*.
* Default: host,source,sourcetype

param.add_comment = <boolean>
* Whether the alert action adds a comment with a link to the search results.
* Default: 1

param.info_severity = <string>
* The severity of the Splunk alert. Splunk supplies this value through the
  $alert.severity$ token. Do not change this setting.
* Default: $alert.severity$

param.info_trigger_time = <string>
* The time that the alert triggered, in epoch seconds. Splunk supplies this
  value through the $trigger_time$ token. Do not change this setting.
* Default: $trigger_time$
