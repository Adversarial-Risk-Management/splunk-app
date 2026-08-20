#!/usr/bin/env bash
# Command line demo for the Adversarial Splunk app.
#
# Each scenario shows one part of the feature. The script prints the command,
# then the proof: the log lines of the alert action, and the record that the
# Adversarial API holds.
#
# Usage:
#     dev/demo.sh --list             show the scenarios
#     dev/demo.sh all                run every quick scenario
#     dev/demo.sh connect adhoc      run named scenarios, in that order
#     dev/demo.sh schedule           run the slow scenario (about 3 minutes)
#
# The script reads .env in the repository root. See DEMO.md for the setup.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
app="adversarial"
incident_action="adversarial_incident"
risk_action="adversarial_risk"
incident_alert="Adversarial demo - brute force"
risk_alert="Adversarial demo - endpoint agent coverage"
splunk_home="/opt/splunk"

set -a
# shellcheck disable=SC1091
source "${root}/.env"
set +a

container="${SPLUNK_CONTAINER:-so1}"
management_uri="https://localhost:8089"

# The API URL differs between the two sides of the demo. The Splunk container
# uses ADVERSARIAL_BASE_URL_CONTAINER, which names the host. The helper scripts
# on this workstation use ADVERSARIAL_BASE_URL.

# ---------------------------------------------------------------- output ----

if [ -t 1 ]; then
    bold="$(tput bold)"; dim="$(tput dim)"; plain="$(tput sgr0)"
else
    bold=""; dim=""; plain=""
fi

rule() { printf '%s\n' "------------------------------------------------------------------------"; }

heading() {
    echo
    printf '%s\n' "========================================================================"
    printf '%s%s%s\n' "${bold}" "  Scenario: $1" "${plain}"
    printf '%s\n' "========================================================================"
    printf '  %s\n' "Goal: $2"
    echo
}

step() { printf '%s\n' "${bold}-> $*${plain}"; }
note() { printf '%s\n' "   $*"; }
failed() { printf '%s\n' "${bold}   FAILED: $*${plain}" >&2; }
shown() { printf '%s\n' "${dim}   \$ $*${plain}"; }

# ----------------------------------------------------------- Splunk calls ----

# Run the Splunk command line tool inside the container.
splunk_cli() {
    docker exec --user splunk "${container}" "${splunk_home}/bin/splunk" "$@" \
        -auth "${SPLUNK_USERNAME}:${SPLUNK_PASSWORD}" 2>/dev/null
}

# Call the Splunk management API inside the container. The management port is
# not published, so the call starts in the container.
splunk_rest() {
    local method="$1" path="$2"; shift 2
    docker exec "${container}" curl -sk -u "${SPLUNK_USERNAME}:${SPLUNK_PASSWORD}" \
        -X "${method}" "${management_uri}${path}" "$@"
}

# Run one of the app scripts on the Splunk server.
app_python() {
    local script="$1"; shift
    docker exec --user splunk \
        -e "SPLUNK_USERNAME=${SPLUNK_USERNAME}" \
        -e "SPLUNK_PASSWORD=${SPLUNK_PASSWORD}" \
        "${container}" "${splunk_home}/bin/splunk" cmd python3 \
        "${splunk_home}/etc/apps/${app}/bin/${script}" "$@"
}

# Make the log of an alert action easy to read. The filter removes the
# timestamp and the Splunk channel, and shortens the request body. It accepts
# the log of both actions.
tidy_log() {
    sed -E -e 's/^[0-9][0-9-]* [0-9:.]* //' \
        -e 's/^\+0000 //' \
        -e 's/^(INFO|WARN|ERROR|FATAL) +sendmodalert \[[^]]*\] - //' \
        -e 's/^action=adversarial_[a-z]+ STDERR -  //' \
        -e 's/^action=adversarial_[a-z]+ - //' \
        -e 's/(Creating the (incident|risk): .{220}).*/\1 .../' \
    | sed 's/^/   /'
}

# Print the alert action log of an ad-hoc search. Splunk writes the log of an
# ad-hoc run into the dispatch directory of the search. Each scenario puts a
# unique marker into a field of its search, so the script finds the correct
# directory.
adhoc_log() {
    local marker="$1" path
    path="$(docker exec --user splunk "${container}" sh -c \
        "grep -la '${marker}' ${splunk_home}/var/run/splunk/dispatch/*/search.log 2>/dev/null | head -1")"
    if [ -z "${path}" ]; then
        note "The log of the alert action is not there yet."
        return 0
    fi
    docker exec --user splunk "${container}" sh -c \
        "grep -a 'action=adversarial_' '${path}'" | tidy_log
}

# Run an ad-hoc search that starts an alert action, then show the log.
#
# The search command exits with status 17 if the alert action fails. The
# function keeps that status and prints it, because two scenarios show a
# failure.
send_alert() {
    local marker="$1" search="$2" status=0 output=""
    shown "splunk search '${search}'"
    output="$(splunk_cli search "${search}")" || status=$?
    if [ -n "${output}" ]; then
        printf '%s\n' "${output}" | sed 's/^/   /'
    fi
    if [ "${status}" -ne 0 ]; then
        note "The search command exits with status ${status}, because the alert"
        note "action did not finish with success."
    fi
    echo
    note "Log of the alert action:"
    adhoc_log "${marker}"
}

# Splunk writes the log of the alert action into splunkd.log, and the summary
# of each scheduled run into scheduler.log. The demo notes the size of each
# file before a run, then reads only the new bytes.
log_size() {
    docker exec --user splunk "${container}" \
        sh -c "wc -c < ${splunk_home}/var/log/splunk/$1" | tr -d ' \r'
}

new_log_lines() {
    local file="$1" offset="$2" pattern="$3"
    docker exec --user splunk "${container}" sh -c \
        "tail -c +$((offset + 1)) ${splunk_home}/var/log/splunk/${file} | grep -a '${pattern}' || true"
}

# Wait until the alert action of a saved search writes its exit code.
scheduled_action_log() {
    local offset="$1" action="$2" limit="${3:-20}" count=0 text=""
    while [ "${count}" -lt "${limit}" ]; do
        text="$(new_log_lines splunkd.log "${offset}" "action=${action}")"
        if printf '%s' "${text}" | grep -q 'exit code='; then
            break
        fi
        count=$((count + 1))
        sleep 1
    done
    if [ -z "${text}" ]; then
        note "Splunk started no alert action for this run."
        return 1
    fi
    printf '%s\n' "${text}" | tidy_log
}

# Keep the fields of the scheduler summary that show the result of the run.
scheduler_summary() {
    new_log_lines scheduler.log "$1" "savedsearch_name=\"$2\"" \
    | sed -E 's/.*status=([a-z]+).*result_count=([0-9]+).*alert_actions="([^"]*)".*suppressed=([0-9]+).*/   status=\1 result_count=\2 alert_actions="\3" suppressed=\4/'
}

# ------------------------------------------------------- Adversarial calls ----

report() { python3 "${root}/dev/api_report.py" "$@"; }

# Print the newest incident, with its comments.
newest_incident() {
    local identifier
    identifier="$(report latest 1 | awk 'NR==2 {print $1}')"
    if [ -z "${identifier}" ]; then
        note "The organization holds no incident."
        return 0
    fi
    report show "${identifier}" | sed 's/^/   /'
}

# Print the newest risk, with its comments.
newest_risk() {
    local identifier
    identifier="$(report risks 1 | awk 'NR==2 {print $1}')"
    if [ -z "${identifier}" ]; then
        note "The organization holds no risk."
        return 0
    fi
    report show-risk "${identifier}" | sed 's/^/   /'
}

# --------------------------------------------------------- alert state ----

url_encode() { printf '%s' "$1" | sed 's/ /%20/g'; }

# Change a setting of an example alert. The first argument is the name of the
# alert. The REST handler uses the key `is_scheduled`, and the configuration
# file uses the key `enableSched`.
set_alert() {
    local name="$1"; shift
    splunk_rest POST "/servicesNS/nobody/${app}/saved/searches/$(url_encode "${name}")" \
        "$@" -o /dev/null -w '' || true
}

# Print the search of an example alert.
show_search() {
    splunk_rest GET "/servicesNS/nobody/${app}/saved/searches/$(url_encode "$1")?output_mode=json" \
        | python3 -c 'import json,sys
content = json.load(sys.stdin)["entry"][0]["content"]
for line in content["search"].strip().splitlines():
    print("   " + line.strip())'
}

# Run one example alert once, with its actions, and show the log of the action.
# `trigger_actions=1` starts the actions of the alert, and it ignores the
# suppression, so the demo does not wait for a suppression period to end.
dispatch_alert() {
    local name="$1" action="$2" offset sid
    set_alert "${name}" -d disabled=0
    offset="$(log_size splunkd.log)"
    shown "curl -X POST .../saved/searches/${name}/dispatch -d trigger_actions=1"
    sid="$(splunk_rest POST "/servicesNS/nobody/${app}/saved/searches/$(url_encode "${name}")/dispatch" \
        -d trigger_actions=1 -d output_mode=json \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["sid"])')"
    note "Search ID: ${sid}"
    echo
    note "Log of the alert action, from splunkd.log:"
    scheduled_action_log "${offset}" "${action}" || true
    echo
    step "Disable the alert again, so the demo leaves no schedule behind"
    set_alert "${name}" -d disabled=1 -d is_scheduled=0
}

# ------------------------------------------------------------ scenarios ----

scenario_connect() {
    heading "connect - check the connection" \
        "The app gets an OAuth access token with the client credentials grant."

    step "Ask Splunk to check the stored credentials"
    shown "splunk cmd python3 configure_credentials.py --verify"
    app_python configure_credentials.py --verify | sed 's/^/   /'
    echo
    step "Read the same service account from this workstation"
    shown "python3 dev/api_report.py whoami"
    report whoami | sed 's/^/   /'
    echo
    step "List the incident sources of the organization"
    note "The value of param.source of adversarial_incident must be one of these."
    report sources | sed 's/^/   /' | head -20
    echo
    step "List the risk sources of the organization"
    note "The value of param.source of adversarial_risk must be one of these."
    report risk-sources | sed 's/^/   /' | head -20
}

scenario_adhoc() {
    heading "adhoc - create an incident from a search" \
        "A search starts the alert action with sendalert. The token cache is empty, so the app uses the client credentials."

    local marker="demo-adhoc-$$"
    step "Empty the token cache"
    shown "splunk cmd python3 configure_credentials.py --clear-token-cache"
    app_python configure_credentials.py --clear-token-cache | sed 's/^/   /'
    echo
    step "Run a search that starts the alert action"
    send_alert "${marker}" "| makeresults \
| eval dest=\"vpn-edge-02\", failed_logins=61, src_ip=\"198.51.100.77\", user=\"jdoe\", demo_marker=\"${marker}\" \
| sendalert ${incident_action} param.title=\"Password spray on vpn-edge-02\" \
param.severity=\"SEV-3\" param.status=\"New\" param.source=\"SIEM\" \
param.fields=\"dest,failed_logins,src_ip,user\" \
param.severity_reasoning=\"The VPN gateway shows a password spray from one address.\""
    echo
    step "Read the new incident from the Adversarial API"
    newest_incident
}

scenario_risk() {
    heading "risk - create a risk from a search" \
        "The same sendalert command creates a risk with the second action. The score fields stay empty, so AI Suggest Score assigns them."

    local marker="demo-risk-$$"
    step "Run a search that starts the risk action"
    note "The search holds no param.iru, no param.likelihood and no"
    note "param.impact, so the platform scores the risk."
    send_alert "${marker}" "| makeresults \
| eval control=\"MFA on the VPN\", exempt_users=48, demo_marker=\"${marker}\" \
| sendalert ${risk_action} param.title=\"MFA exemption list holds 48 users\" \
param.description=\"48 accounts have an exemption from MFA on the VPN. An exempt account needs only a password, so a stolen password gives an attacker a session on the internal network.\" \
param.type=\"Control Deficiency\" param.source=\"Attack Surface Monitoring\" \
param.remediation_task=\"Remove the exemption of each account, and give a hardware key to the accounts that cannot use the mobile application.\" \
param.fields=\"control,exempt_users\""
    echo
    step "Read the new risk from the Adversarial API"
    newest_risk
}

scenario_cache() {
    heading "cache - share one token between processes" \
        "Splunk keeps the token in its secret store, so a second process reuses it."

    local marker="demo-cache-$$"
    step "Get a token in one process. The check does not create an incident."
    shown "splunk cmd python3 configure_credentials.py --verify"
    app_python configure_credentials.py --verify | sed 's/^/   /'
    echo
    step "Start the alert action. It is a new process."
    send_alert "${marker}" "| makeresults \
| eval dest=\"db-prod-07\", table=\"customer_pii\", rows=\"420000\", demo_marker=\"${marker}\" \
| sendalert ${incident_action} param.title=\"Large export from db-prod-07\" \
param.severity=\"SEV-4\" param.source=\"SIEM\" param.fields=\"dest,table,rows\" \
param.severity_reasoning=\"A large export of customer data needs a review.\""
    echo
    note "The log line \"Using the cached access token\" proves that the second"
    note "process found the token of the first process."
    echo
    step "Read the new incident"
    newest_incident
}

scenario_refresh() {
    heading "refresh - get a new token with the refresh token" \
        "Near the expiry time, the app uses the refresh token grant. A service account is a confidential client, so the request also holds the client ID and the client secret."

    local marker="demo-refresh-$$"
    step "Move the expiry time of the cached token into the refresh margin"
    docker cp "${root}/dev/age_token_cache.py" "${container}:/tmp/age_token_cache.py" >/dev/null
    shown "splunk cmd python3 dev/age_token_cache.py"
    docker exec --user splunk \
        -e "SPLUNK_USERNAME=${SPLUNK_USERNAME}" \
        -e "SPLUNK_PASSWORD=${SPLUNK_PASSWORD}" \
        "${container}" "${splunk_home}/bin/splunk" cmd python3 /tmp/age_token_cache.py \
        | sed 's/^/   /'
    echo
    step "Start the alert action"
    send_alert "${marker}" "| makeresults \
| eval dest=\"app-web-01\", rule=\"web_shell_upload\", file=\"/var/www/upload/x.php\", demo_marker=\"${marker}\" \
| sendalert ${incident_action} param.title=\"Web shell upload on app-web-01\" \
param.severity=\"SEV-2\" param.source=\"SIEM\" param.fields=\"dest,rule,file\" \
param.severity_reasoning=\"A web shell gives an attacker remote control of the host.\""
    echo
    note "The log line \"Refreshed the access token with the refresh_token grant\""
    note "proves the refresh path."
    echo
    step "Read the new incident"
    newest_incident
}

scenario_detect() {
    heading "detect - run the example detection over indexed data" \
        "The saved search counts failed logins in the index. The alert creates one incident, and it holds the first result of the search."

    step "Check the data in the index"
    local rows
    rows="$(detection_rows)"
    note "The detection returns ${rows} result(s)."
    if [ "${rows}" -eq 0 ]; then
        load_sample_data
        rows="$(detection_rows)"
        note "The detection now returns ${rows} result(s)."
    fi
    echo
    step "Show the search of the alert"
    show_search "${incident_alert}"
    echo
    step "Enable the alert and start one run with its actions"
    dispatch_alert "${incident_alert}" "${incident_action}"
    echo
    step "Read the new incident"
    newest_incident
}

scenario_posture() {
    heading "posture - run the example posture search over indexed data" \
        "The saved search counts the endpoints with no agent. The whole gap is one condition, so the search gives one row, and the row becomes one risk."

    step "Check the data in the index"
    local rows
    rows="$(posture_rows)"
    note "The posture search returns ${rows} result(s)."
    if [ "${rows}" -eq 0 ]; then
        load_sample_data
        rows="$(posture_rows)"
        note "The posture search now returns ${rows} result(s)."
    fi
    echo
    step "Show the search of the alert"
    note "The second stats command turns the hosts into one row, because the"
    note "whole condition is one risk. The row names every affected host, so"
    note "the description of the risk names them too."
    show_search "${risk_alert}"
    echo
    step "Enable the alert and start one run with its actions"
    dispatch_alert "${risk_alert}" "${risk_action}"
    echo
    step "Read the new risk"
    note "The request holds no likelihood and no impact. The platform assigns"
    note "them, and it then derives the urgency and the due date."
    newest_risk
}

scenario_schedule() {
    heading "schedule - let the Splunk scheduler run the alert" \
        "The scheduler starts the alert without a person. The demo shows one run that creates an incident, and one run that Splunk suppresses."

    step "Check the data in the index"
    local rows
    rows="$(detection_rows)"
    if [ "${rows}" -eq 0 ]; then
        load_sample_data
    fi
    note "The detection returns $(detection_rows) result(s)."
    echo

    step "Set a schedule of one minute and a short suppression period"
    note "The app ships with cron_schedule = */5 * * * * and"
    note "alert.suppress.period = 24h. A demo cannot wait that long, so the"
    note "script uses one minute and 90 seconds. It restores both values at"
    note "the end."
    set_alert "${incident_alert}" -d disabled=0 -d is_scheduled=1 \
        -d "cron_schedule=* * * * *" -d "alert.suppress.period=90s"
    echo

    # The demo needs two runs: one that creates an incident, and the next run,
    # which finds the same condition and is therefore suppressed.
    local seen_incident=0 seen_suppressed=0 attempt=0
    local sched_offset action_offset summary
    while [ "${attempt}" -lt 5 ]; do
        attempt=$((attempt + 1))
        sched_offset="$(log_size scheduler.log)"
        action_offset="$(log_size splunkd.log)"
        step "Wait for the next scheduled run"
        if ! wait_for_scheduled_run "${sched_offset}" "${incident_alert}"; then
            break
        fi
        summary="$(scheduler_summary "${sched_offset}" "${incident_alert}")"
        note "Summary of the run, from scheduler.log:"
        printf '%s\n' "${summary}"
        if printf '%s' "${summary}" | grep -q 'suppressed=0'; then
            note "Log of the alert action, from splunkd.log:"
            scheduled_action_log "${action_offset}" "${incident_action}" || true
            seen_incident=1
        else
            note "Splunk suppressed the actions of this run. The alert action"
            note "did not start, so the condition gives one incident and not"
            note "one for every run."
            seen_suppressed=1
            if [ "${seen_incident}" -eq 1 ]; then
                echo
                break
            fi
            note "A recent run already created the incident. The script waits"
            note "for the suppression period to end."
        fi
        echo
    done

    # Restore the alert first, so a failure does not leave a one minute
    # schedule behind.
    step "Restore the shipped state of the alert"
    set_alert "${incident_alert}" -d disabled=1 -d is_scheduled=0 \
        -d "cron_schedule=*/5 * * * *" -d "alert.suppress.period=24h"
    echo

    # The scenario promises two runs. Report a missing run as a failure, so the
    # demo never shows an incident that an earlier scenario created.
    if [ "${seen_incident}" -eq 0 ] || [ "${seen_suppressed}" -eq 0 ]; then
        failed "the scenario needs one run that creates an incident and one" \
            "run that Splunk suppresses."
        note "saw an incident: ${seen_incident}, saw a suppressed run: ${seen_suppressed}"
        note "Check that the index holds recent data, and that the scheduler"
        note "is running. Then run the scenario again."
        return 1
    fi

    step "Read the newest incident"
    newest_incident
}

scenario_reject() {
    heading "reject - the API refuses the record" \
        "A bad source name gives exit code 4. The app writes the answer of the API into the log."

    local marker="demo-reject-$$"
    step "Send an alert with a source that the organization does not hold"
    send_alert "${marker}" "| makeresults \
| eval dest=\"app-web-02\", demo_marker=\"${marker}\" \
| sendalert ${incident_action} param.title=\"Rejected example\" \
param.source=\"Not A Real Source\" param.severity=\"SEV-5\" param.add_comment=\"0\""
    echo
    note "The alert action stops with exit code 4. Splunk keeps the alert, so an"
    note "operator can read the reason in the log."
}

scenario_invalid() {
    heading "invalid - a setting is not valid" \
        "An empty title gives exit code 2, and a bad enum value gives the same code. The app checks the settings before it calls the API."

    local marker="demo-invalid-$$"
    step "Send an incident with an empty title"
    send_alert "${marker}" "| makeresults | eval demo_marker=\"${marker}\" \
| sendalert ${incident_action} param.title=\"\" param.source=\"SIEM\""
    echo
    note "The app makes no API call, because the settings are not complete."
    echo
    marker="demo-invalid-risk-$$"
    step "Send a risk with a likelihood that the API does not hold"
    send_alert "${marker}" "| makeresults | eval demo_marker=\"${marker}\" \
| sendalert ${risk_action} param.title=\"Bad likelihood\" param.likelihood=\"Very Likely\""
    echo
    note "The log names the valid values, so an operator can correct the alert."
}

# --------------------------------------------------------------- helpers ----

# Count the results of a search. The count proves that the index holds the data
# before the demo starts an alert.
search_rows() {
    splunk_rest POST "/servicesNS/nobody/${app}/search/jobs/export" \
        --data-urlencode "search=$1" \
        -d "earliest_time=$2" -d latest_time=now -d output_mode=json \
        | grep -c '"result"' || true
}

detection_rows() {
    search_rows 'search index=main sourcetype="demo:auth" outcome=failure | stats count AS failed_logins BY dest | where failed_logins >= 20' -60m
}

posture_rows() {
    search_rows 'search index=main sourcetype="demo:posture" check="endpoint_baseline" | stats latest(agent_installed) AS agent_installed BY dest | where agent_installed="false" | stats count AS hosts | where hosts >= 5' -24h
}

load_sample_data() {
    note "The index holds no recent data. The script loads the sample events."
    shown "dev/load_sample_data.sh"
    "${root}/dev/load_sample_data.sh" | sed 's/^/   /'
}

# Wait until the scheduler writes the summary of a new run into scheduler.log.
wait_for_scheduled_run() {
    local offset="$1" name="$2" waited=0
    while [ "${waited}" -lt 120 ]; do
        if [ -n "$(new_log_lines scheduler.log "${offset}" "savedsearch_name=\"${name}\"")" ]; then
            sleep 1
            return 0
        fi
        sleep 3
        waited=$((waited + 3))
    done
    note "The scheduler did not run the alert in 120 s."
    return 1
}

# ------------------------------------------------------------------ main ----

SCENARIOS="connect adhoc risk cache refresh detect posture reject invalid"
SLOW="schedule"

list_scenarios() {
    cat <<'TEXT'
Scenarios:
  connect   Check the connection. Show the service account and the sources.
  adhoc     Create an incident from a search. Cold cache: client credentials.
  risk      Create a risk from a search. The platform scores it.
  cache     Share one access token between two processes.
  refresh   Get a new access token with the refresh token grant.
  detect    Run the example detection over indexed data. One incident.
  posture   Run the example posture search over indexed data. One risk.
  reject    Show a rejected record. Exit code 4.
  invalid   Show a setting that is not valid. Exit code 2.

Slow scenario, not part of "all":
  schedule  Let the Splunk scheduler run the alert twice. It shows the
            suppression. It needs about 3 minutes.

Examples:
  dev/demo.sh all
  dev/demo.sh connect detect posture
  dev/demo.sh schedule
TEXT
}

summary() {
    echo
    rule
    printf '%s\n' "${bold}  Incidents in the organization, newest first${plain}"
    rule
    report latest 5 | sed 's/^/   /'
    echo
    rule
    printf '%s\n' "${bold}  Risks in the organization, newest first${plain}"
    rule
    report risks 5 | sed 's/^/   /'
    echo
    note "Open the platform to read them:"
    note "  incidents : http://localhost:5173/adversarial/incidents"
    note "  risks     : http://localhost:5173/adversarial/risks"
    note "  Splunk app: ${SPLUNK_WEB_URL:-http://localhost:8888}/en-US/app/${app}"
    echo
}

main() {
    local wanted=("$@")
    if [ "${#wanted[@]}" -eq 0 ] || [ "${wanted[0]}" = "--help" ] || [ "${wanted[0]}" = "-h" ]; then
        list_scenarios
        return 0
    fi
    if [ "${wanted[0]}" = "--list" ]; then
        list_scenarios
        return 0
    fi
    if [ "${wanted[0]}" = "all" ]; then
        # shellcheck disable=SC2206
        wanted=(${SCENARIOS})
    fi

    for name in "${wanted[@]}"; do
        case " ${SCENARIOS} ${SLOW} " in
            *" ${name} "*) "scenario_${name}" ;;
            *) echo "unknown scenario: ${name}"; list_scenarios; return 2 ;;
        esac
    done
    summary
}

main "$@"
