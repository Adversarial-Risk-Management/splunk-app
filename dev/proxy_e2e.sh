#!/usr/bin/env bash
# End-to-end test of the proxy setting.
#
# The test starts dev/proxy/compose.yaml. Splunk runs on a network with no route
# out, and an HTTP proxy with a user name and a password is its only path to
# the Adversarial API. The test then shows:
#
#   1. Splunk cannot reach the API on its own.
#   2. Without the proxy setting, an alert fails with exit code 5.
#   3. With a wrong proxy password, the proxy refuses the tunnel, and an alert
#      fails with exit code 5.
#   4. With the proxy setting, an alert creates its incidents over HTTPS, and
#      the proxy log shows the CONNECT tunnel of each request.
#   5. The same works with an http:// API URL, where the proxy forwards each
#      request.
#
# Each check compares the incidents in the API before and after the alert, so
# a record exists only if the request went through the proxy.
#
# The script reads .env: ADVERSARIAL_BASE_URL, ADVERSARIAL_CLIENT_ID,
# ADVERSARIAL_CLIENT_SECRET and SPLUNK_PASSWORD. The API must listen on port
# 8080 of this workstation, on 0.0.0.0. See DEMO.md.
#
# Usage:
#     dev/proxy_e2e.sh          run the test, then stop the containers
#     dev/proxy_e2e.sh --keep   keep the containers for a manual check
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
here="${root}/dev/proxy"
app="adversarial"
splunk_home="/opt/splunk"
keep=0
[ "${1:-}" = "--keep" ] && keep=1

set -a
# shellcheck disable=SC1091
source "${root}/.env"
set +a

export SPLUNK_CONTAINER="adversarial-proxy-splunk"
export PROXY_USER="splunk"
PROXY_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(18))')"
export PROXY_PASSWORD
container="${SPLUNK_CONTAINER}"
compose=(docker compose -f "${here}/compose.yaml")
https_api="https://api.test:8443/api"
http_api="http://host.docker.internal:8080/api"
proxy_url="http://proxy:3128"
run_id="proxy-e2e-$(date +%s)"
failures=0

step() { printf '\n== %s\n' "$*"; }
note() { printf '   %s\n' "$*"; }
pass() { printf '   PASS: %s\n' "$*"; }
fail() { printf '   FAIL: %s\n' "$*"; failures=$((failures + 1)); }

stop() {
    if [ "${keep}" -eq 0 ]; then
        "${compose[@]}" down -v >/dev/null 2>&1 || true
    else
        note "The containers keep running. Splunk Web: http://localhost:8889"
        note "Stop them with: docker compose -f dev/proxy/compose.yaml down -v"
    fi
}
trap stop EXIT

in_splunk() { docker exec --user splunk "${container}" "$@"; }

# Run configure_credentials.py in Splunk. Options with only proxy settings
# change only the proxy.
configure() {
    in_splunk env SPLUNK_USERNAME=admin "SPLUNK_PASSWORD=${SPLUNK_PASSWORD}" "${client_env[@]}" \
        "${splunk_home}/bin/splunk" cmd python3 \
        "${splunk_home}/etc/apps/${app}/bin/configure_credentials.py" "$@"
}
client_env=()

# Store the API URL and the client credentials. Keeps the proxy settings.
configure_api() {
    client_env=("ADVERSARIAL_CLIENT_ID=${ADVERSARIAL_CLIENT_ID}"
                "ADVERSARIAL_CLIENT_SECRET=${ADVERSARIAL_CLIENT_SECRET}")
    configure --base-url "$1"
    client_env=()
}

# Count the incidents whose title holds a text, from this workstation.
count_incidents() {
    python3 "${root}/dev/api_report.py" latest 50 | grep -c -- "$1" || true
}

# Start an alert from a search in Splunk. Prints the exit code of the action.
send_alert() {
    local marker="$1"
    in_splunk "${splunk_home}/bin/splunk" search \
        "| makeresults count=2 | streamstats count AS n | eval host=\"proxy-test-\".n
         | sendalert adversarial_incident param.records=\"each\"
           param.title=\"${marker} {{row.host}}\" param.source=\"SIEM\"
           param.fields=\"host\" param.add_comment=\"1\"" \
        -auth "admin:${SPLUNK_PASSWORD}" >/dev/null 2>&1 || true
    in_splunk sh -c "grep -la '${marker}' ${splunk_home}/var/run/splunk/dispatch/*/search.log \
        | head -1 | xargs grep -a 'action=adversarial_incident'" \
        | sed -E 's/.*(STDERR -  |sendmodalert[^-]*- )//' > "${here}/last_action.log" || true
    grep -oE 'exit code=[0-9]+' "${here}/last_action.log" | tail -1 | cut -d= -f2
}

proxy_log_since() {
    "${compose[@]}" logs --no-log-prefix --since "$1" proxy 2>&1 \
        | grep -E 'Request|Established|[Aa]uth' || true
}

# ---------------------------------------------------------------- start ----

step "Make a test CA and a certificate for api.test"
mkdir -p "${here}/certs"
if [ ! -f "${here}/certs/api.pem" ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=Adversarial proxy test CA" \
        -keyout "${here}/certs/ca.key" -out "${here}/certs/ca.pem" 2>/dev/null
    openssl req -newkey rsa:2048 -nodes -subj "/CN=api.test" \
        -keyout "${here}/certs/api.key" -out "${here}/certs/api.csr" 2>/dev/null
    printf 'subjectAltName=DNS:api.test\n' > "${here}/certs/san.ext"
    openssl x509 -req -in "${here}/certs/api.csr" -CA "${here}/certs/ca.pem" \
        -CAkey "${here}/certs/ca.key" -CAcreateserial -days 30 \
        -extfile "${here}/certs/san.ext" -out "${here}/certs/api.crt" 2>/dev/null
    cat "${here}/certs/api.crt" "${here}/certs/api.key" > "${here}/certs/api.pem"
fi
note "certificate: $(openssl x509 -in "${here}/certs/api.crt" -noout -subject -ext subjectAltName | tr '\n' ' ')"

step "Start the proxy, the TLS front and Splunk"
"${compose[@]}" up -d --build >/dev/null 2>&1
until [ "$(docker inspect -f '{{.State.Health.Status}}' "${container}" 2>/dev/null)" = "healthy" ]; do
    sleep 5
done
note "Splunk is healthy."

step "Install the app"
"${root}/dev/package.sh" >/dev/null
docker cp "${root}/dist/${app}.tar.gz" "${container}:/tmp/${app}.tar.gz"
in_splunk sh -c "rm -rf ${splunk_home}/etc/apps/${app} && tar -xzf /tmp/${app}.tar.gz -C ${splunk_home}/etc/apps/"
# Python in Splunk trusts the test CA of api.test. A proxy that inspects TLS
# needs the same setting for its own CA.
in_splunk sh -c "grep -q SSL_CERT_FILE ${splunk_home}/etc/splunk-launch.conf || echo 'SSL_CERT_FILE=/opt/adversarial-test-ca.pem' >> ${splunk_home}/etc/splunk-launch.conf"
in_splunk "${splunk_home}/bin/splunk" restart >/dev/null 2>&1
note "Installed $(in_splunk grep -m1 '^version' ${splunk_home}/etc/apps/${app}/default/app.conf)."

# ---------------------------------------------------------------- check ----

step "1. Splunk has no route out"
note "networks of ${container}: $(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "${container}")"
note "internal network has no route out: $(docker network inspect -f '{{.Internal}}' adversarial-proxy-test_internal)"
if in_splunk curl -sS -m 5 -o /dev/null "${https_api}/v1/incidents/sources" 2>"${here}/direct.err"; then
    fail "Splunk reached ${https_api} without the proxy"
else
    pass "Splunk cannot reach ${https_api}: $(head -1 "${here}/direct.err")"
fi
if in_splunk curl -sS -m 5 -o /dev/null "${http_api}/v1/incidents/sources" 2>"${here}/direct.err"; then
    fail "Splunk reached ${http_api} without the proxy"
else
    pass "Splunk cannot reach ${http_api}: $(head -1 "${here}/direct.err")"
fi

step "2. Without the proxy setting, the alert fails"
configure_api "${https_api}" >/dev/null
configure --no-proxy >/dev/null
marker="${run_id}-direct"
before="$(count_incidents "${marker}")"
code="$(send_alert "${marker}")"
after="$(count_incidents "${marker}")"
note "action log: $(grep -m1 -E 'not reachable|proxy refused' "${here}/last_action.log" || true)"
if [ "${code}" = "5" ] && [ "${after}" = "${before}" ]; then
    pass "exit code 5, and no incident (${before} -> ${after})"
else
    fail "expected exit code 5 and no incident, got exit code '${code}' and ${before} -> ${after}"
fi

step "3. With a wrong proxy password, the proxy refuses the tunnel"
configure --proxy-url "${proxy_url}" --proxy-user "${PROXY_USER}" --proxy-password "wrong" >/dev/null
marker="${run_id}-badauth"
since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
before="$(count_incidents "${marker}")"
code="$(send_alert "${marker}")"
after="$(count_incidents "${marker}")"
note "action log: $(grep -m1 -E 'not reachable|proxy refused' "${here}/last_action.log" || true)"
note "proxy log for this alert:"
proxy_log_since "${since}" | sed 's/^/     /'
if [ "${code}" = "5" ] && [ "${after}" = "${before}" ] && grep -q 'proxy refused the tunnel' "${here}/last_action.log"; then
    pass "exit code 5, the proxy refused the tunnel, and no incident (${before} -> ${after})"
else
    fail "expected exit code 5, a refused tunnel and no incident, got exit code '${code}' and ${before} -> ${after}"
fi

step "4. With the proxy setting, the alert creates its incidents over HTTPS"
configure --proxy-password "${PROXY_PASSWORD}" >/dev/null
note "stored settings:"
configure --show | sed 's/^/     /'
note "verify:"
configure --verify | sed 's/^/     /'
marker="${run_id}-https"
since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
before="$(count_incidents "${marker}")"
code="$(send_alert "${marker}")"
sleep 2
after="$(count_incidents "${marker}")"
note "action log:"
sed 's/^/     /' "${here}/last_action.log"
note "proxy log for this alert:"
proxy_log_since "${since}" | sed 's/^/     /'
tunnels="$(proxy_log_since "${since}" | grep -c 'CONNECT api.test:8443' || true)"
if [ "${code}" = "0" ] && [ "$((after - before))" = "2" ] && [ "${tunnels}" -ge 1 ]; then
    pass "exit code 0, 2 new incidents (${before} -> ${after}), ${tunnels} CONNECT tunnels in the proxy log"
else
    fail "expected exit code 0, 2 incidents and CONNECT tunnels, got exit code '${code}', ${before} -> ${after}, ${tunnels} tunnels"
fi
note "incidents in the API:"
python3 "${root}/dev/api_report.py" latest 10 | grep -- "${marker}" | sed 's/^/     /' || true

step "5. With an http:// API URL, the proxy forwards each request"
configure_api "${http_api}" >/dev/null
marker="${run_id}-http"
since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
before="$(count_incidents "${marker}")"
code="$(send_alert "${marker}")"
sleep 2
after="$(count_incidents "${marker}")"
note "proxy log for this alert:"
proxy_log_since "${since}" | sed 's/^/     /'
forwarded="$(proxy_log_since "${since}" | grep -c 'http://host.docker.internal:8080/api/v1/' || true)"
if [ "${code}" = "0" ] && [ "$((after - before))" = "2" ] && [ "${forwarded}" -ge 1 ]; then
    pass "exit code 0, 2 new incidents (${before} -> ${after}), ${forwarded} forwarded requests in the proxy log"
else
    fail "expected exit code 0, 2 incidents and forwarded requests, got exit code '${code}', ${before} -> ${after}, ${forwarded} requests"
fi

step "Result"
if [ "${failures}" -eq 0 ]; then
    note "All checks passed. Run ID: ${run_id}"
else
    note "${failures} check(s) failed. Run ID: ${run_id}"
    exit 1
fi
