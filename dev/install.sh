#!/usr/bin/env bash
# Install the app into a local Splunk container, then store the credentials.
#
# The script reads these values from .env:
#   SPLUNK_CONTAINER            container name
#   SPLUNK_USERNAME             Splunk user
#   SPLUNK_PASSWORD             Splunk password
#   ADVERSARIAL_BASE_URL_CONTAINER  API URL that the container can reach
#   ADVERSARIAL_CLIENT_ID           service account client ID
#   ADVERSARIAL_CLIENT_SECRET       service account client secret
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
app="adversarial"

set -a
# shellcheck disable=SC1091
source "${root}/.env"
set +a

container="${SPLUNK_CONTAINER:-so1}"
splunk_home="/opt/splunk"

"${root}/dev/package.sh" >/dev/null
echo "-> copy the archive into ${container}"
docker cp "${root}/dist/${app}.tar.gz" "${container}:/tmp/${app}.tar.gz"

echo "-> extract the app"
docker exec --user splunk "${container}" rm -rf "${splunk_home}/etc/apps/${app}"
docker exec --user splunk "${container}" \
    tar -xzf "/tmp/${app}.tar.gz" -C "${splunk_home}/etc/apps/"

echo "-> restart Splunk"
docker exec --user splunk "${container}" "${splunk_home}/bin/splunk" restart

echo "-> store the credentials"
docker exec --user splunk \
    -e "SPLUNK_USERNAME=${SPLUNK_USERNAME}" \
    -e "SPLUNK_PASSWORD=${SPLUNK_PASSWORD}" \
    -e "ADVERSARIAL_BASE_URL=${ADVERSARIAL_BASE_URL_CONTAINER}" \
    -e "ADVERSARIAL_CLIENT_ID=${ADVERSARIAL_CLIENT_ID}" \
    -e "ADVERSARIAL_CLIENT_SECRET=${ADVERSARIAL_CLIENT_SECRET}" \
    "${container}" "${splunk_home}/bin/splunk" cmd python3 \
    "${splunk_home}/etc/apps/${app}/bin/configure_credentials.py"

echo "-> check the credentials"
docker exec --user splunk \
    -e "SPLUNK_USERNAME=${SPLUNK_USERNAME}" \
    -e "SPLUNK_PASSWORD=${SPLUNK_PASSWORD}" \
    "${container}" "${splunk_home}/bin/splunk" cmd python3 \
    "${splunk_home}/etc/apps/${app}/bin/configure_credentials.py" --verify
