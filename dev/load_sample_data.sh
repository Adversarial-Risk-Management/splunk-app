#!/usr/bin/env bash
# Load the sample data into a local Splunk container.
#
# The script loads two datasets:
#
#   demo:auth      authentication events, for the detection alert
#   demo:posture   endpoint check-in events, for the posture alert
#
# The events cover the last hours, so run the script again before a new demo.
#
# The script reads SPLUNK_CONTAINER, SPLUNK_USERNAME and SPLUNK_PASSWORD from
# .env. Give a dataset name to load only one of them.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

set -a
# shellcheck disable=SC1091
source "${root}/.env"
set +a

container="${SPLUNK_CONTAINER:-so1}"
splunk_home="/opt/splunk"
stamp="$(date +%s)"

load() {
    local dataset="$1" sourcetype="demo:$1"
    local local_file="${root}/dist/demo_${dataset}.log"
    local remote_file="/tmp/demo_${dataset}_${stamp}.log"

    echo "-> build the ${dataset} events"
    mkdir -p "${root}/dist"
    python3 "${root}/dev/make_sample_data.py" "${dataset}" > "${local_file}"
    wc -l < "${local_file}" | xargs echo "   events:"

    echo "-> copy the ${dataset} events into ${container}"
    docker cp "${local_file}" "${container}:${remote_file}"

    echo "-> index the ${dataset} events as ${sourcetype}"
    docker exec --user splunk "${container}" "${splunk_home}/bin/splunk" add oneshot \
        "${remote_file}" -index main -sourcetype "${sourcetype}" \
        -auth "${SPLUNK_USERNAME}:${SPLUNK_PASSWORD}"
}

datasets=("$@")
if [ "${#datasets[@]}" -eq 0 ]; then
    datasets=(auth posture)
fi

for dataset in "${datasets[@]}"; do
    load "${dataset}"
done
