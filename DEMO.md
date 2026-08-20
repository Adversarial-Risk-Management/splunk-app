# Demo guide

This guide sets up a demo of the Adversarial app for Splunk. The demo
runs Splunk alerts over indexed data. The alerts create an incident and a risk
in the Adversarial platform.

The direction of the data is always the same:

    indexed data -> saved search -> alert action -> Adversarial API -> record

The demo uses both alert actions:

| Search | Action | Record |
| --- | --- | --- |
| A detection counts failed logins for each host. | `adversarial_incident` | One incident for the host with the most failed logins |
| A posture check counts the endpoints with no agent. | `adversarial_risk` | One risk for the whole gap |

Splunk starts an alert action one time for each alert firing, and it sends the
first search result. The detection therefore ends with `sort`, and the posture
search aggregates the hosts into one row.

## What you need

| Item | Value in this demo |
| --- | --- |
| Splunk Enterprise in a container | name `so1`, web interface on port 8888 |
| The Adversarial API | `http://localhost:8080/api` |
| A credential service account | client ID and client secret |
| Python 3.9 or later | for the helper scripts |
| [uv](https://docs.astral.sh/uv/) | for the tests |

## Step 1 - create a service account

1. Open the Adversarial platform.
2. Go to **Settings > Team > Service Accounts**.
3. Select **Create**, and give the account the **Incident Editor** and
   **Risk Editor** roles. The demo creates both record types, so it needs both.
   The **Editor** role also works.
4. Copy the client ID and the client secret before you close the dialog. The
   platform shows the secret one time.

To add a role later, select the pencil icon of the service account, add the
role, and select **Confirm**. The client ID and the client secret do not
change.

## Step 2 - write the .env file

Put a `.env` file in the root of this repository:

    ADVERSARIAL_BASE_URL=http://localhost:8080/api
    ADVERSARIAL_BASE_URL_CONTAINER=http://host.docker.internal:8080/api
    ADVERSARIAL_CLIENT_ID=arm_sa_...
    ADVERSARIAL_CLIENT_SECRET=arm_sk_...
    SPLUNK_CONTAINER=so1
    SPLUNK_WEB_URL=http://localhost:8888
    SPLUNK_USERNAME=admin
    SPLUNK_PASSWORD='your-password'

Notes:

- `ADVERSARIAL_BASE_URL` is the URL that your workstation uses.
- `ADVERSARIAL_BASE_URL_CONTAINER` is the URL that the Splunk container uses.
  The two values differ, because the container has its own network.
- Put the Splunk password in single quotes if it holds a `$` character.

## Step 3 - make the API reachable from the container

The Splunk container has its own network. It reaches your workstation through
the name `host.docker.internal`, which is not a loopback address. Your API
server must therefore listen on `0.0.0.0`. A server that listens only on
`localhost`, `127.0.0.1` or `[::1]` accepts no connection from the container.

Test the path from inside the container. A 401 answer is correct, because the
test sends no token:

    docker exec so1 curl -s -o /dev/null -w '%{http_code}\n' \
        http://host.docker.internal:8080/api/v1/incidents/sources

An answer of `000` means the container cannot reach the API. Check the listen
address of your server:

    lsof -nP -iTCP:8080 -sTCP:LISTEN

The address must be `*:8080`, not `[::1]:8080`.

## Step 4 - install the app and store the credentials

    dev/install.sh

The script builds the archive, copies it into the container, restarts Splunk,
writes the credentials into the Splunk secret store, and checks them. The last
line shows the name of the service account.

The restart ends the Splunk Web sessions. Sign in again before you open the
app.

Splunk keeps the client secret encrypted in the secret store. The secret is
never written to a configuration file.

## Step 5 - load the sample data

    dev/load_sample_data.sh

The script writes two datasets into the `main` index:

| Source type | Events | Content |
| --- | --- | --- |
| `demo:auth` | 377 | Authentication events. One host, `auth-gateway-01`, holds 137 failed logins from one address. The other hosts hold normal traffic. |
| `demo:posture` | 124 | Endpoint check-in events for 62 endpoints. Seven endpoints report no endpoint agent. |

Give a dataset name to load only one of them, for example
`dev/load_sample_data.sh auth`.

The auth events cover the last hour, and the posture events cover the last two
days. Run the script again before a new demo, because the detection searches
the last 60 minutes.

## Step 6 - run the demo

    dev/demo.sh --list        # show the scenarios
    dev/demo.sh all           # run every quick scenario
    dev/demo.sh connect       # run one scenario

Each scenario prints the command, the log lines of the alert action, and the
record that the Adversarial API holds.

| Scenario | What it shows |
| --- | --- |
| `connect` | The client credentials grant. The identity of the service account. The list of valid incident sources and risk sources. |
| `adhoc` | A search creates an incident with `sendalert`. The token cache is empty, so the app uses the client credentials. |
| `risk` | The same command creates a risk with the second action. The score fields stay empty, so AI Suggest Score assigns them. |
| `cache` | Two processes share one access token, because Splunk keeps it in the secret store. |
| `refresh` | The app gets a new access token with the refresh token grant. |
| `detect` | The example detection runs over the indexed data and creates one incident for the host above the threshold. |
| `posture` | The example posture search runs over the indexed data. It aggregates 7 endpoints into one row, so the run creates one risk. |
| `reject` | The API refuses a bad source name. The alert action stops with exit code 4. |
| `invalid` | An empty title, and a likelihood that the API does not hold, both stop the alert action with exit code 2, before any API call. |

One slow scenario is not part of `all`:

| Scenario | What it shows |
| --- | --- |
| `schedule` | The Splunk scheduler runs the alert without a person. One run creates an incident. The next run finds the same condition, and Splunk suppresses the action. It needs about 3 minutes. |

The `schedule` scenario changes the schedule to one minute and the suppression
period to 90 seconds, so that you can see both cases. It restores the shipped
values at the end.

## Step 7 - look at the result

- Incidents in the platform: <http://localhost:5173/adversarial/incidents>
- Risks in the platform: <http://localhost:5173/adversarial/risks>. Select
  **Clear all filters**. The default view filters on the urgency, and a new
  risk has no urgency until it holds a likelihood and an impact.
- The app in Splunk: <http://localhost:8888/en-US/app/adversarial>
- The setup page: **Adversarial > Setup**
- The example alerts: **Settings > Searches, reports, and alerts**. Set the
  Owner filter to **All**, because the app owns the alerts, not a person.

To read the records from the command line:

    set -a; source .env; set +a
    python3 dev/api_report.py latest 10
    python3 dev/api_report.py show INC-00001
    python3 dev/api_report.py risks 10
    python3 dev/api_report.py show-risk RSK-00001

## Reset the demo

    set -a; source .env; set +a

    # Get a new token on the next alert.
    docker exec --user splunk -e SPLUNK_USERNAME -e SPLUNK_PASSWORD so1 \
        /opt/splunk/bin/splunk cmd python3 \
        /opt/splunk/etc/apps/adversarial/bin/configure_credentials.py \
        --clear-token-cache

    # Load new sample events, because the alert searches the last hour.
    dev/load_sample_data.sh

The example alerts ship disabled. Every scenario that enables one also
disables it again, so the demo leaves no schedule behind.

## Troubleshooting

| Problem | Cause and action |
| --- | --- |
| `dev/install.sh` stops at the credential check | The container cannot reach the API. Test the path with the `curl` command in step 3. Check that the API listens on `0.0.0.0`. |
| The `detect` or `posture` scenario finds 0 results | The sample events are too old. Run `dev/load_sample_data.sh`. |
| Exit code 3 in the log | The client ID or the client secret is wrong, the service account is not active, or the account does not hold the role for the record type. |
| Exit code 4 in the log | The source name is not one of the sources of the organization. Run `dev/demo.sh connect` to list them. The risk sources and the incident sources are two separate lists. |
| HTTP 403 "Insufficient permissions" | The service account holds no role for that record type. Add **Risk Editor** or **Incident Editor** in step 1. |
| Exit code 5 in the log | The Splunk server cannot reach the API URL. Check `ADVERSARIAL_BASE_URL_CONTAINER`. |
| The setup page stays empty | Reload the page. Splunk needs the app permissions from `metadata/default.meta`. |

## Tests

The unit tests need no network and no Splunk server:

    uv sync
    uv run pytest

The tests cover the shared payload logic, the incident mapping, the risk
mapping, the token lifecycle and the exit codes.
