# Development helpers

These scripts help you test the app on a workstation. They are not part of the
Splunk app.

## App icons

The app holds five icons. They come from the Adversarial brand mark at
https://static.adversarial.com/adversarial_mark.png:

| Path | Size | Where Splunk shows it |
| --- | --- | --- |
| `adversarial/static/appIcon.png` | 36 x 36 | App list |
| `adversarial/static/appIcon_2x.png` | 72 x 72 | The same, high density |
| `adversarial/static/appIconAlt.png` | 36 x 36 | App rail, the bar on the left |
| `adversarial/static/appIconAlt_2x.png` | 72 x 72 | The same, high density |
| `adversarial/appserver/static/appIcon.png` | 36 x 36 | The alert action list |

The app rail reads the `appIconAlt` files, and the app list reads the `appIcon`
files. An app without the `appIconAlt` files gets a letter in the app rail,
because Splunk answers the request with an empty image. Every app of Splunk
holds both sets, and this app holds the same icon in both.

The mark is a black circle with the letter cut out of it. Splunk puts the app
icon on dark chrome, which shows through the cut and hides the letter. The icons
therefore hold white behind the mark. The icon is then a full square, like the
icon of the other Splunk apps.

Splunk sends an icon with a cache time of one year, and Splunk Web keeps its own
copy. After you copy new icons into a running container, restart Splunk Web and
then do a hard reload in the browser:

    docker exec so1 /opt/splunk/bin/splunk restart splunkweb

The restart takes about 4 seconds. It does not stop the indexer or the
scheduler. `dev/install.sh` restarts all of Splunk, so it needs no extra step.

## `make_sample_data.py`

Write sample events as JSON lines. The script takes the name of a dataset.

    python3 dev/make_sample_data.py auth > /tmp/demo_auth.log
    python3 dev/make_sample_data.py posture > /tmp/demo_posture.log

| Dataset | Events | Content | Example alert |
| --- | --- | --- | --- |
| `auth` | 377 | Authentication events over the last hour. One host holds 137 failed logins from one address. | The detection, which creates an incident |
| `posture` | 124 | Endpoint check-in events over the last two days, for 62 endpoints. Seven endpoints report no endpoint agent. | The posture search, which creates a risk |

## `load_sample_data.sh`

Build the sample events, copy them into the Splunk container and index them
into the `main` index. The source type of a dataset is `demo:<dataset>`. Run
the script again before a new demo, because the events must be recent.

    dev/load_sample_data.sh              # both datasets
    dev/load_sample_data.sh posture      # one dataset

## `api_report.py`

Read the Adversarial API and print the result as text. The demo script uses it
to show the records that Splunk created. The script needs the values of `.env`
in the environment:

    set -a; source .env; set +a

| Command | Result |
| --- | --- |
| `whoami` | The identity of the service account |
| `sources` | The incident sources of the organization |
| `risk-sources` | The risk sources of the organization |
| `latest [n]` | The newest incidents, one for each line |
| `risks [n]` | The newest risks, one for each line |
| `show INC-00001` | One incident, with its description and its comments |
| `show-risk RSK-00001` | One risk, with its score, its description and its comments |
| `count` | The number of incidents |

## `age_token_cache.py`

Move the expiry time of the cached access token to a point inside the refresh
margin. The next alert then uses the refresh token. Run it on the Splunk
server.

    $SPLUNK_HOME/bin/splunk cmd python3 age_token_cache.py

## `package.sh`

Build the installable app archive in `dist/`.

    dev/package.sh

## `install.sh`

Build the archive, copy it into a local Splunk container and restart Splunk.
The script reads the settings from `.env`.

    dev/install.sh

## `demo.sh`

Run the command line demo. Each scenario shows one part of the feature, with
the log lines of the alert action and the record that the API holds.

    dev/demo.sh --list
    dev/demo.sh all
    dev/demo.sh schedule

`DEMO.md` holds the setup steps and a table of the scenarios.
