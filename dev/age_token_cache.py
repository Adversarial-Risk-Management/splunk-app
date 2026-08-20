#!/usr/bin/env python
"""Local development helper. It is not part of the Splunk app.

The access token is valid for 15 minutes, so a demo does not usually show the
refresh grant. This script moves the expiry time of the cached token to a point
inside the refresh margin. The next alert then uses the refresh token.

Run it on the Splunk server:

    $SPLUNK_HOME/bin/splunk cmd python3 dev/age_token_cache.py

The script reads the Splunk user name and password from the SPLUNK_USERNAME and
SPLUNK_PASSWORD environment variables.
"""

import json
import os
import sys
import time

# `splunk cmd` replaces PYTHONPATH, so the script adds the app to the path.
SPLUNK_HOME = os.environ.get("SPLUNK_HOME", "/opt/splunk")
sys.path.insert(0, os.path.join(SPLUNK_HOME, "etc", "apps", "adversarial", "bin"))

from splunk_rest import TOKEN_CACHE_USERNAME, SplunkRest  # noqa: E402

SECONDS_LEFT = 30


def main():
    rest = SplunkRest(os.environ.get("SPLUNK_MANAGEMENT_URI", "https://localhost:8089"))
    rest.login(os.environ.get("SPLUNK_USERNAME", "admin"), os.environ["SPLUNK_PASSWORD"])

    raw = rest.read_secret(TOKEN_CACHE_USERNAME)
    if not raw:
        print("The token cache is empty. Run an alert first.")
        return 1

    state = json.loads(raw)
    state["expires_at"] = time.time() + SECONDS_LEFT
    rest.write_secret(TOKEN_CACHE_USERNAME, json.dumps(state))

    print("The cached access token now expires in %d s." % SECONDS_LEFT)
    print("It holds a refresh token: %s" % bool(state.get("refresh_token")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
