#!/usr/bin/env python3
"""Local development helper. It is not part of the Splunk app.

The script writes sample events as JSON lines. The two example alerts search
this data.

    python3 dev/make_sample_data.py auth    > /tmp/demo_auth.log
    python3 dev/make_sample_data.py posture > /tmp/demo_posture.log

`auth` holds authentication events over the last hour. The data holds one
brute-force pattern: many failed logins on one host from one address. The rest
of the events are normal traffic. The example detection alert finds the pattern
and creates an incident.

`posture` holds one daily check-in for each endpoint over the last two days.
Seven hosts report no endpoint agent. The example posture alert finds those
hosts and creates one risk for the whole condition.
"""

import datetime
import json
import random
import sys

# -- authentication events ---------------------------------------------------

NORMAL_HOSTS = ("app-web-01", "app-web-02", "db-prod-07", "vpn-edge-02")
NORMAL_USERS = ("alice", "bob", "carla", "dinesh", "erin")
ATTACK_HOST = "auth-gateway-01"
ATTACK_USER = "svc_backup"
ATTACK_ADDRESS = "203.0.113.42"
ATTACK_COUNT = 137
NORMAL_COUNT = 240
WINDOW_SECONDS = 3600

# -- endpoint check-in events ------------------------------------------------

# The host name holds the code of the business unit, so a name and a unit
# always agree.
BUSINESS_UNITS = (
    ("eng", "Engineering"),
    ("fin", "Finance"),
    ("sales", "Sales"),
    ("support", "Support"),
)
OPERATING_SYSTEMS = ("macOS 15.3", "Windows 11 24H2", "Ubuntu 24.04")
CURRENT_AGENT = "7.4.2"
OLD_AGENT = "6.9.1"
ENDPOINT_COUNT = 62
# Hosts that report no endpoint agent. The posture alert finds these.
UNPROTECTED = (
    "lt-eng-0114",
    "lt-eng-0187",
    "lt-fin-0042",
    "lt-sales-0233",
    "lt-sales-0251",
    "lt-support-0078",
    "srv-build-03",
)
CHECKIN_DAYS = 2


def auth_event(moment, target, user, address, outcome):
    """Build one authentication event.

    The target host uses the field name `dest`. Splunk keeps its own `host`
    field for the machine that sent the data, so the event uses a field name
    that does not clash with it.
    """
    return {
        "timestamp": moment.isoformat().replace("+00:00", "Z"),
        "dest": target,
        "app": "sshd",
        "user": user,
        "src_ip": address,
        "outcome": outcome,
        "port": 22,
    }


def auth_events(now):
    """Build the authentication events of the last hour."""
    start = now - datetime.timedelta(seconds=WINDOW_SECONDS)
    events = []

    # Normal traffic. A few failures are usual, so the alert needs a threshold.
    for _ in range(NORMAL_COUNT):
        moment = start + datetime.timedelta(seconds=random.uniform(0, WINDOW_SECONDS))
        outcome = "failure" if random.random() < 0.04 else "success"
        events.append(auth_event(
            moment,
            random.choice(NORMAL_HOSTS),
            random.choice(NORMAL_USERS),
            "198.51.100.%d" % random.randint(2, 60),
            outcome,
        ))

    # The brute-force pattern. The attempts stop in the last five minutes.
    attack_start = now - datetime.timedelta(seconds=900)
    for index in range(ATTACK_COUNT):
        moment = attack_start + datetime.timedelta(seconds=index * 4)
        if moment > now:
            break
        events.append(auth_event(moment, ATTACK_HOST, ATTACK_USER, ATTACK_ADDRESS, "failure"))
    return events


def endpoint_names():
    """Build the host names of the endpoint inventory.

    The list holds the unprotected hosts and enough protected hosts to show
    that the alert counts only the hosts that fail the check.
    """
    names = list(UNPROTECTED)
    for index in range(ENDPOINT_COUNT - len(UNPROTECTED)):
        code = BUSINESS_UNITS[index % len(BUSINESS_UNITS)][0]
        names.append("lt-%s-%04d" % (code, 300 + index))
    return names


def business_unit(host):
    """Return the business unit of a host, from the code in its name."""
    for code, name in BUSINESS_UNITS:
        if "-%s-" % code in host:
            return name
    # A server has no unit code in its name. Engineering owns the build hosts.
    return "Engineering"


def posture_event(moment, host, index):
    """Build one endpoint check-in event.

    A posture check reports the state of a control on one host. The state is a
    standing condition, so the alert that reads it creates a risk.
    """
    protected = host not in UNPROTECTED
    return {
        "timestamp": moment.isoformat().replace("+00:00", "Z"),
        "dest": host,
        "os": OPERATING_SYSTEMS[index % len(OPERATING_SYSTEMS)],
        "business_unit": business_unit(host),
        "agent_installed": "true" if protected else "false",
        # A host without the agent reports no version.
        "agent_version": (CURRENT_AGENT if index % 9 else OLD_AGENT) if protected else "",
        "disk_encryption": "on" if index % 11 else "off",
        "check": "endpoint_baseline",
    }


def posture_events(now):
    """Build one check-in for each endpoint on each of the last days."""
    events = []
    for host_index, host in enumerate(endpoint_names()):
        for day in range(CHECKIN_DAYS):
            moment = now - datetime.timedelta(
                days=day, minutes=random.uniform(0, 240)
            )
            events.append(posture_event(moment, host, host_index))
    return events


DATASETS = {"auth": auth_events, "posture": posture_events}


def main(argv):
    if len(argv) != 1 or argv[0] not in DATASETS:
        sys.stderr.write("usage: make_sample_data.py {%s}\n" % "|".join(DATASETS))
        return 2

    now = datetime.datetime.now(datetime.timezone.utc)
    # A fixed seed keeps two runs of the same demo comparable.
    random.seed(7)
    events = DATASETS[argv[0]](now)

    events.sort(key=lambda item: item["timestamp"])
    for item in events:
        sys.stdout.write(json.dumps(item) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
