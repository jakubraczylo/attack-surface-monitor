"""
state.py

Keeps track of what we found during the last scan so we can compare it
with the next one.

The idea is pretty simple: instead of showing the entire attack surface
every time, we can spot what's changed since the last scan.

State is stored as a JSON file for now. This is a small project with
relatively simple data, so using a database would be unnecessary.
"""

import json
import os

DEFAULT_STATE = {
    "subdomains": [],
    "ports": {},   # host -> list of open ports
}


def load_state(path: str) -> dict:
    """
    Load the previous scan results.

    On the first run there won't be a state file, so we just start with
    an empty state. That means anything we find will count as new.
    """
    if not os.path.exists(path):
        return dict(DEFAULT_STATE)

    with open(path, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            # Something went wrong with the file, so start fresh.
            print(f"[!] {path} was corrupted, starting from a clean state")
            return dict(DEFAULT_STATE)


def save_state(path: str, subdomains: set[str], ports: dict[str, set[int]]) -> None:
    """Save the latest scan results so they can be used next time."""
    state = {
        "subdomains": sorted(subdomains),
        "ports": {host: sorted(open_ports) for host, open_ports in ports.items()},
    }
    with open(path, "w") as f:
        json.dump(state, f, indent=2)


def diff_subdomains(old: list[str], new: set[str]) -> set[str]:
    """Find subdomains that weren't there during the previous scan."""
    return new - set(old)


def diff_ports(old: dict[str, list[int]], new: dict[str, set[int]]) -> dict[str, set[int]]:
    """
    Find ports that are open now but weren't open during the last scan.

    Hosts with no new ports are left out of the result.
    """
    newly_open = {}
    for host, current_ports in new.items():
        previously_open = set(old.get(host, []))
        added = current_ports - previously_open
        if added:
            newly_open[host] = added
    return newly_open