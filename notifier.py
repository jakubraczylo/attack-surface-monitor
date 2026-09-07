"""
notifier.py

Formats diff results into a message and posts it to a Discord webhook.

Webhook URL comes from an environment variable rather than being hardcoded
or passed on the command line - don't want to end up with a webhook URL
sitting in shell history or, worse, committed to the repo by accident.
"""

import os
import requests

WEBHOOK_ENV_VAR = "DISCORD_WEBHOOK_URL"
EMBED_COLOR = 0xE62222  # red, matches the rest of the project's theme


def _get_webhook_url() -> str | None:
    url = os.environ.get(WEBHOOK_ENV_VAR)
    if not url:
        print(f"[!] {WEBHOOK_ENV_VAR} not set, skipping notification")
        return None
    return url


def _build_embed(target: str, new_subdomains: set[str], new_ports: dict[str, set[int]]) -> dict:
    """Build a single Discord embed summarising everything new this run."""
    fields = []

    if new_subdomains:
        value = "\n".join(f"`{sub}`" for sub in sorted(new_subdomains))
        fields.append({"name": "New subdomains", "value": value, "inline": False})

    if new_ports:
        lines = []
        for host, ports in sorted(new_ports.items()):
            port_list = ", ".join(str(p) for p in sorted(ports))
            lines.append(f"`{host}` → {port_list}")
        fields.append({"name": "New open ports", "value": "\n".join(lines), "inline": False})

    return {
        "title": f"Attack surface change detected: {target}",
        "color": EMBED_COLOR,
        "fields": fields,
    }


def send_alert(target: str, new_subdomains: set[str], new_ports: dict[str, set[int]]) -> bool:
    """
    Post an alert to Discord if there's anything new to report. Returns
    True if a notification was sent (or there was nothing to send),
    False if sending failed - so the caller can decide whether to retry
    or just log it.
    """
    if not new_subdomains and not new_ports:
        # nothing changed, nothing to say - don't spam the channel with
        # "no changes" every single run
        return True

    webhook_url = _get_webhook_url()
    if not webhook_url:
        return False

    payload = {"embeds": [_build_embed(target, new_subdomains, new_ports)]}

    try:
        response = requests.post(webhook_url, json=payload, timeout=10)
        response.raise_for_status()
        return True
    except requests.RequestException as exc:
        print(f"[!] Failed to send Discord alert: {exc}")
        return False


if __name__ == "__main__":
    test_subs = {"vpn.example.com", "staging.example.com"}
    test_ports = {"www.example.com": {8080, 8443}}
    sent = send_alert("example.com", test_subs, test_ports)
    print("Sent!" if sent else "Failed to send.")
