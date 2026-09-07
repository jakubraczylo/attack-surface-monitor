# attack-surface-monitor

A small tool that watches a domain for changes to its attack surface —
new subdomains, newly opened ports, and new TLS certificates — and pushes
alerts to Discord when something changes.

## Why I started this

While learning penetration testing and reconnaissance, I kept coming across
the idea that an organisation's attack surface is constantly changing.
Subdomains appear, services get exposed, certificates are issued, and
infrastructure moves around.

This got me wondering:

> How would you actually notice those changes if you were monitoring a
> target over a period of time?

I wanted to build something small that could answer that question for myself.

Rather than running reconnaissance against a domain once and throwing the
results away, `attack-surface-monitor` keeps track of what it has already seen
and alerts when something new appears.

I started with certificate-transparency-based subdomain discovery and port
scanning, with the intention of gradually expanding it into a more complete
attack-surface monitoring tool.

The main goal is to understand how the individual pieces of reconnaissance
and attack-surface monitoring work by building them myself rather than just
using existing tools.

## Status

Early development. Currently implemented:

- Subdomain enumeration via certificate transparency logs (`crt.sh`)
- Port scanning
- State diffing (only alert on *new* things)
- Discord webhook alerts

More functionality will be added as the project develops.

## Usage

Install the dependencies:

```bash
pip install -r requirements.txt
```

Run subdomain enumeration against a domain:

```bash
python subdomains.py example.com
```

Only scan systems you own or have explicit permission to test.
