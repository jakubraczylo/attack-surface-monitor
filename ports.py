"""
ports.py

Does a basic TCP connect scan against a list of hosts. Not trying to
reinvent nmap, this checks a fixed list of common ports and just
tells you which ones answered.

Went with plain sockets + threads instead of shelling out to nmap because
(a) no extra install dependency for whoever runs this, and (b) writing the
connect logic myself means I can actually explain how it works instead of
just calling someone else's binary.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

# Ports worth checking for a "did something new get exposed" monitor -
# not trying to cover all 65535, just the ones that actually matter if
# they suddenly appear.
COMMON_PORTS = [
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    80,    # HTTP
    110,   # POP3
    143,   # IMAP
    443,   # HTTPS
    445,   # SMB
    3306,  # MySQL
    3389,  # RDP
    5432,  # PostgreSQL
    8080,  # HTTP alt
    8443,  # HTTPS alt
]

CONNECT_TIMEOUT = 2  # seconds - don't want one dead host stalling everything
MAX_WORKERS = 50


def _check_port(host: str, port: int) -> bool:
    """Try to open a TCP connection to host:port. True if it succeeds."""
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        # OSError also covers "host doesn't resolve" / "network unreachable"
        # etc - for this tool's purposes all of those just mean "no port here"
        return False


def scan_host(host: str, ports: list[int] = None) -> set[int]:
    """
    Check a single host against a list of ports (defaults to COMMON_PORTS)
    and return the set of ports that responded.
    """
    ports = ports or COMMON_PORTS
    open_ports = set()

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(_check_port, host, port): port for port in ports}
        for future in as_completed(futures):
            port = futures[future]
            if future.result():
                open_ports.add(port)

    return open_ports


def scan_hosts(hosts: set[str], ports: list[int] = None) -> dict[str, set[int]]:
    """
    Scan multiple hosts and return {host: {open_ports}}. Hosts with no
    open ports found are still included with an empty set, so callers
    can tell "scanned, found nothing" apart from "never scanned".
    """
    results = {}
    for host in hosts:
        results[host] = scan_host(host, ports)
    return results


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <host>", file=sys.stderr)
        sys.exit(1)

    target = sys.argv[1]
    print(f"[+] Scanning {target} on {len(COMMON_PORTS)} common ports...")
    open_ports = scan_host(target)

    if open_ports:
        print(f"[+] Open ports on {target}:")
        for port in sorted(open_ports):
            print(f"    {port}")
    else:
        print(f"[-] No open ports found on {target}")
