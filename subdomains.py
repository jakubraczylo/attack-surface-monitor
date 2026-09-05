"""
subdomains.py
 
Pulls subdomains for a target domain out of crt.sh, which is basically a
searchable frontend for certificate transparency (CT) logs.
 
Went with this instead of brute-forcing a wordlist because every public
TLS cert gets logged to CT by design (that's literally how browsers catch
someone mis-issuing a cert for your domain). So if I search crt.sh for
"%.example.com" I get every subdomain that's ever had a cert issued for
it - including random internal-looking stuff nobody linked anywhere,
which a wordlist would just never find. Bonus: it's 100% passive, no
packets ever touch the actual target, and it costs nothing.
 
Only real dependency here is `requests`, kept it minimal on purpose.
"""
 
import sys
import requests
 
CRTSH_URL = "https://crt.sh/"
 
 
def get_subdomains(domain: str) -> set[str]:
    """
    Hit crt.sh for every cert covering *.{domain} and return the unique
    subdomains pulled out of them.
    """
    params = {"q": f"%.{domain}", "output": "json"}
 
    try:
        response = requests.get(CRTSH_URL, params=params, timeout=30)
        response.raise_for_status()
    except requests.RequestException as exc:
        print(f"[!] Failed to query crt.sh: {exc}", file=sys.stderr)
        return set()
 
    try:
        entries = response.json()
    except ValueError:
        # crt.sh isn't the most reliable - under load it'll sometimes just
        # send back an empty or broken body instead of a proper error.
        # Rather than blow up the whole run over that, just treat it like
        # "found nothing" and move on.
        print("[!] crt.sh returned an unparseable response", file=sys.stderr)
        return set()
 
    subdomains = set()
    for entry in entries:
        name_value = entry.get("name_value", "")
        # certs can cover multiple names at once (SANs), crt.sh just
        # newline-separates them in this field
        for name in name_value.split("\n"):
            name = name.strip().lower()
            if name and not name.startswith("*."):
                subdomains.add(name)
 
    return subdomains
 
 
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <domain>", file=sys.stderr)
        sys.exit(1)
 
    target = sys.argv[1]
    found = get_subdomains(target)
 
    print(f"[+] Found {len(found)} subdomain(s) for {target}:")
    for sub in sorted(found):
        print(f"    {sub}")