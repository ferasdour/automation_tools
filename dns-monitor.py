import time
import socket
from datetime import datetime
from tinydb import TinyDB, Query
import dns.resolver

DOMAIN_DB  = TinyDB("track_domains.json")
RESOLVE_DB = TinyDB("resolutions.json")
DomainList = Query()
Resolution = Query()

def resolve(domain):
    try:
        dnscheck = resolver.Resolver()
        dnscheck.nameservers = ["208.67.222.222","208.67.220.220"]
        result = dnscheck(domain, "A", lifetime=5)
        return sorted({str(r) for r in result})
    except Exception:
        return []

def load_domains():
    return [r["name"] for r in DOMAIN_DB.all()]

def add_domain(name):
    if not DOMAIN_DB.search(DomainList.name == name):
        DOMAIN_DB.insert({"name": name})
        print(f" Added {name} to tracking.")
    else:
        print(f"{name} is already being tracked.")

def get_last_ips(domain):
    recs = RESOLVE_DB.search(Resolution.domain == domain)
    if recs:
        latest = sorted(recs, key=lambda r: r["timestamp"], reverse=True)[0]
        return set(latest["ips"])
    return set()

def log_resolution(domain, new_ips):
    now = datetime.utcnow().isoformat()
    RESOLVE_DB.insert({
        "domain": domain,
        "ips": new_ips,
        "timestamp": now
    })

def timeline(domain):
    recs = RESOLVE_DB.search(Resolution.domain == domain)
    print(f"\nResolution timeline for {domain} ({len(recs)} events):")
    for r in sorted(recs, key=lambda r: r["timestamp"]):
        print(f"{r['timestamp']} → {', '.join(r['ips'])}")

def track_loop(interval=300):
    while True:
        print(f"\n Checking domains @ {datetime.utcnow().isoformat()}")
        domains = load_domains()
        for d in domains:
            new_ips = set(resolve(d))
            old_ips = get_last_ips(d)
            if new_ips != old_ips:
                log_resolution(d, list(new_ips))
                added = new_ips - old_ips
                dropped = old_ips - new_ips
                print(f" {d}: Changed. Added: {added}, Dropped: {dropped}")
            else:
                print(f" {d}: No change.")
        time.sleep(interval)

def cli_menu():
    while True:
        print("\n Domain Tracker Menu:")
        print("1. Start tracking loop")
        print("2. Add domain")
        print("3. View last IPs")
        print("4. Show timeline")
        print("5. Quit")
        choice = input("-> ").strip()
        if choice == "1":
            interval = input("Interval (seconds): ").strip()
            try:
                track_loop(int(interval))
            except KeyboardInterrupt:
                print("\n Tracking paused.")
        elif choice == "2":
            name = input("Domain to add: ").strip()
            add_domain(name)
        elif choice == "3":
            for d in load_domains():
                ips = get_last_ips(d)
                print(f"{d}: {', '.join(sorted(ips))}")
        elif choice == "4":
            name = input("Domain to analyze: ").strip()
            timeline(name)
        elif choice == "5":
            print("exiting")
            break
        else:
            print(" Invalid option.")

if __name__ == "__main__":
    cli_menu()
