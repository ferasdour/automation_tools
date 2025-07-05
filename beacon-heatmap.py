#!/usr/bin/env python3
import os, time, threading, argparse
from datetime import datetime
import numpy as np
import matplotlib
import matplotlib.pyplot as plt
from scapy.all import sniff, PcapReader, Dot11, Dot11Beacon, Dot11ProbeReq, Dot11Elt
from tinydb import TinyDB, Query
from tinydb.operations import increment
from tinydb.storages import JSONStorage
from tinydb.middlewares import CachingMiddleware
from pwn import *
matplotlib.use("TkAgg")

BROADCAST = "ff:ff:ff:ff:ff:ff"

def convert_time_to_weekday(dt_obj):
    return (dt_obj.weekday() + 1) % 7

def insert_or_increment(tbl, host, day, minute):
    Host = Query()
    entry = tbl.get((Host.host == host) &
                    (Host.day == day) &
                    (Host.minute == minute))
    if entry:
        tbl.update(increment("count"), doc_ids=[entry.doc_id])
    else:
        tbl.insert({"host": host, "day": day, "minute": minute, "count": 1})

def process_pcap(pcap_path, db_path):
    p = log.progress('PCAP Processing')
    db = TinyDB(db_path)
    tbl = db.table("counts")
    p.status('Searching')
    p.status('...')
    for pkt in PcapReader(pcap_path):
        if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeReq)):
            continue
        ts = float(pkt.time)
        dt  = datetime.fromtimestamp(ts)
        day = convert_time_to_weekday(dt)
        minute = dt.hour * 60 + dt.minute
        src, dst = pkt[Dot11].addr2, pkt[Dot11].addr1
        host = src if src and src != BROADCAST else dst
        if not host or host == BROADCAST:
            continue
        insert_or_increment(tbl, host, day, minute)
    p.success('Complete.')
    db.close()

def plot_full_week(db_path, mac):
    db  = TinyDB(db_path)
    tbl = db.table("counts")
    Host = Query()
    recs = tbl.search(Host.host == mac)
    db.close()
    if not recs:
        print(f"No data for {mac}")
        return
    mat = np.zeros((1440, 7), dtype=int)
    for r in recs:
        mat[r["minute"], r["day"]] = r["count"]
    fig, ax = plt.subplots(figsize=(10, 6))
    cax = ax.imshow(mat, origin="lower", cmap="Blues", aspect="auto")
    ax.set_xticks(np.arange(7))
    ax.set_xticklabels(["Sun","Mon","Tue","Wed","Thu","Fri","Sat"])
    yt = np.arange(0, 1441, 60)
    ax.set_yticks(yt)
    ax.set_yticklabels([f"{m//60:02d}:{m%60:02d}" for m in yt])
    ax.set_xlabel("Day of Week")
    ax.set_ylabel("Time of Day")
    ax.set_title(f"Weekly Heatmap — {mac}")
    fig.colorbar(cax, ax=ax, label="Count")
    plt.tight_layout()
    plt.show()

class LiveFeed:
    def __init__(self, iface, db_path, max_hosts, least):
        self.iface = iface
        self.db    = TinyDB(db_path, storage=CachingMiddleware(JSONStorage))
        self.tbl   = self.db.table("counts")
        self.Host  = Query()
        self.recent = {}
        self.recent_ssids = {}
        self.max_hosts = max_hosts
        self.least = least

    def insert_or_increment(self, host, day, minute):
        entry = self.tbl.get((self.Host.host == host) &
                             (self.Host.day == day) &
                             (self.Host.minute == minute))
        if entry:
            self.tbl.update(increment("count"), doc_ids=[entry.doc_id])
        else:
            self.tbl.insert({"host": host, "day": day, "minute": minute, "count": 1})

    def extract_ssid(self, pkt):
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 0 and elt.info:
                return elt.info.decode(errors="ignore")
            elt = elt.payload.getlayer(Dot11Elt)
        return None

    def process_packet(self, pkt):
        try:
            if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeReq)):
                return
            ts = time.time()
            cutoff = ts - 60
            dt  = datetime.fromtimestamp(ts)
            day = convert_time_to_weekday(dt)
            minute = dt.hour * 60 + dt.minute
            src, dst = pkt[Dot11].addr2, pkt[Dot11].addr1
            host = src if src and src != BROADCAST else dst
            if not host or host == BROADCAST:
                return
            self.recent.setdefault(host, []).append(ts)
            self.recent[host] = [t for t in self.recent[host] if t >= cutoff]
            ssid = self.extract_ssid(pkt)
            if ssid:
                self.recent_ssids.setdefault(host, []).append((ts, ssid))
                self.recent_ssids[host] = [(t,s) for (t,s) in self.recent_ssids[host] if t >= cutoff]
            self.insert_or_increment(host, day, minute)
        except Exception as e:
            print("process_packet error:", e)

    def start(self):
        threading.Thread(target=lambda: sniff(iface=self.iface,
                                              prn=self.process_packet,
                                              store=False),
                         daemon=True).start()
        try:
            while True:
                os.system("cls" if os.name=="nt" else "clear")
                print(f"Live 60s feed — {time.strftime('%H:%M:%S')}\n")
                stats = [(host, len(self.recent.get(host, []))) for host in self.recent if self.recent[host]]
                stats.sort(key=lambda x: x[1], reverse=not self.least)
                if self.max_hosts > 0 and len(stats) > self.max_hosts:
                    stats = stats[-self.max_hosts:] if self.least else stats[:self.max_hosts]
                print(f"{'Host':20s} {'Cnt':4s}  SSIDs")
                print("-" * 70)
                for host, cnt in stats:
                    ssid_list = [s for _, s in self.recent_ssids.get(host, [])]
                    ssid_counts = {}
                    for s in ssid_list:
                        ssid_counts[s] = ssid_counts.get(s, 0) + 1
                    ssid_str = ", ".join(f"{s}({ssid_counts[s]})" for s in ssid_counts)
                    if len(ssid_str) > 50:
                        ssid_str = ssid_str[:47] + "..."
                    print(f"{host:20s} {cnt:4d}  {ssid_str}")
                print("\nCtrl+C to plot a MAC heatmap.")
                time.sleep(5)

        except KeyboardInterrupt:
            mac = input("\nEnter MAC to plot (blank to resume): ").strip()
            if mac:
                plot_full_week(args.db, mac)
            self.start()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="wifi plotter")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--pcap",   help="path to .pcap for offline mode")
    group.add_argument("--iface",  help="wireless iface for live sniff")
    parser.add_argument("--db",     default="counts.json", help="TinyDB JSON file")
    parser.add_argument("--mac",    help="MAC to plot in offline mode")
    parser.add_argument("-m","--max-hosts", type=int, default=20, help="hosts to show live (0=all)")
    parser.add_argument("--least", action="store_true", help="show least active live hosts (reverse sort)")
    try:
     args = parser.parse_args()
    except:
     print("""
Offline: python wifi_tool.py --pcap capture.pcap --mac 40:d5:21:68:db:b4
Live top-10: sudo python wifi_tool.py --iface wlan0 -m 10
Live all least-active: sudo python wifi_tool.py --iface wlan0 -m 0 --least
Live default (top-20 most active): sudo python wifi_tool.py --iface wlan0
""")
     exit()
    if args.pcap:
        process_pcap(args.pcap, args.db)
        mac = args.mac or input("MAC to plot: ").strip()
        if mac:
            plot_full_week(args.db, mac)
    else:
        feed = LiveFeed(args.iface, args.db,
                        max_hosts=args.max_hosts,
                        least=args.least)
        feed.start()
