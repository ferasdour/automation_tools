#!/usr/bin/env python3
# Do not use this illegally, cops won't have trouble catching you
import os
import re
import time
import threading
import argparse
import subprocess
import sqlite3
from datetime import datetime
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
from scapy.all import *
from pwn import log

BROADCAST = "ff:ff:ff:ff:ff:ff"
DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS sightings (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    host       TEXT    NOT NULL,
    day        INTEGER NOT NULL,
    bucket     INTEGER NOT NULL,
    timestamp  TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_host ON sightings(host);
"""

def init_db(db_path):
    conn = sqlite3.connect(db_path, check_same_thread=False, timeout=float(10))
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.executescript(DB_SCHEMA)
    conn.commit()
    return conn

def convert_time_to_weekday(dt_obj):
    return (dt_obj.weekday() + 1) % 7

def get_bucket(dt, interval=15):
    return (dt.hour * 60 + dt.minute) // interval

def track_sighting(cursor, host, dt):
    day    = convert_time_to_weekday(dt)
    bucket = get_bucket(dt)
    ts     = dt.isoformat()
    cursor.execute("INSERT INTO sightings (host, day, bucket, timestamp) VALUES (?, ?, ?, ?)",(host, day, bucket, ts))

def get_supported_channels(iface):
    try:
        out = subprocess.check_output(["iw", "list"],text=True,stderr=subprocess.DEVNULL)
        chans = re.findall(r'\*\s+\d+\s+MHz\s+\n\[channel\s+(\d+)\n]', out)
        return sorted({int(c) for c in chans})
    except Exception:
        out = subprocess.check_output(["iwlist", iface, "freq"],text=True,stderr=subprocess.DEVNULL)
        chans = re.findall(r'Channel\s+(\d+)\s+:\s+\d+\.\d+\s+GHz', out)
        return sorted({int(c) for c in chans})

def hop_channels(iface, channels, dwell=5):
    def hopper():
        idx = 0
        while True:
            ch = channels[idx % len(channels)]
            subprocess.run(["iwconfig", iface, "channel", str(ch)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            time.sleep(dwell)
            idx += 1
    t = threading.Thread(target=hopper, daemon=True)
    t.start()

def process_pcap(pcap_path, db_path, batch_size=500):
    conn   = init_db(db_path)
    cursor = conn.cursor()
    p = log.progress("PCAP Processing")
    p.status("Parsing packets…")
    count = 0
    for pkt in PcapReader(pcap_path):
        if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeReq)):
            continue
        ts = float(pkt.time)
        dt = datetime.fromtimestamp(ts)
        src = pkt[Dot11].addr2
        dst = pkt[Dot11].addr1
        host = src if src and src != BROADCAST else dst
        if not host or host == BROADCAST:
            continue
        track_sighting(cursor, host, dt)
        count += 1
        if count % batch_size == 0:
            conn.commit()
    conn.commit()
    conn.close()
    p.success(f"Parsed {count} records.")

def plot_full_week(db_path, mac):
    conn   = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT bucket, day, COUNT(*) AS cnt
          FROM sightings
         WHERE host = ?
         GROUP BY bucket, day
    """, (mac,))
    rows = cursor.fetchall()
    conn.close()
    if not rows:
        print(f"No data for {mac}")
        return
    mat = np.zeros((96, 7), dtype=int)
    for bucket, day, cnt in rows:
        mat[bucket, day] = cnt
    masked = np.ma.masked_where(mat == 0, mat)
    fig, ax = plt.subplots(figsize=(10, 6))
    fig.patch.set_facecolor("lightgray")
    ax.set_facecolor("lightgray")
    cmap = plt.get_cmap("magma").copy()
    cmap.set_bad(color="lightgray")
    norm = mcolors.Normalize(vmin=1, vmax=masked.max())
    cax = ax.imshow(masked,origin="lower",cmap=cmap,norm=norm,aspect="auto")
    ax.set_xticks(range(7))
    ax.set_xticklabels(["Sun","Mon","Tue","Wed","Thu","Fri","Sat"])
    yt = np.arange(0, 96, 4)
    ax.set_yticks(yt)
    ax.set_yticklabels([f"{(b*15)//60:02d}:{(b*15)%60:02d}" for b in yt])
    ax.set_xlabel("Day of Week")
    ax.set_ylabel("Start of Time Interval")
    ax.set_title(f"Weekly Heatmap — {mac}")
    fig.colorbar(cax, ax=ax, label="Sightings")
    plt.tight_layout()
    plt.savefig("heatmap.png")

class LiveFeed:
    def __init__(self, iface, db_path, max_hosts, least):
        self.iface = iface
        self.db_path = db_path
        self.conn = init_db(db_path)
        self.cursor = self.conn.cursor()
        self.max_hosts = max_hosts
        self.least = least
        self.recent = {}
        self.recent_ssids = {}
        self.insert_count = 0

    def extract_ssid(self, pkt):
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 0 and elt.info:
                return elt.info.decode(errors="ignore")
            elt = elt.payload.getlayer(Dot11Elt)
        return None

    def process_packet(self, pkt):
        if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeReq)):
            return
        ts   = float(pkt.time)
        dt   = datetime.fromtimestamp(ts)
        src  = pkt[Dot11].addr2
        dst  = pkt[Dot11].addr1
        host = src if src and src != BROADCAST else dst
        if not host or host == BROADCAST:
            return
        cutoff = ts - 60
        self.recent.setdefault(host, []).append(ts)
        self.recent[host] = [t for t in self.recent[host] if t >= cutoff]
        ssid = self.extract_ssid(pkt)
        if ssid:
            self.recent_ssids.setdefault(host, []).append((ts, ssid))
            self.recent_ssids[host] = [
                (t, s) for (t, s) in self.recent_ssids[host] if t >= cutoff
            ]
        track_sighting(self.cursor, host, dt)
        self.insert_count += 1
        if self.insert_count >= 100:
            self.conn.commit()
            self.insert_count = 0

    def run_sniff(self):
        sniff(iface=self.iface, prn=self.process_packet, store=False)

    def start(self):
        channels = get_supported_channels(self.iface)
        hop_channels(self.iface, channels, dwell=3)
        threading.Thread(target=self.run_sniff, daemon=True).start()
        try:
            while True:
                os.system("cls" if os.name == "nt" else "clear")
                print(f"Live 60s feed — {time.strftime('%H:%M:%S')}\n")
                stats = [(h, len(self.recent.get(h, [])))
                         for h in self.recent if self.recent[h]]
                stats.sort(key=lambda x: x[1], reverse=not self.least)
                if self.max_hosts > 0 and len(stats) > self.max_hosts:
                    stats = (stats[:self.max_hosts]
                             if not self.least
                             else stats[-self.max_hosts:])
                print(f"{'Host':20s} {'Cnt':4s}  SSIDs")
                print("-" * 70)
                for host, cnt in stats:
                    ssids = [s for _, s in self.recent_ssids.get(host, [])]
                    counts = {s: ssids.count(s) for s in set(ssids)}
                    ssid_str = ", ".join(f"{s}({counts[s]})" for s in counts)
                    if len(ssid_str) > 50:
                        ssid_str = ssid_str[:47] + "..."
                    print(f"{host:20s} {cnt:4d}  {ssid_str}")
                print("\nCtrl+C to plot heatmap.")
                time.sleep(5)
        except KeyboardInterrupt:
            self.conn.commit()
            self.conn.close()
            try:
                mac = input("\nEnter MAC to plot (blank to resume): ").strip()
                if mac:
                    plot_full_week(self.db_path, mac)
                    time.sleep(2)
                    os.system("ristretto heatmap.png &")
                    self.start()
                else:
                    self.conn = init_db(self.db_path)
                    self.cursor = self.conn.cursor()
                    self.insert_count = 0
                    self.start()
            except (KeyboardInterrupt, EOFError) as e:
                p = log.progress("Terminated.")
                p.status(f"{type(e).__name__}: {e}")
                p.status("Exiting...")
                exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Wi-Fi Heatmap Plotter")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--pcap",  help="Offline PCAP file")
    group.add_argument("--iface", help="Live interface")
    group.add_argument("--nopcap", action="store_true", help="Plot only from existing DB")
    parser.add_argument("--db", default="counts.db", help="SQLite DB path (default: counts.db)")
    parser.add_argument("--mac", help="MAC to plot (offline/nopcap)")
    parser.add_argument("-m", "--max-hosts", type=int, default=20, help="Number of hosts to show live (0=all)")
    parser.add_argument("--least", action="store_true",help="Show least active instead of most")
    args = parser.parse_args()
    if args.nopcap:
        if not args.mac:
            parser.error("--nopcap requires --mac")
        plot_full_week(args.db, args.mac)
    elif args.pcap:
        process_pcap(args.pcap, args.db)
        mac = args.mac or input("MAC to plot: ").strip()
        if mac:
            plot_full_week(args.db, mac)
    else:
        feed = LiveFeed(args.iface, args.db, args.max_hosts, args.least)
        feed.start()
