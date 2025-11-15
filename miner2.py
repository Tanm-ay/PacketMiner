#!/usr/bin/env python3
import os
import re
import socket
import argparse
from datetime import datetime
from urllib.parse import unquote
from collections import defaultdict

from scapy.all import sniff, TCP, IP, Raw, rdpcap
from scapy.layers.tls.all import TLSClientHello, TLS

import geoip2.database
import psutil

# ==============================
# Setup & Globals
# ==============================
OUTPUT_DIR = "files_carved"
LOG_DIR = "logs"

# --- Permission fix helpers ---
def fix_permissions(path):
    """Fix file/directory ownership to original user (if running under sudo)."""
    try:
        uid = int(os.environ.get("SUDO_UID", os.getuid()))
        gid = int(os.environ.get("SUDO_GID", os.getgid()))
        os.chown(path, uid, gid)
    except Exception:
        pass

def fix_tree(path):
    """Recursively fix ownership of all files and directories inside path."""
    for root, dirs, files in os.walk(path):
        for d in dirs:
            fix_permissions(os.path.join(root, d))
        for f in files:
            fix_permissions(os.path.join(root, f))

os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# Ensure dirs themselves are owned by invoking user
fix_permissions(OUTPUT_DIR)
fix_permissions(LOG_DIR)

today = datetime.now().strftime("%Y%m%d")
EXTRACTION_LOG = os.path.join(LOG_DIR, f"extraction_{today}.log")
NETWORK_LOG = os.path.join(LOG_DIR, f"network_{today}.log")

DEFAULT_SIGNATURES = {
    # Images
    'png': b'\x89PNG\r\n\x1a\n',
    'jpg': b'\xff\xd8\xff',
    'jpeg': b'\xff\xd8\xff',
    'gif': b'GIF87a',
    'gif89a': b'GIF89a',
    'bmp': b'\x42\x4D',
    'ico': b'\x00\x01\x00\x00',
    'tif': b'II*\x00',
    'tiff': b'II*\x00',
    # Documents
    'txt': b'',
    'pdf': b'%PDF-',
    'doc': b'\xd0\xcf\x11\xe0',
    'docx': b'PK\x03\x04',
    'xlsx': b'PK\x03\x04',
    'ppt': b'\xd0\xcf\x11\xe0',
    'pptx': b'PK\x03\x04',
    'odt': b'PK\x03\x04',
    'ods': b'PK\x03\x04',
    'odp': b'PK\x03\x04',
    'rtf': b'{\\rtf',
    # Archives
    'zip': b'PK\x03\x04',
    'rar': b'Rar!\x1a\x07\x00',
    '7z': b'7z\xBC\xAF\x27\x1C',
    'tar': b'ustar',
    'gz': b'\x1f\x8b\x08',
    # Scripts / Code
    'php': b'<?php',
    'html': b'<!DOCTYPE html>',
    'htmllc': b'<!doctype html>',
    'js': b'function',
    'py': b'import',
    'sh': b'#!/bin',
    # Media
    'mp3': b'ID3',
    'wav': b'RIFF',
    'ogg': b'OggS',
    'mp4': b'\x00\x00\x00\x18ftyp',
    'avi': b'RIFF',
    'mov': b'\x00\x00\x00\x14ftyp',
    # Misc
    'csv': b'',
    'log': b'',
    'xml': b'<?xml',
    'json': b'{',
    'yml': b'',
    'yaml': b'',
    'md': b'',
    'ini': b'',
}

EMAIL_REGEX = re.compile(rb'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
PASSWORD_REGEX = re.compile(rb'password[=:]\s*([^\s&]+)', re.IGNORECASE)
USER_REGEX = re.compile(rb'user(name)?[=:]\s*([^\s&]+)', re.IGNORECASE)

tcp_streams = defaultdict(lambda: {'data': b'', 'processed_len': 0, 'files_extracted': set()})


# ==============================
# Helpers
# ==============================
def load_self_ips():
    """Return all local IP addresses (loopback + active interfaces)."""
    ips = {"127.0.0.1"}
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                ips.add(addr.address)
    return ips


def load_exclusions():
    exclusions = set()
    if os.path.exists("exclusions"):
        with open("exclusions") as f:
            for line in f:
                ip = line.strip()
                if ip:
                    exclusions.add(ip)
    return exclusions


# ==============================
# GeoIP Wrapper
# ==============================
class GeoIP:
    def __init__(self, enabled, db_path="./geoDb"):
        self.enabled = enabled
        self.city = self.asn = self.country = None
        if enabled:
            try:
                self.city = geoip2.database.Reader(os.path.join(db_path, "GeoLite2-City.mmdb"))
                self.asn = geoip2.database.Reader(os.path.join(db_path, "GeoLite2-ASN.mmdb"))
                self.country = geoip2.database.Reader(os.path.join(db_path, "GeoLite2-Country.mmdb"))
            except Exception:
                self.enabled = False

    def lookup(self, ip):
        if not self.enabled:
            return "GeoIP disabled"
        try:
            asn = self.asn.asn(ip)
            org = f"AS{asn.autonomous_system_number} {asn.autonomous_system_organization}"
        except:
            org = None
        try:
            city = self.city.city(ip)
            loc = f"{city.country.name}"
            if city.city.name:
                loc += f", {city.city.name}"
        except:
            loc = None
        if loc and org:
            return f"{loc}, {org}"
        elif loc:
            return loc
        elif org:
            return org
        else:
            return "No data available"


# ==============================
# NetTracker
# ==============================
class NetTracker:
    def __init__(self, geoip, self_ips, pcap_mode=False):
        self.geoip = geoip
        self.seen = set()
        self.terminal_seen = set()
        self.self_ips = self_ips
        self.pcap_mode = pcap_mode

    def log(self, ip=None, domain=None, proto=None):
        key = (ip, domain, proto)
        if key in self.seen or (ip and ip in self.self_ips):
            return
        self.seen.add(key)

        # Prepare entry for network.log
        lines = []
        if domain:
            lines.append(f"Domain: {domain}")
        if ip:
            lines.append(f"IP Address: {ip}")

        if ip:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                hostname = "unknown"
            lines.append(f"Hostname: {hostname}")
            lines.append(f"GeoIP: {self.geoip.lookup(ip)}")

        entry = "\n".join(lines) + "\n\n" + "="*36 + "\n"
        with open(NETWORK_LOG, "a") as f:
            f.write(entry)
        fix_permissions(NETWORK_LOG)

        # Print reduced entries to terminal
        term_key = domain or ip
        if term_key not in self.terminal_seen:
            self.terminal_seen.add(term_key)
            print(f"[net] {ip or domain} logged ({proto}, {'pcap' if self.pcap_mode else 'live'})")


# ==============================
# File & Cred Extraction
# ==============================
def parse_multipart(body, boundary, conn_key, selected_sigs, files_extracted):
    boundary_bytes = b'--' + boundary
    parts = body.split(boundary_bytes)
    for part in parts:
        if b'Content-Disposition' in part:
            filename_match = re.search(rb'filename="([^"]+)"', part)
            if filename_match:
                filename = filename_match.group(1).decode(errors='ignore')
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                file_id = f"{conn_key}_{filename}_{timestamp}"
                if file_id in files_extracted:
                    continue
                ext = filename.split('.')[-1].lower()
                if ext in selected_sigs:
                    header_end = part.find(b'\r\n\r\n') + 4
                    file_data = part[header_end:].rstrip(b'\r\n-')
                    save_name = f"{OUTPUT_DIR}/{conn_key[0]}_{conn_key[1]}_{conn_key[2]}_{conn_key[3]}_{timestamp}_{filename}"
                    with open(save_name, 'wb') as f:
                        f.write(file_data)
                    fix_permissions(save_name)
                    print(f"[+] Found file: {save_name}")
                    with open(EXTRACTION_LOG, 'a') as f:
                        f.write(f"[FILE] {save_name}\n")
                    fix_permissions(EXTRACTION_LOG)
                    files_extracted.add(file_id)
            else:
                # Form fields
                field_match = re.search(rb'name="([^"]+)"\r\n\r\n(.*?)\r\n', part, re.DOTALL)
                if field_match:
                    field_name = field_match.group(1).decode(errors='ignore')
                    value = field_match.group(2).decode(errors='ignore')
                    if 'user' in field_name.lower() or 'login' in field_name.lower():
                        label = 'USER'
                    elif 'pass' in field_name.lower():
                        label = 'PASSWORD'
                    elif 'email' in field_name.lower():
                        label = 'EMAIL'
                    else:
                        continue
                    print(f"[!] Found {label}: {value}")
                    with open(EXTRACTION_LOG, 'a') as f:
                        f.write(f"[{label}] {value}\n")
                    fix_permissions(EXTRACTION_LOG)


def extract_http(stream_data, selected_sigs, conn_key, files_extracted):
    posts = re.finditer(rb'POST .*? HTTP/1\.[01]\r\n(.*?)\r\n\r\n', stream_data, re.DOTALL)
    for match in posts:
        headers = match.group(1)
        boundary_match = re.search(rb'boundary=(.+)', headers)
        if not boundary_match:
            continue
        boundary = boundary_match.group(1).strip()
        body_start = match.end()
        body = stream_data[body_start:]
        parse_multipart(body, boundary, conn_key, selected_sigs, files_extracted)


def process_packet(pkt, selected_sigs, tracker):
    if TCP in pkt and pkt[IP].payload:
        ip_src, sport, ip_dst, dport = pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport
        key = (ip_src, sport, ip_dst, dport)
        tcp_streams[key]['data'] += bytes(pkt[TCP].payload)
        new_data = tcp_streams[key]['data'][tcp_streams[key]['processed_len']:]
        if not new_data:
            return
        tcp_streams[key]['processed_len'] = len(tcp_streams[key]['data'])

        # --- File/cred extraction (HTTP)
        extract_http(new_data, selected_sigs, key, tcp_streams[key]['files_extracted'])
        for regex, label in [(EMAIL_REGEX, "EMAIL"), (PASSWORD_REGEX, "PASSWORD"), (USER_REGEX, "USER")]:
            for m in regex.findall(new_data):
                try:
                    match_str = unquote(m.decode(errors='ignore'))
                except:
                    match_str = str(m)
                print(f"[!] Found {label}: {match_str}")
                with open(EXTRACTION_LOG, 'a') as f:
                    f.write(f"[{label}] {match_str}\n")
                fix_permissions(EXTRACTION_LOG)

        # --- TLS metadata logging
        if pkt.haslayer(TLSClientHello):
            tracker.log(ip=ip_dst, proto="TLS")

        # --- HTTP IP logging
        if dport == 80 or sport == 80:
            tracker.log(ip=ip_dst, proto="HTTP")


# ==============================
# Capture Modes
# ==============================
def live_capture(selected_sigs, tracker):
    iface = input("Enter network interface (e.g., eth0, tun0): ").strip()
    print(f"[*] Starting live capture on {iface}...")
    try:
        sniff(iface=iface, prn=lambda pkt: process_packet(pkt, selected_sigs, tracker), store=0)
    except KeyboardInterrupt:
        print("\n[*] Live capture stopped.")
        fix_tree(OUTPUT_DIR)
        fix_tree(LOG_DIR)


def pcap_file_capture(selected_sigs, tracker):
    filename = input("Enter path to PCAP file: ").strip()
    print(f"[*] Processing {filename} (PCAP mode)...")
    packets = rdpcap(filename)
    for pkt in packets:
        process_packet(pkt, selected_sigs, tracker)
    print("[*] PCAP processing complete.")
    fix_tree(OUTPUT_DIR)
    fix_tree(LOG_DIR)


# ==============================
# Main
# ==============================
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--geo", action="store_true", help="Enable GeoIP lookups (requires ./geoDb)")
    args = parser.parse_args()

    self_ips = load_self_ips()
    exclusions = load_exclusions()
    all_self_ips = self_ips | exclusions

    geo = GeoIP(args.geo)
    tracker = NetTracker(geo, all_self_ips, pcap_mode=False)

    print("="*60)
    print(" PacketMiner – File/credential extractor + network intel")
    print("="*60)
    print(f"[i] Extraction log: {EXTRACTION_LOG}")
    print(f"[i] Network log:    {NETWORK_LOG}")
    print(f"[i] Self IPs detected: {', '.join(all_self_ips)}")
    if args.geo:
        print("[i] GeoIP enabled (./geoDb)")
    else:
        print("[i] GeoIP disabled")
    print("="*60)

    print("Select Mode:")
    print("1. Live Capture")
    print("2. Extract from PCAP file")
    mode = input("Enter choice (1 or 2): ").strip()

    print("Available extensions:", ", ".join(sorted(DEFAULT_SIGNATURES.keys())))
    exts = input("Enter extensions to capture (comma separated, e.g., png,jpg,zip,docx): ").strip()
    selected_sigs = [e.strip().lower() for e in exts.split(",") if e.strip().lower() in DEFAULT_SIGNATURES]

    if not selected_sigs:
        print("No valid extensions selected. Exiting.")
        return

    if mode == "1":
        tracker.pcap_mode = False
        live_capture(selected_sigs, tracker)
    elif mode == "2":
        tracker.pcap_mode = True
        pcap_file_capture(selected_sigs, tracker)
    else:
        print("Invalid choice. Exiting.")

    # Final recursive permission fix
    fix_tree(OUTPUT_DIR)
    fix_tree(LOG_DIR)


if __name__ == "__main__":
    main()

