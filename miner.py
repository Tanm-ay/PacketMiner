from scapy.all import sniff, TCP, IP, Raw, rdpcap
from collections import defaultdict
import os
import re
from urllib.parse import unquote
from datetime import datetime

OUTPUT_DIR = "files_carved"
LOG_FILE = "extraction.log"
os.makedirs(OUTPUT_DIR, exist_ok=True)

DEFAULT_SIGNATURES = {

    'png': b'\x89PNG\r\n\x1a\n',
    'jpg': b'\xff\xd8\xff',
    'jpeg': b'\xff\xd8\xff',
    'gif': b'GIF87a',
    'gif89a': b'GIF89a',
    'bmp': b'\x42\x4D',
    'ico': b'\x00\x01\x00\x00',
    'tif': b'II*\x00',
    'tiff': b'II*\x00',
    'txt': b'',  # extension only
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
    'zip': b'PK\x03\x04',
    'rar': b'Rar!\x1a\x07\x00',
    '7z': b'7z\xBC\xAF\x27\x1C',
    'tar': b'ustar',
    'gz': b'\x1f\x8b\x08',
    'php': b'<?php',
    'html': b'<!DOCTYPE html>',
    'htmllc': b'<!doctype html>',
    'js': b'function',
    'py': b'import',
    'sh': b'#!/bin',
    'mp3': b'ID3',
    'wav': b'RIFF',
    'ogg': b'OggS',
    'mp4': b'\x00\x00\x00\x18ftyp',
    'avi': b'RIFF',
    'mov': b'\x00\x00\x00\x14ftyp',
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
                    file_data = part[header_end:]
                    file_data = file_data.rstrip(b'\r\n-')
                    save_name = f"{OUTPUT_DIR}/{conn_key[0]}_{conn_key[1]}_{conn_key[2]}_{conn_key[3]}_{timestamp}_{filename}"
                    with open(save_name, 'wb') as f:
                        f.write(file_data)
                    print(f"[+] Found file: {save_name}")
                    with open(LOG_FILE, 'a') as f:
                        f.write(f"[FILE] {save_name}\n")
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
                    with open(LOG_FILE, 'a') as f:
                        f.write(f"[{label}] {value}\n")

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

def process_packet(pkt, selected_sigs):
    if TCP in pkt and pkt[TCP].payload:
        key = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
        tcp_streams[key]['data'] += bytes(pkt[TCP].payload)
        stream_data = tcp_streams[key]['data']
        new_data = stream_data[tcp_streams[key]['processed_len']:]
        if not new_data:
            return
        tcp_streams[key]['processed_len'] = len(stream_data)

        # extract files
        extract_http(new_data, selected_sigs, key, tcp_streams[key]['files_extracted'])

        # extract credentials
        for regex, label in [(EMAIL_REGEX, "EMAIL"), (PASSWORD_REGEX, "PASSWORD"), (USER_REGEX, "USER")]:
            for m in regex.findall(new_data):
                try:
                    match_str = unquote(m.decode(errors='ignore'))
                except:
                    match_str = str(m)
                print(f"[!] Found {label}: {match_str}")
                with open(LOG_FILE, 'a') as f:
                    f.write(f"[{label}] {match_str}\n")

        if len(stream_data) > 5*1024*1024:
            tcp_streams[key]['data'] = stream_data[-5*1024*1024:]
            tcp_streams[key]['processed_len'] = len(tcp_streams[key]['data'])

# live capture
def live_capture(selected_sigs):
    iface = input("Enter network interface (e.g., eth0): ").strip()
    print(f"[*] Starting live capture on {iface}...")
    try:
        sniff(iface=iface, prn=lambda pkt: process_packet(pkt, selected_sigs), store=0)
    except KeyboardInterrupt:
        print("\n[*] Live capture stopped. Check log file for details.")

# pcap file 
def pcap_file_capture(selected_sigs):
    filename = input("Enter path to PCAP file: ").strip()
    print(f"[*] Processing {filename}...")
    packets = rdpcap(filename)
    for pkt in packets:
        process_packet(pkt, selected_sigs)
    print("[*] PCAP processing complete. Check log file for details.")

def main():
    print("Select Mode:")
    print("1. Live Capture")
    print("2. Extract from PCAP file")
    mode = input("Enter choice (1 or 2): ").strip()

    print("Available extensions:", ", ".join(DEFAULT_SIGNATURES.keys()))
    exts = input("Enter extensions to capture (comma separated, e.g., png,jpg,zip,docx): ").strip()
    selected_sigs = [e.strip().lower() for e in exts.split(",") if e.strip().lower() in DEFAULT_SIGNATURES]

    if not selected_sigs:
        print("No valid extensions selected. Exiting.")
        return

    if mode == "1":
        live_capture(selected_sigs)
    elif mode == "2":
        pcap_file_capture(selected_sigs)
    else:
        print("Invalid choice. Exiting.")

if __name__ == "__main__":
    main()

