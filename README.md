# PacketMiner
PacketMiner is a simple tool for automatically detecting and extracting a wide range of file types, including images, documents, archives, media, and scripts, from either a pcap file or a live capture from socket.

## Usage
Install dependencies with 
```
pip install -r requirements.txt
```
Start the tool simply by
```
python3 miner.py
```

The tool features 2 modes for extraction of data,
1. Live from an interface
2. From an existing pcapng file

Either way, the results will be displayed on the terminal, extracted files be stored under '/files_carved' and an 'extraction.log' file will be generated.

Note: Capturing packets live from an interface requires root privs because raw socket access is needed.
