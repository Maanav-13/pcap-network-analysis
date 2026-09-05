# pcap-network-analysis
Network traffic capture and analysis using PCAP files

## Person 1 — PCAP Processing & Feature Extraction

### Overview

The PCAP processing pipeline converts captured network traffic into structured packet-level and flow-level datasets that can be used for IDS detection and dashboard visualization.

### Pipeline

```text
PCAP / PCAPNG
     ↓
packet_parser.py
     ↓
packet_features.csv
     ↓
flow_extractor.py
     ↓
flow_features.csv
```

### 1. Packet Feature Extraction

Run:

```powershell
python scripts\packet_parser.py pcaps\test_capture.pcapng data\packet_features.csv
```

This extracts one row per packet.

The packet-level dataset contains:

| Feature         | Description               |
| --------------- | ------------------------- |
| `timestamp`     | Packet capture timestamp  |
| `packet_length` | Packet size in bytes      |
| `ip_version`    | IPv4 or IPv6              |
| `src_ip`        | Source IP address         |
| `dst_ip`        | Destination IP address    |
| `protocol`      | TCP, UDP, ICMPv6, etc.    |
| `src_port`      | Source port               |
| `dst_port`      | Destination port          |
| `ttl`           | IP TTL/hop limit          |
| `tcp_flags`     | TCP flags when applicable |

### 2. Flow Feature Extraction

Run:

```powershell
python scripts\flow_extractor.py data\packet_features.csv data\flow_features.csv
```

This groups packets into bidirectional flows and generates one row per flow.

The first packet observed determines the forward direction.

The flow-level dataset contains:

| Feature               | Description                                |
| --------------------- | ------------------------------------------ |
| `src_ip`              | Source IP of the first-seen direction      |
| `dst_ip`              | Destination IP of the first-seen direction |
| `src_port`            | Source port                                |
| `dst_port`            | Destination port                           |
| `protocol`            | Network protocol                           |
| `start_time`          | Flow start timestamp                       |
| `end_time`            | Flow end timestamp                         |
| `duration`            | Flow duration in seconds                   |
| `packet_count`        | Total packets in the flow                  |
| `total_bytes`         | Total bytes in the flow                    |
| `forward_packets`     | Packets in the first-seen direction        |
| `backward_packets`    | Packets in the reverse direction           |
| `forward_bytes`       | Bytes in the first-seen direction          |
| `backward_bytes`      | Bytes in the reverse direction             |
| `average_packet_size` | Average packet size                        |
| `packets_per_second`  | Packet transmission rate                   |
| `bytes_per_second`    | Byte transmission rate                     |

### 3. Feature Inspection

To inspect the generated packet dataset:

```powershell
python scripts\inspect_features.py
```

This reports:

* Number of rows and columns
* Missing values
* Protocol distribution
* IP version distribution
* Top source IPs
* Top destination IPs
* Packet length statistics

### Output

The generated CSV files are stored in:

```text
data/
├── packet_features.csv
└── flow_features.csv
```

These files are intentionally excluded from Git using `.gitignore`.

### Handoff to Person 2

Person 2 can use `flow_features.csv` as the primary input for IDS detection and anomaly analysis.

The most relevant initial IDS features are:

```text
duration
packet_count
total_bytes
forward_packets
backward_packets
forward_bytes
backward_bytes
average_packet_size
packets_per_second
bytes_per_second
protocol
src_port
dst_port
```
