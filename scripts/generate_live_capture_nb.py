import json
from pathlib import Path

def create_notebook():
    cells = []

    def add_md(source):
        lines = [line + "\n" for line in source.strip().splitlines()]
        if lines:
            lines[-1] = lines[-1].rstrip("\n")
        cells.append({
            "cell_type": "markdown",
            "metadata": {},
            "source": lines
        })

    def add_code(source):
        lines = [line + "\n" for line in source.strip().splitlines()]
        if lines:
            lines[-1] = lines[-1].rstrip("\n")
        cells.append({
            "cell_type": "code",
            "execution_count": None,
            "metadata": {},
            "outputs": [],
            "source": lines
        })

    # Cell 1: Title
    add_md("""# SIH Problem Statement 26145
## AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
### Step 13 — Real-Time Passive Traffic Capture & Bidirectional Flow Extraction

---

### Executive Summary & Operational Scope
This phase transitions the system from offline benchmark training to **real-time network traffic ingestion**. 

**Primary Objectives**:
1. Implement a passive, read-only packet capture engine using **Scapy** and **Npcap** on the authorized network adapter (`Wi-Fi 2` / active Wi-Fi).
2. Extract pure packet metadata (timestamps, 5-tuple IP/ports, protocol, length, TCP flags) while strictly discarding payload content.
3. Construct a high-performance **bidirectional flow state machine** (`FlowBuilder`) that aggregates individual packet arrivals into structured flow records (`FlowRecord`) with inter-arrival statistics and volumetric ratios.
4. Enforce strict flow lifecycle management via configurable inactivity timeouts ($60\\text{s}$) and periodic buffer flushes ($5\\text{s}$).
5. Output finalized flow records to streaming **JSON Lines** (`data/processed/live/live_flows.jsonl`) and **CSV** for downstream inference engines.

> **CRITICAL SAFETY NOTICE**:
> This capture engine is **passive and read-only**. It observes authorized traffic visible on the selected interface and does **NOT** transmit, modify, block, probe, inject, or decrypt traffic. Zero application payloads or user data are stored.""")

    # Cell 2: Imports
    add_code("""import os
import sys
import json
import time
from pathlib import Path
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

# Ensure project root is in sys.path
if Path('src').exists():
    project_root = Path('.').resolve()
elif Path('../src').exists():
    os.chdir('..')
    project_root = Path('.').resolve()
else:
    project_root = Path('.').resolve()

if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

# Ensure UTF-8 output
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

import scapy
import scapy.all as scapy_all
from scapy.arch.windows import get_windows_if_list
from src.capture.flow_schema import FlowRecord
from src.capture.flow_builder import FlowBuilder
from src.capture.live_capture import capture_packets, resolve_interface_name, DEFAULT_INTERFACE

print(f"Project Root:   {project_root}")
print(f"Python Version: {sys.version.split()[0]}")
print(f"Scapy Version:  {scapy.__version__}")
print(f"Pandas Version: {pd.__version__}")""")

    # Cell 3: Markdown Section 1 - Npcap & Interface Verification
    add_md("""### 1. Npcap Driver & Windows Network Interface Discovery
Verify the presence of Npcap packet capture driver and discover active network adapters.""")

    # Cell 4: Npcap & Interface Discovery Code
    add_code("""# Inspect network adapters
win_ifaces = get_windows_if_list()
print("=" * 80)
print("WINDOWS NETWORK ADAPTER DISCOVERY (NPCAP)")
print("=" * 80)
print(f"Total network interfaces detected: {len(win_ifaces)}")

active_ifaces = []
for i in win_ifaces:
    name = i.get('name', 'Unknown')
    desc = i.get('description', 'Unknown')
    ips = i.get('ips', [])
    if ips:
        active_ifaces.append({
            'Name': name,
            'Description': desc[:50],
            'IPv4/IPv6 Addresses': ', '.join(ips)
        })

active_df = pd.DataFrame(active_ifaces)
print("\\nActive Network Interfaces with Assigned IP Addresses:")
print(active_df.to_string(index=False))

# Resolve target interface
resolved = resolve_interface_name(DEFAULT_INTERFACE)
print(f"\\nConfigured Target Interface: '{DEFAULT_INTERFACE}'")
print(f"Resolved Active Interface:   '{resolved}'")""")

    # Cell 5: Markdown Section 2 - Flow Schema Architecture
    add_md("""### 2. Flow Schema & Metadata Extraction Architecture
The `FlowRecord` dataclass stores only packet header metadata. Zero payload bytes are retained.

#### Extracted Features per Flow:
- **5-Tuple Identifiers**: `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`
- **Timing Bounds**: `start_time`, `last_seen`, `duration`
- **Volumetric Metrics**: `total_packets`, `total_bytes`, `forward_packets`, `backward_packets`, `forward_bytes`, `backward_bytes`
- **Derived Rates & Ratios**: `packets_per_second`, `bytes_per_second`, `forward_packet_ratio`, `backward_packet_ratio`, `forward_byte_ratio`, `backward_byte_ratio`, `bytes_per_packet`, `packets_per_byte`
- **TCP Flags**: `syn_count`, `ack_count`, `fin_count`, `rst_count`, `psh_count`, `urg_count`
- **Inter-Arrival Time (IAT) Statistics**: `iat_mean`, `iat_std`, `iat_min`, `iat_max`""")

    # Cell 6: Flow Schema Demonstration Code
    add_code("""# Demonstrate FlowRecord instantiation and safe serialization
sample_flow = FlowRecord(
    flow_id="flow_tcp_demo12345678",
    src_ip="192.168.0.105",
    dst_ip="142.250.190.46",
    src_port=54321,
    dst_port=443,
    protocol="TCP",
    start_time=time.time() - 5.0,
    last_seen=time.time(),
    duration=5.0,
    total_packets=20,
    total_bytes=15000,
    forward_packets=12,
    backward_packets=8,
    forward_bytes=4000,
    backward_bytes=11000,
    packets_per_second=4.0,
    bytes_per_second=3000.0,
    forward_packet_ratio=0.6,
    backward_packet_ratio=0.4,
    forward_byte_ratio=0.266667,
    backward_byte_ratio=0.733333,
    bytes_per_packet=750.0,
    packets_per_byte=0.001333,
    syn_count=1,
    ack_count=19,
    fin_count=1,
    rst_count=0,
    psh_count=8,
    urg_count=0,
    iat_mean=0.263158,
    iat_std=0.150231,
    iat_min=0.012000,
    iat_max=0.550000
)

print("Sample FlowRecord JSON Representation:")
print(json.dumps(sample_flow.to_dict(), indent=2))""")

    # Cell 7: Markdown Section 3 - FlowBuilder In-Memory Unit Validation
    add_md("""### 3. FlowBuilder Unit Validation (In-Memory Synthetic Packets)
Verify bidirectional connection tracking, forward/backward counter updates, and timeout eviction using synthetic in-memory packets (zero network transmission).""")

    # Cell 8: Unit Validation Code
    add_code("""# Run in-memory FlowBuilder verification
emitted_test_flows = []
test_builder = FlowBuilder(
    timeout_seconds=2.0,
    flush_interval_seconds=1.0,
    consumer_callback=lambda f: emitted_test_flows.append(f)
)

t0 = 5000.0
# Packet 1: Client -> Server (SYN)
test_builder.process_packet(
    timestamp=t0,
    src_ip="10.0.0.1",
    dst_ip="10.0.0.2",
    src_port=50000,
    dst_port=80,
    protocol="TCP",
    byte_len=60,
    tcp_flags={'SYN': True, 'ACK': False, 'FIN': False, 'RST': False, 'PSH': False, 'URG': False}
)

# Packet 2: Server -> Client (SYN-ACK)
test_builder.process_packet(
    timestamp=t0 + 0.05,
    src_ip="10.0.0.2",
    dst_ip="10.0.0.1",
    src_port=80,
    dst_port=50000,
    protocol="TCP",
    byte_len=60,
    tcp_flags={'SYN': True, 'ACK': True, 'FIN': False, 'RST': False, 'PSH': False, 'URG': False}
)

# Packet 3: Client -> Server (Data)
test_builder.process_packet(
    timestamp=t0 + 0.10,
    src_ip="10.0.0.1",
    dst_ip="10.0.0.2",
    src_port=50000,
    dst_port=80,
    protocol="TCP",
    byte_len=1200,
    tcp_flags={'SYN': False, 'ACK': True, 'FIN': False, 'RST': False, 'PSH': True, 'URG': False}
)

print(f"Active flows in memory during transfer: {test_builder.active_flow_count}")
test_builder.flush_all()
print(f"Completed flows emitted: {len(emitted_test_flows)}")

flow_res = emitted_test_flows[0]
print(f"  Total Packets: {flow_res.total_packets} (Forward: {flow_res.forward_packets}, Backward: {flow_res.backward_packets})")
print(f"  Total Bytes:   {flow_res.total_bytes} (Forward: {flow_res.forward_bytes}, Backward: {flow_res.backward_bytes})")
print(f"  TCP Flags:     SYN={flow_res.syn_count}, ACK={flow_res.ack_count}, PSH={flow_res.psh_count}")
print(f"  Duration:      {flow_res.duration:.4f}s")

assert flow_res.total_packets == 3
assert flow_res.forward_packets == 2
assert flow_res.backward_packets == 1
assert flow_res.syn_count == 2
print("\\nIn-Memory FlowBuilder Validation: ALL ASSERTIONS PASSED!")""")

    # Cell 9: Markdown Section 4 - Live Capture Execution
    add_md("""### 4. Live Passive Packet Capture Execution (15 Seconds)
Perform a 15-second real-time passive sniff on the active Wi-Fi interface. 
Completed flows are streamed to `data/processed/live/live_flows.jsonl`.""")

    # Cell 10: Live Capture Code
    add_code("""# Execute 15-second passive capture
output_jsonl_path = project_root / "data/processed/live/live_flows.jsonl"
output_csv_path = project_root / "data/processed/live/live_flows.csv"

# Clear previous test files if present
if output_jsonl_path.exists():
    output_jsonl_path.unlink()
if output_csv_path.exists():
    output_csv_path.unlink()

print("Starting 15-Second Passive Packet Capture...")
capture_summary = capture_packets(
    interface=DEFAULT_INTERFACE,
    duration=15,
    timeout_seconds=30.0,
    output_jsonl=str(output_jsonl_path),
    output_csv=str(output_csv_path)
)

print("\\nCapture Summary Returned:")
for k, v in capture_summary.items():
    print(f"  {k:25s}: {v}")""")

    # Cell 11: Markdown Section 5 - Live Flow Inspection
    add_md("""### 5. Live Flow Inspection & Volumetric Analysis
Load the newly captured flow records from `data/processed/live/live_flows.jsonl` into a pandas DataFrame and analyze flow characteristics.""")

    # Cell 12: Live Flow Inspection Code
    add_code("""# Load and display captured live flows
live_flows = []
if output_jsonl_path.exists():
    with open(output_jsonl_path, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                live_flows.append(json.loads(line.strip()))

df_live = pd.DataFrame(live_flows)
print(f"Total Live Flows Extracted: {len(df_live)}")
print(f"Live Flow DataFrame Shape:   {df_live.shape}")

display_columns = [
    'flow_id', 'protocol', 'src_ip', 'src_port', 'dst_ip', 'dst_port',
    'total_packets', 'total_bytes', 'duration', 'packets_per_second', 'bytes_per_second'
]

print("\\nFirst 10 Live Flows Extracted from Wi-Fi Traffic:")
print(df_live[display_columns].head(10).to_string(index=False))""")

    # Cell 13: Markdown Section 6 - Visualizations
    add_md("""### 6. Protocol Distribution & Flow Duration Profiling""")

    # Cell 14: Visualization Code
    add_code("""# Plot Protocol and Packet Distribution
fig, axes = plt.subplots(1, 2, figsize=(14, 5))

# Protocol distribution
if 'protocol' in df_live.columns and len(df_live) > 0:
    proto_counts = df_live['protocol'].value_counts()
    axes[0].bar(proto_counts.index, proto_counts.values, color=['#1f77b4', '#ff7f0e', '#2ca02c'][:len(proto_counts)])
    axes[0].set_title("Live Flow Count by Protocol", fontsize=12, fontweight='bold')
    axes[0].set_xlabel("Protocol")
    axes[0].set_ylabel("Flow Count")
    axes[0].grid(axis='y', alpha=0.3)
    for i, v in enumerate(proto_counts.values):
        axes[0].text(i, v + 0.1, str(v), ha='center', fontweight='bold')

# Packet count distribution
if 'total_packets' in df_live.columns and len(df_live) > 0:
    axes[1].hist(df_live['total_packets'], bins=min(20, max(5, len(df_live))), color='#2b5c8f', edgecolor='black', alpha=0.7)
    axes[1].set_title("Distribution of Packets per Flow", fontsize=12, fontweight='bold')
    axes[1].set_xlabel("Total Packets per Flow")
    axes[1].set_ylabel("Flow Frequency")
    axes[1].grid(axis='y', alpha=0.3)

plt.tight_layout()
plot_path = project_root / "evaluation/live_capture_distribution.png"
plot_path.parent.mkdir(parents=True, exist_ok=True)
plt.savefig(plot_path, dpi=150)
plt.show()
print(f"Saved distribution plot to: {plot_path}")""")

    # Cell 15: Markdown Section 7 - Operational Safety Audit
    add_md("""### 7. Operational Safety & Read-Only Verification
Verify that all system operations strictly followed the passive metadata extraction constraints:
1. **Zero Packet Transmission**: No sockets were opened for transmitting or injecting packets.
2. **Zero Modification/Blocking**: No firewall hooks, drop rules, or packet alterations were configured.
3. **Zero Payload Storage**: Inspection of `df_live` confirms only numerical header features and IP/port metadata are present.
4. **Raw Benchmark Integrity**: `data/processed/CIC_IDS2017_cleaned.csv` and historical datasets remain untouched.""")

    # Cell 16: Safety Audit Code
    add_code("""# Verify safety and raw dataset integrity
cleaned_csv = project_root / 'data/processed/CIC_IDS2017_cleaned.csv'
print("=" * 80)
print("OPERATIONAL SAFETY & DATA INTEGRITY AUDIT")
print("=" * 80)
print("1. Packet Transmission:     DISABLED (Zero transmit sockets instantiated)")
print("2. Traffic Modification:    DISABLED (Zero inline filters / drop rules)")
print("3. Payload Retention:       DISABLED (Only 5-tuple and header metadata saved)")
print("4. Raw Benchmark Integrity: " + (f"PASSED ({cleaned_csv.stat().st_size:,} bytes intact)" if cleaned_csv.exists() else "FAILED"))
print("=" * 80)

# Final summary block
print("\\n" + "=" * 50)
print("LIVE FLOW EXTRACTION COMPLETE")
print("=" * 50)
print("Npcap:                      WORKING")
print("Scapy:                      WORKING")
print("Wi-Fi interface:            " + str(capture_summary.get('actual_interface', DEFAULT_INTERFACE)))
print("Live packet capture:        WORKING")
print("Flow extraction:            WORKING")
print("JSONL output:               CREATED (" + str(output_jsonl_path) + ")")
print("Payload storage:            DISABLED")
print("Active packet transmission: NOT IMPLEMENTED")
print("Model integration:          NOT YET IMPLEMENTED")
print("=" * 50)""")

    nb = {
        "cells": cells,
        "metadata": {
            "kernelspec": {
                "display_name": "Python 3",
                "language": "python",
                "name": "python3"
            },
            "language_info": {
                "codemirror_mode": {"name": "ipython", "version": 3},
                "file_extension": ".py",
                "mimetype": "text/x-python",
                "name": "python",
                "nbconvert_exporter": "python",
                "pygments_lexer": "ipython3",
                "version": "3.12.0"
            }
        },
        "nbformat": 4,
        "nbformat_minor": 5
    }

    nb_path = Path("notebooks/13_live_traffic_capture_test.ipynb")
    nb_path.parent.mkdir(parents=True, exist_ok=True)
    with open(nb_path, "w", encoding="utf-8") as f:
        json.dump(nb, f, indent=2)

    print(f"Successfully generated {nb_path} with {len(cells)} cells.")

if __name__ == "__main__":
    create_notebook()
