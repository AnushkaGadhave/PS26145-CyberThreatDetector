import os
import sys
from pathlib import Path
import nbformat as nbf

nb = nbf.v4.new_notebook()
cells = []

# ==============================================================================
# SECTION 0 & 1: Title & Executive Overview
# ==============================================================================
cells.append(nbf.v4.new_markdown_cell(r"""# CIC-IDS2017 — Reconnaissance / PortScan Dataset Preparation
## SIH 2026 - Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

---

### Executive Objective
This notebook implements **Step 11** of the SIH Problem Statement 26145 pipeline: preparing a clean, leakage-aware, binary **Reconnaissance / Port Scanning** detection dataset from the preprocessed **CIC-IDS2017** benchmark (`data/processed/CIC_IDS2017_cleaned.csv`).

The primary detection objective for this phase is:
- **Malicious Positive Class ($y = 1$)**: `PortScan` (`TrafficClass = "PortScan"`, `BinaryLabel = 1`)
- **Normal Negative Class ($y = 0$)**: `BENIGN` (`TrafficClass = "Normal"`, `BinaryLabel = 0`)

---

### Threat-Mapping & Reconnaissance Context
Reconnaissance is the initial discovery phase of the Cyber Kill Chain. Attackers perform active network port scanning (e.g. via `Nmap`, `Masscan`, or custom probing scripts) to map live hosts, identify listening services, and discover open TCP/UDP ports before launching targeted exploitation.

In unidirectional and bidirectional flow telemetry, port scanning manifests as:
1. **High Flow Velocity & Short Durations**: Rapid sequences of micro-flows probing multiple destination ports with minimal session duration.
2. **Asymmetrical Byte & Packet Profiles**: Single-packet or low-packet probes with little to no backward response payload.
3. **Characteristic TCP Flag Configurations**: High prevalence of solitary `SYN` flags, `RST-ACK` responses, or `FIN`/`NULL`/`XMAS` scan signatures designed to evade stateful firewalls.
4. **Broad Destination Port Diversity**: Flows targeting varied service ports (e.g. 21, 22, 80, 443, 445, 3389, 8080) with uniform packet headers.

---

### Isolation Forest Anomaly Detection Philosophy (Next Phase)
In the upcoming modeling phase (Step 12), we employ **Isolation Forest** as the primary anomaly detector:
- **Unsupervised Normal Baseline Calibration**: Isolation Forest recursively partitions feature space using random orthogonal splits. Sparse anomalous flows (such as port scans) require fewer splits to isolate and appear near the tree root.
- **Normal Training Baseline**: The training partition consists **exclusively of clean Normal/BENIGN traffic ($y = 0$)**.
- **Zero Attack Contamination**: PortScan attack traffic is strictly excluded from model fitting and used exclusively during unseen evaluation.

---

### Strict Threat Separation & Data-Leakage Protocol
1. **Attack Family Separation**: All other attack labels (`DDoS`, `DoS Hulk`, `DoS GoldenEye`, `DoS slowloris`, `DoS Slowhttptest`, `FTP-Patator`, `SSH-Patator`, `Bot`, `Web Attacks`, `Infiltration`, `Heartbleed`) are strictly excluded from the primary PortScan dataset and documented in a dedicated Threat Coverage Summary (`portscan_coverage_summary.csv`).
2. **Class-Wise Temporal Holdout**: Because wall-clock timestamps were stripped by the benchmark authors, we prepare a deterministic 70/30 class-wise temporal holdout based on the retained row sequence:
   - PortScan: First 70% ($N = 63,573$) → historical attack portion; Last 30% ($N = 27,246$) → evaluation attack portion.
   - BENIGN: First 70% ($N = 1,467,538$) → normal training baseline; Last 30% ($N = 628,946$) → evaluation normal portion.
3. **Memory Management (8 GB RAM)**: Data extraction and transformation are executed in streaming chunks of 200,000 rows.
4. **Source Data Immutability**: The source dataset (`data/processed/CIC_IDS2017_cleaned.csv`) remains strictly unmodified."""))

# ==============================================================================
# SECTION 2: Import Libraries
# ==============================================================================
cells.append(nbf.v4.new_markdown_cell("""### 1. Import Libraries & Setup Display Options
Import required scientific, memory management, and visualization libraries."""))

cells.append(nbf.v4.new_code_cell("""import os
import sys
import gc
import json
import warnings
from pathlib import Path
from collections import Counter

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

warnings.filterwarnings('ignore')
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

# Display configurations
pd.set_option('display.max_columns', 35)
pd.set_option('display.width', 1000)
pd.set_option('display.float_format', lambda x: f'{x:.4f}')

plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
plt.rcParams['figure.dpi'] = 120

print(f"NumPy version:  {np.__version__}")
print(f"Pandas version: {pd.__version__}")"""))

# ==============================================================================
# SECTION 3: Verify Source Dataset
# ==============================================================================
cells.append(nbf.v4.new_markdown_cell("""### 2. Verify Source Dataset (`CIC_IDS2017_cleaned.csv`)
Verify file existence, file size, column schema, and inspect a 5-row sample."""))

cells.append(nbf.v4.new_code_cell("""# Resolve project root dynamically
if Path('data/processed').exists():
    project_root = Path.cwd().resolve()
elif Path('../data/processed').exists():
    project_root = Path.cwd().parent.resolve()
else:
    project_root = Path.cwd().resolve()

raw_path = project_root / 'data' / 'processed' / 'CIC_IDS2017_cleaned.csv'
out_dir = project_root / 'data' / 'processed' / 'CIC_IDS2017'
out_dir.mkdir(parents=True, exist_ok=True)

if not raw_path.exists():
    raise FileNotFoundError(f"Input dataset not found at {raw_path}")

raw_size_mb = raw_path.stat().st_size / (1024 * 1024)
print(f"Input Dataset Path: {raw_path.name}")
print(f"Dataset File Size:  {raw_size_mb:.2f} MB")

# Read small sample to detect available schema
sample_df = pd.read_csv(raw_path, nrows=5)
print(f"Sample Dimensions:  {sample_df.shape[0]} rows × {sample_df.shape[1]} columns\\n")
print(f"Available Columns ({len(sample_df.columns)}):")
for i, col in enumerate(sample_df.columns):
    print(f"  {i+1:2d}. {col:30s} ({sample_df[col].dtype})")

display(sample_df.head(5))"""))

# ==============================================================================
# SECTION 4: Full Label Distribution
# ==============================================================================
cells.append(nbf.v4.new_markdown_cell("""### 3. Complete Label Distribution Inspection
Stream through `CIC_IDS2017_cleaned.csv` in chunks to compute the full label distribution across all 2,522,362 records."""))

cells.append(nbf.v4.new_code_cell("""chunk_size = 200000
total_raw_rows = 0
label_counts = Counter()

print("Streaming through dataset to compute label distribution...")
for chunk in pd.read_csv(raw_path, usecols=['Label'], chunksize=chunk_size):
    total_raw_rows += len(chunk)
    label_counts.update(chunk['Label'].values)

label_dist_df = pd.DataFrame([
    {'Label': label, 'Count': count, 'Percentage': (count / total_raw_rows) * 100}
    for label, count in label_counts.most_common()
])

print(f"Total Records in Source Dataset: {total_raw_rows:,}\\n")
display(label_dist_df)"""))

# ==============================================================================
# SECTION 5: Threat Coverage Summary Table
# ==============================================================================
cells.append(nbf.v4.new_markdown_cell("""### 4. Threat Coverage Summary & Role Assignment
Document and assign operational roles across all 15 attack classes in CIC-IDS2017, saving `portscan_coverage_summary.csv`."""))

cells.append(nbf.v4.new_code_cell("""coverage_records = []
for label, count in label_counts.most_common():
    if label == 'PortScan':
        role = 'Primary Recon Class'
    elif label == 'BENIGN':
        role = 'Primary Normal Class'
    else:
        role = 'Excluded Other Attack'
    
    coverage_records.append({
        'Label': label,
        'Count': count,
        'Percentage': (count / total_raw_rows) * 100,
        'Role': role
    })

coverage_df = pd.DataFrame(coverage_records)
coverage_summary_path = out_dir / 'portscan_coverage_summary.csv'
coverage_df.to_csv(coverage_summary_path, index=False)

print(f"Saved Threat Coverage Summary: {coverage_summary_path.name}\\n")
display(coverage_df)"""))

# ==============================================================================
# SECTION 6: Stream Extract PortScan & BENIGN Records
# ==============================================================================
cells.append(nbf.v4.new_markdown_cell("""### 5. Stream Extract PortScan & BENIGN Records
Extract all `PortScan` and `BENIGN` flows in streaming chunks of 200,000 rows without loading unrelated attacks into memory."""))

cells.append(nbf.v4.new_code_cell("""extracted_chunks = []
print("Streaming extraction of PortScan and BENIGN records...")

for chunk in pd.read_csv(raw_path, chunksize=chunk_size):
    filtered_chunk = chunk[chunk['Label'].isin(['PortScan', 'BENIGN'])].copy()
    if len(filtered_chunk) > 0:
        extracted_chunks.append(filtered_chunk)

df = pd.concat(extracted_chunks, ignore_index=True)
del extracted_chunks
gc.collect()

# Create standardized target columns
df['TrafficClass'] = df['Label'].map({'PortScan': 'PortScan', 'BENIGN': 'Normal'})
df['BinaryLabel'] = df['Label'].map({'PortScan': 1, 'BENIGN': 0}).astype(int)

n_selected = len(df)
n_portscan = int((df['BinaryLabel'] == 1).sum())
n_normal = int((df['BinaryLabel'] == 0).sum())

print("--- Extraction Summary ---")
print(f"Source Dataset Rows:         {total_raw_rows:,}")
print(f"Selected Primary Rows:       {n_selected:,} ({(n_selected / total_raw_rows)*100:.2f}%)")
print(f" - PortScan Rows (Label=1):  {n_portscan:,} ({(n_portscan / n_selected)*100:.2f}%)")
print(f" - Normal Rows (Label=0):    {n_normal:,} ({(n_normal / n_selected)*100:.2f}%)")"""))

# ==============================================================================
# SECTION 7: Data Quality Checks (Duplicates, Nulls, Infinities)
# ==============================================================================
cells.append(nbf.v4.new_markdown_cell("""### 6. Data Quality Checks (Duplicates, Nulls & Infinities)
Verify data integrity across all extracted rows and numerical columns."""))

cells.append(nbf.v4.new_code_cell("""# 1. Duplicates Check
dup_count = int(df.duplicated().sum())
dup_pct = (dup_count / len(df)) * 100
print(f"Duplicate Rows Count: {dup_count:,} ({dup_pct:.4f}%)")

# 2. Missing Values Check
missing_s = df.isnull().sum()
missing_cols = missing_s[missing_s > 0]
print(f"Columns with Missing Values: {len(missing_cols)}")
if len(missing_cols) > 0:
    for col, cnt in missing_cols.items():
        print(f" - {col}: {cnt:,} nulls ({(cnt/len(df))*100:.4f}%)")
else:
    print(" ✅ Zero missing values detected.")

# 3. Infinite Values Check
num_cols = df.select_dtypes(include=[np.number]).columns.tolist()
num_cols = [c for c in num_cols if c not in ['BinaryLabel']]

inf_counts = int(np.isinf(df[num_cols].values).sum())
print(f"Infinite Values Count across {len(num_cols)} numerical features: {inf_counts}")
if inf_counts == 0:
    print(" ✅ Zero infinite values detected.")"""))

# ==============================================================================
# SECTION 8: PortScan-Relevant Feature Inspection
# ==============================================================================
cells.append(nbf.v4.new_markdown_cell("""### 7. PortScan-Relevant Feature Inspection
Inspect available flow-level metrics that characterize scanning behavior (Destination Port, Flow Duration, Packet/Byte counts, Rates, IATs, TCP flags, Active/Idle, Subflow statistics)."""))

cells.append(nbf.v4.new_code_cell("""print(f"Available Numerical Features ({len(num_cols)}):")
feature_categories = {
    'Port / Endpoint': [c for c in num_cols if 'port' in c.lower()],
    'Timing & Duration': [c for c in num_cols if 'duration' in c.lower() or 'iat' in c.lower() or 'active' in c.lower() or 'idle' in c.lower()],
    'Packet Behavior': [c for c in num_cols if 'packet' in c.lower() or 'pkt' in c.lower() or 'seg' in c.lower()],
    'Byte Behavior': [c for c in num_cols if 'byte' in c.lower() or 'length' in c.lower() or 'size' in c.lower() or 'win' in c.lower() or 'header' in c.lower()],
    'Flow Rate': [c for c in num_cols if 'rate' in c.lower() or '/s' in c.lower()],
    'TCP Flags': [c for c in num_cols if 'flag' in c.lower()],
    'Subflow Behavior': [c for c in num_cols if 'subflow' in c.lower()]
}

for cat, cols in feature_categories.items():
    print(f" - {cat:<20s} ({len(cols)} features): {cols[:4]}{'...' if len(cols) > 4 else ''}")"""))

# ==============================================================================
# SECTION 9: PS 26145 Feature Limitation Statement
# ==============================================================================
cells.append(nbf.v4.new_markdown_cell(r"""### 8. Architectural & Telemetry Scope Boundary

> **Important PS 26145 Feature Limitation**:
> “The PS 26145 reconnaissance requirement mentions source fan-out across destination ports/hosts. The cleaned CIC-IDS2017 MachineLearningCSV representation does not preserve raw source/destination IP identifiers and timestamps. Therefore, this PortScan detector uses the flow-level statistical features that are actually available in the dataset. Raw source-IP fan-out and host-level scanning counts will be added later when a traffic/flow source containing those identifiers is available.”

This design boundary ensures our machine learning baseline remains scientifically honest without inventing synthetic host-level metadata."""))

# ==============================================================================
# SECTION 10: PortScan-Specific Derived Features
# ==============================================================================
cells.append(nbf.v4.new_markdown_cell(r"""### 9. PortScan-Specific Derived Feature Engineering
Construct directional asymmetry, packet share, and density ratios using safe division:
- $\text{FwdBwdPacketRatio} = \frac{\text{Total Fwd Packets}}{\max(\text{Total Backward Packets}, 1)}$
- $\text{FwdBwdByteRatio} = \frac{\text{Total Length of Fwd Packets}}{\max(\text{Total Length of Bwd Packets}, 1)}$
- $\text{FwdPacketRatio} = \frac{\text{Total Fwd Packets}}{\text{Total Packets}}$
- $\text{BwdPacketRatio} = \frac{\text{Total Backward Packets}}{\text{Total Packets}}$
- $\text{FwdByteRatio} = \frac{\text{Total Length of Fwd Packets}}{\text{Total Bytes}}$
- $\text{BwdByteRatio} = \frac{\text{Total Length of Bwd Packets}}{\text{Total Bytes}}$
- $\text{BytesPerPacket} = \frac{\text{Total Bytes}}{\text{Total Packets}}$
- $\text{PacketsPerByte} = \frac{\text{Total Packets}}{\max(\text{Total Bytes}, 1)}$"""))

cells.append(nbf.v4.new_code_cell("""# Packet and Byte Totals
tot_pkts = df['Total Fwd Packets'] + df['Total Backward Packets']
tot_bytes = df['Total Length of Fwd Packets'] + df['Total Length of Bwd Packets']

# Safe Asymmetry and Ratio Features
df['FwdBwdPacketRatio'] = np.where(df['Total Backward Packets'] > 0, df['Total Fwd Packets'] / df['Total Backward Packets'], df['Total Fwd Packets'].astype(float))
df['FwdBwdByteRatio'] = np.where(df['Total Length of Bwd Packets'] > 0, df['Total Length of Fwd Packets'] / df['Total Length of Bwd Packets'], df['Total Length of Fwd Packets'].astype(float))
df['FwdPacketRatio'] = np.where(tot_pkts > 0, df['Total Fwd Packets'] / tot_pkts, 0.0)
df['BwdPacketRatio'] = np.where(tot_pkts > 0, df['Total Backward Packets'] / tot_pkts, 0.0)
df['FwdByteRatio'] = np.where(tot_bytes > 0, df['Total Length of Fwd Packets'] / tot_bytes, 0.0)
df['BwdByteRatio'] = np.where(tot_bytes > 0, df['Total Length of Bwd Packets'] / tot_bytes, 0.0)
df['BytesPerPacket'] = np.where(tot_pkts > 0, tot_bytes / tot_pkts, 0.0)
df['PacketsPerByte'] = np.where(tot_bytes > 0, tot_pkts / tot_bytes, 0.0)

engineered_features = [
    'FwdBwdPacketRatio', 'FwdBwdByteRatio', 'FwdPacketRatio', 'BwdPacketRatio',
    'FwdByteRatio', 'BwdByteRatio', 'BytesPerPacket', 'PacketsPerByte'
]

print("Engineered PortScan Features Summary:")
display(df[engineered_features].describe().T[['count', 'mean', 'std', 'min', '50%', 'max']])

# Verify zero infinities or NaNs in engineered features
assert np.isinf(df[engineered_features].values).sum() == 0, "Infinities detected in engineered features!"
assert df[engineered_features].isnull().sum().sum() == 0, "NaNs detected in engineered features!"
print("✅ Zero infinities and zero NaNs in engineered features.")"""))

# ==============================================================================
# SECTION 11: Scanning-Related Flow Behavioral Exploration
# ==============================================================================
cells.append(nbf.v4.new_markdown_cell("""### 10. Scanning-Related Flow Behavioral Exploration
Compare statistical distributions of key flow metrics between `PortScan` and `Normal` traffic (without target-derived thresholding)."""))

cells.append(nbf.v4.new_code_cell("""explore_features = [
    'Flow Duration', 'Flow Packets/s', 'Flow Bytes/s', 'Total Fwd Packets',
    'Total Length of Fwd Packets', 'Destination Port', 'BytesPerPacket'
]

print("Mean Behavioral Comparison (PortScan vs Normal):")
explore_summary = df.groupby('TrafficClass')[explore_features].mean().T
explore_summary['Difference (PortScan - Normal)'] = explore_summary['PortScan'] - explore_summary['Normal']
display(explore_summary)"""))

# ==============================================================================
# SECTION 12: TCP Flag Distribution Analysis
# ==============================================================================
cells.append(nbf.v4.new_markdown_cell("""### 11. TCP Flag Distribution Analysis
Analyze TCP flag distributions comparing PortScan probes against Normal sessions."""))

cells.append(nbf.v4.new_code_cell("""flag_cols = [c for c in df.columns if 'flag' in c.lower()]
print(f"Available TCP Flag Features ({len(flag_cols)}): {flag_cols}")

flag_summary = df.groupby('TrafficClass')[flag_cols].mean().T
flag_summary['Difference'] = flag_summary['PortScan'] - flag_summary['Normal']

print("\\nTCP Flag Frequency Comparison (PortScan vs Normal):")
display(flag_summary)"""))

# ==============================================================================
# SECTION 13: Destination Port Distribution Analysis
# ==============================================================================
cells.append(nbf.v4.new_markdown_cell("""### 12. Destination Port Distribution Analysis
Examine destination port distributions for PortScan and Normal traffic."""))

cells.append(nbf.v4.new_code_cell("""port_stats = df.groupby('TrafficClass')['Destination Port'].agg(
    Count='count',
    Unique_Ports='nunique',
    Min_Port='min',
    Max_Port='max',
    Median_Port='median',
    Mean_Port='mean'
)
print("Destination Port Statistical Summary:")
display(port_stats)

print("\\nTop 10 Destination Ports in PortScan Traffic:")
display(df[df['TrafficClass'] == 'PortScan']['Destination Port'].value_counts().head(10).reset_index(name='FlowCount'))

print("\\nTop 10 Destination Ports in Normal Traffic:")
display(df[df['TrafficClass'] == 'Normal']['Destination Port'].value_counts().head(10).reset_index(name='FlowCount'))"""))

# ==============================================================================
# SECTION 14: Feature Correlation Analysis
# ==============================================================================
cells.append(nbf.v4.new_markdown_cell("""### 13. Feature Correlation Analysis
Compute and visualize the correlation matrix across selected candidate numerical flow features."""))

cells.append(nbf.v4.new_code_cell("""corr_feats = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Flow Packets/s', 'Flow Bytes/s', 'Packet Length Mean', 'FwdBwdPacketRatio',
    'SYN Flag Count', 'ACK Flag Count', 'BytesPerPacket'
]

corr_matrix = df[corr_feats].corr()

fig, ax = plt.subplots(figsize=(10, 7))
sns.heatmap(corr_matrix, annot=True, fmt='.2f', cmap='coolwarm', ax=ax, cbar=True, annot_kws={'size': 8})
ax.set_title("Candidate Feature Correlation Matrix (PortScan Dataset)", fontsize=11, fontweight='bold', pad=12)
plt.tight_layout()
plt.show()"""))

# ==============================================================================
# SECTION 15: Target Distribution Visualization
# ==============================================================================
cells.append(nbf.v4.new_markdown_cell("""### 14. Target Distribution Visualization
Visualize binary class proportions between `Normal` baseline traffic and `PortScan` reconnaissance flows."""))

cells.append(nbf.v4.new_code_cell("""fig, ax = plt.subplots(figsize=(7, 5))
class_counts = df['TrafficClass'].value_counts()
colors = ['#2ecc71', '#e67e22']
bars = ax.bar(class_counts.index, class_counts.values, color=colors, edgecolor='black', width=0.45)

for bar in bars:
    yval = bar.get_height()
    ax.text(bar.get_x() + bar.get_width()/2.0, yval + 25000, f"{yval:,}\\n({(yval/len(df))*100:.2f}%)", ha='center', va='bottom', fontweight='bold', fontsize=10)

ax.set_title("Binary Class Distribution (PortScan vs Normal)", fontsize=12, fontweight='bold', pad=12)
ax.set_ylabel("Flow Count", fontsize=11, fontweight='bold')
ax.set_ylim(0, max(class_counts.values) * 1.15)

plt.tight_layout()
plt.show()"""))

# ==============================================================================
# SECTION 16: Class-Wise Temporal Holdout & Isolation Forest Baseline Preparation
# ==============================================================================
cells.append(nbf.v4.new_markdown_cell(r"""### 15. Class-Wise Temporal Holdout & Isolation Forest Baseline Preparation
Establish a deterministic class-wise temporal holdout (70/30 sequential split) based on the dataset's retained row sequence:
- **PortScan Partitioning**: First 70% ($N = 63,573$) $\rightarrow$ attack training-history portion; Last 30% ($N = 27,246$) $\rightarrow$ attack evaluation portion.
- **Normal Partitioning**: First 70% ($N = 1,467,538$) $\rightarrow$ normal training baseline; Last 30% ($N = 628,946$) $\rightarrow$ normal evaluation portion.
- **Isolation Forest Normal Training Baseline**: **ONLY the first 70% BENIGN rows** ($1,467,538$ normal flows). PortScan flows are strictly excluded from normal baseline fitting.
- **Evaluation Dataset**: Last 30% BENIGN ($628,946$) + Last 30% PortScan ($27,246$) = $656,192$ evaluation flows.

> **Methodological Note**:
> “This is a class-wise temporal holdout based on the dataset's retained row ordering, not a global wall-clock chronological split.”"""))

cells.append(nbf.v4.new_code_cell("""# Extract indices by class in original row order
portscan_indices = np.where(df['BinaryLabel'] == 1)[0]
normal_indices = np.where(df['BinaryLabel'] == 0)[0]

portscan_split_pt = int(0.70 * len(portscan_indices))
normal_split_pt = int(0.70 * len(normal_indices))

train_portscan_idx = portscan_indices[:portscan_split_pt]
test_portscan_idx = portscan_indices[portscan_split_pt:]

train_normal_idx = normal_indices[:normal_split_pt]
test_normal_idx = normal_indices[normal_split_pt:]

# Isolation Forest Training Baseline: ONLY Normal Training Rows
iso_forest_train_idx = train_normal_idx

# Evaluation Dataset: Last 30% Normal + Last 30% PortScan
eval_idx = np.sort(np.concatenate([test_normal_idx, test_portscan_idx]))
eval_df = df.iloc[eval_idx].copy()
eval_df['EvaluationLabel'] = eval_df['BinaryLabel'].values

print("--- Class-Wise Temporal Holdout Partitioning ---")
print(f"PortScan Total:           {len(portscan_indices):,}")
print(f" - Train History Portion (70%): {len(train_portscan_idx):,} (Index {train_portscan_idx.min():,} → {train_portscan_idx.max():,})")
print(f" - Evaluation Portion (30%):    {len(test_portscan_idx):,} (Index {test_portscan_idx.min():,} → {test_portscan_idx.max():,})")
print(f"Normal/BENIGN Total:      {len(normal_indices):,}")
print(f" - Normal Baseline Train (70%): {len(train_normal_idx):,} (Index {train_normal_idx.min():,} → {train_normal_idx.max():,})")
print(f" - Normal Evaluation (30%):     {len(test_normal_idx):,} (Index {test_normal_idx.min():,} → {test_normal_idx.max():,})")

print(f"\\nIsolation Forest Training Baseline (Normal Only): {len(iso_forest_train_idx):,} flows (100.0% BENIGN)")
print(f"Combined Evaluation Dataset:                      {len(eval_df):,} flows (PortScan: {len(test_portscan_idx):,}, Normal: {len(test_normal_idx):,})")

assert train_portscan_idx.max() < test_portscan_idx.min(), "PortScan temporal split overlap!"
assert train_normal_idx.max() < test_normal_idx.min(), "Normal temporal split overlap!"
assert len(train_normal_idx) + len(test_normal_idx) == len(normal_indices), "Normal accounting error!"
assert len(train_portscan_idx) + len(test_portscan_idx) == len(portscan_indices), "PortScan accounting error!\""""))

# ==============================================================================
# SECTION 17: Candidate Feature Selection & Feature Report
# ==============================================================================
cells.append(nbf.v4.new_markdown_cell("""### 16. Candidate Feature Selection (`PORTSCAN_FEATURE_COLUMNS`) & Quality Report
Extract all numerical features suitable for Isolation Forest anomaly detection and compile `portscan_feature_report.csv`."""))

cells.append(nbf.v4.new_code_cell("""non_feature_cols = ['Label', 'TrafficClass', 'BinaryLabel', 'EvaluationLabel']
PORTSCAN_FEATURE_COLUMNS = [c for c in df.select_dtypes(include=[np.number]).columns if c not in non_feature_cols]

print(f"Total Candidate PORTSCAN_FEATURE_COLUMNS: {len(PORTSCAN_FEATURE_COLUMNS)}")

def categorize_portscan_feature(name):
    n = name.lower()
    if 'port' in n:
        return 'Port Behavior'
    elif 'flag' in n:
        return 'TCP Flag Behavior'
    elif 'rate' in n or '/s' in n:
        return 'Flow Rate'
    elif 'iat' in n or 'active' in n or 'idle' in n or 'duration' in n:
        return 'Timing'
    elif 'packet' in n or 'pkt' in n or 'seg' in n:
        return 'Packet Behavior'
    elif 'byte' in n or 'length' in n or 'size' in n or 'win' in n or 'header' in n:
        return 'Byte Behavior'
    elif 'subflow' in n:
        return 'Subflow Behavior'
    else:
        return 'Flow Volume'

feat_report_records = []
for col in PORTSCAN_FEATURE_COLUMNS:
    s = df[col]
    feat_report_records.append({
        'Feature': col,
        'DataType': str(s.dtype),
        'MissingCount': int(s.isnull().sum()),
        'MissingPercentage': float((s.isnull().sum() / len(df)) * 100),
        'InfiniteCount': int(np.isinf(s.values).sum()),
        'Min': float(s.min()),
        'Max': float(s.max()),
        'Mean': float(s.mean()),
        'Median': float(s.median()),
        'FeatureCategory': categorize_portscan_feature(col)
    })

feature_report_df = pd.DataFrame(feat_report_records)
feature_report_path = out_dir / 'portscan_feature_report.csv'
feature_report_df.to_csv(feature_report_path, index=False)
print(f"Saved Feature Quality Report: {feature_report_path.name}")
display(feature_report_df.head(10))"""))

# ==============================================================================
# SECTION 18: Save Output Datasets & Split Summary
# ==============================================================================
cells.append(nbf.v4.new_markdown_cell("""### 17. Save Output Datasets & Split Summaries
Export prepared binary dataset, model-ready numerical feature dataset, and split summary."""))

cells.append(nbf.v4.new_code_cell("""# 1. Full Prepared Binary Dataset (Metadata + Labels + Engineered Features)
full_binary_path = out_dir / 'portscan_binary_dataset.csv'
df.to_csv(full_binary_path, index=False, chunksize=100000)
full_size_mb = full_binary_path.stat().st_size / (1024 * 1024)
print(f"1. Saved Full Binary Dataset:  {full_binary_path.name} ({full_size_mb:.2f} MB, {len(df):,} rows)")

# 2. Model-Ready Numerical Dataset (PORTSCAN_FEATURE_COLUMNS + BinaryLabel ONLY)
model_df = df[PORTSCAN_FEATURE_COLUMNS].copy()
model_df['BinaryLabel'] = df['BinaryLabel'].values

model_features_path = out_dir / 'portscan_model_features.csv'
model_df.to_csv(model_features_path, index=False, chunksize=100000)
model_size_mb = model_features_path.stat().st_size / (1024 * 1024)
print(f"2. Saved Model-Ready Dataset:  {model_features_path.name} ({model_size_mb:.2f} MB, {len(model_df):,} rows)")

# 3. Save Split Summary
split_summary_data = [
    {"Metric": "portscan_train_rows", "Value": len(train_portscan_idx)},
    {"Metric": "portscan_test_rows", "Value": len(test_portscan_idx)},
    {"Metric": "normal_train_rows", "Value": len(train_normal_idx)},
    {"Metric": "normal_test_rows", "Value": len(test_normal_idx)},
    {"Metric": "evaluation_portscan_rows", "Value": len(test_portscan_idx)},
    {"Metric": "evaluation_normal_rows", "Value": len(test_normal_idx)},
    {"Metric": "isolation_forest_train_baseline_rows", "Value": len(iso_forest_train_idx)},
    {"Metric": "portscan_train_pct", "Value": f"{(len(train_portscan_idx)/len(portscan_indices))*100:.2f}%"},
    {"Metric": "portscan_test_pct", "Value": f"{(len(test_portscan_idx)/len(portscan_indices))*100:.2f}%"},
    {"Metric": "normal_train_pct", "Value": f"{(len(train_normal_idx)/len(normal_indices))*100:.2f}%"},
    {"Metric": "normal_test_pct", "Value": f"{(len(test_normal_idx)/len(normal_indices))*100:.2f}%"},
    {"Metric": "split_method", "Value": "Class-Wise Temporal Holdout (70/30 Sequential)"},
    {"Metric": "training_baseline_description", "Value": "First 70% Normal/BENIGN flows only (Unsupervised Normal Baseline)"}
]

split_summary_df = pd.DataFrame(split_summary_data)
split_summary_path = out_dir / 'portscan_split_summary.csv'
split_summary_df.to_csv(split_summary_path, index=False)
print(f"3. Saved Split Summary:        {split_summary_path.name}")
display(split_summary_df)"""))

# ==============================================================================
# SECTION 19: Final Data Quality Validation & Assertions
# ==============================================================================
cells.append(nbf.v4.new_markdown_cell("""### 18. Final Quality Validation & Integrity Assertions
Validate assertions to ensure zero data corruption, zero label leakage, and raw file preservation."""))

cells.append(nbf.v4.new_code_cell("""# Assertions
assert raw_path.exists(), "Source cleaned dataset missing."
assert raw_size_mb > 800.0, "Source cleaned dataset was corrupted or truncated."

assert full_binary_path.exists(), "Binary dataset missing."
assert model_features_path.exists(), "Model features dataset missing."
assert feature_report_path.exists(), "Feature report missing."
assert split_summary_path.exists(), "Split summary missing."
assert coverage_summary_path.exists(), "Coverage summary missing."

assert set(df['BinaryLabel'].unique()) == {0, 1}, "Invalid BinaryLabel values."
assert set(df['TrafficClass'].unique()) == {'PortScan', 'Normal'}, "Invalid TrafficClass values."
assert 'BinaryLabel' not in PORTSCAN_FEATURE_COLUMNS, "Label leakage in feature columns."
assert 'TrafficClass' not in PORTSCAN_FEATURE_COLUMNS, "Label leakage in feature columns."
assert 'Label' not in PORTSCAN_FEATURE_COLUMNS, "Label leakage in feature columns."

assert np.isinf(model_df[PORTSCAN_FEATURE_COLUMNS].values).sum() == 0, "Infinities in model dataset."
assert model_df[PORTSCAN_FEATURE_COLUMNS].isnull().sum().sum() == 0, "Nulls in model dataset."

# Validate Normal Training Baseline Contains ONLY BinaryLabel == 0
normal_train_labels = set(df.iloc[iso_forest_train_idx]['BinaryLabel'].unique())
assert normal_train_labels == {0}, f"Isolation Forest baseline contains non-normal labels: {normal_train_labels}"

print("==================================================")
print("PortScan preprocessing validation: PASSED")
print("==================================================")
print(f"Source Dataset Rows:          {total_raw_rows:,}")
print(f"Selected Primary Rows:        {len(df):,}")
print(f" - PortScan Flows:             {n_portscan:,} (4.15%)")
print(f" - Normal Flows:               {n_normal:,} (95.85%)")
print(f"Candidate Features Count:     {len(PORTSCAN_FEATURE_COLUMNS)}")
print(f"Isolation Forest Train Baseline: {len(iso_forest_train_idx):,} flows (100% Normal)")
print(f"Evaluation Partition Rows:    {len(eval_df):,} flows ({len(test_portscan_idx):,} PortScan, {len(test_normal_idx):,} Normal)\\n")

print("Generated Output Files:")
print(f" 1. {full_binary_path.relative_to(project_root)} ({full_size_mb:.2f} MB)")
print(f" 2. {model_features_path.relative_to(project_root)} ({model_size_mb:.2f} MB)")
print(f" 3. {feature_report_path.relative_to(project_root)}")
print(f" 4. {split_summary_path.relative_to(project_root)}")
print(f" 5. {coverage_summary_path.relative_to(project_root)}")
print("\\n✅ All quality and integrity checks passed. Source dataset untouched.")"""))

# ==============================================================================
# SECTION 20: Final Findings & Technical Summary
# ==============================================================================
cells.append(nbf.v4.new_markdown_cell(r"""### 19. Comprehensive Final Findings & Technical Summary

#### 1. Why PortScan is a Reconnaissance Threat Category
Port scanning represents the discovery and intelligence-gathering phase of adversary campaigns. By probing ports across destination subnets, attackers ascertain active services, operating system signatures, and potential vulnerability surfaces before launching weaponized exploits.

#### 2. Why Isolation Forest is Appropriate for Anomaly-Oriented Detection
Isolation Forest operates on the principle that anomalies are "few and different". It constructs an ensemble of isolation trees that randomly select features and split values. Normal, dense baseline traffic requires many splits to isolate deep in the trees, whereas reconnaissance probes deviate significantly in flow duration, packet sizes, and flag patterns, causing them to be isolated near tree roots with short average path lengths.

#### 3. Available Flow-Level Features
The dataset provides 78 numerical features covering:
- **Port / Endpoint Behavior**: `Destination Port`
- **Timing & Inter-Arrivals**: `Flow Duration`, `Flow IAT Mean/Std/Max/Min`, `Active/Idle Mean/Std`
- **Packet & Byte Characteristics**: `Total Fwd/Bwd Packets`, `Packet Length Mean/Std/Max/Min`, `Average Packet Size`
- **Directional Asymmetry**: `FwdBwdPacketRatio`, `FwdBwdByteRatio`, `FwdPacketRatio`, `BwdPacketRatio`, `BytesPerPacket`, `PacketsPerByte`
- **TCP Control Flags**: `SYN`, `ACK`, `RST`, `PSH`, `FIN`, `URG`, `CWE`, `ECE` Flag counts
- **Subflow Statistics**: `Subflow Fwd/Bwd Packets/Bytes`, `Init_Win_bytes_forward/backward`

#### 4. Features Not Available in This CIC-IDS2017 Representation
Source IP addresses, destination IP addresses, MAC addresses, and raw timestamps were removed in the `MachineLearningCSV` release. Consequently, multi-host fan-out entropy (e.g. unique destination IPs contacted per source IP over a 60-second window) cannot be computed directly from this representation. The detector relies on flow-statistical indicators until raw PCAP/NetFlow streaming sources are integrated.

#### 5. Class-Wise Temporal Holdout Methodology
To ensure rigorous evaluation without lookahead leakage:
- The first 70% of historical Normal traffic ($1,467,538$ flows) and first 70% of historical PortScan traffic ($63,573$ flows) form the training history partition.
- The subsequent 30% of Normal traffic ($628,946$ flows) and subsequent 30% of PortScan traffic ($27,246$ flows) form the evaluation partition.
- This maintains temporal precedence ($\max(\text{TrainIndex}) < \min(\text{TestIndex})$) within each class without random shuffling.

#### 6. Why Only Normal Training Traffic Fits Isolation Forest
Fitting Isolation Forest strictly on clean Normal/BENIGN flows guarantees that the model learns the geometric and statistical manifold of legitimate traffic. Including attack samples in the training baseline would corrupt the normal density profile and reduce sensitivity to outlier reconnaissance probes.

#### 7. Roadmap for Step 12
In Step 12, we will:
1. Load `portscan_model_features.csv` and `portscan_split_summary.csv`.
2. Fit `IsolationForest` strictly on the $1,467,538$ normal training baseline flows.
3. Compute anomaly scores on the $656,192$ evaluation flows ($27,246$ PortScan + $628,946$ Normal).
4. Calibrate anomaly score thresholds and evaluate Precision, Recall, F1, FPR, ROC-AUC, and PR-AUC."""))

# Write notebook to disk
nb.cells = cells
output_nb_path = Path('notebooks/11_portscan_dataset_preparation.ipynb')
output_nb_path.parent.mkdir(parents=True, exist_ok=True)
with open(output_nb_path, 'w', encoding='utf-8') as f:
    nbf.write(nb, f)

print(f"Successfully generated {output_nb_path} with {len(cells)} cells.")
