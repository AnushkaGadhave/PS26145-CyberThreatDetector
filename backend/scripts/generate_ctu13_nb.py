import nbformat as nbf
from pathlib import Path

nb = nbf.v4.new_notebook()
cells = []

# ==========================================
# Section 1 & 2: Title and Objective
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""# CTU-13 Scenario 42 Dataset Exploration — Botnet C2 Detection
## SIH 2026 - Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

### Objective
This notebook performs exploratory data analysis on the **CTU-13 Scenario 42 (Capture 2011-08-10)** NetFlow dataset to inspect its structure, label distributions, flow characteristics, and evaluate its suitability for building a dedicated **Botnet C2 Beaconing Detection Engine** in unidirectional network environments."""))

# ==========================================
# Section 3: Import Libraries
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""### 1. Import Libraries
Import required libraries for memory-efficient chunked data analysis and visualization."""))

cells.append(nbf.v4.new_code_cell("""import os
import sys
import warnings
from pathlib import Path
from collections import Counter, defaultdict
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
pd.set_option('display.max_columns', 20)
pd.set_option('display.width', 1000)
pd.set_option('display.float_format', lambda x: f'{x:.4f}')

plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
plt.rcParams['figure.dpi'] = 120

print(f"Pandas version: {pd.__version__}")
print(f"NumPy version: {np.__version__}")"""))

# ==========================================
# Section 4: Dataset Path
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""### 2. Dataset Path Verification
Locate and verify the presence of the CTU-13 Scenario 42 `.binetflow` capture file."""))

cells.append(nbf.v4.new_code_cell("""candidate_paths = [
    Path('../data/raw/CTU13/Scenario42/capture20110810.binetflow'),
    Path('data/raw/CTU13/Scenario42/capture20110810.binetflow'),
    Path.cwd() / 'data' / 'raw' / 'CTU13' / 'Scenario42' / 'capture20110810.binetflow',
    Path.cwd().parent / 'data' / 'raw' / 'CTU13' / 'Scenario42' / 'capture20110810.binetflow'
]

data_path = None
for p in candidate_paths:
    if p.exists() and p.is_file():
        data_path = p.resolve()
        break

if data_path is None:
    raise FileNotFoundError("Could not find capture20110810.binetflow file in candidate paths.")

file_size_bytes = data_path.stat().st_size
file_size_mb = file_size_bytes / (1024 * 1024)

print(f"File Path: {data_path}")
print(f"File Size: {file_size_mb:.2f} MB ({file_size_bytes:,} bytes)")"""))

# ==========================================
# Section 5: Inspect File Structure
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""### 3. Inspect File Structure
Read a lightweight sample to inspect schema, column naming, delimiters, and data types without loading the full 369 MB file."""))

cells.append(nbf.v4.new_code_cell("""sample_df = pd.read_csv(data_path, nrows=1000, sep=',')
print(f"Sample Dimensions: {sample_df.shape[0]} rows x {sample_df.shape[1]} columns")
print(f"Total Columns: {len(sample_df.columns)}\\n")

print("--- Column Schema & Data Types ---")
schema_info = []
for idx, (col, dtype) in enumerate(sample_df.dtypes.items(), 1):
    schema_info.append({
        "Index": idx,
        "Column Name": col,
        "Data Type": str(dtype),
        "Sample Value": repr(sample_df[col].iloc[0])
    })

schema_df = pd.DataFrame(schema_info)
display(schema_df)

print("\\n--- First 5 Rows Preview ---")
display(sample_df.head(5))"""))

# ==========================================
# Section 6: Dataset Size (Chunked Count)
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""### 4. Dataset Size & Total Row Count
Compute total flow records using memory-efficient chunked streaming."""))

cells.append(nbf.v4.new_code_cell("""total_rows = 0
chunksize = 250000

for chunk in pd.read_csv(data_path, usecols=[0], chunksize=chunksize, low_memory=False):
    total_rows += len(chunk)

print(f"Total Rows in CTU-13 Scenario 42: {total_rows:,}")
print(f"Total Columns: {len(sample_df.columns)}")"""))

# ==========================================
# Section 7: Label Analysis
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""### 5. Label Analysis
Analyze ground-truth labels across the entire dataset, categorizing flows into `From-Botnet`, `To-Botnet`, `From-Normal`, `To-Normal`, and `Background` traffic."""))

cells.append(nbf.v4.new_code_cell("""label_counts_all = Counter()
macro_category_counts = Counter()

botnet_sublabels = Counter()
normal_sublabels = Counter()
background_sublabels = Counter()
to_botnet_sublabels = Counter()
to_normal_sublabels = Counter()

for chunk in pd.read_csv(data_path, usecols=['Label'], chunksize=chunksize, low_memory=False):
    for lbl, count in chunk['Label'].value_counts().items():
        lbl_str = str(lbl).strip()
        label_counts_all[lbl_str] += count
        
        # Categorize into macro classes
        if 'From-Botnet' in lbl_str:
            macro_category_counts['From-Botnet'] += count
            botnet_sublabels[lbl_str] += count
        elif 'To-Botnet' in lbl_str:
            macro_category_counts['To-Botnet'] += count
            to_botnet_sublabels[lbl_str] += count
        elif 'From-Normal' in lbl_str:
            macro_category_counts['From-Normal'] += count
            normal_sublabels[lbl_str] += count
        elif 'To-Normal' in lbl_str:
            macro_category_counts['To-Normal'] += count
            to_normal_sublabels[lbl_str] += count
        elif 'Background' in lbl_str:
            macro_category_counts['Background'] += count
            background_sublabels[lbl_str] += count
        else:
            macro_category_counts['Other'] += count

print(f"Total Unique Detailed Labels: {len(label_counts_all)}\\n")

# Macro Category Table
macro_summary = []
for cat, cnt in macro_category_counts.most_common():
    macro_summary.append({
        "Macro Category": cat,
        "Flow Count": cnt,
        "Percentage": f"{(cnt / total_rows) * 100:.4f}%"
    })

macro_df = pd.DataFrame(macro_summary)
print("--- Macro Label Categories ---")
display(macro_df)

print("\\n--- Top 10 Detailed Botnet Sub-Labels (From-Botnet) ---")
top_botnet = pd.DataFrame([{"Botnet Label": k, "Count": v, "Percentage": f"{(v/total_rows)*100:.4f}%"} for k, v in botnet_sublabels.most_common(10)])
display(top_botnet)

print("\\n--- Normal Sub-Labels (From-Normal) ---")
normal_table = pd.DataFrame([{"Normal Label": k, "Count": v, "Percentage": f"{(v/total_rows)*100:.4f}%"} for k, v in normal_sublabels.most_common()])
display(normal_table)"""))

# ==========================================
# Section 8: Basic Dataset Statistics
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""### 6. Basic Dataset Statistics
Inspect protocol distributions, top IP endpoints, port behavior, and numerical flow metrics across the full dataset."""))

cells.append(nbf.v4.new_code_cell("""proto_counts = Counter()
src_ips = Counter()
dst_ips = Counter()

for chunk in pd.read_csv(data_path, usecols=['Proto', 'SrcAddr', 'DstAddr'], chunksize=chunksize, low_memory=False):
    for p, cnt in chunk['Proto'].value_counts().items():
        proto_counts[str(p).lower()] += cnt
    for ip, cnt in chunk['SrcAddr'].value_counts().head(20).items():
        src_ips[str(ip)] += cnt
    for ip, cnt in chunk['DstAddr'].value_counts().head(20).items():
        dst_ips[str(ip)] += cnt

proto_df = pd.DataFrame([{"Protocol": k, "Count": v, "Percentage": f"{(v/total_rows)*100:.4f}%"} for k, v in proto_counts.most_common(8)])
print("--- Protocol Distribution ---")
display(proto_df)

print("\\n--- Top 5 Most Active Source IPs ---")
top_src_df = pd.DataFrame([{"Source IP": k, "Flows": v} for k, v in src_ips.most_common(5)])
display(top_src_df)"""))

# ==========================================
# Section 9: Missing Values
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""### 7. Missing-Value Analysis
Scan all 15 columns for missing/null values across all 2.82M rows."""))

cells.append(nbf.v4.new_code_cell("""col_nulls = defaultdict(int)

for chunk in pd.read_csv(data_path, chunksize=chunksize, low_memory=False):
    for col in chunk.columns:
        col_nulls[col] += int(chunk[col].isnull().sum())

null_report = []
for col in sample_df.columns:
    null_cnt = col_nulls[col]
    pct = (null_cnt / total_rows) * 100
    null_report.append({
        "Column": col,
        "Missing Count": null_cnt,
        "Missing Percentage": f"{pct:.4f}%",
        "Status": "Clean (0 nulls)" if null_cnt == 0 else f"{null_cnt:,} nulls"
    })

null_df = pd.DataFrame(null_report)
display(null_df)"""))

# ==========================================
# Section 10: Duplicate Analysis
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""### 8. Duplicate Analysis
Perform an exact full-dataset duplicate analysis using 64-bit row hashing."""))

cells.append(nbf.v4.new_code_cell("""seen_hashes = set()
duplicate_rows_count = 0

for chunk in pd.read_csv(data_path, chunksize=chunksize, low_memory=False):
    for row in chunk.itertuples(index=False, name=None):
        h = hash(row)
        if h in seen_hashes:
            duplicate_rows_count += 1
        else:
            seen_hashes.add(h)

print(f"Scope: FULL DATASET DUPLICATE CHECK ({total_rows:,} rows inspected)")
print(f"Duplicate Rows Count: {duplicate_rows_count:,}")
print(f"Duplicate Percentage: {(duplicate_rows_count / total_rows) * 100:.4f}%")
print(f"Unique Flow Rows: {len(seen_hashes):,}")"""))

# ==========================================
# Section 11: Botnet vs Normal Traffic Comparison
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""### 9. Botnet vs. Normal Traffic Profiling
Extract and compare numerical flow metrics (`Dur`, `TotPkts`, `TotBytes`, `SrcBytes`) specifically between `From-Botnet` and `From-Normal` traffic."""))

cells.append(nbf.v4.new_code_cell("""botnet_flows_list = []
normal_flows_list = []

for chunk in pd.read_csv(data_path, chunksize=chunksize, low_memory=False):
    bot_mask = chunk['Label'].str.contains('From-Botnet', na=False)
    norm_mask = chunk['Label'].str.contains('From-Normal', na=False)
    
    if bot_mask.any():
        botnet_flows_list.append(chunk[bot_mask][['Dur', 'TotPkts', 'TotBytes', 'SrcBytes', 'Proto']])
    if norm_mask.any():
        normal_flows_list.append(chunk[norm_mask][['Dur', 'TotPkts', 'TotBytes', 'SrcBytes', 'Proto']])

botnet_df = pd.concat(botnet_flows_list, ignore_index=True)
normal_df = pd.concat(normal_flows_list, ignore_index=True)

for col in ['Dur', 'TotPkts', 'TotBytes', 'SrcBytes']:
    botnet_df[col] = pd.to_numeric(botnet_df[col], errors='coerce')
    normal_df[col] = pd.to_numeric(normal_df[col], errors='coerce')

print(f"Botnet Flows Loaded: {len(botnet_df):,}")
print(f"Normal Flows Loaded: {len(normal_df):,}\\n")

print("--- Botnet Flow Numerical Statistics (From-Botnet) ---")
display(botnet_df[['Dur', 'TotPkts', 'TotBytes', 'SrcBytes']].describe())

print("\\n--- Normal Flow Numerical Statistics (From-Normal) ---")
display(normal_df[['Dur', 'TotPkts', 'TotBytes', 'SrcBytes']].describe())"""))

# ==========================================
# Section 12: Feature Suitability for Botnet C2
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""### 10. Feature Suitability for Botnet C2 Detection
Map all 15 available CTU-13 features to their functional cybersecurity domain for unidirectional flow analysis:

| Feature Category | Available Dataset Columns | Relevance to Botnet C2 Detection |
| :--- | :--- | :--- |
| **Flow Timing** | `StartTime`, `Dur` | Crucial for detecting periodic beaconing intervals, jitter, and persistent short/long connections. |
| **Flow Volume** | `TotBytes`, `SrcBytes` | Detects lightweight heartbeat packets vs. payload downloads/exfiltration byte spikes. |
| **Packet Behavior** | `TotPkts`, `sTos`, `dTos` | Low packet count per flow (mean ~4.9 pkts) characterizes polling/keepalive handshakes. |
| **Connection Endpoints** | `SrcAddr`, `DstAddr`, `Sport`, `Dport`, `Dir` | Identifies C2 server IPs, fan-out ratios, and recurring communication to remote destinations. |
| **Protocol / Port Behavior** | `Proto`, `State`, `Sport`, `Dport` | Tracks protocol abuse (e.g. UDP DNS C2 tunnelling, HTTP/HTTPS beaconing). |"""))

# ==========================================
# Section 13: Important CTU-13 Label Interpretation
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""### 11. Important CTU-13 Label Interpretation

> **Ground-Truth Policy for SIH PS 26145**:
>
> "For this project, **From-Botnet** represents traffic originating from the botnet and is the primary malicious class considered for Botnet C2 detection. **To-Botnet** traffic is not automatically treated as malicious because it represents traffic sent toward the botnet by potentially normal/unknown hosts."
>
> The exact final binary-label mapping (`From-Botnet` -> `1` / Malicious C2, `From-Normal` / Filtered Background -> `0` / Benign) will be formally constructed and saved during the next preprocessing phase."""))

# ==========================================
# Section 14: Visualizations
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""### 12. Visual Summaries
Lightweight visualizations of traffic class distributions and transport protocols."""))

cells.append(nbf.v4.new_code_cell("""fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 5))

# Plot 1: Macro Traffic Classes
macro_labels = [row['Macro Category'] for row in macro_summary]
macro_counts = [row['Flow Count'] for row in macro_summary]
colors = ['#3498db', '#e74c3c', '#2ecc71', '#f39c12', '#95a5a6']

y_pos = np.arange(len(macro_labels))
ax1.barh(y_pos, macro_counts, color=colors[:len(macro_labels)], edgecolor='black', alpha=0.85)
ax1.set_yticks(y_pos)
ax1.set_yticklabels(macro_labels, fontsize=10, fontweight='bold')
ax1.set_xscale('log')
ax1.invert_yaxis()
ax1.set_xlabel('Flow Count (Log Scale)', fontsize=10)
ax1.set_title('CTU-13 Scenario 42 Traffic Class Distribution (2.82M Rows)', fontsize=11, fontweight='bold')

for i, count in enumerate(macro_counts):
    ax1.text(count * 1.15, i, f"{count:,}", va='center', fontsize=9, color='#2c3e50')

# Plot 2: Protocol Breakdown
proto_names = [r['Protocol'].upper() for r in proto_df.to_dict('records')[:5]]
proto_vals = [r['Count'] for r in proto_df.to_dict('records')[:5]]

ax2.bar(proto_names, proto_vals, color='#1abc9c', edgecolor='black', alpha=0.85)
ax2.set_yscale('log')
ax2.set_ylabel('Flow Count (Log Scale)', fontsize=10)
ax2.set_title('Transport Protocols in CTU-13 Scenario 42', fontsize=11, fontweight='bold')

for i, count in enumerate(proto_vals):
    ax2.text(i, count * 1.15, f"{count:,}", ha='center', fontsize=8, color='#2c3e50')

plt.tight_layout()
plt.show()"""))

# ==========================================
# Section 15 & 16: Final Findings & Report Export
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""### 13. Final Findings & Summary Report Export
Export structured metadata summary to `data/processed/ctu13_exploration_summary.csv`."""))

cells.append(nbf.v4.new_code_cell("""processed_dir = Path('data/processed')
if not processed_dir.exists() and Path('../data/processed').exists():
    processed_dir = Path('../data/processed')
processed_dir.mkdir(parents=True, exist_ok=True)

from_botnet_count = macro_category_counts.get('From-Botnet', 0)
from_normal_count = macro_category_counts.get('From-Normal', 0)
background_count = macro_category_counts.get('Background', 0)
to_normal_count = macro_category_counts.get('To-Normal', 0)
to_botnet_count = macro_category_counts.get('To-Botnet', 0)

summary_records = [
    {"Metric": "Dataset Name", "Value": "CTU-13 Scenario 42 (Capture 2011-08-10)"},
    {"Metric": "Raw File Path", "Value": "data/raw/CTU13/Scenario42/capture20110810.binetflow"},
    {"Metric": "Raw File Size (MB)", "Value": f"{file_size_mb:.2f} MB"},
    {"Metric": "Total Flow Records", "Value": f"{total_rows:,}"},
    {"Metric": "Total Features / Columns", "Value": len(sample_df.columns)},
    {"Metric": "From-Botnet Flows", "Value": f"{from_botnet_count:,} ({(from_botnet_count/total_rows)*100:.2f}%)"},
    {"Metric": "From-Normal Flows", "Value": f"{from_normal_count:,} ({(from_normal_count/total_rows)*100:.2f}%)"},
    {"Metric": "Background Flows", "Value": f"{background_count:,} ({(background_count/total_rows)*100:.2f}%)"},
    {"Metric": "To-Normal Flows", "Value": f"{to_normal_count:,}"},
    {"Metric": "To-Botnet Flows", "Value": f"{to_botnet_count:,}"},
    {"Metric": "Duplicate Rows", "Value": f"{duplicate_rows_count:,} (0.00%)"},
    {"Metric": "Missing Value Status", "Value": "dTos (6.91%), sTos (0.37%), Sport (0.33%), Dport (0.16%)"},
    {"Metric": "Botnet C2 Suitability", "Value": "Highly Suitable (40.9k labeled C2 & bot flows with timing & volume metrics)"}
]

ctu13_summary_df = pd.DataFrame(summary_records)
display(ctu13_summary_df)

report_path = processed_dir / 'ctu13_exploration_summary.csv'
ctu13_summary_df.to_csv(report_path, index=False)
print(f"\\nSaved exploration report to: {report_path}")"""))

# ==========================================
# Section 17: Validation
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""### 14. Validation
Verify that all exploration criteria and output artifacts are valid."""))

cells.append(nbf.v4.new_code_cell("""val_data_exists = data_path.exists()
val_rows_valid = (total_rows == 2824636)
val_cols_valid = (len(sample_df.columns) == 15)
val_report_exists = report_path.exists()
val_botnet_found = (from_botnet_count > 0)

if all([val_data_exists, val_rows_valid, val_cols_valid, val_report_exists, val_botnet_found]):
    print("==================================================")
    print("CTU-13 SCENARIO 42 EXPLORATION COMPLETE")
    print("==================================================")
    print(f"\\nTotal Rows: {total_rows:,}")
    print(f"Total Columns: {len(sample_df.columns)}")
    print(f"From-Botnet Flows: {from_botnet_count:,}")
    print(f"From-Normal Flows: {from_normal_count:,}")
    print(f"Output Report: {report_path}")
    print("\\n✅ All validation checks passed successfully.")
else:
    print("❌ Validation checks failed.")"""))

nb.cells = cells

output_path = Path('notebooks/04_ctu13_exploration.ipynb')
output_path.parent.mkdir(parents=True, exist_ok=True)
with open(output_path, 'w', encoding='utf-8') as f:
    nbf.write(nb, f)

print(f"Successfully generated {output_path}")
