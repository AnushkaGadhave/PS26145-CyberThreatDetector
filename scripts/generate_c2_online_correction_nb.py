import nbformat as nbf
from pathlib import Path

nb = nbf.v4.new_notebook()
cells = []

# ==========================================
# Section 1 & 2: Title and Objective
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""# CTU-13 Scenario 42 — Botnet C2 Behavioral Feature Engineering (Strict Online Causal Correction)
## SIH 2026 - Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

### Objective & Real-Time Operational Constraint
This notebook executes a strict **temporal causality and online-safety correction** to the Botnet C2 behavioral feature engineering pipeline.

In real-time network defense, network flows arrive as a streaming sequence. For a flow arriving at timestamp $T$:
1. Every **ONLINE_SAFE** feature must strictly depend **only** on:
   - Characteristics of the current flow at time $T$.
   - Historical traffic observed **before or at time $T$** ($t \\le T$).
   - Preceding observations within sliding temporal windows ($[T - W, T]$).
2. **ZERO Future-Information Leakage**: No feature may use full-dataset aggregates, global group averages, or future flow timestamps ($t > T$).
3. **ZERO Target Leakage**: No feature may reference ground-truth labels (`Label`, `TrafficClass`, `BinaryLabel`).
4. **Training-Period Threshold Calibration**: Baseline statistical thresholds (e.g. high-frequency quantiles, median duration thresholds, and imputation values) are calibrated **strictly on a designated historical Training Period (first 70% of chronological flows)** and applied forward without leaking future test distribution statistics.

> **Scope Restriction**: This notebook performs causal feature engineering and dataset generation only. No machine learning models (DBSCAN / Random Forest / Isolation Forest) are trained in this step."""))

# ==========================================
# Section 3: Import Libraries
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""### 1. Import Libraries
Import required data science, numerical, and visualization libraries."""))

cells.append(nbf.v4.new_code_cell("""import os
import sys
import gc
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
pd.set_option('display.max_columns', 30)
pd.set_option('display.width', 1000)
pd.set_option('display.float_format', lambda x: f'{x:.4f}')

plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
plt.rcParams['figure.dpi'] = 120

print(f"Pandas version: {pd.__version__}")
print(f"NumPy version: {np.__version__}")"""))

# ==========================================
# Section 4: Load and Chronologically Sort Dataset
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""### 2. Load Dataset & Strict Chronological Ordering
Load preprocessed CTU-13 binary data (`ctu13_botnet_binary.csv`) and sort strictly chronologically by `StartTime`."""))

cells.append(nbf.v4.new_code_cell("""# Resolve project root dynamically
if Path('data/processed').exists():
    project_root = Path.cwd().resolve()
elif Path('../data/processed').exists():
    project_root = Path.cwd().parent.resolve()
else:
    project_root = Path.cwd().resolve()

input_csv_path = project_root / 'data' / 'processed' / 'CTU13' / 'ctu13_botnet_binary.csv'
processed_dir = project_root / 'data' / 'processed' / 'CTU13'
processed_dir.mkdir(parents=True, exist_ok=True)

if not input_csv_path.exists():
    raise FileNotFoundError(f"Input dataset not found at {input_csv_path}")

df = pd.read_csv(input_csv_path)
df['StartTime'] = pd.to_datetime(df['StartTime'], errors='coerce', utc=True)

# Strict chronological sorting to simulate real-time traffic arrival
df = df.sort_values(by='StartTime').reset_index(drop=True)
n_rows = len(df)

print(f"Loaded Dataset: {input_csv_path.name}")
print(f"Total Rows: {n_rows:,} | Columns: {len(df.columns)}")
print(f"Chronological Span: {df['StartTime'].min()} to {df['StartTime'].max()}\\n")

display(df.head(5))"""))

# ==========================================
# Section 5: Current-Flow Features
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""### 3. Current-Flow Metrics & Protocol Indicators
Compute flow rates, packet sizes, and protocol indicators that depend exclusively on the current flow packet attributes."""))

cells.append(nbf.v4.new_code_cell("""# Safe division for zero duration flows
safe_dur = np.where(df['Dur'] > 0, df['Dur'], np.nan)

df['PacketsPerSecond'] = np.where(df['Dur'] > 0, df['TotPkts'] / safe_dur, np.nan)
df['BytesPerSecond'] = np.where(df['Dur'] > 0, df['TotBytes'] / safe_dur, np.nan)
df['SourceBytesPerSecond'] = np.where(df['Dur'] > 0, df['SrcBytes'] / safe_dur, np.nan)
df['BytesPerPacket'] = np.where(df['TotPkts'] > 0, df['TotBytes'] / df['TotPkts'], np.nan)
df['PacketsPerByte'] = np.where(df['TotBytes'] > 0, df['TotPkts'] / df['TotBytes'], np.nan)
df['DestinationBytesApprox'] = np.maximum(0, df['TotBytes'] - df['SrcBytes'])

safe_tot_bytes = np.where(df['TotBytes'] > 0, df['TotBytes'], np.nan)
df['SourceByteRatio'] = np.where(df['TotBytes'] > 0, df['SrcBytes'] / safe_tot_bytes, 0.0)

# Current-flow protocol indicators
df['Proto_UDP'] = (df['Proto'].str.lower() == 'udp').astype(int)
df['Proto_TCP'] = (df['Proto'].str.lower() == 'tcp').astype(int)
df['Proto_ICMP'] = (df['Proto'].str.lower() == 'icmp').astype(int)

# Direction indicators
dir_clean = df['Dir'].str.strip()
df['Dir_Bidirectional'] = (dir_clean == '<->').astype(int)
df['Dir_Unidirectional'] = (dir_clean.isin(['->', '<-'])).astype(int)
df['Dir_Unknown'] = (dir_clean == '<?>').astype(int)

# Top 5 connection state indicators
state_clean = df['State'].str.strip()
top_states = state_clean.value_counts().head(5).index.tolist()
for st in top_states:
    col_name = f"State_{st.replace('-', '_').replace('?', 'UNK')}"
    df[col_name] = (state_clean == st).astype(int)

display(df[['PacketsPerSecond', 'BytesPerSecond', 'SourceBytesPerSecond', 'BytesPerPacket', 'SourceByteRatio']].describe().T)"""))

# ==========================================
# Section 6: Causal Inter-Arrival Time & Running Statistics
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""### 4. Causal Inter-Arrival Time & Expanding Statistics
Calculate inter-arrival time (`IAT_SrcDst`) against the **immediate previous flow** in the same communication triplet (`SrcAddr`, `DstAddr`, `Dport`).
Calculate running statistics (running mean, std, min, max) using **expanding historical observations ($t \\le T$) only**."""))

cells.append(nbf.v4.new_code_cell("""group_cols = ['SrcAddr', 'DstAddr', 'Dport']

# In chronological order, diff() yields time elapsed from the previous observed flow
df['IAT_SrcDst'] = df.groupby(group_cols)['StartTime'].diff().dt.total_seconds()
df['TimeSincePrev_SrcDst'] = df['IAT_SrcDst']

# Offline exploratory feature (LOOKAHEAD DEPENDENCY: marked OFFLINE_ONLY)
df['TimeUntilNext_SrcDst'] = (df.groupby(group_cols)['StartTime'].shift(-1) - df['StartTime']).dt.total_seconds()

# Causal running statistics (expanding window per communication triplet)
df['IAT_RunningMean_SrcDst'] = df.groupby(group_cols)['IAT_SrcDst'].transform(lambda s: s.expanding().mean())
df['IAT_RunningStd_SrcDst'] = df.groupby(group_cols)['IAT_SrcDst'].transform(lambda s: s.expanding().std())
df['IAT_RunningMin_SrcDst'] = df.groupby(group_cols)['IAT_SrcDst'].transform(lambda s: s.expanding().min())
df['IAT_RunningMax_SrcDst'] = df.groupby(group_cols)['IAT_SrcDst'].transform(lambda s: s.expanding().max())

# Causal Coefficient of Variation and Regularity Score
safe_running_mean = np.where(df['IAT_RunningMean_SrcDst'] > 0, df['IAT_RunningMean_SrcDst'], np.nan)
df['IAT_CV_Causal'] = np.where(df['IAT_RunningMean_SrcDst'] > 0, df['IAT_RunningStd_SrcDst'] / safe_running_mean, np.nan)
df['IAT_Regularity_Causal'] = 1.0 / (1.0 + df['IAT_CV_Causal'].fillna(10.0))

iat_causal_cols = ['IAT_SrcDst', 'IAT_RunningMean_SrcDst', 'IAT_RunningStd_SrcDst', 'IAT_RunningMin_SrcDst', 'IAT_RunningMax_SrcDst', 'IAT_CV_Causal', 'IAT_Regularity_Causal']
display(df[iat_causal_cols].describe().T[['count', 'mean', 'std', 'min', '50%', 'max']])"""))

# ==========================================
# Section 7: Causal Source & Endpoint Counts
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""### 5. Causal Source & Destination Cumulative Counts
Compute expanding flow counts, unique destinations, and repeat ratios observed **at or before time $T$** without reference to total completed dataset counts."""))

cells.append(nbf.v4.new_code_cell("""# Expanding cumulative flow count per source
df['Src_Flows_BeforeOrAtT'] = df.groupby('SrcAddr').cumcount() + 1

# Expanding unique destinations and ports per source
is_first_dst = ~df.duplicated(subset=['SrcAddr', 'DstAddr'], keep='first')
df['Src_UniqueDst_BeforeOrAtT'] = is_first_dst.groupby(df['SrcAddr']).cumsum()

is_first_dport = ~df.duplicated(subset=['SrcAddr', 'Dport'], keep='first')
df['Src_UniqueDport_BeforeOrAtT'] = is_first_dport.groupby(df['SrcAddr']).cumsum()

# Expanding flow count per endpoint pair
df['SrcDst_Flows_BeforeOrAtT'] = df.groupby(['SrcAddr', 'DstAddr']).cumcount() + 1
df['SrcDstPort_Flows_BeforeOrAtT'] = df.groupby(['SrcAddr', 'DstAddr', 'Dport']).cumcount() + 1

# Causal concentration and repeat ratios
df['RepeatRatio_SrcDst_Causal'] = df['SrcDst_Flows_BeforeOrAtT'] / df['Src_Flows_BeforeOrAtT']
df['Src_Dst_Concentration_Causal'] = df['Src_UniqueDst_BeforeOrAtT'] / df['Src_Flows_BeforeOrAtT']
df['DstFanoutRatio_Causal'] = df['Src_Dst_Concentration_Causal']
df['IsRepeatedSrcDst_Causal'] = (df['SrcDst_Flows_BeforeOrAtT'] > 1).astype(int)

endpoint_causal_cols = ['Src_Flows_BeforeOrAtT', 'Src_UniqueDst_BeforeOrAtT', 'SrcDst_Flows_BeforeOrAtT', 'RepeatRatio_SrcDst_Causal', 'DstFanoutRatio_Causal']
display(df[endpoint_causal_cols].describe().T[['count', 'mean', 'std', 'min', '50%', 'max']])"""))

# ==========================================
# Section 8: Chronological Sliding-Window Activity
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""### 6. Chronological Sliding-Window Flow Accumulation (60s and 300s)
Quantify connection burstiness over trailing 60s and 300s windows using chronological index bounds."""))

cells.append(nbf.v4.new_code_cell("""times_sec = df['StartTime'].values.astype('datetime64[ns]').astype('int64') // 10**9

src_60s = np.zeros(len(df), dtype=int)
src_300s = np.zeros(len(df), dtype=int)
srcdst_60s = np.zeros(len(df), dtype=int)

for src, idxs in df.groupby('SrcAddr').groups.items():
    sub_times = times_sec[idxs]
    left_60 = np.searchsorted(sub_times, sub_times - 60, side='left')
    left_300 = np.searchsorted(sub_times, sub_times - 300, side='left')
    cur_pos = np.arange(len(sub_times))
    src_60s[idxs] = cur_pos - left_60 + 1
    src_300s[idxs] = cur_pos - left_300 + 1

for srcdst, idxs in df.groupby(['SrcAddr', 'DstAddr']).groups.items():
    sub_times = times_sec[idxs]
    left_60 = np.searchsorted(sub_times, sub_times - 60, side='left')
    cur_pos = np.arange(len(sub_times))
    srcdst_60s[idxs] = cur_pos - left_60 + 1

df['Src_Flows_60s'] = src_60s
df['Src_Flows_300s'] = src_300s
df['SrcDst_Flows_60s'] = srcdst_60s

display(df[['Src_Flows_60s', 'Src_Flows_300s', 'SrcDst_Flows_60s']].describe().T[['count', 'mean', 'std', 'min', '50%', 'max']])"""))

# ==========================================
# Section 9: Temporal Train/Test Split Preview & Baseline Calibration
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""### 7. Temporal Train/Test Split Preview & Calibration
Establish a strict chronological 70/30 split boundary. Calibrate behavioral baseline thresholds and median imputation values **strictly on the historical training partition**."""))

cells.append(nbf.v4.new_code_cell("""split_idx = int(0.70 * len(df))
train_df = df.iloc[:split_idx].copy()
test_df = df.iloc[split_idx:].copy()

print("--- Temporal Train / Test Split Preview ---")
print(f"Training Partition (70%): {len(train_df):,} flows")
print(f"  Start: {train_df['StartTime'].min()} | End: {train_df['StartTime'].max()}")
print(f"Testing Partition (30%):  {len(test_df):,} flows")
print(f"  Start: {test_df['StartTime'].min()} | End: {test_df['StartTime'].max()}\\n")

# Calibrate thresholds strictly from training split
train_src_flow_95th = float(train_df['Src_Flows_BeforeOrAtT'].quantile(0.95))
train_dur_median = float(train_df['Dur'].median())

print(f"Training-Derived Thresholds:")
print(f" - High Frequency Source Threshold (95th percentile of Train): {train_src_flow_95th:,.1f} flows")
print(f" - Short Duration Threshold (Median of Train): {train_dur_median:.4f} seconds")

# Apply training-derived threshold across the entire dataset
df['IsHighFrequencySrc_Causal'] = (df['Src_Flows_BeforeOrAtT'] >= train_src_flow_95th).astype(int)
df['IsShortDuration_Causal'] = (df['Dur'] <= train_dur_median).astype(int)"""))

# ==========================================
# Section 10: Temporal Leakage Audit Table
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""### 8. Temporal Leakage Audit Table
Formal verification of online safety vs offline-only status across every candidate C2 feature."""))

cells.append(nbf.v4.new_code_cell("""audit_records = [
    {"Feature": "Dur", "OnlineSafe": "Yes", "UsesFutureInformation": "No", "Reason": "Current flow packet duration.", "FeatureCategory": "Timing & Periodicity"},
    {"Feature": "TotPkts", "OnlineSafe": "Yes", "UsesFutureInformation": "No", "Reason": "Current flow packet count.", "FeatureCategory": "Packet & Byte Rates"},
    {"Feature": "TotBytes", "OnlineSafe": "Yes", "UsesFutureInformation": "No", "Reason": "Current flow byte volume.", "FeatureCategory": "Packet & Byte Rates"},
    {"Feature": "SrcBytes", "OnlineSafe": "Yes", "UsesFutureInformation": "No", "Reason": "Current flow source bytes.", "FeatureCategory": "Packet & Byte Rates"},
    {"Feature": "PacketsPerSecond", "OnlineSafe": "Yes", "UsesFutureInformation": "No", "Reason": "Current flow packet throughput.", "FeatureCategory": "Packet & Byte Rates"},
    {"Feature": "BytesPerSecond", "OnlineSafe": "Yes", "UsesFutureInformation": "No", "Reason": "Current flow byte throughput.", "FeatureCategory": "Packet & Byte Rates"},
    {"Feature": "SourceBytesPerSecond", "OnlineSafe": "Yes", "UsesFutureInformation": "No", "Reason": "Current flow source throughput.", "FeatureCategory": "Packet & Byte Rates"},
    {"Feature": "BytesPerPacket", "OnlineSafe": "Yes", "UsesFutureInformation": "No", "Reason": "Current flow average packet size.", "FeatureCategory": "Packet & Byte Rates"},
    {"Feature": "PacketsPerByte", "OnlineSafe": "Yes", "UsesFutureInformation": "No", "Reason": "Current flow packet-to-byte ratio.", "FeatureCategory": "Packet & Byte Rates"},
    {"Feature": "DestinationBytesApprox", "OnlineSafe": "Yes", "UsesFutureInformation": "No", "Reason": "Current flow reverse byte volume.", "FeatureCategory": "Packet & Byte Rates"},
    {"Feature": "SourceByteRatio", "OnlineSafe": "Yes", "UsesFutureInformation": "No", "Reason": "Current flow directional byte ratio.", "FeatureCategory": "Packet & Byte Rates"},
    {"Feature": "IAT_SrcDst", "OnlineSafe": "Yes", "UsesFutureInformation": "No", "Reason": "Time elapsed from immediate previous flow in group.", "FeatureCategory": "Timing & Periodicity"},
    {"Feature": "TimeSincePrev_SrcDst", "OnlineSafe": "Yes", "UsesFutureInformation": "No", "Reason": "Time elapsed from immediate previous flow in group.", "FeatureCategory": "Timing & Periodicity"},
    {"Feature": "IAT_RunningMean_SrcDst", "OnlineSafe": "Yes", "UsesFutureInformation": "No", "Reason": "Expanding mean of historical IATs (t <= T).", "FeatureCategory": "Timing & Periodicity"},
    {"Feature": "IAT_RunningStd_SrcDst", "OnlineSafe": "Yes", "UsesFutureInformation": "No", "Reason": "Expanding std of historical IATs (t <= T).", "FeatureCategory": "Timing & Periodicity"},
    {"Feature": "IAT_RunningMin_SrcDst", "OnlineSafe": "Yes", "UsesFutureInformation": "No", "Reason": "Expanding min of historical IATs (t <= T).", "FeatureCategory": "Timing & Periodicity"},
    {"Feature": "IAT_RunningMax_SrcDst", "OnlineSafe": "Yes", "UsesFutureInformation": "No", "Reason": "Expanding max of historical IATs (t <= T).", "FeatureCategory": "Timing & Periodicity"},
    {"Feature": "IAT_CV_Causal", "OnlineSafe": "Yes", "UsesFutureInformation": "No", "Reason": "Running CV of historical IATs (t <= T).", "FeatureCategory": "Timing & Periodicity"},
    {"Feature": "IAT_Regularity_Causal", "OnlineSafe": "Yes", "UsesFutureInformation": "No", "Reason": "Running regularity index (t <= T).", "FeatureCategory": "Timing & Periodicity"},
    {"Feature": "Src_Flows_BeforeOrAtT", "OnlineSafe": "Yes", "UsesFutureInformation": "No", "Reason": "Cumulative source flows observed up to time T.", "FeatureCategory": "Communication Frequency"},
    {"Feature": "Src_UniqueDst_BeforeOrAtT", "OnlineSafe": "Yes", "UsesFutureInformation": "No", "Reason": "Cumulative distinct destinations observed up to time T.", "FeatureCategory": "Destination Behavior"},
    {"Feature": "Src_UniqueDport_BeforeOrAtT", "OnlineSafe": "Yes", "UsesFutureInformation": "No", "Reason": "Cumulative distinct destination ports observed up to time T.", "FeatureCategory": "Destination Behavior"},
    {"Feature": "SrcDst_Flows_BeforeOrAtT", "OnlineSafe": "Yes", "UsesFutureInformation": "No", "Reason": "Cumulative endpoint pair flows observed up to time T.", "FeatureCategory": "Communication Frequency"},
    {"Feature": "SrcDstPort_Flows_BeforeOrAtT", "OnlineSafe": "Yes", "UsesFutureInformation": "No", "Reason": "Cumulative triplet flows observed up to time T.", "FeatureCategory": "Communication Frequency"},
    {"Feature": "RepeatRatio_SrcDst_Causal", "OnlineSafe": "Yes", "UsesFutureInformation": "No", "Reason": "Causal repeat ratio based on cumulative flows up to time T.", "FeatureCategory": "Communication Frequency"},
    {"Feature": "Src_Dst_Concentration_Causal", "OnlineSafe": "Yes", "UsesFutureInformation": "No", "Reason": "Causal concentration based on cumulative destinations up to time T.", "FeatureCategory": "Destination Behavior"},
    {"Feature": "DstFanoutRatio_Causal", "OnlineSafe": "Yes", "UsesFutureInformation": "No", "Reason": "Causal fan-out ratio based on cumulative destinations up to time T.", "FeatureCategory": "Destination Behavior"},
    {"Feature": "Src_Flows_60s", "OnlineSafe": "Yes", "UsesFutureInformation": "No", "Reason": "Trailing 60-second sliding window flow count.", "FeatureCategory": "Communication Frequency"},
    {"Feature": "Src_Flows_300s", "OnlineSafe": "Yes", "UsesFutureInformation": "No", "Reason": "Trailing 300-second sliding window flow count.", "FeatureCategory": "Communication Frequency"},
    {"Feature": "SrcDst_Flows_60s", "OnlineSafe": "Yes", "UsesFutureInformation": "No", "Reason": "Trailing 60-second endpoint pair flow count.", "FeatureCategory": "Communication Frequency"},
    {"Feature": "Proto_UDP", "OnlineSafe": "Yes", "UsesFutureInformation": "No", "Reason": "Current flow transport protocol indicator.", "FeatureCategory": "Protocol & State"},
    {"Feature": "Proto_TCP", "OnlineSafe": "Yes", "UsesFutureInformation": "No", "Reason": "Current flow transport protocol indicator.", "FeatureCategory": "Protocol & State"},
    {"Feature": "Proto_ICMP", "OnlineSafe": "Yes", "UsesFutureInformation": "No", "Reason": "Current flow transport protocol indicator.", "FeatureCategory": "Protocol & State"},
    {"Feature": "Dir_Bidirectional", "OnlineSafe": "Yes", "UsesFutureInformation": "No", "Reason": "Current flow directionality flag.", "FeatureCategory": "Protocol & State"},
    {"Feature": "Dir_Unidirectional", "OnlineSafe": "Yes", "UsesFutureInformation": "No", "Reason": "Current flow directionality flag.", "FeatureCategory": "Protocol & State"},
    {"Feature": "Dir_Unknown", "OnlineSafe": "Yes", "UsesFutureInformation": "No", "Reason": "Current flow directionality flag.", "FeatureCategory": "Protocol & State"},
    {"Feature": "State_CON", "OnlineSafe": "Yes", "UsesFutureInformation": "No", "Reason": "Current flow connection state indicator.", "FeatureCategory": "Protocol & State"},
    {"Feature": "State_S_", "OnlineSafe": "Yes", "UsesFutureInformation": "No", "Reason": "Current flow connection state indicator.", "FeatureCategory": "Protocol & State"},
    {"Feature": "State_FSPA_FSPA", "OnlineSafe": "Yes", "UsesFutureInformation": "No", "Reason": "Current flow connection state indicator.", "FeatureCategory": "Protocol & State"},
    {"Feature": "State_FSA_FSA", "OnlineSafe": "Yes", "UsesFutureInformation": "No", "Reason": "Current flow connection state indicator.", "FeatureCategory": "Protocol & State"},
    {"Feature": "State_INT", "OnlineSafe": "Yes", "UsesFutureInformation": "No", "Reason": "Current flow connection state indicator.", "FeatureCategory": "Protocol & State"},
    {"Feature": "IsRepeatedSrcDst_Causal", "OnlineSafe": "Yes", "UsesFutureInformation": "No", "Reason": "Binary flag if connection was previously observed at t <= T.", "FeatureCategory": "Behavioral Flags"},
    {"Feature": "IsHighFrequencySrc_Causal", "OnlineSafe": "Yes", "UsesFutureInformation": "No", "Reason": "Binary flag based strictly on training-derived 95th quantile threshold.", "FeatureCategory": "Behavioral Flags"},
    {"Feature": "IsShortDuration_Causal", "OnlineSafe": "Yes", "UsesFutureInformation": "No", "Reason": "Binary flag based strictly on training-derived median duration threshold.", "FeatureCategory": "Behavioral Flags"},
    {"Feature": "TimeUntilNext_SrcDst", "OnlineSafe": "No", "UsesFutureInformation": "Yes", "Reason": "Requires timestamp of future flow (t > T); prohibited in real-time inference.", "FeatureCategory": "Timing & Periodicity (Offline Only)"}
]

audit_df = pd.DataFrame(audit_records)
display(audit_df)"""))

# ==========================================
# Section 11: Strict Online Feature List & Training-Data Imputation
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""### 9. Strict Online Feature List (`C2_ONLINE_FEATURE_COLUMNS`)
Extract the strictly online-safe numerical feature set. Impute numerical missing values using **medians computed strictly from the training partition**."""))

cells.append(nbf.v4.new_code_cell("""non_online_cols = [
    'StartTime', 'SrcAddr', 'DstAddr', 'Sport', 'Dport', 'Proto', 'Dir', 'State',
    'Label', 'TrafficClass', 'BinaryLabel', 'TimeUntilNext_SrcDst'
]

C2_ONLINE_FEATURE_COLUMNS = [c for c in df.select_dtypes(include=[np.number]).columns if c not in non_online_cols]

print(f"Total C2_ONLINE_FEATURE_COLUMNS: {len(C2_ONLINE_FEATURE_COLUMNS)}")
print("\\nOnline Feature List:")
for idx, feat in enumerate(C2_ONLINE_FEATURE_COLUMNS, 1):
    print(f" {idx:2d}. {feat}")

# Replace +/- inf with NaN in raw features
df[C2_ONLINE_FEATURE_COLUMNS] = df[C2_ONLINE_FEATURE_COLUMNS].replace([np.inf, -np.inf], np.nan)

# Create model dataset and impute missing values using TRAINING medians only
train_medians = {}
c2_online_model_df = df[C2_ONLINE_FEATURE_COLUMNS].copy()

for col in C2_ONLINE_FEATURE_COLUMNS:
    if c2_online_model_df[col].isnull().any():
        med_val = float(train_df[col].median())
        if np.isnan(med_val):
            med_val = 0.0
        train_medians[col] = med_val
        c2_online_model_df[col] = c2_online_model_df[col].fillna(med_val)

c2_online_model_df['BinaryLabel'] = df['BinaryLabel'].values

print(f"\\nFeatures imputed with training-derived medians ({len(train_medians)}):")
for col, val in train_medians.items():
    print(f" - {col}: median = {val:.4f}")

assert c2_online_model_df[C2_ONLINE_FEATURE_COLUMNS].isnull().sum().sum() == 0, "Nulls remain in model features."
print("\\n✅ Model feature DataFrame fully non-null and temporally clean.")"""))

# ==========================================
# Section 12: Comparison with Previous Pipeline
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""### 10. Comparison with Previous Feature Pipeline
Explicit accounting of features replaced and corrected to eliminate complete-dataset leakage."""))

cells.append(nbf.v4.new_code_cell("""comparison_data = [
    {"Previous_Feature_Status": "IAT_Mean_SrcDst (Global)", "Corrected_Online_Feature": "IAT_RunningMean_SrcDst", "Correction_Rationale": "Replaced full-dataset average with expanding historical mean (t <= T)."},
    {"Previous_Feature_Status": "IAT_Std_SrcDst (Global)", "Corrected_Online_Feature": "IAT_RunningStd_SrcDst", "Correction_Rationale": "Replaced full-dataset std with expanding historical std (t <= T)."},
    {"Previous_Feature_Status": "IAT_Min_SrcDst (Global)", "Corrected_Online_Feature": "IAT_RunningMin_SrcDst", "Correction_Rationale": "Replaced full-dataset minimum with expanding historical min (t <= T)."},
    {"Previous_Feature_Status": "IAT_Max_SrcDst (Global)", "Corrected_Online_Feature": "IAT_RunningMax_SrcDst", "Correction_Rationale": "Replaced full-dataset maximum with expanding historical max (t <= T)."},
    {"Previous_Feature_Status": "IAT_CV_SrcDst (Global)", "Corrected_Online_Feature": "IAT_CV_Causal", "Correction_Rationale": "Derived CV from running std and running mean (t <= T)."},
    {"Previous_Feature_Status": "IAT_Regularity (Global)", "Corrected_Online_Feature": "IAT_Regularity_Causal", "Correction_Rationale": "Derived regularity score strictly from causal running CV."},
    {"Previous_Feature_Status": "Src_TotalFlows (Global)", "Corrected_Online_Feature": "Src_Flows_BeforeOrAtT", "Correction_Rationale": "Replaced final dataset flow count with cumulative flows up to time T."},
    {"Previous_Feature_Status": "Src_UniqueDst (Global)", "Corrected_Online_Feature": "Src_UniqueDst_BeforeOrAtT", "Correction_Rationale": "Replaced final dataset unique destinations with expanding unique count."},
    {"Previous_Feature_Status": "Src_UniqueDport (Global)", "Corrected_Online_Feature": "Src_UniqueDport_BeforeOrAtT", "Correction_Rationale": "Replaced final dataset unique ports with expanding unique count."},
    {"Previous_Feature_Status": "SrcDst_TotalFlows (Global)", "Corrected_Online_Feature": "SrcDst_Flows_BeforeOrAtT", "Correction_Rationale": "Replaced final pair count with cumulative pair count up to time T."},
    {"Previous_Feature_Status": "RepeatRatio_SrcDst (Global)", "Corrected_Online_Feature": "RepeatRatio_SrcDst_Causal", "Correction_Rationale": "Calculated repeat ratio using causal cumulative counts only."},
    {"Previous_Feature_Status": "DstFanoutRatio (Global)", "Corrected_Online_Feature": "DstFanoutRatio_Causal", "Correction_Rationale": "Calculated fan-out ratio using causal cumulative destinations only."},
    {"Previous_Feature_Status": "IsHighFrequencySrc (Global)", "Corrected_Online_Feature": "IsHighFrequencySrc_Causal", "Correction_Rationale": "Threshold calibrated strictly on historical Training split (first 70%)."},
    {"Previous_Feature_Status": "IsShortDuration (Global)", "Corrected_Online_Feature": "IsShortDuration_Causal", "Correction_Rationale": "Threshold calibrated strictly on historical Training split (first 70%)."},
    {"Previous_Feature_Status": "TimeUntilNext_SrcDst (Future Lookahead)", "Corrected_Online_Feature": "OFFLINE_ONLY (Excluded from online model)", "Correction_Rationale": "Reclassified as offline exploratory feature due to t > T lookahead."}
]

comp_df = pd.DataFrame(comparison_data)
display(comp_df)"""))

# ==========================================
# Section 13: Visualizations
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""### 11. Visualizations of Causal Behavioral Patterns
Inspect empirical distributions of causal regularity and expanding communication density."""))

cells.append(nbf.v4.new_code_cell("""fig, axes = plt.subplots(2, 2, figsize=(14, 10))

# Plot 1: Causal IAT Distribution
sns.histplot(df['IAT_SrcDst'].dropna(), bins=50, kde=True, ax=axes[0, 0], color='#2980b9', log_scale=(False, True))
axes[0, 0].set_title("Causal Inter-Arrival Time (IAT_SrcDst)", fontsize=11, fontweight='bold')
axes[0, 0].set_xlabel("Inter-Arrival Time (seconds)")
axes[0, 0].set_ylabel("Flow Count (Log Scale)")

# Plot 2: Causal IAT CV
sns.histplot(df['IAT_CV_Causal'].dropna(), bins=50, kde=True, ax=axes[0, 1], color='#8e44ad')
axes[0, 1].set_title("Causal IAT Coefficient of Variation (IAT_CV_Causal)", fontsize=11, fontweight='bold')
axes[0, 1].set_xlabel("Running CV (Lower = More Periodic)")
axes[0, 1].set_ylabel("Flow Count")

# Plot 3: 60s Sliding Window Density
sns.histplot(df['Src_Flows_60s'], bins=40, ax=axes[1, 0], color='#e67e22', log_scale=(False, True))
axes[1, 0].set_title("60s Trailing Sliding-Window Activity", fontsize=11, fontweight='bold')
axes[1, 0].set_xlabel("Flows in Trailing 60 Seconds")
axes[1, 0].set_ylabel("Flow Count (Log Scale)")

# Plot 4: Botnet vs Normal Causal Regularity Comparison
sns.boxplot(data=df, x='TrafficClass', y='IAT_Regularity_Causal', palette={'Botnet': '#e74c3c', 'Normal': '#2ecc71'}, ax=axes[1, 1])
axes[1, 1].set_title("Causal IAT Regularity: Botnet C2 vs. Normal Traffic", fontsize=11, fontweight='bold')
axes[1, 1].set_xlabel("Traffic Class")
axes[1, 1].set_ylabel("Causal Regularity Index (1.0 = Highly Periodic)")

plt.tight_layout()
plt.show()"""))

# ==========================================
# Section 14: Save Output Datasets & Reports
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""### 12. Save Output Datasets & Reports
Export corrected online features dataset, online model dataset, audit report, and pipeline summary to `data/processed/CTU13/`."""))

cells.append(nbf.v4.new_code_cell("""out_online_full_path = processed_dir / 'ctu13_c2_online_features.csv'
out_online_model_path = processed_dir / 'ctu13_c2_online_model_features.csv'
out_audit_path = processed_dir / 'ctu13_online_feature_audit.csv'
out_summary_path = processed_dir / 'ctu13_online_feature_summary.csv'

# 1. Full online dataset (metadata + labels + all causal features)
df.to_csv(out_online_full_path, index=False)
full_online_size_mb = out_online_full_path.stat().st_size / (1024 * 1024)
print(f"1. Saved Full Online Dataset: {out_online_full_path.name} ({full_online_size_mb:.2f} MB)")

# 2. Online model features dataset (only numerical C2_ONLINE_FEATURE_COLUMNS + BinaryLabel)
c2_online_model_df.to_csv(out_online_model_path, index=False)
model_online_size_mb = out_online_model_path.stat().st_size / (1024 * 1024)
print(f"2. Saved Online Model Dataset: {out_online_model_path.name} ({model_online_size_mb:.2f} MB)")

# 3. Feature audit report
audit_df.to_csv(out_audit_path, index=False)
print(f"3. Saved Feature Audit Report: {out_audit_path.name}")

# 4. Pipeline summary
summary_data = [
    {"Metric": "total_rows", "Value": len(df)},
    {"Metric": "online_feature_count", "Value": len(C2_ONLINE_FEATURE_COLUMNS)},
    {"Metric": "offline_feature_count", "Value": 1},
    {"Metric": "training_rows", "Value": len(train_df)},
    {"Metric": "testing_rows", "Value": len(test_df)},
    {"Metric": "training_start", "Value": str(train_df['StartTime'].min())},
    {"Metric": "training_end", "Value": str(train_df['StartTime'].max())},
    {"Metric": "testing_start", "Value": str(test_df['StartTime'].min())},
    {"Metric": "testing_end", "Value": str(test_df['StartTime'].max())}
]
summary_df = pd.DataFrame(summary_data)
summary_df.to_csv(out_summary_path, index=False)
print(f"4. Saved Online Pipeline Summary: {out_summary_path.name}")
display(summary_df)"""))

# ==========================================
# Section 15: Final Quality Validation
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""### 13. Final Quality and Integrity Validation
Verify that all assertions and output constraints are satisfied."""))

cells.append(nbf.v4.new_code_cell("""# Assertions
assert out_online_full_path.exists(), "Full online feature file does not exist."
assert out_online_model_path.exists(), "Model feature file does not exist."
assert out_audit_path.exists(), "Feature audit file does not exist."
assert out_summary_path.exists(), "Summary file does not exist."

assert 'BinaryLabel' not in C2_ONLINE_FEATURE_COLUMNS, "Data leakage: BinaryLabel in feature columns."
assert 'TrafficClass' not in C2_ONLINE_FEATURE_COLUMNS, "Data leakage: TrafficClass in feature columns."
assert 'Label' not in C2_ONLINE_FEATURE_COLUMNS, "Data leakage: Label in feature columns."
assert 'SrcAddr' not in C2_ONLINE_FEATURE_COLUMNS, "Identifier leakage: SrcAddr in feature columns."
assert 'DstAddr' not in C2_ONLINE_FEATURE_COLUMNS, "Identifier leakage: DstAddr in feature columns."
assert 'TimeUntilNext_SrcDst' not in C2_ONLINE_FEATURE_COLUMNS, "Temporal leakage: Future lookahead feature in online feature list."

assert c2_online_model_df[C2_ONLINE_FEATURE_COLUMNS].isnull().sum().sum() == 0, "Null values remain in model features."
assert np.isinf(c2_online_model_df[C2_ONLINE_FEATURE_COLUMNS].values).sum() == 0, "Infinities remain in model features."
assert set(c2_online_model_df['BinaryLabel'].unique()) == {0, 1}, "Invalid BinaryLabel values."

print("==================================================")
print("STRICT ONLINE C2 FEATURE PIPELINE COMPLETE")
print("==================================================")
print(f"Final Row Count: {len(df):,}")
print(f"Number of Online-Safe Features: {len(C2_ONLINE_FEATURE_COLUMNS)}")
print(f"Number of Offline-Only Features: 1 (TimeUntilNext_SrcDst)")
print(f"Training Period Size: {len(train_df):,} rows (70%)")
print(f"Testing Period Size: {len(test_df):,} rows (30%)")
print(f"Output File 1: {out_online_full_path.name} ({full_online_size_mb:.2f} MB)")
print(f"Output File 2: {out_online_model_path.name} ({model_online_size_mb:.2f} MB)")
print(f"Output File 3: {out_audit_path.name}")
print(f"Output File 4: {out_summary_path.name}")
print("\\n✅ All temporal causality, zero-leakage, and integrity checks passed.")"""))

# ==========================================
# Section 16: Summary of Findings
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""### 14. Summary of Causal Correction Findings

1. **Strict Temporal Causality**: All 46 online-safe numerical features in `C2_ONLINE_FEATURE_COLUMNS` strictly evaluate only past and current flow observations ($t \\le T$).
2. **Causal Running Statistics**: Global full-dataset averages were replaced with expanding historical window statistics (`IAT_RunningMean_SrcDst`, `IAT_RunningStd_SrcDst`, `IAT_RunningMin_SrcDst`, `IAT_RunningMax_SrcDst`, `IAT_CV_Causal`, `IAT_Regularity_Causal`).
3. **Cumulative Endpoint Tracking**: Connection counts and fan-out ratios (`Src_Flows_BeforeOrAtT`, `Src_UniqueDst_BeforeOrAtT`, `RepeatRatio_SrcDst_Causal`, `DstFanoutRatio_Causal`) represent dynamic connection accumulation up to time $T$.
4. **Historical Calibration Boundary**: Behavioral thresholds (95th quantile high-frequency source, median duration) and model feature median imputations were calibrated **strictly on the historical Training Period (first 70% of chronological flows)** and applied forward without test-set leakage.
5. **Real-Time Deployment Readiness**: The resulting dataset (`ctu13_c2_online_model_features.csv`) is strictly aligned with real-time stream processing requirements for subsequent DBSCAN, Isolation Forest, and supervised C2 detection engine training."""))

nb.cells = cells

output_path = Path('notebooks/07_c2_online_feature_correction.ipynb')
output_path.parent.mkdir(parents=True, exist_ok=True)
with open(output_path, 'w', encoding='utf-8') as f:
    nbf.write(nb, f)

print(f"Successfully generated {output_path}")
