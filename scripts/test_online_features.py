import pandas as pd
import numpy as np
from pathlib import Path
import time

t0 = time.time()
csv_path = Path('data/processed/CTU13/ctu13_botnet_binary.csv')
df = pd.read_csv(csv_path)
df['StartTime'] = pd.to_datetime(df['StartTime'], errors='coerce', utc=True)

# Strictly sort chronologically by StartTime
df = df.sort_values(by='StartTime').reset_index(drop=True)
n_rows = len(df)
print(f"Loaded {n_rows:,} rows sorted chronologically.")

# ----------------------------------------------------
# Step 2: Current Flow Features (Safe non-zero division)
# ----------------------------------------------------
safe_dur = np.where(df['Dur'] > 0, df['Dur'], np.nan)
df['PacketsPerSecond'] = np.where(df['Dur'] > 0, df['TotPkts'] / safe_dur, np.nan)
df['BytesPerSecond'] = np.where(df['Dur'] > 0, df['TotBytes'] / safe_dur, np.nan)
df['SourceBytesPerSecond'] = np.where(df['Dur'] > 0, df['SrcBytes'] / safe_dur, np.nan)
df['BytesPerPacket'] = np.where(df['TotPkts'] > 0, df['TotBytes'] / df['TotPkts'], np.nan)
df['PacketsPerByte'] = np.where(df['TotBytes'] > 0, df['TotPkts'] / df['TotBytes'], np.nan)
df['DestinationBytesApprox'] = np.maximum(0, df['TotBytes'] - df['SrcBytes'])
safe_tot_bytes = np.where(df['TotBytes'] > 0, df['TotBytes'], np.nan)
df['SourceByteRatio'] = np.where(df['TotBytes'] > 0, df['SrcBytes'] / safe_tot_bytes, 0.0)

# Protocol & direction indicators (Current flow only)
df['Proto_UDP'] = (df['Proto'].str.lower() == 'udp').astype(int)
df['Proto_TCP'] = (df['Proto'].str.lower() == 'tcp').astype(int)
df['Proto_ICMP'] = (df['Proto'].str.lower() == 'icmp').astype(int)

dir_clean = df['Dir'].str.strip()
df['Dir_Bidirectional'] = (dir_clean == '<->').astype(int)
df['Dir_Unidirectional'] = (dir_clean.isin(['->', '<-'])).astype(int)
df['Dir_Unknown'] = (dir_clean == '<?>').astype(int)

state_clean = df['State'].str.strip()
top_states = state_clean.value_counts().head(5).index.tolist()
for st in top_states:
    col_name = f"State_{st.replace('-', '_').replace('?', 'UNK')}"
    df[col_name] = (state_clean == st).astype(int)

# ----------------------------------------------------
# Step 3: Causal IAT & Running Statistics
# ----------------------------------------------------
group_cols = ['SrcAddr', 'DstAddr', 'Dport']
df['IAT_SrcDst'] = df.groupby(group_cols)['StartTime'].diff().dt.total_seconds()
df['TimeSincePrev_SrcDst'] = df['IAT_SrcDst']

# Offline only feature (lookahead)
df['TimeUntilNext_SrcDst'] = (df.groupby(group_cols)['StartTime'].shift(-1) - df['StartTime']).dt.total_seconds()

# Fast causal expanding statistics per group
df['IAT_RunningMean_SrcDst'] = df.groupby(group_cols)['IAT_SrcDst'].transform(lambda s: s.expanding().mean())
df['IAT_RunningStd_SrcDst'] = df.groupby(group_cols)['IAT_SrcDst'].transform(lambda s: s.expanding().std())
df['IAT_RunningMin_SrcDst'] = df.groupby(group_cols)['IAT_SrcDst'].transform(lambda s: s.expanding().min())
df['IAT_RunningMax_SrcDst'] = df.groupby(group_cols)['IAT_SrcDst'].transform(lambda s: s.expanding().max())

# ----------------------------------------------------
# Step 4: Causal IAT Variability / Regularity
# ----------------------------------------------------
safe_running_mean = np.where(df['IAT_RunningMean_SrcDst'] > 0, df['IAT_RunningMean_SrcDst'], np.nan)
df['IAT_CV_Causal'] = np.where(df['IAT_RunningMean_SrcDst'] > 0, df['IAT_RunningStd_SrcDst'] / safe_running_mean, np.nan)
df['IAT_Regularity_Causal'] = 1.0 / (1.0 + df['IAT_CV_Causal'].fillna(10.0))

# ----------------------------------------------------
# Step 5: Causal Source Counts (Before or at time T)
# ----------------------------------------------------
# Using cumcount() + 1 for chronological expanding count
df['Src_Flows_BeforeOrAtT'] = df.groupby('SrcAddr').cumcount() + 1

# Causal expanding unique destinations and unique destination ports per source
# We can compute expanding unique counts by tracking first occurrence of (SrcAddr, DstAddr)
is_first_dst = ~df.duplicated(subset=['SrcAddr', 'DstAddr'], keep='first')
df['Src_UniqueDst_BeforeOrAtT'] = is_first_dst.groupby(df['SrcAddr']).cumsum()

is_first_dport = ~df.duplicated(subset=['SrcAddr', 'Dport'], keep='first')
df['Src_UniqueDport_BeforeOrAtT'] = is_first_dport.groupby(df['SrcAddr']).cumsum()

# ----------------------------------------------------
# Step 6: Causal Source-Destination Counts
# ----------------------------------------------------
df['SrcDst_Flows_BeforeOrAtT'] = df.groupby(['SrcAddr', 'DstAddr']).cumcount() + 1
df['SrcDstPort_Flows_BeforeOrAtT'] = df.groupby(['SrcAddr', 'DstAddr', 'Dport']).cumcount() + 1
df['RepeatRatio_SrcDst_Causal'] = df['SrcDst_Flows_BeforeOrAtT'] / df['Src_Flows_BeforeOrAtT']
df['IsRepeatedSrcDst_Causal'] = (df['SrcDst_Flows_BeforeOrAtT'] > 1).astype(int)

# ----------------------------------------------------
# Step 7: Causal Destination Fan-Out & Concentration
# ----------------------------------------------------
df['Src_Dst_Concentration_Causal'] = df['Src_UniqueDst_BeforeOrAtT'] / df['Src_Flows_BeforeOrAtT']
df['DstFanoutRatio_Causal'] = df['Src_Dst_Concentration_Causal']

# ----------------------------------------------------
# Step 8: Chronological Sliding-Window Activity
# ----------------------------------------------------
times_sec = df['StartTime'].values.astype('datetime64[ns]').astype('int64') // 10**9

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

# ----------------------------------------------------
# Step 9 & 10: Training-Period Derived Thresholds
# ----------------------------------------------------
split_idx = int(0.70 * len(df))
train_df = df.iloc[:split_idx]
test_df = df.iloc[split_idx:]

train_src_flow_95th = float(train_df['Src_Flows_BeforeOrAtT'].quantile(0.95))
train_dur_median = float(train_df['Dur'].median())

print(f"Chronological Split: Train={len(train_df):,} rows (70%), Test={len(test_df):,} rows (30%)")
print(f"Training Start: {train_df['StartTime'].min()} | Training End: {train_df['StartTime'].max()}")
print(f"Testing Start: {test_df['StartTime'].min()} | Testing End: {test_df['StartTime'].max()}")
print(f"Training-Derived 95th Percentile Flow Threshold: {train_src_flow_95th}")
print(f"Training-Derived Median Duration Threshold: {train_dur_median:.4f} s")

# Apply training-derived threshold across the dataset
df['IsHighFrequencySrc_Causal'] = (df['Src_Flows_BeforeOrAtT'] >= train_src_flow_95th).astype(int)
df['IsShortDuration_Causal'] = (df['Dur'] <= train_dur_median).astype(int)

# ----------------------------------------------------
# Step 13: Strict Online Feature List
# ----------------------------------------------------
non_online_cols = [
    'StartTime', 'SrcAddr', 'DstAddr', 'Sport', 'Dport', 'Proto', 'Dir', 'State',
    'Label', 'TrafficClass', 'BinaryLabel', 'TimeUntilNext_SrcDst'
]

C2_ONLINE_FEATURE_COLUMNS = [c for c in df.select_dtypes(include=[np.number]).columns if c not in non_online_cols]
print(f"\nTotal C2_ONLINE_FEATURE_COLUMNS: {len(C2_ONLINE_FEATURE_COLUMNS)}")

# Check missing values and compute medians strictly from training split
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

print(f"Features imputed with training medians ({len(train_medians)}):")
for col, val in train_medians.items():
    print(f"  - {col}: median = {val:.4f}")

elapsed = time.time() - t0
print(f"\nCompleted in {elapsed:.2f} seconds. Shape: {df.shape}")
