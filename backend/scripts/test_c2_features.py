import pandas as pd
import numpy as np
from pathlib import Path

csv_path = Path('data/processed/CTU13/ctu13_botnet_binary.csv')
df = pd.read_csv(csv_path)
print(f"Loaded {len(df)} rows, {len(df.columns)} columns.")

# Datetime
df['StartTime'] = pd.to_datetime(df['StartTime'], errors='coerce', utc=True)
print(f"Valid StartTime: {df['StartTime'].notnull().sum()}, Invalid: {df['StartTime'].isnull().sum()}")

# 1. Flow Rates
safe_dur = np.where(df['Dur'] > 0, df['Dur'], np.nan)
df['PacketsPerSecond'] = np.where(df['Dur'] > 0, df['TotPkts'] / safe_dur, np.nan)
df['BytesPerSecond'] = np.where(df['Dur'] > 0, df['TotBytes'] / safe_dur, np.nan)
df['SourceBytesPerSecond'] = np.where(df['Dur'] > 0, df['SrcBytes'] / safe_dur, np.nan)
df['BytesPerPacket'] = np.where(df['TotPkts'] > 0, df['TotBytes'] / df['TotPkts'], np.nan)
df['PacketsPerByte'] = np.where(df['TotBytes'] > 0, df['TotPkts'] / df['TotBytes'], np.nan)

# 2. Sort by endpoints and time for IAT
df = df.sort_values(by=['SrcAddr', 'DstAddr', 'Dport', 'StartTime']).reset_index(drop=True)

# 3. IAT calculation
df['IAT_SrcDst'] = df.groupby(['SrcAddr', 'DstAddr', 'Dport'])['StartTime'].diff().dt.total_seconds()
df['TimeSincePrev_SrcDst'] = df['IAT_SrcDst']
df['TimeUntilNext_SrcDst'] = (df.groupby(['SrcAddr', 'DstAddr', 'Dport'])['StartTime'].shift(-1) - df['StartTime']).dt.total_seconds()

# Group IAT aggregates
iat_stats = df.groupby(['SrcAddr', 'DstAddr', 'Dport'])['IAT_SrcDst'].agg(
    IAT_Mean_SrcDst='mean',
    IAT_Std_SrcDst='std',
    IAT_Median_SrcDst='median',
    IAT_Min_SrcDst='min',
    IAT_Max_SrcDst='max'
).reset_index()

df = df.merge(iat_stats, on=['SrcAddr', 'DstAddr', 'Dport'], how='left')

# 4. Periodicity / Regularity
safe_iat_mean = np.where(df['IAT_Mean_SrcDst'] > 0, df['IAT_Mean_SrcDst'], np.nan)
df['IAT_CV_SrcDst'] = np.where(df['IAT_Mean_SrcDst'] > 0, df['IAT_Std_SrcDst'] / safe_iat_mean, np.nan)
df['IAT_Regularity'] = 1.0 / (1.0 + df['IAT_CV_SrcDst'].fillna(10.0))

# 5. Source Frequency & Endpoints
df['Src_TotalFlows'] = df.groupby('SrcAddr')['StartTime'].transform('count')
df['Src_UniqueDst'] = df.groupby('SrcAddr')['DstAddr'].transform('nunique')
df['Src_UniqueDport'] = df.groupby('SrcAddr')['Dport'].transform('nunique')
df['Src_Dst_Concentration'] = df['Src_UniqueDst'] / df['Src_TotalFlows']
df['DstFanoutRatio'] = df['Src_Dst_Concentration']

# 6. Source-Destination Repeat Features
df['SrcDst_TotalFlows'] = df.groupby(['SrcAddr', 'DstAddr'])['StartTime'].transform('count')
df['SrcDstPort_TotalFlows'] = df.groupby(['SrcAddr', 'DstAddr', 'Dport'])['StartTime'].transform('count')
df['RepeatRatio_SrcDst'] = df['SrcDst_TotalFlows'] / df['Src_TotalFlows']

# 7. Sliding Window Activity (60s and 300s)
# Sort by StartTime for chronological rolling
df_chrono = df.sort_values(by='StartTime').reset_index(drop=True)

# Using searchsorted for fast sliding window counts
times = df_chrono['StartTime'].values.astype('datetime64[ns]').astype('int64') // 10**9 # epoch seconds

# Rolling for each source
src_60s = np.zeros(len(df_chrono), dtype=int)
src_300s = np.zeros(len(df_chrono), dtype=int)
srcdst_60s = np.zeros(len(df_chrono), dtype=int)

for src, idxs in df_chrono.groupby('SrcAddr').groups.items():
    sub_times = times[idxs]
    # For each flow in sub_times, count how many occurred in [t - 60, t]
    left_60 = np.searchsorted(sub_times, sub_times - 60, side='left')
    left_300 = np.searchsorted(sub_times, sub_times - 300, side='left')
    current_pos = np.arange(len(sub_times))
    src_60s[idxs] = current_pos - left_60 + 1
    src_300s[idxs] = current_pos - left_300 + 1

for srcdst, idxs in df_chrono.groupby(['SrcAddr', 'DstAddr']).groups.items():
    sub_times = times[idxs]
    left_60 = np.searchsorted(sub_times, sub_times - 60, side='left')
    current_pos = np.arange(len(sub_times))
    srcdst_60s[idxs] = current_pos - left_60 + 1

df_chrono['Src_Flows_60s'] = src_60s
df_chrono['Src_Flows_300s'] = src_300s
df_chrono['SrcDst_Flows_60s'] = srcdst_60s

df = df_chrono

# 8. Protocol & Direction & State Flags
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

# 9. Packet & Byte Behavior
df['DestinationBytesApprox'] = np.maximum(0, df['TotBytes'] - df['SrcBytes'])
safe_tot_bytes = np.where(df['TotBytes'] > 0, df['TotBytes'], np.nan)
df['SourceByteRatio'] = np.where(df['TotBytes'] > 0, df['SrcBytes'] / safe_tot_bytes, 0.0)

# 10. Behavioral Indicators
df['IsRepeatedSrcDst'] = (df['SrcDst_TotalFlows'] > 1).astype(int)
src_95th = float(df['Src_TotalFlows'].quantile(0.95))
dur_median = float(df['Dur'].median())
df['IsHighFrequencySrc'] = (df['Src_TotalFlows'] >= src_95th).astype(int)
df['IsShortDuration'] = (df['Dur'] <= dur_median).astype(int)

print("Features calculated successfully.")
print("DataFrame shape:", df.shape)
print("95th percentile Src_TotalFlows threshold:", src_95th)
print("Median Duration threshold:", dur_median)
