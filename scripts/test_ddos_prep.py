import gc
import json
from pathlib import Path
from collections import Counter
import numpy as np
import pandas as pd

def main():
    raw_path = Path("data/processed/CIC_IDS2017_cleaned.csv")
    out_dir = Path("data/processed/CIC_IDS2017")
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Reading {raw_path} in chunks...")
    chunk_size = 200000
    
    # Check labels and extract DDoS + BENIGN
    chunks = []
    total_raw_rows = 0
    label_counts = Counter()
    
    for chunk in pd.read_csv(raw_path, chunksize=chunk_size):
        total_raw_rows += len(chunk)
        label_counts.update(chunk['Label'].values)
        
        mask = chunk['Label'].isin(['DDoS', 'BENIGN'])
        sub_chunk = chunk[mask].copy()
        chunks.append(sub_chunk)
        gc.collect()

    df = pd.concat(chunks, ignore_index=True)
    del chunks
    gc.collect()

    print(f"Total raw rows: {total_raw_rows:,}")
    print(f"Selected DDoS + BENIGN rows: {len(df):,}")
    
    # Map TrafficClass and BinaryLabel
    df['TrafficClass'] = np.where(df['Label'] == 'DDoS', 'DDoS', 'Normal')
    df['BinaryLabel'] = np.where(df['Label'] == 'DDoS', 1, 0).astype(int)

    n_ddos = (df['BinaryLabel'] == 1).sum()
    n_normal = (df['BinaryLabel'] == 0).sum()
    print(f"DDoS count: {n_ddos:,} ({n_ddos/len(df)*100:.2f}%)")
    print(f"Normal count: {n_normal:,} ({n_normal/len(df)*100:.2f}%)")

    # Feature Engineering (DDoS specific asymmetry & rates)
    tot_pkts = df['Total Fwd Packets'] + df['Total Backward Packets']
    tot_bytes = df['Total Length of Fwd Packets'] + df['Total Length of Bwd Packets']
    
    df['FwdBwdPacketRatio'] = np.where(df['Total Backward Packets'] > 0, df['Total Fwd Packets'] / df['Total Backward Packets'], df['Total Fwd Packets'])
    df['FwdBwdByteRatio'] = np.where(df['Total Length of Bwd Packets'] > 0, df['Total Length of Fwd Packets'] / df['Total Length of Bwd Packets'], df['Total Length of Fwd Packets'])
    df['FwdPacketShare'] = np.where(tot_pkts > 0, df['Total Fwd Packets'] / tot_pkts, 0.0)
    df['BwdPacketShare'] = np.where(tot_pkts > 0, df['Total Backward Packets'] / tot_pkts, 0.0)

    # Clean infinities and NaN if any
    num_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    num_cols = [c for c in num_cols if c not in ['BinaryLabel']]
    
    print(f"Checking {len(num_cols)} numerical features for inf/nan...")
    inf_count = np.isinf(df[num_cols].values).sum()
    nan_count = df[num_cols].isnull().sum().sum()
    print(f"Inf count: {inf_count}, NaN count: {nan_count}")

    # Model features
    DDOS_FEATURE_COLUMNS = num_cols
    print(f"Total candidate DDOS_FEATURE_COLUMNS: {len(DDOS_FEATURE_COLUMNS)}")

    # Deterministic Stratified Split 70/30 (since Timestamp is not in MachineLearningCSV)
    from sklearn.model_selection import train_test_split
    train_idx, test_idx = train_test_split(
        np.arange(len(df)),
        test_size=0.30,
        random_state=42,
        stratify=df['BinaryLabel'].values
    )
    
    train_df = df.iloc[train_idx]
    test_df = df.iloc[test_idx]
    
    print(f"Train rows: {len(train_df):,} | DDoS: {(train_df['BinaryLabel']==1).sum():,}, Normal: {(train_df['BinaryLabel']==0).sum():,}")
    print(f"Test rows:  {len(test_df):,} | DDoS: {(test_df['BinaryLabel']==1).sum():,}, Normal: {(test_df['BinaryLabel']==0).sum():,}")

if __name__ == '__main__':
    main()
