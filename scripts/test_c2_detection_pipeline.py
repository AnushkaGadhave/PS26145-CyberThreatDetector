import json
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from scipy.spatial import cKDTree

from test_custom_ml import CustomPCA, FastDBSCAN, compute_classification_metrics, compute_confusion_matrix

def main():
    print("--- 1. Load Data ---")
    df_full = pd.read_csv('data/processed/CTU13/ctu13_c2_online_features.csv')
    df_model = pd.read_csv('data/processed/CTU13/ctu13_c2_online_model_features.csv')
    audit = pd.read_csv('data/processed/CTU13/ctu13_online_feature_audit.csv')

    print(f"Full dataset shape: {df_full.shape}")
    print(f"Model dataset shape: {df_model.shape}")
    
    assert len(df_full) == len(df_model), "Row counts mismatch"
    assert (df_full['BinaryLabel'] == df_model['BinaryLabel']).all(), "BinaryLabels mismatch"
    
    online_features = [c for c in df_model.columns if c != 'BinaryLabel']
    print(f"Online feature count: {len(online_features)}")

    # Chronological Split
    split_idx = int(0.70 * len(df_full))
    train_full = df_full.iloc[:split_idx].copy()
    test_full = df_full.iloc[split_idx:].copy()
    
    train_model = df_model.iloc[:split_idx].copy()
    test_model = df_model.iloc[split_idx:].copy()
    
    y_train = train_model['BinaryLabel'].values
    y_test = test_model['BinaryLabel'].values

    print(f"Train split: {len(train_model)} flows | Botnet: {(y_train==1).sum()}, Normal: {(y_train==0).sum()}")
    print(f"Test split:  {len(test_model)} flows | Botnet: {(y_test==1).sum()}, Normal: {(y_test==0).sum()}")

    # Normal Training Baseline
    normal_mask_train = (y_train == 0)
    X_train_normal = train_model.loc[normal_mask_train, online_features].copy()
    print(f"Normal training baseline size: {len(X_train_normal)}")

    # Missing value handling check
    print(f"Any nulls in X_train_normal: {X_train_normal.isnull().sum().sum()}")
    print(f"Any nulls in test_model: {test_model[online_features].isnull().sum().sum()}")

    # StandardScaler fitted on Normal Training Baseline ONLY
    scaler = StandardScaler()
    X_train_normal_scaled = scaler.fit_transform(X_train_normal)
    X_train_all_scaled = scaler.transform(train_model[online_features])
    X_test_scaled = scaler.transform(test_model[online_features])

    # PCA fitted on Normal Training Baseline ONLY
    # Target 95% variance capped at max 15 components
    pca_pre = CustomPCA().fit(X_train_normal_scaled)
    cum_var = np.cumsum(pca_pre.explained_variance_ratio_)
    k_95 = int(np.argmax(cum_var >= 0.95) + 1)
    n_components = min(k_95, 15)
    print(f"PCA components needed for >=95% variance: {k_95}, capped at: {n_components}")
    print(f"Explained variance with {n_components} components: {cum_var[n_components-1]:.4f}")

    pca = CustomPCA(n_components=n_components, random_state=42)
    X_train_normal_pca = pca.fit_transform(X_train_normal_scaled)
    X_train_all_pca = pca.transform(X_train_all_scaled)
    X_test_pca = pca.transform(X_test_scaled)

    # Subsample normal training baseline if >20000 for DBSCAN execution
    if len(X_train_normal_pca) > 20000:
        np.random.seed(42)
        sample_indices = np.random.choice(len(X_train_normal_pca), size=20000, replace=False)
        X_dbscan_train = X_train_normal_pca[sample_indices]
        print(f"Subsampled normal training baseline to {len(X_dbscan_train)} flows for DBSCAN")
    else:
        X_dbscan_train = X_train_normal_pca
        print(f"Using full normal training baseline of {len(X_dbscan_train)} flows for DBSCAN")

    # Epsilon calibration via k-distance graph (k = min_samples = 20)
    min_samples = 20
    k = min_samples
    tree_kdist = cKDTree(X_dbscan_train)
    distances, _ = tree_kdist.query(X_dbscan_train, k=k)
    k_distances = distances[:, -1]
    
    eps_95 = float(np.percentile(k_distances, 95))
    eps_90 = float(np.percentile(k_distances, 90))
    print(f"k-distance (k={k}): min={k_distances.min():.4f}, median={np.median(k_distances):.4f}, 90th={eps_90:.4f}, 95th={eps_95:.4f}, max={k_distances.max():.4f}")
    calibrated_eps = eps_95
    print(f"Selected DBSCAN eps = {calibrated_eps:.4f}")

    # Train DBSCAN
    dbscan = FastDBSCAN(eps=calibrated_eps, min_samples=min_samples)
    dbscan.fit(X_dbscan_train)

    n_clusters = len(set(dbscan.labels_)) - (1 if -1 in dbscan.labels_ else 0)
    n_noise = (dbscan.labels_ == -1).sum()
    pct_noise = (n_noise / len(dbscan.labels_)) * 100
    print(f"DBSCAN training results on Normal baseline:")
    print(f" - Clusters: {n_clusters}")
    print(f" - Noise points: {n_noise} ({pct_noise:.2f}%)")
    print(f" - Core samples count: {len(dbscan.core_sample_indices_)}")

    # Out-of-sample DBSCAN scoring using cKDTree on core samples
    train_normal_dist, train_normal_dbscan_anomaly = dbscan.predict_distance_and_anomaly(X_train_normal_pca)
    test_dist, dbscan_test_anomaly = dbscan.predict_distance_and_anomaly(X_test_pca)

    print(f"DBSCAN Test Anomaly count: {dbscan_test_anomaly.sum()} / {len(dbscan_test_anomaly)} ({dbscan_test_anomaly.mean()*100:.2f}%)")

    # --- Statistical C2 Beaconing Detector ---
    beaconing_feat_defs = [
        ('IAT_Regularity_Causal', 'ascending'),      # high regularity is suspicious
        ('RepeatRatio_SrcDst_Causal', 'ascending'),  # high repeat ratio is suspicious
        ('SrcDst_Flows_60s', 'ascending'),           # high 60s count is suspicious
        ('SrcDst_Flows_BeforeOrAtT', 'ascending'),   # high cumulative count is suspicious
    ]
    
    print("\n--- Statistical Beaconing Calibration ---")
    train_normal_vals = {}
    for feat, _ in beaconing_feat_defs:
        train_normal_vals[feat] = np.sort(X_train_normal[feat].values)

    def score_beaconing(df_in):
        scores = np.zeros(len(df_in), dtype=float)
        for feat, direction in beaconing_feat_defs:
            ref_vals = train_normal_vals[feat]
            pos = np.searchsorted(ref_vals, df_in[feat].values, side='right')
            pct = pos / len(ref_vals)  # 0 to 1
            if direction == 'ascending':
                feat_score = pct
            else:
                feat_score = 1.0 - pct
            scores += feat_score
        return scores / len(beaconing_feat_defs)

    train_normal_beacon_scores = score_beaconing(X_train_normal)
    test_beacon_scores = score_beaconing(test_model[online_features])

    # Calibrate thresholds on Normal Training Baseline
    th_1pct = float(np.percentile(train_normal_beacon_scores, 99))
    th_5pct = float(np.percentile(train_normal_beacon_scores, 95))
    th_10pct = float(np.percentile(train_normal_beacon_scores, 90))

    print(f"Statistical Beaconing Thresholds (calibrated on Normal Train Baseline):")
    print(f" - 1% FPR Threshold: {th_1pct:.4f} (Actual Train-Normal FPR: {(train_normal_beacon_scores >= th_1pct).mean()*100:.2f}%)")
    print(f" - 5% FPR Threshold (Default): {th_5pct:.4f} (Actual Train-Normal FPR: {(train_normal_beacon_scores >= th_5pct).mean()*100:.2f}%)")
    print(f" - 10% FPR Threshold: {th_10pct:.4f} (Actual Train-Normal FPR: {(train_normal_beacon_scores >= th_10pct).mean()*100:.2f}%)")

    stat_test_anomaly = (test_beacon_scores >= th_5pct).astype(int)
    print(f"Statistical Beaconing Test Anomaly count: {stat_test_anomaly.sum()} / {len(stat_test_anomaly)} ({stat_test_anomaly.mean()*100:.2f}%)")

    # --- Hybrid Detector ---
    sorted_normal_dist = np.sort(train_normal_dist)
    def normalize_dbscan_dist(dist_arr):
        pos = np.searchsorted(sorted_normal_dist, dist_arr, side='right')
        return pos / len(sorted_normal_dist)

    train_normal_dbscan_norm = normalize_dbscan_dist(train_normal_dist)
    test_dbscan_norm = normalize_dbscan_dist(test_dist)

    train_normal_hybrid_score = 0.5 * train_normal_dbscan_norm + 0.5 * train_normal_beacon_scores
    test_hybrid_score = 0.5 * test_dbscan_norm + 0.5 * test_beacon_scores

    hybrid_th_5pct = float(np.percentile(train_normal_hybrid_score, 95))
    print(f"\nHybrid Score 5% FPR Threshold (calibrated on Normal Train): {hybrid_th_5pct:.4f} (Actual Train-Normal FPR: {(train_normal_hybrid_score >= hybrid_th_5pct).mean()*100:.2f}%)")

    hybrid_test_anomaly = (test_hybrid_score >= hybrid_th_5pct).astype(int)

    # Detection Reason for test rows
    reasons = []
    for d_anom, b_anom in zip(dbscan_test_anomaly, stat_test_anomaly):
        if d_anom == 1 and b_anom == 1:
            reasons.append("DBSCAN + C2 beaconing")
        elif d_anom == 1:
            reasons.append("DBSCAN anomaly")
        elif b_anom == 1:
            reasons.append("C2 beaconing behavior")
        else:
            reasons.append("No anomaly")

    # Evaluation Metrics
    m_dbscan = compute_classification_metrics(y_test, dbscan_test_anomaly, test_dist)
    m_stat = compute_classification_metrics(y_test, stat_test_anomaly, test_beacon_scores)
    m_hybrid = compute_classification_metrics(y_test, hybrid_test_anomaly, test_hybrid_score)

    print("\n================ EVALUATION ON TEST PERIOD ================")
    eval_df = pd.DataFrame([
        {'Detector': 'DBSCAN', **m_dbscan},
        {'Detector': 'Statistical Beaconing', **m_stat},
        {'Detector': 'Hybrid', **m_hybrid}
    ])
    print(eval_df[['Detector', 'Precision', 'Recall', 'F1', 'FPR', 'TPR', 'ROC_AUC', 'PR_AUC']])

if __name__ == '__main__':
    main()
