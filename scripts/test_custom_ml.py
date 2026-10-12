import numpy as np
import scipy.spatial
import scipy.linalg
from scipy.spatial import cKDTree

# 1. Exact PCA Implementation via SVD
class CustomPCA:
    def __init__(self, n_components=None, random_state=None):
        self.n_components = n_components
        self.random_state = random_state
        self.components_ = None
        self.explained_variance_ = None
        self.explained_variance_ratio_ = None
        self.mean_ = None
        self.n_components_ = None

    def fit(self, X):
        X = np.asarray(X, dtype=np.float64)
        n_samples, n_features = X.shape
        self.mean_ = np.mean(X, axis=0)
        X_centered = X - self.mean_
        
        # SVD of centered matrix
        U, S, Vt = np.linalg.svd(X_centered, full_matrices=False)
        
        # Explained variance
        explained_variance = (S ** 2) / (n_samples - 1)
        total_var = np.sum(explained_variance)
        explained_variance_ratio = explained_variance / total_var
        
        if self.n_components is None:
            n_comp = n_features
        elif isinstance(self.n_components, (int, np.integer)):
            n_comp = min(self.n_components, n_features)
        elif isinstance(self.n_components, float) and 0.0 < self.n_components < 1.0:
            cum_var = np.cumsum(explained_variance_ratio)
            n_comp = int(np.argmax(cum_var >= self.n_components) + 1)
        else:
            n_comp = n_features
            
        self.n_components_ = n_comp
        self.components_ = Vt[:n_comp]
        self.explained_variance_ = explained_variance[:n_comp]
        self.explained_variance_ratio_ = explained_variance_ratio[:n_comp]
        return self

    def transform(self, X):
        X = np.asarray(X, dtype=np.float64)
        X_centered = X - self.mean_
        return np.dot(X_centered, self.components_.T)

    def fit_transform(self, X):
        return self.fit(X).transform(X)

# 2. Exact Fast DBSCAN Implementation via cKDTree
class FastDBSCAN:
    def __init__(self, eps=0.5, min_samples=5):
        self.eps = eps
        self.min_samples = min_samples
        self.labels_ = None
        self.core_sample_indices_ = None
        self.components_ = None
        self.tree_ = None

    def fit(self, X):
        X = np.asarray(X, dtype=np.float64)
        n_samples = X.shape[0]
        self.tree_ = cKDTree(X)
        
        # Find all points within eps
        neighbors = self.tree_.query_ball_point(X, r=self.eps)
        
        # Identify core points
        is_core = np.array([len(nbrs) >= self.min_samples for nbrs in neighbors], dtype=bool)
        self.core_sample_indices_ = np.where(is_core)[0]
        self.components_ = X[self.core_sample_indices_]
        
        labels = np.full(n_samples, -1, dtype=int)
        cluster_id = 0
        
        for i in range(n_samples):
            if labels[i] != -1 or not is_core[i]:
                continue
            
            # Start a new cluster
            labels[i] = cluster_id
            queue = list(neighbors[i])
            visited = set(queue)
            visited.add(i)
            
            head = 0
            while head < len(queue):
                neighbor_idx = queue[head]
                head += 1
                
                if labels[neighbor_idx] == -1:
                    labels[neighbor_idx] = cluster_id
                
                if is_core[neighbor_idx]:
                    for next_nbr in neighbors[neighbor_idx]:
                        if next_nbr not in visited:
                            visited.add(next_nbr)
                            queue.append(next_nbr)
            
            cluster_id += 1
            
        self.labels_ = labels
        return self

    def predict_distance_and_anomaly(self, X):
        X = np.asarray(X, dtype=np.float64)
        if len(self.core_sample_indices_) == 0:
            # If no core points, everything is an anomaly
            return np.full(len(X), np.inf), np.ones(len(X), dtype=int)
            
        core_tree = cKDTree(self.components_)
        distances, _ = core_tree.query(X, k=1)
        anomalies = (distances > self.eps).astype(int)
        return distances, anomalies

# 3. Pure Vectorized Classification & Curve Metrics
def compute_confusion_matrix(y_true, y_pred):
    y_true = np.asarray(y_true, dtype=int)
    y_pred = np.asarray(y_pred, dtype=int)
    tp = np.sum((y_true == 1) & (y_pred == 1))
    fp = np.sum((y_true == 0) & (y_pred == 1))
    tn = np.sum((y_true == 0) & (y_pred == 0))
    fn = np.sum((y_true == 1) & (y_pred == 0))
    return np.array([[tn, fp], [fn, tp]])

def compute_classification_metrics(y_true, y_pred, y_prob=None):
    cm = compute_confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    total = tn + fp + fn + tp
    acc = (tp + tn) / total if total > 0 else 0.0
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    tpr = rec
    
    roc_auc = np.nan
    pr_auc = np.nan
    
    if y_prob is not None:
        y_prob = np.asarray(y_prob, dtype=np.float64)
        y_true = np.asarray(y_true, dtype=int)
        
        # Vectorized ROC-AUC via rank-sum (Wilcoxon-Mann-Whitney)
        pos_scores = y_prob[y_true == 1]
        neg_scores = y_prob[y_true == 0]
        n_pos = len(pos_scores)
        n_neg = len(neg_scores)
        
        if n_pos > 0 and n_neg > 0:
            order = np.argsort(y_prob)
            ranks = np.empty_like(order, dtype=float)
            ranks[order] = np.arange(1, len(y_prob) + 1)
            
            # Handle ties
            unique_vals, inverse, counts = np.unique(y_prob, return_inverse=True, return_counts=True)
            if len(unique_vals) < len(y_prob):
                tie_ranks = np.bincount(inverse, weights=ranks) / counts
                ranks = tie_ranks[inverse]
                
            rank_sum_pos = np.sum(ranks[y_true == 1])
            roc_auc = (rank_sum_pos - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg)
            
            # Vectorized PR-AUC via thresholds
            sort_idx = np.argsort(-y_prob)
            y_sorted = y_true[sort_idx]
            cum_tp = np.cumsum(y_sorted == 1)
            cum_fp = np.cumsum(y_sorted == 0)
            
            precision_arr = cum_tp / (cum_tp + cum_fp)
            recall_arr = cum_tp / n_pos
            
            # Prepend (recall=0, precision=1) and trapezoidal integration
            rec_full = np.concatenate(([0.0], recall_arr))
            prec_full = np.concatenate(([1.0], precision_arr))
            if hasattr(np, 'trapezoid'):
                pr_auc = float(np.trapezoid(prec_full, rec_full))
            else:
                # Manual trapezoidal integration
                pr_auc = float(np.sum(np.diff(rec_full) * (prec_full[1:] + prec_full[:-1]) / 2.0))

    return {
        'Accuracy': float(acc),
        'Precision': float(prec),
        'Recall': float(rec),
        'F1': float(f1),
        'FPR': float(fpr),
        'TPR': float(tpr),
        'TP': int(tp),
        'FP': int(fp),
        'TN': int(tn),
        'FN': int(fn),
        'ROC_AUC': float(roc_auc) if not np.isnan(roc_auc) else None,
        'PR_AUC': float(pr_auc) if not np.isnan(pr_auc) else None
    }

print("All components defined successfully.")
