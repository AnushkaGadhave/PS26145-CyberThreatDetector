"""
NETRA Local Windows Sensor - Feature Validation Module
Validates real-time extracted flow feature vectors against the exact input schemas
expected by the trained DDoS (74), PortScan (78), and Botnet C2 (46) models.
Ensures zero NaN/Inf values, correct column ordering, and physical sanity bounds.
"""

import json
import math
import logging
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional, Union
import numpy as np
import pandas as pd

from src.capture.flow_schema import FlowRecord
from src.detection.feature_adapter import FeatureAdapter

logger = logging.getLogger(__name__)


def _resolve_config_path(rel_or_abs: str) -> Path:
    """Resolve config path relative to workspace or backend root."""
    p = Path(rel_or_abs)
    if p.exists():
        return p
    backend_root = Path(__file__).resolve().parent.parent.parent
    candidate = backend_root / rel_or_abs
    if candidate.exists():
        return candidate
    return p


@dataclass
class ValidationResult:
    """Structured report of feature schema validation for a specific model."""
    model_name: str
    is_valid: bool
    expected_count: int
    actual_count: int
    ordering_matches: bool
    missing_features: List[str] = field(default_factory=list)
    extra_features: List[str] = field(default_factory=list)
    nan_inf_features: List[str] = field(default_factory=list)
    invalid_type_features: List[str] = field(default_factory=list)
    out_of_range_features: List[str] = field(default_factory=list)
    sample_values: Dict[str, float] = field(default_factory=dict)
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to serializable dictionary."""
        return asdict(self)


class FeatureValidator:
    """
    Validates runtime feature vectors against serialized model schema specifications.
    """
    def __init__(
        self,
        ddos_config_path: str = "models/ddos/ddos_model_config.json",
        portscan_config_path: str = "models/portscan/portscan_model_config.json",
        c2_config_path: str = "models/c2/c2_model_config.json"
    ):
        self.ddos_expected_features = self._load_features(ddos_config_path, default_count=74)
        self.portscan_expected_features = self._load_features(portscan_config_path, default_count=78)
        self.c2_expected_features = self._load_features(c2_config_path, default_count=46)

    def _load_features(self, config_path: str, default_count: int) -> List[str]:
        """Load feature column list from JSON configuration."""
        p = _resolve_config_path(config_path)
        if p.exists():
            try:
                with open(p, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                    features = cfg.get("feature_list", cfg.get("features", []))
                    if features:
                        return list(features)
            except Exception as e:
                logger.error(f"Error loading features from {config_path}: {e}")
        logger.warning(f"Feature config not found at {config_path}; using empty list.")
        return []

    def validate_vector(
        self,
        df: pd.DataFrame,
        model_name: str,
        expected_features: List[str]
    ) -> ValidationResult:
        """
        Validates a single-row DataFrame feature vector against expected schema.
        """
        if df is None or df.empty:
            return ValidationResult(
                model_name=model_name,
                is_valid=False,
                expected_count=len(expected_features),
                actual_count=0,
                ordering_matches=False,
                error_message="Feature DataFrame is empty or None."
            )

        actual_cols = list(df.columns)
        actual_count = len(actual_cols)
        expected_count = len(expected_features)

        missing = [f for f in expected_features if f not in actual_cols]
        extra = [f for f in actual_cols if f not in expected_features]
        ordering_matches = (actual_cols == expected_features)

        nan_inf = []
        invalid_type = []
        out_of_range = []
        sample_values = {}

        row_series = df.iloc[0]

        for col in actual_cols:
            val = row_series[col]

            # 1. Type validation
            if not isinstance(val, (int, float, np.integer, np.floating)):
                invalid_type.append(f"{col}: {type(val).__name__}")
                continue

            float_val = float(val)

            # 2. NaN / Infinite check
            if math.isnan(float_val) or math.isinf(float_val):
                nan_inf.append(col)
                continue

            # 3. Range sanity check
            # Flow Duration must be non-negative
            if "duration" in col.lower() and float_val < 0.0:
                out_of_range.append(f"{col} < 0 ({float_val})")
            # Packets / Bytes counts must be non-negative
            elif ("packet" in col.lower() or "byte" in col.lower()) and "ratio" not in col.lower() and "per" not in col.lower() and float_val < 0.0:
                out_of_range.append(f"{col} < 0 ({float_val})")
            # Proportion / share metrics must be between 0.0 and 1.0
            elif any(tag in col.lower() for tag in ["share", "repeatratio", "sourcebyteratio"]) or (
                ("packetratio" in col.lower() or "byteratio" in col.lower())
                and "fwdbwd" not in col.lower()
                and "fwd_bwd" not in col.lower()
            ):
                if float_val < -0.01 or float_val > 1.01:
                    out_of_range.append(f"{col} out of [0, 1] ({float_val})")

            # Sample first 10 columns for quick telemetry inspection
            if len(sample_values) < 10:
                sample_values[col] = round(float_val, 4)

        is_valid = (
            len(missing) == 0
            and len(extra) == 0
            and len(nan_inf) == 0
            and len(invalid_type) == 0
            and len(out_of_range) == 0
            and ordering_matches
        )

        error_parts = []
        if missing:
            error_parts.append(f"Missing {len(missing)} features: {missing[:3]}")
        if extra:
            error_parts.append(f"Unexpected extra {len(extra)} features: {extra[:3]}")
        if not ordering_matches and not missing and not extra:
            error_parts.append("Feature column ordering does not match expected schema.")
        if nan_inf:
            error_parts.append(f"Found {len(nan_inf)} NaN/Inf values: {nan_inf[:3]}")
        if invalid_type:
            error_parts.append(f"Found {len(invalid_type)} invalid types: {invalid_type[:3]}")
        if out_of_range:
            error_parts.append(f"Found {len(out_of_range)} out of range values: {out_of_range[:3]}")

        error_message = "; ".join(error_parts) if error_parts else None

        return ValidationResult(
            model_name=model_name,
            is_valid=is_valid,
            expected_count=expected_count,
            actual_count=actual_count,
            ordering_matches=ordering_matches,
            missing_features=missing,
            extra_features=extra,
            nan_inf_features=nan_inf,
            invalid_type_features=invalid_type,
            out_of_range_features=out_of_range,
            sample_values=sample_values,
            error_message=error_message
        )

    def validate_ddos_features(self, df: pd.DataFrame) -> ValidationResult:
        """Validate feature vector for DDoS Random Forest model (74 features)."""
        return self.validate_vector(df, "RandomForest_DDoS", self.ddos_expected_features)

    def validate_portscan_features(self, df: pd.DataFrame) -> ValidationResult:
        """Validate feature vector for PortScan Isolation Forest model (78 features)."""
        return self.validate_vector(df, "IsolationForest_PortScan", self.portscan_expected_features)

    def validate_c2_features(self, df: pd.DataFrame) -> ValidationResult:
        """Validate feature vector for Botnet C2 Hybrid PCA model (46 features)."""
        return self.validate_vector(df, "HybridPCA_Botnet_C2", self.c2_expected_features)

    def validate_flow_all_models(
        self,
        adapter: FeatureAdapter,
        flow: FlowRecord
    ) -> Dict[str, ValidationResult]:
        """
        Translates a FlowRecord using FeatureAdapter and validates against all 3 models.
        """
        df_ddos = adapter.to_ddos_dataframe(flow)
        df_ps = adapter.to_portscan_dataframe(flow)
        df_c2 = adapter.to_c2_dataframe(flow)

        return {
            "ddos": self.validate_ddos_features(df_ddos),
            "portscan": self.validate_portscan_features(df_ps),
            "c2": self.validate_c2_features(df_c2)
        }
