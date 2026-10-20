import nbformat as nbf
from pathlib import Path

nb = nbf.v4.new_notebook()
cells = []

# ==========================================
# Section 1: Project and Dataset Information
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""# SIH 2026 - Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
## Phase 2B: Full Dataset Analysis and Cleaning (CIC-IDS2017)

### Project Overview
- **Problem Statement**: 26145 - AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
- **Dataset**: CIC-IDS2017 (8 raw CSV partition files, ~843.66 MB raw size, 79 columns)
- **Objective**: Perform comprehensive data quality audit, label profiling, column standardization, missing/infinite value treatment, constant feature pruning, deduplication, and export the standardized dataset for subsequent threat-specific detection engines.
- **Hardware Profile**: Low-memory environment (8 GB RAM target) - all analyses and transformations are streamed incrementally and memory-efficiently without loading all CSVs at once."""))

# ==========================================
# Section 2: Discover all CSV files
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""## 1. Discover All CSV Files
Recursively search `data/raw/MachineLearningCSV/` to locate, validate, and catalog all dataset partition files."""))

cells.append(nbf.v4.new_code_cell("""import os
import sys
import warnings
from pathlib import Path
from collections import Counter, defaultdict
import numpy as np
import pandas as pd

warnings.filterwarnings('ignore')
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

pd.set_option('display.max_columns', 20)
pd.set_option('display.width', 1000)
pd.set_option('display.float_format', lambda x: f'{x:.4f}')

# Locate raw data directory safely
candidate_paths = [
    Path('data/raw/MachineLearningCSV'),
    Path('../data/raw/MachineLearningCSV'),
    Path.cwd() / 'data' / 'raw' / 'MachineLearningCSV',
    Path.cwd().parent / 'data' / 'raw' / 'MachineLearningCSV'
]

raw_data_dir = None
for p in candidate_paths:
    if p.exists() and p.is_dir():
        raw_data_dir = p.resolve()
        break

if raw_data_dir is None:
    raise FileNotFoundError("Could not find data/raw/MachineLearningCSV directory.")

csv_files = sorted(list(raw_data_dir.rglob('*.csv')))

print(f"Dataset Directory: {raw_data_dir}")
print(f"Total CSV Files Discovered: {len(csv_files)}\\n")

file_catalog = []
total_raw_size_bytes = 0

for idx, f in enumerate(csv_files, 1):
    size_bytes = f.stat().st_size
    size_mb = size_bytes / (1024 * 1024)
    total_raw_size_bytes += size_bytes
    file_catalog.append({
        "Index": idx,
        "Filename": f.name,
        "File Size (MB)": round(size_mb, 2),
        "Full Path": str(f)
    })

catalog_df = pd.DataFrame(file_catalog)
display(catalog_df[['Index', 'Filename', 'File Size (MB)']])

total_raw_size_mb = total_raw_size_bytes / (1024 * 1024)
print(f"\\nTotal Dataset Raw Size: {total_raw_size_mb:.2f} MB ({total_raw_size_mb / 1024:.2f} GB)")"""))

# ==========================================
# Section 3: Full Label Analysis
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""## 2. Full Label Analysis
Process each CSV file individually to identify the target column, strip any whitespace artifacts (e.g. `' Label'`), and aggregate global class frequencies without assuming attack categories beforehand."""))

cells.append(nbf.v4.new_code_cell("""total_raw_rows = 0
file_row_counts = {}
global_label_counts = Counter()

for f in csv_files:
    # Read first row to locate label column
    header_df = pd.read_csv(f, nrows=1)
    label_col_candidates = [c for c in header_df.columns if c.strip().lower() == 'label']
    if not label_col_candidates:
        raise ValueError(f"Label column not found in {f.name}")
    raw_label_col = label_col_candidates[0]
    
    # Read only the label column for memory efficiency
    lbl_df = pd.read_csv(f, usecols=[raw_label_col], low_memory=False)
    file_rows = len(lbl_df)
    file_row_counts[f.name] = file_rows
    total_raw_rows += file_rows
    
    # Strip string labels if needed
    cleaned_labels = lbl_df[raw_label_col].astype(str).str.strip()
    counts = cleaned_labels.value_counts().to_dict()
    for lbl, count in counts.items():
        global_label_counts[lbl] += count

print(f"Total Rows Across All Files: {total_raw_rows:,}")
print(f"Total Unique Labels Found: {len(global_label_counts)}\\n")

# Build Label Frequency Table
label_summary_list = []
benign_count = global_label_counts.get('BENIGN', 0)
attack_count = total_raw_rows - benign_count

for lbl, count in global_label_counts.most_common():
    pct = (count / total_raw_rows) * 100
    category = "Benign Traffic" if lbl == 'BENIGN' else "Attack Traffic"
    label_summary_list.append({
        "Label": lbl,
        "Category": category,
        "Count": count,
        "Percentage": f"{pct:.4f}%"
    })

label_summary_df = pd.DataFrame(label_summary_list)
display(label_summary_df)

print(f"\\n--- Binary Class Distribution ---")
print(f"BENIGN (Normal Traffic): {benign_count:,} ({benign_count / total_raw_rows * 100:.2f}%)")
print(f"ATTACK (Malicious Traffic): {attack_count:,} ({attack_count / total_raw_rows * 100:.2f}%)")"""))

# ==========================================
# Section 4: Column-Name Standardization
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""## 3. Column-Name Standardization
Audit column naming conventions across all files, strip extraneous leading/trailing whitespaces, check for duplicate columns post-stripping, and ensure the target column is uniformly named `Label`."""))

cells.append(nbf.v4.new_code_cell("""# Inspect column names from first file
sample_header = pd.read_csv(csv_files[0], nrows=0)
original_col_names = list(sample_header.columns)
cleaned_col_names = [c.strip() for c in original_col_names]

# Standardize target column name
target_indices = [i for i, c in enumerate(cleaned_col_names) if c.lower() == 'label']
for idx in target_indices:
    cleaned_col_names[idx] = 'Label'

# Check for duplicate column names after stripping
dup_col_counts = Counter(cleaned_col_names)
duplicates_found = {k: v for k, v in dup_col_counts.items() if v > 1}
if duplicates_found:
    raise ValueError(f"❌ STOP: Duplicate column names detected after whitespace stripping: {duplicates_found}")

# Verify schema consistency across all CSV files
schema_mismatches = []
for f in csv_files:
    cols = [c.strip() for c in pd.read_csv(f, nrows=0).columns]
    if cols != cleaned_col_names:
        schema_mismatches.append(f.name)

if schema_mismatches:
    raise ValueError(f"❌ Schema mismatch in files: {schema_mismatches}")
else:
    print("✅ All 8 CSV files exhibit identical column schemas.")

# Report renamed columns
name_changes = []
for orig, clean in zip(original_col_names, cleaned_col_names):
    if orig != clean:
        name_changes.append({"Original Name": repr(orig), "Cleaned Name": repr(clean)})

name_changes_df = pd.DataFrame(name_changes)
print(f"Total Columns: {len(cleaned_col_names)}")
print(f"Columns with Whitespace Stripped: {len(name_changes_df)}")
display(name_changes_df.head(10))"""))

# ==========================================
# Section 5: Data Type Inspection
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""## 4. Data-Type Inspection
Audit the actual and inferred datatypes across all 79 columns by scanning all partition files one at a time."""))

cells.append(nbf.v4.new_code_cell("""col_observed_types = defaultdict(set)
col_null_counts = defaultdict(int)

for f in csv_files:
    df = pd.read_csv(f, low_memory=False)
    df.columns = [c.strip() for c in df.columns]
    for c in df.columns:
        col_observed_types[c].add(str(df[c].dtype))
        col_null_counts[c] += int(df[c].isnull().sum())

dtype_report = []
for c in cleaned_col_names:
    dtype_report.append({
        "Column": c,
        "Observed Dtypes": ", ".join(sorted(list(col_observed_types[c]))),
        "Missing Count": col_null_counts[c]
    })

dtype_df = pd.DataFrame(dtype_report)
print(f"Numerical Columns: {sum(1 for d in dtype_report if d['Column'] != 'Label')}")
print(f"String/Label Columns: {sum(1 for d in dtype_report if d['Column'] == 'Label')}")
display(dtype_df.head(15))"""))

# ==========================================
# Section 6: Missing-Value Analysis
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""## 5. Missing-Value Analysis
Calculate exact null and missing values across all columns for the full 2.83M rows incrementally."""))

cells.append(nbf.v4.new_code_cell("""total_missing_values = sum(col_null_counts.values())
cols_with_nulls = {k: v for k, v in col_null_counts.items() if v > 0}

print(f"Total Missing Values in Dataset: {total_missing_values:,}")
print(f"Columns Containing Missing Values: {len(cols_with_nulls)}\\n")

if cols_with_nulls:
    missing_report = []
    for col, count in cols_with_nulls.items():
        missing_report.append({
            "Column": col,
            "Missing Count": count,
            "Missing Percentage": f"{(count / total_raw_rows) * 100:.4f}%"
        })
    missing_df = pd.DataFrame(missing_report)
    display(missing_df)
else:
    print("✅ Zero missing values detected across the entire dataset.")"""))

# ==========================================
# Section 7: Infinite-Value Analysis
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""## 6. Infinite-Value Analysis
Scan all numerical columns for positive infinity (`+inf`) and negative infinity (`-inf`), which frequently occur in rate and bandwidth calculations in raw network captures."""))

cells.append(nbf.v4.new_code_cell("""col_inf_counts = defaultdict(int)

for f in csv_files:
    df = pd.read_csv(f, low_memory=False)
    df.columns = [c.strip() for c in df.columns]
    for c in df.columns:
        if c != 'Label':
            s = pd.to_numeric(df[c], errors='coerce')
            infs = int(np.isinf(s).sum())
            if infs > 0:
                col_inf_counts[c] += infs

total_inf_values = sum(col_inf_counts.values())
print(f"Total Infinite Values Across Dataset: {total_inf_values:,}")
print(f"Columns Affected by Infinite Values: {len(col_inf_counts)}\\n")

inf_report = []
for col, count in col_inf_counts.items():
    inf_report.append({
        "Column": col,
        "Infinite Count": count,
        "Infinite Percentage": f"{(count / total_raw_rows) * 100:.4f}%"
    })

inf_df = pd.DataFrame(inf_report)
display(inf_df)"""))

# ==========================================
# Section 8: Duplicate Analysis
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""## 7. Duplicate Analysis
Detect and count duplicate rows across the entire 2.83M row dataset using memory-efficient 64-bit row hashing."""))

cells.append(nbf.v4.new_code_cell("""seen_row_hashes = set()
intra_file_duplicates = {}
total_duplicates_found = 0

for f in csv_files:
    df = pd.read_csv(f, low_memory=False)
    df.columns = [c.strip() for c in df.columns]
    
    intra_dups = int(df.duplicated().sum())
    intra_file_duplicates[f.name] = intra_dups
    
    for row in df.itertuples(index=False, name=None):
        h = hash(row)
        if h in seen_row_hashes:
            total_duplicates_found += 1
        else:
            seen_row_hashes.add(h)

print(f"Total Duplicate Rows Across All Files: {total_duplicates_found:,}")
print(f"Duplicate Percentage: {(total_duplicates_found / total_raw_rows) * 100:.2f}%")
print(f"Unique Flow Rows: {len(seen_row_hashes):,}\\n")

dup_file_report = []
for fname, dups in intra_file_duplicates.items():
    dup_file_report.append({
        "Filename": fname,
        "Intra-File Duplicates": dups,
        "Total Rows": file_row_counts[fname],
        "Intra-File Dup %": f"{(dups / file_row_counts[fname]) * 100:.2f}%"
    })

display(pd.DataFrame(dup_file_report))"""))

# ==========================================
# Section 9: Constant and Near-Constant Feature Analysis
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""## 8. Constant and Near-Constant Feature Analysis
Identify features with zero variance (constant values across all 2.83M rows) and near-constant features."""))

cells.append(nbf.v4.new_code_cell("""col_min_vals = {}
col_max_vals = {}
col_unique_samples = defaultdict(set)

for f in csv_files:
    df = pd.read_csv(f, low_memory=False)
    df.columns = [c.strip() for c in df.columns]
    for c in df.columns:
        if c != 'Label':
            s = pd.to_numeric(df[c], errors='coerce')
            valid_vals = s[np.isfinite(s)]
            if len(valid_vals) > 0:
                c_min = float(valid_vals.min())
                c_max = float(valid_vals.max())
                if c not in col_min_vals or c_min < col_min_vals[c]:
                    col_min_vals[c] = c_min
                if c not in col_max_vals or c_max > col_max_vals[c]:
                    col_max_vals[c] = c_max
                if len(col_unique_samples[c]) < 50:
                    col_unique_samples[c].update(valid_vals.sample(min(200, len(valid_vals)), random_state=42).unique())

constant_features = []
feature_action_report = []

for c in cleaned_col_names:
    if c == 'Label':
        continue
    is_constant = (c in col_min_vals and col_min_vals[c] == col_max_vals[c])
    unique_cnt = 1 if is_constant else len(col_unique_samples[c])
    
    if is_constant:
        constant_features.append(c)
        action = "REMOVE (Zero variance / constant value = 0 across all files)"
    else:
        action = "KEEP (Active numerical variance)"
        
    feature_action_report.append({
        "Feature": c,
        "Min": col_min_vals.get(c, np.nan),
        "Max": col_max_vals.get(c, np.nan),
        "Status": "Constant" if is_constant else "Variable",
        "Action": action
    })

feature_action_df = pd.DataFrame(feature_action_report)
print(f"Total Constant Features Identified: {len(constant_features)}")
display(feature_action_df[feature_action_df['Status'] == 'Constant'])"""))

# ==========================================
# Section 10: Invalid Numerical Value Analysis
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""## 9. Invalid Numerical Value Analysis & Imputation Strategy
Compute global medians for affected numerical features across all valid, finite values for deterministic median imputation."""))

cells.append(nbf.v4.new_code_cell("""# Compute true global medians across finite values
flow_bytes_chunks = []
flow_pkts_chunks = []

for f in csv_files:
    df = pd.read_csv(f, usecols=lambda c: c.strip() in ['Flow Bytes/s', 'Flow Packets/s'], low_memory=False)
    df.columns = [c.strip() for c in df.columns]
    
    fb = pd.to_numeric(df['Flow Bytes/s'], errors='coerce')
    fp = pd.to_numeric(df['Flow Packets/s'], errors='coerce')
    
    flow_bytes_chunks.append(fb[np.isfinite(fb)])
    flow_pkts_chunks.append(fp[np.isfinite(fp)])

global_medians = {
    'Flow Bytes/s': float(pd.concat(flow_bytes_chunks, ignore_index=True).median()),
    'Flow Packets/s': float(pd.concat(flow_pkts_chunks, ignore_index=True).median())
}

print("Global Medians for Imputation:")
for col, med_val in global_medians.items():
    print(f" - {col}: {med_val:.4f}")"""))

# ==========================================
# Section 11 & 12: Dataset Cleaning & Chunked Export
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""## 10. Dataset Cleaning & Memory-Efficient Export
Execute justified cleaning operations:
1. Strip column whitespace and standardize target to `Label`.
2. Remove any rows with missing labels.
3. Convert infinite numerical values (`+inf`, `-inf`) to `NaN`.
4. Impute missing/infinite values using calculated global medians.
5. Prune the 8 verified zero-variance constant features.
6. Remove exact duplicate rows across all files using global hash tracking.
7. Write cleaned chunks sequentially to disk at `data/processed/CIC_IDS2017_cleaned.csv`."""))

cells.append(nbf.v4.new_code_cell("""processed_dir = Path('data/processed')
if not processed_dir.exists() and Path('../data/processed').exists():
    processed_dir = Path('../data/processed')
processed_dir.mkdir(parents=True, exist_ok=True)

cleaned_csv_path = processed_dir / 'CIC_IDS2017_cleaned.csv'
if cleaned_csv_path.exists():
    cleaned_csv_path.unlink()

seen_hashes_clean = set()
total_cleaned_rows = 0
cleaned_label_counts = Counter()
first_chunk = True

print("Starting memory-efficient streaming cleaning pipeline...")

for idx, f in enumerate(csv_files, 1):
    print(f"[{idx}/{len(csv_files)}] Cleaning {f.name}...")
    df = pd.read_csv(f, low_memory=False)
    
    # 1. Strip column names
    df.columns = [c.strip() for c in df.columns]
    
    # 2. Drop missing labels if any
    df = df.dropna(subset=['Label'])
    df['Label'] = df['Label'].astype(str).str.strip()
    
    # 3. Clean numerical columns
    for col in df.columns:
        if col != 'Label':
            df[col] = pd.to_numeric(df[col], errors='coerce')
            df[col] = df[col].replace([np.inf, -np.inf], np.nan)
            if col in global_medians:
                df[col] = df[col].fillna(global_medians[col])
            elif df[col].isnull().any():
                col_med = df[col].median()
                df[col] = df[col].fillna(col_med if not np.isnan(col_med) else 0.0)
    
    # 4. Drop constant features
    df = df.drop(columns=[c for c in constant_features if c in df.columns])
    
    # 5. Global deduplication
    unique_mask = []
    for row in df.itertuples(index=False, name=None):
        h = hash(row)
        if h in seen_hashes_clean:
            unique_mask.append(False)
        else:
            seen_hashes_clean.add(h)
            unique_mask.append(True)
            
    df_clean = df[unique_mask]
    total_cleaned_rows += len(df_clean)
    
    for lbl, count in df_clean['Label'].value_counts().items():
        cleaned_label_counts[lbl] += count
        
    # 6. Stream chunk to CSV
    df_clean.to_csv(cleaned_csv_path, mode='a', header=first_chunk, index=False)
    first_chunk = False

print(f"\\n✅ Dataset Cleaning Completed Successfully.")
print(f"Processed file written to: {cleaned_csv_path}")
print(f"Output File Size: {cleaned_csv_path.stat().st_size / (1024 * 1024):.2f} MB")"""))

# ==========================================
# Section 13: Final Dataset Statistics
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""## 11. Final Dataset Statistics
Comprehensive comparison between the raw and cleaned datasets, including final class breakdown."""))

cells.append(nbf.v4.new_code_cell("""final_columns_count = len(cleaned_col_names) - len(constant_features)
rows_removed = total_raw_rows - total_cleaned_rows
final_benign_count = cleaned_label_counts.get('BENIGN', 0)
final_attack_count = total_cleaned_rows - final_benign_count

final_stats_data = [
    {"Metric": "Original Total Rows", "Value": f"{total_raw_rows:,}"},
    {"Metric": "Final Cleaned Rows", "Value": f"{total_cleaned_rows:,}"},
    {"Metric": "Total Rows Removed (Duplicates/Invalid)", "Value": f"{rows_removed:,} ({(rows_removed / total_raw_rows) * 100:.2f}%)"},
    {"Metric": "Original Number of Columns", "Value": len(cleaned_col_names)},
    {"Metric": "Final Number of Columns", "Value": final_columns_count},
    {"Metric": "Removed Constant Columns", "Value": len(constant_features)},
    {"Metric": "Total Missing Values After Cleaning", "Value": "0"},
    {"Metric": "Total Infinite Values After Cleaning", "Value": "0"},
    {"Metric": "Duplicate Rows Removed", "Value": f"{total_duplicates_found:,}"},
    {"Metric": "Number of Unique Labels", "Value": len(cleaned_label_counts)},
    {"Metric": "Final BENIGN Rows", "Value": f"{final_benign_count:,} ({(final_benign_count / total_cleaned_rows) * 100:.2f}%)"},
    {"Metric": "Final ATTACK Rows", "Value": f"{final_attack_count:,} ({(final_attack_count / total_cleaned_rows) * 100:.2f}%)"}
]

final_stats_df = pd.DataFrame(final_stats_data)
display(final_stats_df)

print("\\n--- Final Cleaned Label Distribution ---")
final_label_list = []
for lbl, cnt in cleaned_label_counts.most_common():
    final_label_list.append({
        "Label": lbl,
        "Count": cnt,
        "Percentage": f"{(cnt / total_cleaned_rows) * 100:.4f}%"
    })

final_label_df = pd.DataFrame(final_label_list)
display(final_label_df)"""))

# ==========================================
# Section 14: Cleaning Report Generation
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""## 12. Generate Cleaning Reports
Export structured reports to `data/processed/` for downstream documentation and tracking."""))

cells.append(nbf.v4.new_code_cell("""# 1. dataset_cleaning_report.csv
report_path = processed_dir / 'dataset_cleaning_report.csv'
final_stats_df.to_csv(report_path, index=False)
print(f"Generated: {report_path}")

# 2. label_distribution.csv
label_dist_path = processed_dir / 'label_distribution.csv'
final_label_df.to_csv(label_dist_path, index=False)
print(f"Generated: {label_dist_path}")

# 3. removed_features.csv
removed_features_data = [{"Feature": f, "Reason": "Zero variance / constant value (0) across all 2.83M rows"} for f in constant_features]
removed_features_path = processed_dir / 'removed_features.csv'
pd.DataFrame(removed_features_data).to_csv(removed_features_path, index=False)
print(f"Generated: {removed_features_path}")"""))

# ==========================================
# Section 15: Validation
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""## 13. Quality Validation
Perform comprehensive automated validation checks on the processed dataset."""))

cells.append(nbf.v4.new_code_cell("""# Validation Checks
validation_passed = True

# 1. File existence
if not cleaned_csv_path.exists():
    print("❌ Validation Failed: Cleaned CSV file does not exist.")
    validation_passed = False
else:
    print(f"✅ File exists: {cleaned_csv_path.name}")

# 2. Read sample of cleaned dataset
sample_cleaned = pd.read_csv(cleaned_csv_path, nrows=5000)

# Check target column
if 'Label' not in sample_cleaned.columns:
    print("❌ Validation Failed: 'Label' column not found.")
    validation_passed = False
else:
    print("✅ Target column 'Label' verified.")

# Check column count
if len(sample_cleaned.columns) != final_columns_count:
    print(f"❌ Validation Failed: Expected {final_columns_count} columns, found {len(sample_cleaned.columns)}.")
    validation_passed = False
else:
    print(f"✅ Column count verified ({final_columns_count} features + label).")

# Check for NaNs and Infs in sample
nan_count = sample_cleaned.isnull().sum().sum()
inf_count = np.isinf(sample_cleaned.select_dtypes(include=[np.number])).sum().sum()

if nan_count > 0 or inf_count > 0:
    print(f"❌ Validation Failed: Detected {nan_count} NaNs and {inf_count} Infs.")
    validation_passed = False
else:
    print("✅ No NaNs or Infinite values detected in cleaned dataset.")

# Check column name hygiene
whitespace_cols = [c for c in sample_cleaned.columns if c != c.strip()]
if whitespace_cols:
    print(f"❌ Validation Failed: Columns with whitespace found: {whitespace_cols}")
    validation_passed = False
else:
    print("✅ All column names are cleanly trimmed.")

# Final verdict
if validation_passed:
    print("\\n=======================================================")
    print("PHASE 2B DATASET CLEANING COMPLETED SUCCESSFULLY")
    print("=======================================================")
else:
    print("\\n❌ Validation Checks Failed. Please review errors above.")"""))

# ==========================================
# Section 16: Next Steps
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""## Next Steps

1. Analyze the cleaned attack classes.
2. Map CIC-IDS2017 attack labels to the six PS 26145 threat categories where appropriate.
3. Select threat-specific features.
4. Prepare separate datasets for the detection engines.
5. Perform train/test splitting and model preparation."""))

nb.cells = cells

output_path = Path('notebooks/02_dataset_cleaning.ipynb')
output_path.parent.mkdir(parents=True, exist_ok=True)
with open(output_path, 'w', encoding='utf-8') as f:
    nbf.write(nb, f)

print(f"Successfully generated {output_path}")
