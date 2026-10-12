import nbformat as nbf
from pathlib import Path

nb = nbf.v4.new_notebook()

cells = []

# Title
cells.append(nbf.v4.new_markdown_cell("""# SIH 2026 - Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
## Stage 1: Dataset Exploration (CIC-IDS2017)

This notebook performs a memory-safe exploratory analysis of the raw CIC-IDS2017 network traffic dataset.
It discovers all raw CSV partition files, inspects the schema and data structure, identifies target labels, and analyzes data quality (missing values and duplicate records) using a lightweight sample to preserve system memory (8 GB RAM target)."""))

# Section A Markdown
cells.append(nbf.v4.new_markdown_cell("""### A. Import Libraries
Import the necessary standard and data processing libraries (`pandas`, `pathlib`, `numpy`)."""))

# Section A Code
cells.append(nbf.v4.new_code_cell("""import os
import sys
import warnings
from pathlib import Path
import numpy as np
import pandas as pd

# Filter warnings for cleaner presentation
warnings.filterwarnings('ignore')

# Display settings for clear, readable outputs
pd.set_option('display.max_columns', 15)
pd.set_option('display.width', 1000)
pd.set_option('display.float_format', lambda x: f'{x:.4f}')

print(f"Pandas version: {pd.__version__}")
print(f"NumPy version: {np.__version__}")"""))

# Section B Markdown
cells.append(nbf.v4.new_markdown_cell("""### B. Locate the CIC-IDS2017 CSV Files
Search recursively inside `data/raw/MachineLearningCSV/` to identify all dataset partition files and display their sizes in MB without hardcoding filenames."""))

# Section B Code
cells.append(nbf.v4.new_code_cell("""# Resolve dataset directory relative to project root or current working directory
possible_dirs = [
    Path('data/raw/MachineLearningCSV'),
    Path('../data/raw/MachineLearningCSV'),
    Path.cwd() / 'data' / 'raw' / 'MachineLearningCSV',
    Path.cwd().parent / 'data' / 'raw' / 'MachineLearningCSV'
]

dataset_dir = None
for p in possible_dirs:
    if p.exists() and p.is_dir():
        dataset_dir = p.resolve()
        break

if dataset_dir is None:
    print(f"❌ ERROR: Dataset directory not found in candidate paths: {[str(p) for p in possible_dirs]}")
    csv_files = []
    total_size_mb = 0.0
else:
    # Recursively find all CSV files
    csv_files = sorted(list(dataset_dir.rglob('*.csv')))

print(f"Dataset Directory: {dataset_dir}")
print(f"Number of CSV files: {len(csv_files)}\\n")

if not csv_files:
    print("❌ ERROR: No CSV files found inside the dataset directory. Please verify that the dataset is extracted.")
    total_size_mb = 0.0
else:
    print(f"{'#':<3} | {'Filename':<55} | {'File Size (MB)':>15}")
    print("-" * 78)
    total_size_mb = 0.0
    for idx, f in enumerate(csv_files, 1):
        size_mb = f.stat().st_size / (1024 * 1024)
        total_size_mb += size_mb
        print(f"{idx:<3} | {f.name:<55} | {size_mb:>12.2f} MB")
    print("-" * 78)
    print(f"Total Approximate Size: {total_size_mb:.2f} MB ({total_size_mb / 1024:.2f} GB)")"""))

# Section C Markdown
cells.append(nbf.v4.new_markdown_cell("""### C. Inspect the Dataset Safely
Load a 1,000-row sample from the first discovered CSV file to inspect schema and structure safely without exhausting memory.
Display the filename, sample dimensions, column names, preview rows, and DataFrame info."""))

# Section C Code
cells.append(nbf.v4.new_code_cell("""sample_df = None
sample_file = None

if not csv_files:
    print("⚠️ Skipping inspection because no CSV files were found.")
else:
    sample_file = csv_files[0]
    try:
        sample_df = pd.read_csv(sample_file, nrows=1000)
        print(f"Filename: {sample_file.name}")
        print(f"Number of rows in sample: {len(sample_df)}")
        print(f"Number of columns: {len(sample_df.columns)}")
        
        print("\\n--- Column Names ---")
        for i, col in enumerate(sample_df.columns):
            print(f"{i+1:2d}. {repr(col)}")
        
        print("\\n--- First 5 Rows Preview ---")
        display(sample_df.head())
        
        print("\\n--- DataFrame Info ---")
        sample_df.info(verbose=True, show_counts=True)
    except Exception as e:
        print(f"❌ Error reading CSV file '{sample_file}': {e}")"""))

# Section D Markdown
cells.append(nbf.v4.new_markdown_cell("""### D. Identify the Target Label Column
Identify whether the target column `Label` exists (accounting for potential whitespace padding) and inspect class distribution within the 1,000-row sample."""))

# Section D Code
cells.append(nbf.v4.new_code_cell("""target_col = None

if sample_df is not None:
    # Check for 'Label' column (handling leading/trailing whitespace common in CIC-IDS2017)
    for col in sample_df.columns:
        if col.strip() == 'Label':
            target_col = col
            break

    if target_col is not None:
        print(f"✅ Found target label column: {repr(target_col)}")
        print(f"\\nLabel Distribution (1,000-row sample):")
        label_dist = sample_df[target_col].value_counts(dropna=False)
        print(label_dist)
        print(f"\\nNumber of unique labels in sample: {len(label_dist)}")
    else:
        print("⚠️ Warning: No column named 'Label' was found in the sample.")
        print(f"Available columns: {list(sample_df.columns)}")
else:
    print("⚠️ No sample data loaded.")"""))

# Section E Markdown
cells.append(nbf.v4.new_markdown_cell("""### E. Missing-Value Analysis
Calculate missing values per column, list columns with missing entries, and calculate total missing values across the sample."""))

# Section E Code
cells.append(nbf.v4.new_code_cell("""if sample_df is not None:
    missing_per_col = sample_df.isnull().sum()
    cols_with_missing = missing_per_col[missing_per_col > 0]
    total_missing = int(missing_per_col.sum())

    print(f"Total missing values in sample: {total_missing}")
    print(f"Number of columns with missing values: {len(cols_with_missing)}")
    
    if len(cols_with_missing) > 0:
        print("\\nColumns with Missing Values:")
        for col, count in cols_with_missing.items():
            pct = (count / len(sample_df)) * 100
            print(f" - {repr(col)}: {count} missing ({pct:.2f}%)")
    else:
        print("✅ No missing values detected in this 1,000-row sample.")
else:
    print("⚠️ No sample data loaded.")"""))

# Section F Markdown
cells.append(nbf.v4.new_markdown_cell("""### F. Duplicate Analysis
Calculate the number of duplicate rows present in the 1,000-row sample."""))

# Section F Code
cells.append(nbf.v4.new_code_cell("""if sample_df is not None:
    duplicate_count = int(sample_df.duplicated().sum())
    print(f"Number of duplicate rows in sample: {duplicate_count}")
    if duplicate_count > 0:
        pct_dup = (duplicate_count / len(sample_df)) * 100
        print(f"Duplicate percentage in sample: {pct_dup:.2f}%")
    else:
        print("✅ No duplicate rows found in this 1,000-row sample.")
else:
    print("⚠️ No sample data loaded.")"""))

# Section G Markdown
cells.append(nbf.v4.new_markdown_cell("""### G. Basic Numerical Inspection
Compute and display a compact descriptive-statistics table for numeric columns using `describe()`. Transposed summary view is used to maintain readability."""))

# Section G Code
cells.append(nbf.v4.new_code_cell("""if sample_df is not None:
    numeric_df = sample_df.select_dtypes(include=[np.number])
    print(f"Number of numeric columns: {len(numeric_df.columns)} / {len(sample_df.columns)}")
    
    # Generate descriptive statistics
    desc = numeric_df.describe().T
    
    # Display compact summary: count, mean, std, min, median (50%), max
    compact_desc = desc[['count', 'mean', 'std', 'min', '50%', 'max']].rename(columns={'50%': 'median'})
    
    print("\\n--- Compact Numerical Feature Statistics (First 15 Features) ---")
    display(compact_desc.head(15))
    
    print(f"\\nDescriptive statistics computed for all {len(numeric_df.columns)} numeric columns.")
else:
    print("⚠️ No sample data loaded.")"""))

# Section H Markdown
cells.append(nbf.v4.new_markdown_cell("""### H. Dataset Summary
Create a comprehensive summary table aggregating key findings from the exploratory inspection."""))

# Section H Code
cells.append(nbf.v4.new_code_cell("""summary_data = {
    "Metric": [
        "Number of CSV files",
        "Total approximate size of CSV files",
        "Sample rows inspected",
        "Number of features/columns",
        "Target column",
        "Number of unique labels in the sample",
        "Duplicate count",
        "Total missing values"
    ],
    "Value": [
        len(csv_files) if 'csv_files' in locals() else 0,
        f"{total_size_mb:.2f} MB ({total_size_mb / 1024:.2f} GB)" if 'total_size_mb' in locals() else "N/A",
        len(sample_df) if sample_df is not None else 0,
        len(sample_df.columns) if sample_df is not None else 0,
        repr(target_col) if target_col is not None else "Not Found",
        len(sample_df[target_col].value_counts()) if (sample_df is not None and target_col is not None) else 0,
        duplicate_count if 'duplicate_count' in locals() else 0,
        total_missing if 'total_missing' in locals() else 0
    ]
}

summary_df = pd.DataFrame(summary_data)
display(summary_df)"""))

# Next Steps Markdown
cells.append(nbf.v4.new_markdown_cell("""## Next Steps
- Clean and standardize the dataset
- Analyze attack classes
- Prepare datasets for threat-specific detection engines
- Split data for model training and evaluation"""))

nb.cells = cells

output_path = Path('notebooks/01_dataset_exploration.ipynb')
output_path.parent.mkdir(parents=True, exist_ok=True)
with open(output_path, 'w', encoding='utf-8') as f:
    nbf.write(nb, f)

print(f"Successfully generated {output_path}")
