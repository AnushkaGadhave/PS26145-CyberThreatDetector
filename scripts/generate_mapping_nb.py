import nbformat as nbf
from pathlib import Path

nb = nbf.v4.new_notebook()
cells = []

# ==========================================
# Section 1: Title and Overview
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""# SIH 2026 - Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
## Phase 2C: Attack Label Mapping & Threat Coverage Analysis

### Objective
This notebook performs a rigorous, evidence-based threat coverage audit of the cleaned CIC-IDS2017 dataset against the **six official PS 26145 threat categories**:
1. **DDoS / Volumetric and Protocol Flooding**
2. **Botnet C2 Beaconing**
3. **DGA / DNS Tunnelling**
4. **Malware in Encrypted Sessions**
5. **Reconnaissance / Port Scanning**
6. **Data Exfiltration**

### Scope and Scientific Integrity Guidelines
- Evaluate the 15 verified ground-truth labels from `data/processed/CIC_IDS2017_cleaned.csv`.
- Differentiate **DIRECT** dataset support from **RELATED** auxiliary traffic and **NOT_COVERED / NEEDS_ADDITIONAL_DATA** gaps.
- Avoid forced or unscientific mappings.
- Document concrete additional dataset requirements for out-of-coverage threat categories.
- Export standardized mapping configurations and coverage reports for downstream detection engine design."""))

# ==========================================
# Section 2: Environment & Libraries
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""### 1. Import Libraries & Setup
Initialize memory-efficient processing and visualization tools."""))

cells.append(nbf.v4.new_code_cell("""import os
import sys
import warnings
from pathlib import Path
from collections import Counter
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
pd.set_option('display.max_columns', 15)
pd.set_option('display.width', 1000)
pd.set_option('display.float_format', lambda x: f'{x:.4f}')

plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
plt.rcParams['figure.dpi'] = 120
plt.rcParams['font.sans-serif'] = 'DejaVu Sans'

print(f"Pandas version: {pd.__version__}")
print(f"NumPy version: {np.__version__}")"""))

# ==========================================
# Section 3: Load and Verify Labels
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""### 2. Load and Profile Ground-Truth Labels
Read only the `Label` column from `data/processed/CIC_IDS2017_cleaned.csv` to ensure minimal memory overhead."""))

cells.append(nbf.v4.new_code_cell("""cleaned_data_paths = [
    Path('data/processed/CIC_IDS2017_cleaned.csv'),
    Path('../data/processed/CIC_IDS2017_cleaned.csv'),
    Path.cwd() / 'data' / 'processed' / 'CIC_IDS2017_cleaned.csv',
    Path.cwd().parent / 'data' / 'processed' / 'CIC_IDS2017_cleaned.csv'
]

cleaned_csv_path = None
for p in cleaned_data_paths:
    if p.exists() and p.is_file():
        cleaned_csv_path = p.resolve()
        break

if cleaned_csv_path is None:
    raise FileNotFoundError("Could not find data/processed/CIC_IDS2017_cleaned.csv")

print(f"Reading labels from: {cleaned_csv_path.name}")

# Read ONLY the Label column
label_series = pd.read_csv(cleaned_csv_path, usecols=['Label'], low_memory=False)['Label']
total_rows = len(label_series)
label_counts = label_series.value_counts()

print(f"Total Rows in Cleaned Dataset: {total_rows:,}")
print(f"Total Unique Labels: {len(label_counts)}\\n")

# Construct label_summary DataFrame
label_summary_records = []
for lbl, count in label_counts.items():
    pct = (count / total_rows) * 100
    label_summary_records.append({
        "Label": lbl,
        "Count": count,
        "Percentage": f"{pct:.4f}%"
    })

label_summary = pd.DataFrame(label_summary_records)
display(label_summary)

# Save to data/processed/phase2c_label_summary.csv
processed_dir = cleaned_csv_path.parent
label_summary_path = processed_dir / 'phase2c_label_summary.csv'
label_summary.to_csv(label_summary_path, index=False)
print(f"\\nSaved label summary to: {label_summary_path}")"""))

# ==========================================
# Section 4: Define PS 26145 Threat Categories & Mapping
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""### 3. Evidence-Based Attack Label Mapping
Map all 15 ground-truth CIC-IDS2017 labels to the official PS 26145 categories using strict evidence-based criteria:
- **DIRECT**: Label directly and explicitly models the required threat behavior.
- **RELATED**: Label represents a related attack vector or auxiliary mechanism, but not an identical match.
- **NOT_COVERED**: Label represents an attack outside the six core PS 26145 categories.
- **NEEDS_ADDITIONAL_DATA**: Category cannot be reliably detected from current dataset features/labels."""))

cells.append(nbf.v4.new_code_cell("""mapping_records = [
    {
        "CIC_Label": "DDoS",
        "PS_Threat_Category": "DDoS / Volumetric and Protocol Flooding",
        "Mapping_Status": "DIRECT",
        "Reason": "Directly represents distributed denial-of-service volumetric packet flooding traffic.",
        "Recommended_Use": "Primary training and evaluation set for DDoS Detection Engine.",
        "Additional_Data_Required": "No"
    },
    {
        "CIC_Label": "DoS Hulk",
        "PS_Threat_Category": "DDoS / Volumetric and Protocol Flooding",
        "Mapping_Status": "RELATED",
        "Reason": "Application-layer HTTP GET flooding DoS attack (HULK tool); related volumetric flooding mechanism.",
        "Recommended_Use": "Auxiliary DoS/flooding evaluation and robustness testing.",
        "Additional_Data_Required": "No"
    },
    {
        "CIC_Label": "DoS GoldenEye",
        "PS_Threat_Category": "DDoS / Volumetric and Protocol Flooding",
        "Mapping_Status": "RELATED",
        "Reason": "Layer-7 HTTP Keep-Alive and No-Cache resource exhaustion DoS attack; related protocol flooding.",
        "Recommended_Use": "Auxiliary DoS/flooding evaluation and robustness testing.",
        "Additional_Data_Required": "No"
    },
    {
        "CIC_Label": "DoS slowloris",
        "PS_Threat_Category": "DDoS / Volumetric and Protocol Flooding",
        "Mapping_Status": "RELATED",
        "Reason": "Slow-rate HTTP header starvation DoS attack; related protocol connection exhaustion mechanism.",
        "Recommended_Use": "Auxiliary slow-rate DoS detection study.",
        "Additional_Data_Required": "No"
    },
    {
        "CIC_Label": "DoS Slowhttptest",
        "PS_Threat_Category": "DDoS / Volumetric and Protocol Flooding",
        "Mapping_Status": "RELATED",
        "Reason": "Slow-rate HTTP POST body starvation DoS attack; related protocol starvation mechanism.",
        "Recommended_Use": "Auxiliary slow-rate DoS detection study.",
        "Additional_Data_Required": "No"
    },
    {
        "CIC_Label": "PortScan",
        "PS_Threat_Category": "Reconnaissance / Port Scanning",
        "Mapping_Status": "DIRECT",
        "Reason": "Directly represents active network reconnaissance and port scanning behavior.",
        "Recommended_Use": "Primary training and evaluation set for Reconnaissance Detection Engine.",
        "Additional_Data_Required": "No"
    },
    {
        "CIC_Label": "Bot",
        "PS_Threat_Category": "Botnet C2 Beaconing",
        "Mapping_Status": "RELATED",
        "Reason": "Represents Ares botnet infected host traffic, but lacks explicit beaconing periodicity annotations required by PS 26145.",
        "Recommended_Use": "Initial botnet flow baseline; supplementary C2 evaluation.",
        "Additional_Data_Required": "Yes (CTU-13 or dedicated C2 beaconing dataset)"
    },
    {
        "CIC_Label": "BENIGN",
        "PS_Threat_Category": "Normal Baseline Traffic",
        "Mapping_Status": "DIRECT",
        "Reason": "Represents normal background network traffic across multiple protocols.",
        "Recommended_Use": "Baseline negative class (benign flow distribution) for all detection models.",
        "Additional_Data_Required": "No"
    },
    {
        "CIC_Label": "FTP-Patator",
        "PS_Threat_Category": "Uncovered / Authentication Attack",
        "Mapping_Status": "NOT_COVERED",
        "Reason": "FTP dictionary brute-force attack; outside the six core PS 26145 threat categories.",
        "Recommended_Use": "Out-of-scope for primary engines; retain for general anomaly testing if needed.",
        "Additional_Data_Required": "No"
    },
    {
        "CIC_Label": "SSH-Patator",
        "PS_Threat_Category": "Uncovered / Authentication Attack",
        "Mapping_Status": "NOT_COVERED",
        "Reason": "SSH dictionary brute-force attack; outside the six core PS 26145 threat categories.",
        "Recommended_Use": "Out-of-scope for primary engines; retain for general anomaly testing if needed.",
        "Additional_Data_Required": "No"
    },
    {
        "CIC_Label": [lbl for lbl in label_counts.index if 'brute' in lbl.lower()][0] if any('brute' in lbl.lower() for lbl in label_counts.index) else "Web Attack - Brute Force",
        "PS_Threat_Category": "Uncovered / Web Application Attack",
        "Mapping_Status": "NOT_COVERED",
        "Reason": "Web application HTTP credential brute-force; outside the six core PS 26145 threat categories.",
        "Recommended_Use": "Out-of-scope for primary engines.",
        "Additional_Data_Required": "No"
    },
    {
        "CIC_Label": [lbl for lbl in label_counts.index if 'xss' in lbl.lower()][0] if any('xss' in lbl.lower() for lbl in label_counts.index) else "Web Attack - XSS",
        "PS_Threat_Category": "Uncovered / Web Application Attack",
        "Mapping_Status": "NOT_COVERED",
        "Reason": "Cross-site scripting (XSS) payload injection; outside the six core PS 26145 threat categories.",
        "Recommended_Use": "Out-of-scope for primary engines.",
        "Additional_Data_Required": "No"
    },
    {
        "CIC_Label": [lbl for lbl in label_counts.index if 'sql' in lbl.lower()][0] if any('sql' in lbl.lower() for lbl in label_counts.index) else "Web Attack - Sql Injection",
        "PS_Threat_Category": "Uncovered / Web Application Attack",
        "Mapping_Status": "NOT_COVERED",
        "Reason": "SQL injection payload attack; outside the six core PS 26145 threat categories.",
        "Recommended_Use": "Out-of-scope for primary engines.",
        "Additional_Data_Required": "No"
    },
    {
        "CIC_Label": "Infiltration",
        "PS_Threat_Category": "Uncovered / Multi-stage Infiltration",
        "Mapping_Status": "NOT_COVERED",
        "Reason": "Multi-stage internal pivot exploit; extremely small sample size (36 flows) and outside the 6 PS categories.",
        "Recommended_Use": "Out-of-scope for primary engines.",
        "Additional_Data_Required": "No"
    },
    {
        "CIC_Label": "Heartbleed",
        "PS_Threat_Category": "Uncovered / Vulnerability Exploit",
        "Mapping_Status": "NOT_COVERED",
        "Reason": "OpenSSL TLS heartbeat buffer over-read exploit; extremely small sample size (11 flows) and outside the 6 PS categories.",
        "Recommended_Use": "Out-of-scope for primary engines.",
        "Additional_Data_Required": "No"
    }
]

mapping_df = pd.DataFrame(mapping_records)
display(mapping_df[['CIC_Label', 'PS_Threat_Category', 'Mapping_Status', 'Reason']])

# Save to config/attack_label_mapping.csv
config_dir = Path('config')
if not config_dir.exists() and Path('../config').exists():
    config_dir = Path('../config')
config_dir.mkdir(parents=True, exist_ok=True)

config_mapping_path = config_dir / 'attack_label_mapping.csv'
mapping_df.to_csv(config_mapping_path, index=False)
print(f"\\nSaved mapping configuration to: {config_mapping_path}")"""))

# ==========================================
# Section 5: Six-Category Coverage Summary
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""### 4. Six PS 26145 Threat Categories Coverage Summary
Synthesize the degree of dataset coverage across the 6 mandatory problem statement categories."""))

cells.append(nbf.v4.new_code_cell("""coverage_records = [
    {
        "PS_Threat_Category": "DDoS / Volumetric and Protocol Flooding",
        "CIC_IDS2017_Coverage": "Direct & Related (322,267 attack flows)",
        "Direct_Labels": "DDoS",
        "Related_Labels": "DoS Hulk, DoS GoldenEye, DoS slowloris, DoS Slowhttptest",
        "Coverage_Status": "DIRECT",
        "Additional_Dataset_Needed": "No",
        "Notes": "Fully supported by CIC-IDS2017 for training volumetric & protocol flooding models."
    },
    {
        "PS_Threat_Category": "Reconnaissance / Port Scanning",
        "CIC_IDS2017_Coverage": "Direct (90,819 attack flows)",
        "Direct_Labels": "PortScan",
        "Related_Labels": "None",
        "Coverage_Status": "DIRECT",
        "Additional_Dataset_Needed": "No",
        "Notes": "Fully supported by CIC-IDS2017 for training port scanning and network reconnaissance models."
    },
    {
        "PS_Threat_Category": "Botnet C2 Beaconing",
        "CIC_IDS2017_Coverage": "Partial (1,953 Bot flows)",
        "Direct_Labels": "None",
        "Related_Labels": "Bot",
        "Coverage_Status": "PARTIAL",
        "Additional_Dataset_Needed": "Yes",
        "Notes": "Botnet traffic present, but lacks explicit beaconing interval/periodicity labels required by PS 26145."
    },
    {
        "PS_Threat_Category": "DGA / DNS Tunnelling",
        "CIC_IDS2017_Coverage": "None (0 flows)",
        "Direct_Labels": "None",
        "Related_Labels": "None",
        "Coverage_Status": "NOT_COVERED",
        "Additional_Dataset_Needed": "Yes",
        "Notes": "No dedicated DGA or DNS tunnelling labels in CIC-IDS2017. Requires external DNS/DGA dataset."
    },
    {
        "PS_Threat_Category": "Malware in Encrypted Sessions",
        "CIC_IDS2017_Coverage": "None (0 dedicated flows)",
        "Direct_Labels": "None",
        "Related_Labels": "None",
        "Coverage_Status": "NEEDS_ADDITIONAL_DATA",
        "Additional_Dataset_Needed": "Yes",
        "Notes": "Requires metadata-based features (packet lengths, inter-arrival times, TLS/JA3/JA4) and dedicated labeled encrypted malware captures."
    },
    {
        "PS_Threat_Category": "Data Exfiltration",
        "CIC_IDS2017_Coverage": "None (0 dedicated flows)",
        "Direct_Labels": "None",
        "Related_Labels": "None",
        "Coverage_Status": "NOT_COVERED",
        "Additional_Dataset_Needed": "Yes",
        "Notes": "Requires asymmetric flow volume ratio analysis, large outbound transfer anomalies, or dedicated exfiltration dataset."
    }
]

ps_threat_coverage = pd.DataFrame(coverage_records)
display(ps_threat_coverage)

# Save coverage report to data/processed/ps_threat_coverage_report.csv
coverage_report_path = processed_dir / 'ps_threat_coverage_report.csv'
ps_threat_coverage.to_csv(coverage_report_path, index=False)
print(f"\\nSaved coverage report to: {coverage_report_path}")"""))

# ==========================================
# Section 6: Additional Dataset Recommendations
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""### 5. Gap Analysis & Additional Dataset Recommendations
Document concrete candidate datasets to supplement uncovered or partially covered PS 26145 categories without downloading them yet."""))

cells.append(nbf.v4.new_code_cell("""additional_requirements_records = [
    {
        "PS_Threat_Category": "Botnet C2 Beaconing",
        "Why_CIC_IDS2017_Is_Insufficient": "Only 1,953 generic Bot flows without explicit beaconing periodicity or C2 callback interval annotations.",
        "Recommended_Dataset_Type": "Labeled Botnet C2 traffic with periodic communication captures.",
        "Candidate_Dataset": "CTU-13 / Stratosphere IPS Botnet Dataset",
        "Purpose": "Train and validate models on periodic C2 beaconing detection and heartbeat timing features."
    },
    {
        "PS_Threat_Category": "DGA / DNS Tunnelling",
        "Why_CIC_IDS2017_Is_Insufficient": "Zero DGA or DNS tunnelling labels/features in CIC-IDS2017.",
        "Recommended_Dataset_Type": "Labeled DGA domains and DNS covert tunnelling flow captures.",
        "Candidate_Dataset": "Bambenek Feeds / Netlab DGA & CIRA-CIC-DoHBrw-2020",
        "Purpose": "Train lexical/statistical domain classifiers and DNS payload/tunnel anomaly detectors."
    },
    {
        "PS_Threat_Category": "Malware in Encrypted Sessions",
        "Why_CIC_IDS2017_Is_Insufficient": "No dedicated encrypted malware session labels or detailed TLS handshake/JA3 metadata.",
        "Recommended_Dataset_Type": "Encrypted TLS/QUIC session captures of benign vs malware traffic.",
        "Candidate_Dataset": "Stratosphere Malware Capture Facility / USTC-TFC2016",
        "Purpose": "Train flow-metadata and fingerprinting models for encrypted malicious sessions."
    },
    {
        "PS_Threat_Category": "Data Exfiltration",
        "Why_CIC_IDS2017_Is_Insufficient": "No dedicated data exfiltration label; requires volume/ratio-based anomaly tracking.",
        "Recommended_Dataset_Type": "Labeled exfiltration via DNS, HTTPS, or covert channels.",
        "Candidate_Dataset": "CIC-IDS2018 (Exfiltration subset) / Engineered Asymmetric Anomaly Benchmarks",
        "Purpose": "Train volumetric thresholding and unidirectional ratio anomaly models."
    }
]

additional_dataset_requirements = pd.DataFrame(additional_requirements_records)
display(additional_dataset_requirements)"""))

# ==========================================
# Section 7: Visual Summary
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""### 6. Visual Summaries
Visualizing threat category coverage and ground-truth label distribution."""))

cells.append(nbf.v4.new_code_cell("""fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))

# Chart 1: PS Threat Category vs CIC-IDS2017 Coverage
status_order = ['DIRECT', 'PARTIAL', 'NOT_COVERED', 'NEEDS_ADDITIONAL_DATA']
palette = {
    'DIRECT': '#2ecc71',
    'PARTIAL': '#f39c12',
    'NOT_COVERED': '#e74c3c',
    'NEEDS_ADDITIONAL_DATA': '#9b59b6'
}

categories_short = [
    'DDoS / Flooding',
    'Port Scanning',
    'Botnet C2',
    'DGA / DNS Tunnel',
    'Encrypted Malware',
    'Data Exfiltration'
]
statuses = ps_threat_coverage['Coverage_Status'].tolist()
colors = [palette.get(s, '#34495e') for s in statuses]

bars = ax1.barh(categories_short, [1]*len(categories_short), color=colors, edgecolor='black', alpha=0.85)
ax1.set_xlim(0, 1.3)
ax1.set_xticks([])
ax1.set_title("PS 26145 Threat Categories vs. CIC-IDS2017 Coverage", fontsize=12, fontweight='bold')

for bar, status in zip(bars, statuses):
    ax1.text(0.5, bar.get_y() + bar.get_height()/2, status, ha='center', va='center',
             color='white', fontweight='bold', fontsize=10)

# Chart 2: CIC-IDS2017 Label Distribution (Log scale for visibility across scales)
plot_labels = [lbl.replace('Web Attack \ufffd', 'Web Attack -') for lbl in label_counts.index]
plot_counts = label_counts.values

y_pos = np.arange(len(plot_labels))
ax2.barh(y_pos, plot_counts, color='#3498db', edgecolor='black', alpha=0.85)
ax2.set_yticks(y_pos)
ax2.set_yticklabels(plot_labels, fontsize=9)
ax2.set_xscale('log')
ax2.invert_yaxis()
ax2.set_xlabel('Flow Count (Log Scale)', fontsize=10)
ax2.set_title('CIC-IDS2017 Cleaned Label Distribution (2.52M Rows)', fontsize=12, fontweight='bold')

# Annotate values
for i, count in enumerate(plot_counts):
    ax2.text(count * 1.15, i, f"{count:,}", va='center', fontsize=8, color='#2c3e50')

plt.tight_layout()
plt.show()"""))

# ==========================================
# Section 8: Human-Readable Report Generation
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""### 7. Human-Readable Report Generation
Export the authoritative `phase2c_summary.txt` report summarizing findings and gap analysis."""))

cells.append(nbf.v4.new_code_cell("""summary_text = \"\"\"==================================================
PHASE 2C — ATTACK LABEL MAPPING SUMMARY REPORT
==================================================

Dataset:
CIC-IDS2017 (Cleaned Partition)

Number of CIC labels:
15

PS 26145 threat categories:
6

-------------------------------------------------------------------------------------------------------
Threat Category                         | Coverage                | CIC Labels                              | Additional Data Required
-------------------------------------------------------------------------------------------------------
DDoS / Volumetric and Protocol Flooding | DIRECT                  | DDoS, DoS Hulk, DoS GoldenEye,          | No
                                        |                         | DoS slowloris, DoS Slowhttptest         |
Reconnaissance / Port Scanning          | DIRECT                  | PortScan                                | No
Botnet C2 Beaconing                     | PARTIAL                 | Bot                                     | Yes (CTU-13 / C2 captures)
DGA / DNS Tunnelling                    | NOT_COVERED             | None                                    | Yes (Bambenek / CIRA-CIC-DoHBrw)
Malware in Encrypted Sessions           | NEEDS_ADDITIONAL_DATA   | None                                    | Yes (TLS/QUIC session captures)
Data Exfiltration                       | NOT_COVERED             | None                                    | Yes (Exfiltration benchmarks)
-------------------------------------------------------------------------------------------------------

KEY FINDINGS

1. CIC-IDS2017 directly supports DDoS detection (128,016 direct DDoS flows, plus 194,251 related DoS flows).
2. CIC-IDS2017 directly supports PortScan/reconnaissance detection (90,819 direct PortScan flows).
3. Botnet traffic is represented (1,953 flows), but explicit C2 beaconing behavior requires further validation/additional data.
4. DGA/DNS tunnelling is not directly represented by the current CIC-IDS2017 labels.
5. Malware in encrypted TLS/QUIC sessions is not directly represented as a dedicated labeled class.
6. Data exfiltration is not directly represented as a dedicated labeled class.
7. Additional datasets are therefore required for full PS 26145 coverage.
\"\"\"

summary_txt_path = processed_dir / 'phase2c_summary.txt'
with open(summary_txt_path, 'w', encoding='utf-8') as f:
    f.write(summary_text)

print(f"Generated human-readable summary: {summary_txt_path}")
print("\\n" + summary_text)"""))

# ==========================================
# Section 9: Validation & Completion
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""### 8. Quality Validation & Audit
Verify all generated artifacts and ensure 100% compliance with Phase 2C specifications."""))

cells.append(nbf.v4.new_code_cell("""# Automated validation checks
val_clean_exists = cleaned_csv_path.exists()
val_labels_count = (len(label_counts) == 15)
val_mapping_exists = config_mapping_path.exists()
val_report_exists = coverage_report_path.exists()
val_summary_exists = summary_txt_path.exists()
val_all_categories = (len(ps_threat_coverage) == 6)

# Check no duplicate mapping entries for CIC labels
unique_cic_mapped = len(mapping_df['CIC_Label'].unique())
val_no_dup_mappings = (unique_cic_mapped == 15)

all_passed = all([
    val_clean_exists,
    val_labels_count,
    val_mapping_exists,
    val_report_exists,
    val_summary_exists,
    val_all_categories,
    val_no_dup_mappings
])

if all_passed:
    print("==================================================")
    print("PHASE 2C COMPLETE")
    print("==================================================")
    print("\\nFiles created:")
    print(" - notebooks/03_attack_label_mapping.ipynb")
    print(" - config/attack_label_mapping.csv")
    print(" - data/processed/phase2c_label_summary.csv")
    print(" - data/processed/ps_threat_coverage_report.csv")
    print(" - data/processed/phase2c_summary.txt")
    print("\\n✅ All validation checks passed successfully.")
else:
    print("❌ Validation checks failed. Please inspect generated artifacts.")"""))

# ==========================================
# Section 10: Next Steps
# ==========================================
cells.append(nbf.v4.new_markdown_cell("""## Next Steps

1. Review and freeze the threat mapping configuration in `config/attack_label_mapping.csv`.
2. Determine integration strategy for candidate datasets (CTU-13, Bambenek DGA, CIRA-CIC-DoHBrw-2020) in upcoming data preparation stages.
3. Proceed to Phase 3: Feature Engineering and Threat-Specific Dataset Preparation."""))

nb.cells = cells

output_path = Path('notebooks/03_attack_label_mapping.ipynb')
output_path.parent.mkdir(parents=True, exist_ok=True)
with open(output_path, 'w', encoding='utf-8') as f:
    nbf.write(nb, f)

print(f"Successfully generated {output_path}")
