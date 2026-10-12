import sys
import time
from pathlib import Path
import nbformat
from nbconvert.preprocessors import ExecutePreprocessor

if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

nb_path = Path('notebooks/11_portscan_dataset_preparation.ipynb')
print(f"Reading {nb_path}...")
with open(nb_path, 'r', encoding='utf-8') as f:
    nb = nbformat.read(f, as_version=4)

ep = ExecutePreprocessor(timeout=1200, kernel_name='python3')

print("Executing all cells in notebook...")
t0 = time.time()
try:
    ep.preprocess(nb, {'metadata': {'path': str(nb_path.parent.resolve())}})
    exec_time = time.time() - t0
    print(f"Notebook execution completed successfully in {exec_time:.2f} seconds ({exec_time/60:.2f} minutes).")
except Exception as e:
    print(f"Execution error: {e}")
    raise
finally:
    print(f"Saving executed notebook to {nb_path}...")
    with open(nb_path, 'w', encoding='utf-8') as f:
        nbformat.write(nb, f)

# Verify execution status
errors = [
    (i + 1, o.ename, o.evalue)
    for i, c in enumerate(nb.cells)
    if c.cell_type == 'code'
    for o in getattr(c, 'outputs', [])
    if getattr(o, 'output_type', '') == 'error'
]
unexecuted = [
    i + 1
    for i, c in enumerate(nb.cells)
    if c.cell_type == 'code' and getattr(c, 'execution_count', None) is None
]

print(f"Unexecuted cells count: {len(unexecuted)} ({unexecuted})")
print(f"Error cells count:      {len(errors)} ({errors})")
if not errors and not unexecuted:
    print("STATUS: EXECUTED SUCCESSFULLY")
else:
    print("STATUS: NOT FULLY EXECUTED")
