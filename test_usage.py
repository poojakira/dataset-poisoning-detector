import numpy as np
from poison_detector import detect

print("Running usage script...")

# 1. Try to USE it
clean_data = np.random.randn(100, 5).tolist()
poisoned_data = [[10.0, 10.0, 10.0, 10.0, 10.0], [-10.0, -10.0, -10.0, -10.0, -10.0]]
X_use = clean_data + poisoned_data
report = detect(X_use, method="ensemble")
print(f"Usage test poisoned count: {report.poisoned_count}")

# 2. Try to BREAK it
print("Running break script...")
try:
    X_nan = clean_data + [[np.nan]*5]
    detect(X_nan)
    print("Failed to break on NaN (or it handled it)")
except Exception as e:
    print(f"Broke on NaN: {type(e).__name__} - {e}")

try:
    detect([])
    print("Failed to break on empty (or it handled it)")
except Exception as e:
    print(f"Broke on empty: {type(e).__name__} - {e}")

try:
    # wrong shapes
    X_shapes = [[1, 2], [1, 2, 3], [1]]
    detect(X_shapes)
    print("Handled wrong shapes")
except Exception as e:
    print(f"Broke on wrong shapes: {type(e).__name__} - {e}")

print("Done.")
