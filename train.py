"""Train and evaluate. Run:  python train.py"""
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from redact import redact
from model_utils import load_data, build_pipeline, train_and_save

df = load_data()
X_tr, X_te, y_tr, y_te, s_tr, s_te = train_test_split(df.text, df.y, df.src, test_size=0.2, random_state=42, stratify=df.y)
model = build_pipeline().fit(X_tr, y_tr)
pred = model.predict(X_te)
print("=== Held-out test (same distribution as training) ===")
print(classification_report(y_te, pred, target_names=["safe", "scam"], digits=3))
for s in sorted(df.src.unique()):
    m = s_te == s
    print(f"  accuracy on {s}: {(pred[m] == y_te[m]).mean():.3f}")

try:
    mt = pd.read_csv("data/my_tests.csv")
    p = model.predict(mt.text.map(redact))
    print("\n=== Hand-written test set (ML model alone) ===")
    print(classification_report(mt.y, p, target_names=["safe", "scam"], digits=3))
except FileNotFoundError:
    print("\n(no data/my_tests.csv found)")

train_and_save()
print("\nSaved model.joblib")
