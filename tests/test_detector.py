"""Run:  python -m pytest -q   (or)   python tests/test_detector.py"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pandas as pd
from detector import analyze

BASE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


def _acc(path):
    df = pd.read_csv(os.path.join(BASE, path))
    pred = [analyze(t)["level"] != "Low" for t in df.text]
    return sum(int(p) == y for p, y in zip(pred, df.y)) / len(df)


def test_known_scams_flagged():
    for t in ["Your SBI account will be blocked today. Update KYC at http://sbi-kyc.xyz",
              "You are under digital arrest. Do not tell anyone. This is CBI."]:
        assert analyze(t)["level"] == "High"


def test_normal_message_low():
    assert analyze("Hi, are we meeting at 6 pm tomorrow?")["level"] == "Low"


def test_accuracy_on_hand_written_sets():
    assert _acc("holdout_tests.csv") >= 0.85
    assert _acc("my_tests.csv") >= 0.85


if __name__ == "__main__":
    print("holdout_tests acc:", round(_acc("holdout_tests.csv"), 3))
    print("my_tests acc:", round(_acc("my_tests.csv"), 3))
