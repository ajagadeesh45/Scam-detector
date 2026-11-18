import os, joblib
from rules import check
from redact import redact

_model = None


def _load():
    global _model
    if _model is None:
        try:
            _model = joblib.load(os.path.join(os.path.dirname(os.path.abspath(__file__)), "model.joblib"))
        except Exception:
            # model missing or built with another scikit-learn version -> retrain automatically
            from model_utils import train_and_save
            _model = train_and_save()
    return _model


def analyze(text: str):
    flags, rule_score = check(text)
    ml_prob = float(_load().predict_proba([redact(text)])[0][1])  # 0..1
    combined = 0.5 * rule_score + 0.5 * (ml_prob * 100)
    combined = max(combined, rule_score * 0.9)             # strong rules alone still raise the alarm
    combined = round(min(combined, 100))
    level = "High" if combined >= 40 else "Medium" if combined >= 22 else "Low"
    return {"score": combined, "level": level, "ml_prob": round(ml_prob * 100),
            "rule_score": rule_score, "flags": flags}
