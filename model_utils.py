"""Shared training code. Used by train.py and as an automatic fallback by detector.py."""
import os
import pandas as pd, joblib
from redact import redact
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline, make_union

BASE = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE, "model.joblib")


def load_data():
    sms = pd.read_csv(os.path.join(BASE, "data", "sms.tsv"), sep="\t", header=None, names=["label", "text"])
    sms["y"] = (sms.label == "spam").astype(int)
    sms["src"] = "uci"
    frames = [sms[["text", "y", "src"]]]
    ind_path = os.path.join(BASE, "data", "indian.csv")
    if os.path.exists(ind_path):
        ind = pd.read_csv(ind_path)
        ind["y"] = (ind.label > 0).astype(int)  # 0 = legit, 1-4 = scam types
        ind["src"] = "indian"
        frames.append(ind[["text", "y", "src"]])
    df = pd.concat(frames, ignore_index=True)
    df["text"] = df["text"].astype(str).map(redact)
    return df.drop_duplicates("text")


def build_pipeline():
    feats = make_union(
        TfidfVectorizer(lowercase=True, ngram_range=(1, 2), min_df=2, sublinear_tf=True),
        TfidfVectorizer(lowercase=True, analyzer="char_wb", ngram_range=(3, 5), min_df=3, sublinear_tf=True),
    )
    return Pipeline([("f", feats), ("clf", LogisticRegression(max_iter=2000, class_weight="balanced", C=3))])


def train_and_save():
    df = load_data()
    model = build_pipeline().fit(df.text, df.y)
    joblib.dump(model, MODEL_PATH)
    return model
